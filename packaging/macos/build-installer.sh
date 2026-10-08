#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPOSITORY_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
PYTHON_BIN="${PYTHON_BIN:-python3}"
VERSION="${1:-${WIFI_AGENT_VERSION:-}}"

cd "$REPOSITORY_ROOT"
if [[ -z "$VERSION" ]]; then
    VERSION="$($PYTHON_BIN -c 'import wifi_agent; print(wifi_agent.APP_VERSION)')"
fi

BUILD_ROOT="$REPOSITORY_ROOT/build/macos"
ASSET_DIRECTORY="$BUILD_ROOT/assets"
OUTPUT_DIRECTORY="$BUILD_ROOT/installer"
APP_PATH="$BUILD_ROOT/dist/WiFi Agent.app"
ARCHITECTURE="$(uname -m)"
ARTIFACT_STEM="WiFiAgent-$VERSION-macOS-$ARCHITECTURE"

rm -rf "$BUILD_ROOT"
mkdir -p "$ASSET_DIRECTORY" "$OUTPUT_DIRECTORY"

"$PYTHON_BIN" packaging/generate_assets.py --version "$VERSION" --output-dir "$ASSET_DIRECTORY"

PYINSTALLER_ARGUMENTS=(
    --noconfirm
    --clean
    --windowed
    --onedir
    --name "WiFi Agent"
    --icon "$ASSET_DIRECTORY/wifi-agent.icns"
    --osx-bundle-identifier "com.akshajtiwari.wifiagent"
    --target-architecture "$ARCHITECTURE"
    --paths "$ASSET_DIRECTORY"
    --collect-submodules keyring.backends
    --hidden-import pystray._darwin
    --hidden-import PyObjCTools.AppHelper
    --distpath "$BUILD_ROOT/dist"
    --workpath "$BUILD_ROOT/work"
    --specpath "$BUILD_ROOT/spec"
)
if [[ -n "${MACOS_APP_SIGNING_IDENTITY:-}" ]]; then
    PYINSTALLER_ARGUMENTS+=(--codesign-identity "$MACOS_APP_SIGNING_IDENTITY")
fi
"$PYTHON_BIN" -m PyInstaller "${PYINSTALLER_ARGUMENTS[@]}" wifi_agent.py

/usr/libexec/PlistBuddy -c "Add :CFBundleShortVersionString string $VERSION" "$APP_PATH/Contents/Info.plist" 2>/dev/null \
    || /usr/libexec/PlistBuddy -c "Set :CFBundleShortVersionString $VERSION" "$APP_PATH/Contents/Info.plist"
/usr/libexec/PlistBuddy -c "Add :CFBundleVersion string $VERSION" "$APP_PATH/Contents/Info.plist" 2>/dev/null \
    || /usr/libexec/PlistBuddy -c "Set :CFBundleVersion $VERSION" "$APP_PATH/Contents/Info.plist"
# macOS 15 asks before an app may reach local-network hosts such as the
# 192.168.x.x portal; without a usage description the request is unexplained.
plutil -replace NSLocalNetworkUsageDescription -string \
    "WiFi Agent connects to your campus or office login portal on the local network to keep you signed in." \
    "$APP_PATH/Contents/Info.plist"
plutil -replace LSMinimumSystemVersion -string "10.13" "$APP_PATH/Contents/Info.plist"

if [[ -n "${MACOS_APP_SIGNING_IDENTITY:-}" ]]; then
    codesign --force --options runtime --timestamp --sign "$MACOS_APP_SIGNING_IDENTITY" "$APP_PATH"
else
    codesign --force --options runtime --sign - "$APP_PATH"
fi
codesign --verify --deep --strict --verbose=2 "$APP_PATH"

# Catch the most common "installs but will not open" failures before an
# installer is published: invalid final signing, missing Tcl/Tk, tray backend,
# vault, or image modules.
APP_EXECUTABLE="$APP_PATH/Contents/MacOS/WiFi Agent"
if ! "$APP_EXECUTABLE" self-test; then
    echo "The packaged macOS application failed its startup self-test." >&2
    exit 1
fi

PACKAGE_PATH="$OUTPUT_DIRECTORY/$ARTIFACT_STEM.pkg"
PACKAGE_PAYLOAD="$BUILD_ROOT/package-payload"
COMPONENT_PACKAGE="$BUILD_ROOT/WiFiAgent-component.pkg"
COMPONENT_PLIST="$BUILD_ROOT/component.plist"
mkdir -p "$PACKAGE_PAYLOAD/Applications"
ditto "$APP_PATH" "$PACKAGE_PAYLOAD/Applications/WiFi Agent.app"
# Bundles are relocatable by default: Installer then updates any other copy
# of the app it finds (a mounted DMG, Downloads) instead of /Applications,
# and the app never appears where the user and postinstall expect it.
pkgbuild --analyze --root "$PACKAGE_PAYLOAD" "$COMPONENT_PLIST"
COMPONENT_INDEX=0
while /usr/libexec/PlistBuddy -c "Print :$COMPONENT_INDEX" "$COMPONENT_PLIST" >/dev/null 2>&1; do
    /usr/libexec/PlistBuddy -c "Set :$COMPONENT_INDEX:BundleIsRelocatable false" "$COMPONENT_PLIST"
    COMPONENT_INDEX=$((COMPONENT_INDEX + 1))
done
pkgbuild \
    --root "$PACKAGE_PAYLOAD" \
    --component-plist "$COMPONENT_PLIST" \
    --identifier "com.akshajtiwari.wifiagent" \
    --version "$VERSION" \
    --install-location / \
    --scripts "$SCRIPT_DIR/scripts" \
    "$COMPONENT_PACKAGE"

PRODUCTBUILD_ARGUMENTS=(--package "$COMPONENT_PACKAGE")
if [[ -n "${MACOS_INSTALLER_SIGNING_IDENTITY:-}" ]]; then
    PRODUCTBUILD_ARGUMENTS+=(--sign "$MACOS_INSTALLER_SIGNING_IDENTITY")
fi
productbuild "${PRODUCTBUILD_ARGUMENTS[@]}" "$PACKAGE_PATH"

EXPANDED_PACKAGE="$BUILD_ROOT/expanded-package"
pkgutil --expand "$PACKAGE_PATH" "$EXPANDED_PACKAGE"
if sed -n '/<relocate>/,/<\/relocate>/p' "$EXPANDED_PACKAGE"/*.pkg/PackageInfo | grep -q '<bundle'; then
    echo "The package still marks WiFi Agent.app as relocatable." >&2
    exit 1
fi

DMG_STAGE="$BUILD_ROOT/dmg"
mkdir -p "$DMG_STAGE"
ditto "$APP_PATH" "$DMG_STAGE/WiFi Agent.app"
ln -s /Applications "$DMG_STAGE/Applications"
DMG_PATH="$OUTPUT_DIRECTORY/$ARTIFACT_STEM.dmg"
hdiutil create -volname "WiFi Agent" -srcfolder "$DMG_STAGE" -ov -format UDZO "$DMG_PATH"
if [[ -n "${MACOS_APP_SIGNING_IDENTITY:-}" ]]; then
    codesign --force --timestamp --sign "$MACOS_APP_SIGNING_IDENTITY" "$DMG_PATH"
fi

if [[ -n "${APPLE_NOTARY_KEYCHAIN_PROFILE:-}" ]]; then
    for artifact in "$PACKAGE_PATH" "$DMG_PATH"; do
        xcrun notarytool submit "$artifact" --keychain-profile "$APPLE_NOTARY_KEYCHAIN_PROFILE" --wait
        xcrun stapler staple "$artifact"
    done
fi

echo "macOS installers created in $OUTPUT_DIRECTORY"
