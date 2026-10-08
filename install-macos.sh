#!/usr/bin/env bash
# Install the latest WiFi Agent release on macOS from Terminal:
#
#   curl -fsSL https://raw.githubusercontent.com/akshajtiwari/Wifi-Agent/main/install-macos.sh | bash
#
# The release packages are not yet signed with an Apple Developer ID, so a
# package downloaded in a browser is blocked by Gatekeeper until it is
# allowed in System Settings. Files downloaded with curl carry no quarantine
# flag, so this installs directly. The package is verified against the
# SHA-256 digest GitHub publishes for the release asset before it is opened.
set -euo pipefail

REPOSITORY="akshajtiwari/Wifi-Agent"

fail() {
    echo "WiFi Agent install failed: $*" >&2
    exit 1
}

[[ "$(uname -s)" == "Darwin" ]] || fail "this installer is for macOS."
case "$(uname -m)" in
    arm64) ARCHITECTURE="arm64" ;;
    x86_64) ARCHITECTURE="x86_64" ;;
    *) fail "unsupported Mac architecture $(uname -m)." ;;
esac

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

curl -fsSL -H "Accept: application/vnd.github+json" \
    "https://api.github.com/repos/$REPOSITORY/releases/latest" -o "$WORK/release.json" \
    || fail "could not read the latest release from GitHub."

# JavaScript for Automation ships with macOS, so no Python is required.
ASSET="$(/usr/bin/osascript -l JavaScript -e '
function run(argv) {
    ObjC.import("Foundation");
    var text = $.NSString.stringWithContentsOfFileEncodingError(argv[0], $.NSUTF8StringEncoding, null).js;
    var release = JSON.parse(text);
    var suffix = "-macOS-" + argv[1] + ".pkg";
    var asset = (release.assets || []).find(function (item) { return item.name.endsWith(suffix); });
    if (!asset) { return ""; }
    return [asset.name, asset.browser_download_url, String(asset.digest || "").replace(/^sha256:/, "")].join("\n");
}' "$WORK/release.json" "$ARCHITECTURE")"
[[ -n "$ASSET" ]] || fail "the latest release has no package for $ARCHITECTURE Macs."

NAME="$(sed -n 1p <<<"$ASSET")"
URL="$(sed -n 2p <<<"$ASSET")"
DIGEST="$(sed -n 3p <<<"$ASSET" | tr '[:upper:]' '[:lower:]')"
[[ "$NAME" =~ ^WiFiAgent-[0-9]+\.[0-9]+\.[0-9]+-macOS-(arm64|x86_64)\.pkg$ ]] || fail "unexpected package name $NAME."
[[ "$URL" == "https://github.com/$REPOSITORY/releases/download/"* ]] || fail "untrusted download URL."
[[ "$DIGEST" =~ ^[0-9a-f]{64}$ ]] || fail "the release does not publish a SHA-256 digest for $NAME."

echo "Downloading $NAME…"
curl -fL --progress-bar "$URL" -o "$WORK/$NAME" || fail "download failed."
ACTUAL="$(shasum -a 256 "$WORK/$NAME" | awk '{print $1}')"
[[ "$ACTUAL" == "$DIGEST" ]] || fail "the download does not match GitHub's SHA-256 digest."

echo "Installing $NAME. macOS will ask for your administrator password."
sudo /usr/sbin/installer -pkg "$WORK/$NAME" -target / || fail "the macOS installer reported an error."
echo "WiFi Agent is installed in /Applications. Its settings window opens now; finish setup there."
