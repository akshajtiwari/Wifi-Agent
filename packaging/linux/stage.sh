#!/bin/sh
# Install WiFi Agent into a package staging root.
# Usage: stage.sh <destination-root> <version>
set -eu

DESTINATION=$1
VERSION=$2
ROOT=$(cd "$(dirname "$0")/../.." && pwd)

install -Dm644 "$ROOT/wifi_agent.py" "$DESTINATION/usr/lib/wifi-agent/wifi_agent.py"
install -Dm755 "$ROOT/packaging/linux/wifi-agent" "$DESTINATION/usr/bin/wifi-agent"
install -Dm755 "$ROOT/packaging/linux/user-services.sh" "$DESTINATION/usr/lib/wifi-agent/user-services.sh"
install -Dm644 "$ROOT/packaging/linux/wifi-agent.desktop" "$DESTINATION/usr/share/applications/wifi-agent.desktop"
install -Dm644 "$ROOT/packaging/linux/wifi-agent.svg" "$DESTINATION/usr/share/icons/hicolor/scalable/apps/wifi-agent.svg"
install -Dm644 "$ROOT/README.md" "$DESTINATION/usr/share/doc/wifi-agent/README.md"
install -Dm644 "$ROOT/CHANGELOG.md" "$DESTINATION/usr/share/doc/wifi-agent/CHANGELOG.md"

# Report the package version, as frozen Windows/macOS builds do.
sed -i "s/^APP_VERSION = \".*\"$/APP_VERSION = \"$VERSION\"/" "$DESTINATION/usr/lib/wifi-agent/wifi_agent.py"
grep -q "^APP_VERSION = \"$VERSION\"$" "$DESTINATION/usr/lib/wifi-agent/wifi_agent.py"
