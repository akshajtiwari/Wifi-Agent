#!/bin/sh
# Build the Debian/Ubuntu package.
# Usage: build-deb.sh [version] [output-directory]
set -eu

ROOT=$(cd "$(dirname "$0")/../.." && pwd)
VERSION=${1:-$(sed -n 's/^APP_VERSION = "\(.*\)"$/\1/p' "$ROOT/wifi_agent.py")}
OUTPUT=${2:-$ROOT/build/linux}
STAGE=$(mktemp -d)
trap 'rm -rf "$STAGE"' EXIT
chmod 755 "$STAGE"

"$ROOT/packaging/linux/stage.sh" "$STAGE" "$VERSION"
install -d -m755 "$STAGE/DEBIAN"
SIZE=$(du -sk "$STAGE" | cut -f1)
sed -e "s/@VERSION@/$VERSION/" -e "s/@SIZE@/$SIZE/" "$ROOT/packaging/debian/control.in" > "$STAGE/DEBIAN/control"
install -m755 "$ROOT/packaging/debian/postinst" "$ROOT/packaging/debian/prerm" "$STAGE/DEBIAN/"

mkdir -p "$OUTPUT"
dpkg-deb --root-owner-group -Zxz --build "$STAGE" "$OUTPUT/wifi-agent_${VERSION}_all.deb"
