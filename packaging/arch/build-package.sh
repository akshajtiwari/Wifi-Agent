#!/bin/sh
# Build the Arch Linux package and an AUR-ready PKGBUILD.
# Usage: build-package.sh [version] [output-directory]
# WIFI_AGENT_SOURCE_URL overrides where the PKGBUILD downloads the source.
set -eu

ROOT=$(cd "$(dirname "$0")/../.." && pwd)
VERSION=${1:-$(sed -n 's/^APP_VERSION = "\(.*\)"$/\1/p' "$ROOT/wifi_agent.py")}
OUTPUT=${2:-$ROOT/build/arch}
WORK="$OUTPUT/work"
TARBALL="wifi-agent-$VERSION.tar.gz"
SOURCE_URL=${WIFI_AGENT_SOURCE_URL:-https://github.com/akshajtiwari/Wifi-Agent/releases/download/v$VERSION/$TARBALL}

rm -rf "$WORK"
mkdir -p "$WORK"
# Package the working tree (tracked and new, non-ignored files) so local
# builds include uncommitted changes.
(cd "$ROOT" && git ls-files -z --cached --others --exclude-standard \
    | xargs -0 tar --ignore-failed-read --transform "s,^,wifi-agent-$VERSION/," -czf "$WORK/$TARBALL")
SHA256=$(sha256sum "$WORK/$TARBALL" | cut -d' ' -f1)
sed -e "s|@VERSION@|$VERSION|" -e "s|@SOURCE_URL@|$SOURCE_URL|" -e "s|@SHA256@|$SHA256|" \
    "$ROOT/packaging/arch/PKGBUILD.in" > "$WORK/PKGBUILD"
cp "$ROOT/packaging/arch/wifi-agent.install" "$WORK/"

# The source tarball is already beside the PKGBUILD, so nothing is downloaded.
(cd "$WORK" && makepkg --force --nodeps --cleanbuild)
mv "$WORK"/wifi-agent-"$VERSION"-*.pkg.tar.zst "$OUTPUT/"
cp "$WORK/PKGBUILD" "$WORK/wifi-agent.install" "$WORK/$TARBALL" "$OUTPUT/"
echo "Arch package written to $OUTPUT"
