#!/usr/bin/env bash
# CI check: install a built package and launch the app the way Finder does.
# Usage: verify-installer.sh <package.pkg>
set -euo pipefail

PACKAGE=$1
APP="/Applications/WiFi Agent.app"
sudo /usr/sbin/installer -pkg "$PACKAGE" -target /
if [[ ! -d "$APP" ]]; then
    echo "The installer did not place WiFi Agent.app in /Applications." >&2
    exit 1
fi
codesign --verify --deep --strict "$APP"
# postinstall opens Settings for the console user; close it before testing.
pkill -f "$APP/Contents/MacOS/WiFi Agent" || true

RESULT="$(mktemp -d)/self-test.txt"
# Launch through LaunchServices (as Finder, Launchpad, and Spotlight do),
# not by executable path, so bundle and launch problems surface here.
open -n "$APP" --args self-test --result-file "$RESULT"
for _ in $(seq 1 120); do
    [[ -s "$RESULT" ]] && break
    sleep 1
done
if [[ ! -s "$RESULT" ]]; then
    echo "WiFi Agent did not finish its self-test after a LaunchServices launch." >&2
    exit 1
fi
cat "$RESULT"
[[ "$(head -n 1 "$RESULT")" == "ok" ]]
