#!/bin/sh
# Install a built package in a clean container and exercise it.
# Usage: smoke-test.sh <package-file>
set -eu

PACKAGE=$1
case "$PACKAGE" in
    *.deb)
        export DEBIAN_FRONTEND=noninteractive
        apt-get update -qq
        apt-get install -y -qq "$PACKAGE" dbus >/dev/null
        ;;
    *.pkg.tar.*)
        pacman -Sy --noconfirm --needed dbus >/dev/null
        pacman -U --noconfirm "$PACKAGE" >/dev/null
        ;;
    *)
        echo "Unsupported package: $PACKAGE" >&2
        exit 2
        ;;
esac

wifi-agent --version
wifi-agent self-test

# Run the service briefly on a private session bus with no panel and no
# notification daemon: the tray code must connect and degrade cleanly.
HOME=$(mktemp -d)
export HOME
dbus-run-session -- sh -c 'timeout 8 wifi-agent run; true'
LOG="$HOME/.config/WiFiAgent/agent.log"
cat "$LOG"
grep -q "Agent monitor started" "$LOG"
grep -q "No system-tray host is running" "$LOG"
if grep -q "Traceback\|Desktop tray/notifications unavailable" "$LOG"; then
    echo "Smoke test failed: the desktop integration did not start cleanly." >&2
    exit 1
fi
echo "Smoke test passed"
