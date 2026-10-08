#!/bin/sh
# Apply a systemctl verb to the WiFi Agent user service of every logged-in
# user. Package scripts run as root, so each user's manager is reached with
# `systemctl --user --machine=<user>@` (systemd 248 or newer).
# Usage: user-services.sh try-restart|stop
set -u

VERB=$1
command -v loginctl >/dev/null 2>&1 || exit 0
for user in $(loginctl list-users --no-legend 2>/dev/null | awk '{print $2}'); do
    systemctl --user --machine="$user@" "$VERB" wifi-agent.service >/dev/null 2>&1 || true
done
exit 0
