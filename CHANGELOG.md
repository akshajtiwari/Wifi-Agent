# Changelog

## 1.4.0 — 2026-10-08

### Linux reliability

- Fixed the agent silently stopping on Linux when no Secret Service password
  vault was reachable at login. The vault is now re-detected while the agent
  runs, a vault call that hangs on an unlock prompt times out instead of
  freezing monitoring, and the outage is reported as its own
  `vault-unavailable` state.
- Linux systems without a Secret Service vault (for example Hyprland, Sway,
  or i3 sessions) keep the password in a private, user-only file instead of
  failing.
- The systemd user service now uses `Type=notify` with a watchdog,
  `Restart=always`, and `systemctl status` messages. It skips itself when the
  program was uninstalled. Services installed by earlier versions are updated
  automatically.

### Faster reconnection after portal logouts

- Sophos/Cyberoam keep-alive replies (`ack` / `login_again`) are now
  understood, so a portal logout is detected on the next check and followed
  by an immediate login.
- Checks run every 10 seconds while something is wrong and at once after
  sleep, cable, or address changes.
- Login retries depend on the failure: quick retries for timeouts, 30 seconds
  for the maximum-login limit, and exponential backoff only for a rejected
  password.
- Requests include the portal's timestamp and product-type parameters.

### Tray icon and notifications everywhere

- Linux now has an always-on, colour-coded tray icon with the full menu
  (StatusNotifierItem over D-Bus; no GTK needed), working on KDE, Cinnamon,
  XFCE, MATE, Budgie, Ubuntu GNOME, and Waybar-based desktops.
- Desktop notifications on Linux, Windows, and macOS for sign-ins, automatic
  re-logins, failed logins, rejected passwords, unreachable portals, and setup
  or vault problems. On Linux desktops without a notification service, those
  problems open the WiFi Agent window instead.

### Linux packages

- New `.deb` package for Debian 12+ and Ubuntu 22.04+, and an Arch Linux
  package with an AUR-ready `PKGBUILD`. Both add a menu entry and icon and
  restart running agents on upgrade.
- `install.sh` installs missing Python venv/Tk packages with apt, pacman, dnf,
  or zypper, and restarts a running agent after updating it.

### macOS

- Fixed the package installing the app outside `/Applications` when another
  copy existed (the bundle was relocatable), which left nothing to open.
- Opening WiFi Agent while the menu-bar agent runs now shows Settings instead
  of doing nothing; the menu-bar agent no longer shows a Dock icon.
- Startup errors show an alert and are written to
  `~/Library/Logs/WiFiAgent/crash.log` instead of failing silently.
- Added the local-network usage description required by macOS 15.
- New `install-macos.sh` Terminal installer that verifies the release digest
  and avoids the Gatekeeper download block for the unsigned package.
- CI now installs each package and launches it through LaunchServices.

## 1.3.0 — 2026-08-22

### Highlights

- Added an in-app updater for native Windows and macOS installations.
- Added quiet update checks on dashboard launch plus explicit update actions in
  the dashboard and notification-area/menu-bar menu.
- Selects the correct Windows x64, Apple silicon, or Intel Mac installer from
  the latest stable GitHub Release.
- Restricts release metadata and downloads to trusted GitHub HTTPS URLs, caps
  download size, and requires SHA-256 digest verification before installation.
- Preserves portal credentials, connection settings, and login-time startup
  state during updates.
- Restarts the Windows tray process after a silent update and uses the native
  macOS administrator authorization prompt for package installation.

## 1.2.0 — 2026-08-22

### Highlights

- Added a first-run setup flow that collects portal credentials and completes
  login-time installation before revealing the management dashboard.
- Made the Windows connection settings vertically scrollable so Test
  Connection, Save, and installation controls remain accessible in compact or
  non-maximized windows.
- Added authenticated portal-session tracking. A confirmed Sophos/Cyberoam
  session now remains visibly connected when a public connectivity probe is
  blocked or inconclusive.
- Fixed macOS package post-install launching by opening the installed app bundle
  by filesystem path.
- Added native frozen-application startup self-tests to both Windows and macOS
  builders to prevent broken installers from being published.
- Changed installer automation so manual and tagged builds publish `.exe`,
  `.pkg`, and `.dmg` files as direct GitHub Release downloads.

### Packaging

- Windows: per-user x64 setup executable.
- macOS Apple silicon: PKG and DMG installers.
- macOS Intel: PKG and DMG installers.
- Version metadata updated to 1.2.0 throughout the application and installers.

### Validation

- 25 regression tests pass.
- Ruff, Python compilation, shell syntax, workflow YAML, and Tk interface smoke
  checks pass.

### Signing note

The repository currently has no Apple Developer ID or Windows signing secrets
configured. CI can therefore produce the release installers, but Windows may
show an unknown-publisher warning and macOS may require **Open Anyway** from
Privacy & Security. Configure the secrets documented in the README to enable
trusted signing and Apple notarization on a future rebuild.

## 1.1.0 — 2026-08-21

- Added native Windows and macOS packaging, tray/menu-bar management, signing
  hooks, and automated installer builds.

## 1.0.0 — 2026-08-21

- Initial WiFi Agent release.
