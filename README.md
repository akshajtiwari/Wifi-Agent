# WiFi Agent

**Reliable Sophos/Cyberoam captive-portal authentication for wired networks.**

WiFi Agent monitors Ethernet connectivity, signs you back in within seconds
whenever the portal ends your session, and keeps its status visible from a
tray icon, desktop notifications, and a native settings window.

[![Website](https://img.shields.io/badge/Website-wifi--agent.vercel.app-black?logo=vercel)](https://wifi-agent.vercel.app/)
[![Latest release](https://img.shields.io/github/v/release/akshajtiwari/Wifi-Agent?display_name=tag&sort=semver)](https://github.com/akshajtiwari/Wifi-Agent/releases/latest)
[![Native installer builds](https://github.com/akshajtiwari/Wifi-Agent/actions/workflows/build-installers.yml/badge.svg)](https://github.com/akshajtiwari/Wifi-Agent/actions/workflows/build-installers.yml)
[![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-3776AB?logo=python&logoColor=white)](#source-installation)
[![Platforms](https://img.shields.io/badge/Platforms-Windows%20%7C%20macOS%20%7C%20Linux-555)](#downloads)

[Download](#downloads) · [Website](https://wifi-agent.vercel.app/) · [Quick start](#quick-start) · [Usage](#using-wifi-agent) · [Troubleshooting](#troubleshooting) · [Development](#development)

> **Official website:** https://wifi-agent.vercel.app/ — static download site for WiFi Agent, deployed from [`frontend/index.html`](frontend/index.html).

## Overview

WiFi Agent is a lightweight background service for networks protected by a
Sophos or Cyberoam captive portal. It distinguishes the physical Ethernet link,
portal reachability, authenticated portal session, and public internet access,
then logs in only when action is required.

### Core capabilities

| Area | Capability |
| --- | --- |
| Connection | Detects active physical Ethernet interfaces and monitors portal reachability |
| Authentication | Detects a portal logout from its keep-alive reply and logs in again immediately |
| Status | Separately reports Ethernet, portal session, internet access, process, and startup health |
| Notifications | Announces sign-ins, logouts, rejected passwords, and setup problems on every desktop |
| Credentials | Uses the OS credential vault; on Linux without one, a private user-only file |
| Reliability | Rechecks after sleep or cable changes, retries quickly, and runs under a systemd watchdog on Linux |
| Management | Dashboard, diagnostics, logs, and a tray/menu-bar icon on Windows, macOS, and Linux |
| Updates | Finds the correct native installer, verifies its SHA-256 digest, and updates in place |

## Downloads

**Official website / download site:** [https://wifi-agent.vercel.app/](https://wifi-agent.vercel.app/)

### WiFi Agent 1.4.0

Native installers bundle everything they need. End users do not need the
repository source code.

| Platform | Architecture | Recommended installer | Alternative |
| --- | --- | --- | --- |
| Windows | x86-64 | [Download setup `.exe`](https://github.com/akshajtiwari/Wifi-Agent/releases/download/v1.4.0/WiFiAgent-1.4.0-Windows-x64-Setup.exe) | — |
| macOS | Apple silicon | [Download package `.pkg`](https://github.com/akshajtiwari/Wifi-Agent/releases/download/v1.4.0/WiFiAgent-1.4.0-macOS-arm64.pkg) | [Disk image `.dmg`](https://github.com/akshajtiwari/Wifi-Agent/releases/download/v1.4.0/WiFiAgent-1.4.0-macOS-arm64.dmg) |
| macOS | Intel | [Download package `.pkg`](https://github.com/akshajtiwari/Wifi-Agent/releases/download/v1.4.0/WiFiAgent-1.4.0-macOS-x86_64.pkg) | [Disk image `.dmg`](https://github.com/akshajtiwari/Wifi-Agent/releases/download/v1.4.0/WiFiAgent-1.4.0-macOS-x86_64.dmg) |
| Debian 12+, Ubuntu 22.04+, Mint, Pop!_OS | Any | [Download `.deb`](https://github.com/akshajtiwari/Wifi-Agent/releases/download/v1.4.0/wifi-agent_1.4.0_all.deb) | [Source installation](#source-installation) |
| Arch Linux, Manjaro, EndeavourOS | Any | [Download package](https://github.com/akshajtiwari/Wifi-Agent/releases/download/v1.4.0/wifi-agent-1.4.0-1-any.pkg.tar.zst) | [`PKGBUILD`](https://github.com/akshajtiwari/Wifi-Agent/releases/download/v1.4.0/PKGBUILD) |
| Fedora, openSUSE, other Linux | Any | [Source installation](#source-installation) | — |

[View the v1.4.0 release notes](https://github.com/akshajtiwari/Wifi-Agent/releases/tag/v1.4.0) or browse the [complete changelog](CHANGELOG.md).

> [!IMPORTANT]
> The current public installers are not backed by Windows or Apple Developer ID
> certificates because signing secrets are not configured for this repository.
> Windows may show an unknown-publisher warning. macOS blocks the downloaded
> package until it is allowed (see [macOS first launch](#macos-first-launch)).
> Native builds still run packaged-runtime checks, and in-app updates are
> SHA-256 verified before use.

## Quick start

1. Install WiFi Agent:
   - **Windows:** run the `.exe` setup.
   - **macOS:** run in Terminal
     `curl -fsSL https://raw.githubusercontent.com/akshajtiwari/Wifi-Agent/main/install-macos.sh | bash`,
     or open the `.pkg` and follow [macOS first launch](#macos-first-launch).
   - **Debian/Ubuntu:** `sudo apt install ./wifi-agent_1.4.0_all.deb`
   - **Arch:** `sudo pacman -U wifi-agent-1.4.0-1-any.pkg.tar.zst`
2. Open **WiFi Agent** (on Linux, from the applications menu or `wifi-agent setup`).
3. Enter the portal username or roll number and password.
4. Confirm the portal address and select an Ethernet adapter if automatic
   detection is unsuitable.
5. Choose **Test Connection**.
6. Choose **Save & install** (**Save & Install at Login** on macOS).

The first launch displays only initial setup. After credentials and login-time
monitoring are configured, WiFi Agent reveals the live dashboard, shows its
tray or menu-bar icon, and starts monitoring in the background at every login.

### Install from the terminal

macOS (Apple silicon and Intel):

```sh
curl -fsSL https://raw.githubusercontent.com/akshajtiwari/Wifi-Agent/main/install-macos.sh | bash
```

Debian 12+, Ubuntu 22.04+, Linux Mint, Pop!_OS:

```sh
curl -LO https://github.com/akshajtiwari/Wifi-Agent/releases/download/v1.4.0/wifi-agent_1.4.0_all.deb
sudo apt install ./wifi-agent_1.4.0_all.deb
```

Arch Linux, Manjaro, EndeavourOS:

```sh
curl -LO https://github.com/akshajtiwari/Wifi-Agent/releases/download/v1.4.0/wifi-agent-1.4.0-1-any.pkg.tar.zst
sudo pacman -U wifi-agent-1.4.0-1-any.pkg.tar.zst
```

Fedora, openSUSE, and other distributions:

```sh
git clone https://github.com/akshajtiwari/Wifi-Agent.git
cd Wifi-Agent
./install.sh
```

Then open **WiFi Agent** from the applications menu (or run
`wifi-agent setup` with a Linux package), enter your credentials, and choose
**Save & install**. Check on the agent any time with:

```sh
wifi-agent status
wifi-agent doctor
systemctl --user status wifi-agent   # Linux background service
```

### macOS first launch

The packages are not yet notarized by Apple, so macOS 15 shows *"Apple could
not verify ‘WiFiAgent-….pkg’ is free of malware"* the first time. Either:

- install from Terminal with the `install-macos.sh` command above. It
  downloads with `curl`, checks GitHub's SHA-256 digest, and runs the standard
  macOS installer, so Gatekeeper's download block does not apply; or
- after the warning, choose **Done**, open **System Settings → Privacy &
  Security**, choose **Open Anyway** next to the WiFi Agent message, and open
  the package again.

After installation, opening WiFi Agent from Launchpad, Spotlight, or the
Applications folder always shows its settings window, even while the
menu-bar agent is running.

## How it works

Each monitoring cycle follows the same conservative sequence:

1. Detect an active wired interface.
2. Check whether the configured portal port is reachable.
3. Send the portal's keep-alive request. A `login_again` reply means the
   portal ended the session, and WiFi Agent logs in immediately.
4. Otherwise, verify public internet access without following captive-portal
   redirects.
5. Log in when Ethernet and the portal are reachable but neither a valid
   portal session nor internet access is available.
6. Publish an atomic status snapshot for the dashboard, tray/menu bar,
   notifications, CLI, and diagnostics viewer.

While everything is healthy WiFi Agent checks every 45 seconds (configurable).
While something is wrong it checks every 10 seconds, and it checks at once
after the computer wakes from sleep or the Ethernet cable or address changes.
Retries depend on the failure: transient errors retry within 10–60 seconds,
a "maximum login limit" reply retries after 30 seconds, and a rejected
password backs off exponentially so the account is not locked.

A confirmed portal session remains visibly **Connected** when a public probe is
blocked or inconclusive. This prevents a working background login from appearing
to have failed.

## Using WiFi Agent

### Dashboard

| Pane | Purpose |
| --- | --- |
| **Overview** / **General** | Live connection, portal, process, and startup health |
| **Settings** / **Connection** | Credentials, portal address, interface selection, and retry policy |
| **Diagnostics** | Sanitized status snapshot and recent logs, ready to copy for troubleshooting |

The Windows settings pane scrolls in compact, non-maximized windows so every
connection-test and save action remains accessible.

### Tray, menu bar, and notifications

WiFi Agent shows an icon in the Windows notification area, the macOS menu
bar, and the Linux system tray. On Linux the icon is green when signed in,
amber while reconnecting, red when it needs attention, and grey when paused.
It works with KDE Plasma, Cinnamon, XFCE, MATE, Budgie, Ubuntu's GNOME, and
panels such as Waybar. On plain GNOME, enable the **AppIndicator and
KStatusNotifierItem Support** extension (`gnome-shell-extension-appindicator`)
to see it; notifications work either way.

Desktop notifications report when WiFi Agent signs you in or back in after the
portal ends a session, when a login fails or the portal rejects the password,
when the portal stays unreachable, and when setup or the password vault needs
attention. On a Linux desktop with no notification service at all, those
problems open the WiFi Agent window instead.

The icon menu provides quick access to:

- Current connection status
- Check and log in now
- Pause or resume monitoring
- Check for updates
- Settings and diagnostics
- Log files
- Quit until the next user login

### In-app updates

Version 1.3.0 and later can install future stable releases from **Check for
updates** in the dashboard or tray/menu-bar menu. Native dashboard launches also
perform a quiet update check.

The updater:

1. Reads the latest stable GitHub Release.
2. Selects the Windows x64, Apple silicon, or Intel Mac package.
3. Requires a trusted GitHub HTTPS URL and a valid published SHA-256 digest.
4. Downloads into the private application-data directory with a strict size
   limit.
5. Verifies the complete file before starting the native installer.

Windows updates run silently and restart the notification-area process. macOS
uses the standard administrator authorization prompt. Credentials, settings,
logs, and startup configuration remain in the user profile and survive an app
replacement.

Users on 1.2.0 install 1.3.0 once with a native installer; subsequent releases
can be installed from inside WiFi Agent. On Linux, **Check for updates** opens
the release page; install the new `.deb` or Arch package with the package
manager, which restarts running agents onto the new version.

## Source installation

Source installation is intended for Linux distributions without a package,
development, and troubleshooting.

### Requirements

- Python 3.10 or newer with the `venv` module and Tk
- A credential vault:
  - Windows Credential Manager
  - macOS Keychain
  - Linux Secret Service (GNOME Keyring or KWallet); without one, Linux keeps
    the password in a private user-only file

### Install

On macOS or Linux:

```sh
./install.sh
```

On Linux, `install.sh` first installs missing system packages (Python venv
and Tk) with apt, pacman, dnf, or zypper, asking before it uses `sudo`.
Re-running it updates the private runtime and restarts a running agent.

On Windows, double-click `install.cmd` or run:

```powershell
.\install.ps1
```

The script installer creates an isolated runtime in the user's application-data
directory. It does not depend on the downloaded repository directory after
installation.

## Command-line management

With a Linux package, use `wifi-agent <command>`. For a source installation on
macOS or Linux, use `./install.sh <command>`. On Windows, use
`install.cmd <command>`.

| Command | Description |
| --- | --- |
| `setup` | Open credentials and connection settings |
| `run` | Run the monitor interactively (with the Linux tray icon) |
| `run --once` | Perform one connection and login cycle |
| `run --no-tray` | Run the monitor without a Linux tray icon or notifications |
| `check` | Ask the running agent to check immediately |
| `status` | Display live state and recent logs |
| `doctor` | Validate configuration, credential vault, startup, and interfaces |
| `open-logs` | Open the log location |
| `install` | Install or repair login-time monitoring |
| `install --repair` | Rewrite the startup service without checking credentials |
| `uninstall` | Remove login-time monitoring while keeping settings and credentials |

Example:

```sh
./install.sh doctor
./install.sh status
```

## Data and security

| Data | Storage |
| --- | --- |
| Password | Operating-system credential vault; on Linux without a Secret Service vault, `WiFiAgent/credentials.json` (mode 0600) |
| Username and connection settings | Per-user `WiFiAgent/config.json` |
| Runtime status | Per-user `WiFiAgent/status.json` |
| Logs | Per-user `WiFiAgent/agent.log`, with rotation; startup failures in `WiFiAgent/crash.log` |
| Verified update installers | Per-user `WiFiAgent/updates/` |

Platform configuration roots:

- Windows: `%APPDATA%\WiFiAgent`
- macOS: `~/Library/Application Support/WiFiAgent`
- Linux: `${XDG_CONFIG_HOME:-~/.config}/WiFiAgent`

Security properties:

- Passwords are never written to project files, configuration JSON, status
  snapshots, diagnostics, or logs.
- On Linux machines without a Secret Service vault (for example a bare
  Hyprland, Sway, or i3 session), the password is stored in
  `credentials.json`, readable only by your user account (file mode 0600 in a
  0700 directory). It is Base64-encoded, which is not encryption. Install and
  unlock GNOME Keyring or KWallet, then save the password again, to move it
  into the vault.
- Portal responses are sanitized before logging.
- Public connectivity checks reject captive-portal redirects and retain normal
  TLS verification.
- TLS verification can be relaxed only for the configured portal when its
  appliance uses a self-signed certificate.
- Update metadata and downloads must use trusted GitHub HTTPS URLs.
- Update files must match GitHub's published SHA-256 digest before execution.
- Temporary and partial update downloads are not executed and are removed after
  verification failures.

WiFi Agent starts after user login rather than during pre-login boot because OS
credential vaults are normally unavailable before the interactive session. On
Linux it runs as a systemd user service with `Restart=always` and a watchdog,
so a crash or a hung check restarts it automatically.

## Troubleshooting

| Symptom | Recommended action |
| --- | --- |
| macOS blocks the installer or app | Use the Terminal installer, or open **System Settings → Privacy & Security** and choose **Open Anyway** ([details](#macos-first-launch)) |
| Nothing appears when WiFi Agent is opened on macOS | Install 1.4.0 or later; startup errors now show an alert and are saved to `~/Library/Logs/WiFiAgent/crash.log` |
| Linux notification says the password vault is unavailable | Unlock GNOME Keyring/KWallet, or open WiFi Agent and enter the password again to keep it in a private file |
| No tray icon on GNOME | Enable the AppIndicator and KStatusNotifierItem Support extension; notifications work without it |
| Windows shows an unknown publisher | Confirm the download came from this repository's Release page before continuing |
| No Ethernet interface is detected | Connect the cable, choose **Refresh**, and select the adapter explicitly in Connection settings |
| Portal shows reachable but not connected | Re-enter credentials, save them, and choose **Check Now** |
| Portal is connected but internet is unavailable | The authenticated session is valid; inspect Diagnostics for upstream/probe failures |
| Update verification fails | Retry the update; the rejected file is not executed and partial data is removed |
| The agent is not running | Choose **Install / repair** or run the `doctor` command; on Linux also check `systemctl --user status wifi-agent` |

Diagnostics and logs can be opened from the dashboard or tray/menu-bar menu.
They do not include the saved password.

## Development

### Run tests

The regression suite does not require installed runtime dependencies. Install
`jeepney` as well to run the Linux tray D-Bus tests:

```sh
python -m unittest discover -s tests -v
```

Run the same lint version used in CI:

```sh
python -m pip install ruff==0.15.17
ruff check wifi_agent.py install.py packaging/generate_assets.py tests/test_wifi_agent.py
```

### Build native installers

PyInstaller must run on the target operating system; native installers cannot
be cross-compiled.

Install build dependencies:

```sh
python -m pip install -r requirements.txt -r packaging/requirements-build.txt
```

Windows requires Inno Setup 6 or 7:

```powershell
.\packaging\windows\build-installer.ps1
```

Build on macOS with:

```sh
./packaging/macos/build-installer.sh
```

Build the Linux packages on Linux (the `.deb` needs `dpkg-deb`, the Arch
package needs `makepkg`):

```sh
./packaging/debian/build-deb.sh
./packaging/arch/build-package.sh
```

Build outputs are written to:

- `build/windows/installer`
- `build/macos/installer`
- `build/linux` (`.deb`)
- `build/arch` (Arch package, AUR-ready `PKGBUILD`, and source tarball)

Every native builder runs the frozen application's runtime self-test before
creating an installer.

### Signing and notarization

Local Windows signing uses:

- `WINDOWS_SIGNING_CERTIFICATE` — path to a PFX certificate
- `WINDOWS_SIGNING_PASSWORD` — PFX password

Local macOS signing and notarization use:

- `MACOS_APP_SIGNING_IDENTITY`
- `MACOS_INSTALLER_SIGNING_IDENTITY`
- `APPLE_NOTARY_KEYCHAIN_PROFILE`

The GitHub Actions workflow accepts the corresponding repository secrets listed
in [the workflow](.github/workflows/build-installers.yml). When secrets are
absent, CI publishes explicitly marked unsigned development installers.

## Release automation

The **Build native installers** workflow:

- Runs tests and Ruff on Ubuntu.
- Builds a Windows x64 installer on Windows.
- Builds Apple silicon and Intel PKG/DMG installers on native macOS runners,
  installs each package, and launches it through LaunchServices.
- Builds the `.deb` and Arch packages, then installs and runs them on
  Debian 12, Ubuntu 22.04, Ubuntu 24.04, and Arch Linux.
- Runs packaged-runtime startup checks before publishing.
- Publishes manual workflow runs as prereleases with direct installer assets.
- Publishes version tags such as `v1.4.0` as stable GitHub Releases with the
  matching file from `.github/release-notes/`.

See [CHANGELOG.md](CHANGELOG.md) for release history.
