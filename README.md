# WiFi Agent

**Reliable Sophos/Cyberoam captive-portal authentication for wired networks.**

WiFi Agent monitors Ethernet connectivity, restores authenticated portal
sessions, and keeps connection status visible from a native desktop interface.

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
| Authentication | Restores sessions automatically and sends portal keep-alive requests |
| Status | Separately reports Ethernet, portal session, internet access, process, and startup health |
| Credentials | Stores passwords in the operating-system credential vault, never in `config.json` |
| Reliability | Prevents duplicate monitors, reloads settings live, and applies bounded retry backoff |
| Management | Provides a dashboard, diagnostics viewer, logs, and Windows tray/macOS menu-bar controls |
| Updates | Finds the correct native installer, verifies its SHA-256 digest, and updates in place |

## Downloads

**Official website / download site:** [https://wifi-agent.vercel.app/](https://wifi-agent.vercel.app/)

### WiFi Agent 1.3.0

Native installers bundle the complete runtime. End users do not need Python or
the repository source code.

| Platform | Architecture | Recommended installer | Alternative |
| --- | --- | --- | --- |
| Windows | x86-64 | [Download setup `.exe`](https://github.com/akshajtiwari/Wifi-Agent/releases/download/v1.3.0/WiFiAgent-1.3.0-Windows-x64-Setup.exe) | — |
| macOS | Apple silicon | [Download package `.pkg`](https://github.com/akshajtiwari/Wifi-Agent/releases/download/v1.3.0/WiFiAgent-1.3.0-macOS-arm64.pkg) | [Disk image `.dmg`](https://github.com/akshajtiwari/Wifi-Agent/releases/download/v1.3.0/WiFiAgent-1.3.0-macOS-arm64.dmg) |
| macOS | Intel | [Download package `.pkg`](https://github.com/akshajtiwari/Wifi-Agent/releases/download/v1.3.0/WiFiAgent-1.3.0-macOS-x86_64.pkg) | [Disk image `.dmg`](https://github.com/akshajtiwari/Wifi-Agent/releases/download/v1.3.0/WiFiAgent-1.3.0-macOS-x86_64.dmg) |
| Linux | Distribution-independent | [Source installation](#source-installation) | — |

[View the v1.3.0 release notes](https://github.com/akshajtiwari/Wifi-Agent/releases/tag/v1.3.0) or browse the [complete changelog](CHANGELOG.md).

> [!IMPORTANT]
> The current public installers are not backed by Windows or Apple Developer ID
> certificates because signing secrets are not configured for this repository.
> Windows may show an unknown-publisher warning. macOS may require **Open
> Anyway** in **System Settings → Privacy & Security**. Native builds still run
> packaged-runtime checks, and in-app updates are SHA-256 verified before use.

## Quick start

1. Download the installer matching the computer from the table above.
2. Install WiFi Agent:
   - On Windows, run the `.exe` setup.
   - On macOS, run the `.pkg`; or copy **WiFi Agent.app** from the `.dmg` into
     **Applications** and open it once.
3. Enter the portal username or roll number and password.
4. Confirm the portal address and select an Ethernet adapter if automatic
   detection is unsuitable.
5. Choose **Test Connection**.
6. Choose **Save & install** on Windows or **Save & Install at Login** on macOS.

The first launch displays only initial setup. After credentials and login-time
monitoring are configured, WiFi Agent reveals the live dashboard and begins
monitoring in the background.

## How it works

Each monitoring cycle follows the same conservative sequence:

1. Detect an active wired interface.
2. Check whether the configured portal port is reachable.
3. Query the portal for an existing authenticated session.
4. Verify public internet access without following captive-portal redirects.
5. Log in only when Ethernet and the portal are reachable but neither a valid
   portal session nor internet access is available.
6. Publish an atomic status snapshot for the dashboard, tray/menu bar, CLI, and
   diagnostics viewer.

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

### Tray and menu bar

The Windows notification-area icon and macOS menu-bar item provide quick access
to:

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
can be installed from inside WiFi Agent.

## Source installation

Source installation is intended for Linux, development, and troubleshooting.

### Requirements

- Python 3.10 or newer
- An unlocked credential vault:
  - Windows Credential Manager
  - macOS Keychain
  - Linux Secret Service
- `python3-tk` on Linux distributions that package Tk separately

### Install

On macOS or Linux:

```sh
./install.sh
```

On Windows, double-click `install.cmd` or run:

```powershell
.\install.ps1
```

The script installer creates an isolated runtime in the user's application-data
directory. It does not depend on the downloaded repository directory after
installation.

## Command-line management

For POSIX systems, use `./install.sh <command>`. On Windows, use
`install.cmd <command>`.

| Command | Description |
| --- | --- |
| `setup` | Open credentials and connection settings |
| `run` | Run the monitor interactively |
| `run --once` | Perform one connection and login cycle |
| `check` | Ask the running agent to check immediately |
| `status` | Display live state and recent logs |
| `doctor` | Validate configuration, credential vault, startup, and interfaces |
| `open-logs` | Open the log location |
| `install` | Install or repair login-time monitoring |
| `uninstall` | Remove login-time monitoring while keeping settings and credentials |

Example:

```sh
./install.sh doctor
./install.sh status
```

## Data and security

| Data | Storage |
| --- | --- |
| Password | Operating-system credential vault |
| Username and connection settings | Per-user `WiFiAgent/config.json` |
| Runtime status | Per-user `WiFiAgent/status.json` |
| Logs | Per-user `WiFiAgent/agent.log`, with rotation |
| Verified update installers | Per-user `WiFiAgent/updates/` |

Platform configuration roots:

- Windows: `%APPDATA%\WiFiAgent`
- macOS: `~/Library/Application Support/WiFiAgent`
- Linux: `${XDG_CONFIG_HOME:-~/.config}/WiFiAgent`

Security properties:

- Passwords are never written to project files, configuration JSON, status
  snapshots, diagnostics, or logs.
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
credential vaults are normally unavailable before the interactive session.

## Troubleshooting

| Symptom | Recommended action |
| --- | --- |
| macOS blocks the installer or app | Open **System Settings → Privacy & Security** and choose **Open Anyway**, then reopen WiFi Agent |
| Windows shows an unknown publisher | Confirm the download came from this repository's Release page before continuing |
| No Ethernet interface is detected | Connect the cable, choose **Refresh**, and select the adapter explicitly in Connection settings |
| Portal shows reachable but not connected | Re-enter credentials, save them, and choose **Check Now** |
| Portal is connected but internet is unavailable | The authenticated session is valid; inspect Diagnostics for upstream/probe failures |
| Update verification fails | Retry the update; the rejected file is not executed and partial data is removed |
| The agent is not running | Choose **Install / repair** or run the `doctor` command |

Diagnostics and logs can be opened from the dashboard or tray/menu-bar menu.
They do not include the saved password.

## Development

### Run tests

The regression suite does not require installed runtime dependencies:

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

Build outputs are written to:

- `build/windows/installer`
- `build/macos/installer`

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
- Builds Apple silicon and Intel PKG/DMG installers on native macOS runners.
- Runs packaged-runtime startup checks before publishing.
- Publishes manual workflow runs as prereleases with direct installer assets.
- Publishes version tags such as `v1.3.0` as stable GitHub Releases with the
  matching file from `.github/release-notes/`.

See [CHANGELOG.md](CHANGELOG.md) for release history.
