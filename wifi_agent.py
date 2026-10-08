#!/usr/bin/env python3
"""WiFi Agent: cross-platform Sophos/Cyberoam captive-portal automation."""

from __future__ import annotations

import argparse
import base64
from contextlib import AbstractContextManager
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import faulthandler
from functools import lru_cache
import getpass
import hashlib
from html import escape as xml_escape
import ipaddress
import json
import logging
from logging.handlers import RotatingFileHandler
import math
import os
from pathlib import Path
import platform
import plistlib
import queue
import random
import re
import shutil
import signal
import socket
import ssl
import subprocess
import sys
import threading
import time
import traceback
from typing import Any, NamedTuple
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlencode, urlparse
from urllib.request import HTTPRedirectHandler, HTTPSHandler, Request, build_opener

try:
    import keyring
    from keyring.errors import KeyringError, NoKeyringError
except ImportError:  # Helpful error before the installer has installed dependencies.
    keyring = None

    class KeyringError(Exception):  # type: ignore[no-redef]
        """Stand-in so error handling does not swallow unrelated exceptions."""

    NoKeyringError = KeyringError  # type: ignore[misc]

try:
    import psutil
except ImportError:
    psutil = None

APP_NAME = "WiFiAgent"
APP_DISPLAY_NAME = "WiFi Agent"
APP_VERSION = "1.4.0"
if getattr(sys, "frozen", False):
    try:
        from wifi_agent_build import BUILD_VERSION

        APP_VERSION = BUILD_VERSION
    except ImportError:
        pass
KEYRING_SERVICE = "WiFi Agent"
RELEASES_API_URL = "https://api.github.com/repos/akshajtiwari/Wifi-Agent/releases/latest"
GITHUB_API_VERSION = "2026-03-10"
MAX_UPDATE_SIZE = 250 * 1024 * 1024
DEFAULT_CONFIG: dict[str, Any] = {
    "username": "",
    "portal_scheme": "https",
    "portal_host": "192.168.1.2",
    "portal_port": 8090,
    "check_interval_seconds": 45,
    "login_backoff_max_seconds": 600,
    "network_interface": "auto",
    "allow_self_signed_portal": True,
    "credential_store": "",
    "config_revision": 0,
}
# Phases in which the agent is not doing its job and should look again soon.
HEALTHY_PHASES = frozenset({"online", "connected", "paused"})
ATTENTION_PHASES = frozenset({"needs-setup", "vault-unavailable", "error"})
DEGRADED_CHECK_SECONDS = 10
SYSTEMD_UNIT_NAME = "wifi-agent.service"
# Exit status for "another monitor already holds the lock"; the systemd unit
# lists it in RestartPreventExitStatus so a duplicate never restart-loops.
EXIT_ALREADY_RUNNING = 75


def app_dir() -> Path:
    if sys.platform == "win32":
        root = Path(os.environ.get("APPDATA", Path.home() / "AppData" / "Roaming"))
    elif sys.platform == "darwin":
        root = Path.home() / "Library" / "Application Support"
    else:
        root = Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config"))
    return root / APP_NAME


CONFIG_PATH = app_dir() / "config.json"
LOG_PATH = app_dir() / "agent.log"
STATUS_PATH = app_dir() / "status.json"
LOCK_PATH = app_dir() / "agent.lock"
WAKE_PATH = app_dir() / "check.request"
UI_STATE_PATH = app_dir() / "ui-state.json"
CREDENTIALS_PATH = app_dir() / "credentials.json"
CRASH_LOG_PATH = app_dir() / "crash.log"
WINDOWS_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)


def utc_now() -> str:
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


def _version_tuple(value: str) -> tuple[int, int, int]:
    match = re.fullmatch(r"v?(\d+)\.(\d+)\.(\d+)", value.strip())
    if not match:
        raise ValueError(f"Unsupported release version: {value!r}")
    return tuple(int(part) for part in match.groups())  # type: ignore[return-value]


@dataclass(frozen=True)
class UpdateInfo:
    version: str
    asset_name: str
    download_url: str
    release_url: str
    size: int
    sha256: str


def _update_asset_name(version: str, system: str | None = None, machine: str | None = None) -> str:
    system = system or sys.platform
    machine = (machine or platform.machine()).casefold()
    if system == "win32":
        if machine not in {"amd64", "x86_64"}:
            raise RuntimeError(f"Automatic updates are not available for Windows architecture {machine}.")
        return f"WiFiAgent-{version}-Windows-x64-Setup.exe"
    if system == "darwin":
        if machine in {"arm64", "aarch64"}:
            architecture = "arm64"
        elif machine in {"amd64", "x86_64"}:
            architecture = "x86_64"
        else:
            raise RuntimeError(f"Automatic updates are not available for Mac architecture {machine}.")
        return f"WiFiAgent-{version}-macOS-{architecture}.pkg"
    raise RuntimeError("Automatic updates are currently available only for native Windows and macOS installations.")


def _fetch_latest_release(opener=None) -> dict[str, Any]:
    request = Request(
        RELEASES_API_URL,
        headers={
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": GITHUB_API_VERSION,
            "User-Agent": f"{APP_NAME}/{APP_VERSION}",
        },
    )
    release_opener = opener or build_opener(HTTPSHandler(context=ssl.create_default_context()))
    try:
        with release_opener.open(request, timeout=15) as response:
            payload = json.loads(response.read(1024 * 1024).decode("utf-8"))
    except (HTTPError, URLError, OSError, TimeoutError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"Could not check for updates: {exc}") from exc
    if not isinstance(payload, dict):
        raise RuntimeError("GitHub returned an invalid release response.")
    return payload


def check_for_release_page(*, opener=None) -> tuple[str, str] | None:
    """Return (version, release page) when a newer release exists.

    Linux packages are owned by the distribution package manager, so Linux
    only links to the release instead of installing anything itself.
    """
    payload = _fetch_latest_release(opener)
    latest = _version_tuple(str(payload.get("tag_name", "")))
    if latest <= _version_tuple(APP_VERSION):
        return None
    release_url = str(payload.get("html_url", ""))
    parsed_release = urlparse(release_url)
    if parsed_release.scheme != "https" or parsed_release.hostname != "github.com":
        raise RuntimeError("The update release URL is not a trusted GitHub HTTPS URL.")
    return ".".join(str(part) for part in latest), release_url


def check_for_update(*, opener=None, system: str | None = None, machine: str | None = None) -> UpdateInfo | None:
    """Return the latest compatible stable update, if it is newer."""
    payload = _fetch_latest_release(opener)
    tag = str(payload.get("tag_name", ""))
    latest = _version_tuple(tag)
    if latest <= _version_tuple(APP_VERSION):
        return None
    version = ".".join(str(part) for part in latest)
    expected_name = _update_asset_name(version, system, machine)
    assets = payload.get("assets")
    if not isinstance(assets, list):
        raise RuntimeError(f"Release {version} does not contain installer assets.")
    asset = next(
        (candidate for candidate in assets if isinstance(candidate, dict) and candidate.get("name") == expected_name),
        None,
    )
    if asset is None or asset.get("state") not in {None, "uploaded"}:
        raise RuntimeError(f"Release {version} does not include {expected_name}.")

    download_url = str(asset.get("browser_download_url", ""))
    parsed_download = urlparse(download_url)
    if parsed_download.scheme != "https" or parsed_download.hostname != "github.com":
        raise RuntimeError("The update download URL is not a trusted GitHub HTTPS URL.")
    release_url = str(payload.get("html_url", ""))
    parsed_release = urlparse(release_url)
    if parsed_release.scheme != "https" or parsed_release.hostname != "github.com":
        raise RuntimeError("The update release URL is not a trusted GitHub HTTPS URL.")
    try:
        size = int(asset.get("size", 0))
    except (TypeError, ValueError) as exc:
        raise RuntimeError("The update has an invalid download size.") from exc
    if not 0 < size <= MAX_UPDATE_SIZE:
        raise RuntimeError("The update download size is invalid or exceeds the safety limit.")
    digest = str(asset.get("digest", ""))
    if not re.fullmatch(r"sha256:[0-9a-fA-F]{64}", digest):
        raise RuntimeError("The update does not provide a valid SHA-256 digest.")
    return UpdateInfo(version, expected_name, download_url, release_url, size, digest.partition(":")[2].casefold())


def download_update(update: UpdateInfo, *, opener=None) -> Path:
    """Download and verify an update installer into the private app directory."""
    update_directory = app_dir() / "updates"
    update_directory.mkdir(parents=True, exist_ok=True)
    destination = update_directory / update.asset_name
    temporary = destination.with_suffix(destination.suffix + ".part")
    request = Request(update.download_url, headers={"User-Agent": f"{APP_NAME}/{APP_VERSION}"})
    download_opener = opener or build_opener(HTTPSHandler(context=ssl.create_default_context()))
    digest = hashlib.sha256()
    downloaded = 0
    try:
        with download_opener.open(request, timeout=30) as response, temporary.open("wb") as output:
            while True:
                chunk = response.read(1024 * 1024)
                if not chunk:
                    break
                downloaded += len(chunk)
                if downloaded > update.size or downloaded > MAX_UPDATE_SIZE:
                    raise RuntimeError("The update download exceeded its declared size.")
                digest.update(chunk)
                output.write(chunk)
        if downloaded != update.size:
            raise RuntimeError(f"The update download was incomplete ({downloaded} of {update.size} bytes).")
        if digest.hexdigest().casefold() != update.sha256.casefold():
            raise RuntimeError("The update failed SHA-256 verification and was not opened.")
        temporary.replace(destination)
    except (HTTPError, URLError, OSError, TimeoutError) as exc:
        temporary.unlink(missing_ok=True)
        raise RuntimeError(f"Could not download the update: {exc}") from exc
    except RuntimeError:
        temporary.unlink(missing_ok=True)
        raise
    return destination


def install_downloaded_update(installer: Path) -> None:
    """Start the platform-native installer for a verified update."""
    installer = installer.resolve(strict=True)
    if installer.parent != (app_dir() / "updates").resolve():
        raise RuntimeError("Refusing to open an update outside the private update directory.")
    if sys.platform == "win32":
        subprocess.Popen(
            [
                str(installer),
                "/VERYSILENT",
                "/SUPPRESSMSGBOXES",
                "/NORESTART",
                "/CLOSEAPPLICATIONS",
                "/FORCECLOSEAPPLICATIONS",
            ],
            cwd=str(installer.parent),
            creationflags=WINDOWS_NO_WINDOW,
        )
        return
    if sys.platform == "darwin":
        apple_script = (
            'on run argv\n'
            'do shell script "/usr/sbin/installer -pkg " & quoted form of item 1 of argv & '
            '" -target /" with administrator privileges\n'
            'end run'
        )
        subprocess.run(
            ["osascript", "-e", apple_script, str(installer)],
            check=True,
            capture_output=True,
            text=True,
        )
        return
    raise RuntimeError("Automatic installation is currently available only on Windows and macOS.")


def _portal_authority(host: str, port: int) -> str:
    try:
        address = ipaddress.ip_address(host)
        rendered_host = f"[{host}]" if address.version == 6 else host
    except ValueError:
        rendered_host = host
    return f"{rendered_host}:{port}"


def validate_config(candidate: dict[str, Any], *, require_username: bool = False) -> dict[str, Any]:
    """Return a normalized configuration or raise a user-facing ValueError."""
    config = DEFAULT_CONFIG.copy()
    config.update({key: value for key, value in candidate.items() if key in DEFAULT_CONFIG})
    username = str(config.get("username", "")).strip()
    if require_username and not username:
        raise ValueError("Portal username is required.")
    if len(username) > 256 or any(ord(char) < 32 for char in username):
        raise ValueError("Portal username contains unsupported characters.")

    scheme = str(config.get("portal_scheme", "https")).strip().casefold()
    if scheme not in {"http", "https"}:
        raise ValueError("Portal protocol must be HTTP or HTTPS.")
    host = str(config.get("portal_host", "")).strip().rstrip(".")
    if not host or len(host) > 253 or any(char.isspace() for char in host) or "/" in host or "://" in host:
        raise ValueError("Enter only a valid portal hostname or IP address, without a URL path.")
    try:
        ipaddress.ip_address(host)
    except ValueError:
        if not re.fullmatch(r"(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)*[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", host):
            raise ValueError("Portal hostname is not valid.")

    try:
        port = int(config.get("portal_port", 0))
        interval = int(config.get("check_interval_seconds", 0))
        max_backoff = int(config.get("login_backoff_max_seconds", 0))
        revision = int(config.get("config_revision", 0) or 0)
    except (TypeError, ValueError) as exc:
        raise ValueError("Port, interval, and retry limit must be whole numbers.") from exc
    if not 1 <= port <= 65535:
        raise ValueError("Portal port must be between 1 and 65535.")
    if not 15 <= interval <= 3600:
        raise ValueError("Check interval must be between 15 and 3600 seconds.")
    if not 30 <= max_backoff <= 3600:
        raise ValueError("Maximum login retry delay must be between 30 and 3600 seconds.")
    interface = str(config.get("network_interface", "auto")).strip() or "auto"
    if len(interface) > 256 or any(ord(char) < 32 for char in interface):
        raise ValueError("Network interface name is not valid.")
    credential_store = str(config.get("credential_store", "") or "").strip().casefold()
    if credential_store not in {"", "vault", "file"}:
        credential_store = ""

    return {
        "username": username,
        "portal_scheme": scheme,
        "portal_host": host,
        "portal_port": port,
        "check_interval_seconds": interval,
        "login_backoff_max_seconds": max_backoff,
        "network_interface": interface,
        "allow_self_signed_portal": bool(config.get("allow_self_signed_portal", True)),
        "credential_store": credential_store,
        "config_revision": revision,
    }


def ensure_dependencies(*required: str) -> None:
    required = required or ("keyring", "psutil")
    missing = []
    if "keyring" in required and keyring is None:
        missing.append("keyring")
    if "psutil" in required and psutil is None:
        missing.append("psutil")
    if missing:
        raise SystemExit(
            "Missing dependencies: " + ", ".join(missing)
            + ". Run install.py first, or: python -m pip install -r requirements.txt"
        )


def load_config() -> dict[str, Any]:
    config = DEFAULT_CONFIG.copy()
    if CONFIG_PATH.exists():
        try:
            saved = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
            if isinstance(saved, dict):
                config.update(saved)
        except (OSError, json.JSONDecodeError) as exc:
            raise RuntimeError(f"Cannot read {CONFIG_PATH}: {exc}") from exc
    return validate_config(config)


def save_config(config: dict[str, Any]) -> None:
    config = validate_config(config)
    config["config_revision"] = time.time_ns()
    app_dir().mkdir(parents=True, exist_ok=True)
    temporary = CONFIG_PATH.with_suffix(".tmp")
    temporary.write_text(json.dumps(config, indent=2) + "\n", encoding="utf-8")
    if os.name != "nt":
        temporary.chmod(0o600)
    temporary.replace(CONFIG_PATH)


def write_status(status: dict[str, Any]) -> None:
    app_dir().mkdir(parents=True, exist_ok=True)
    # The monitor and tray threads can both publish; give each writer its own
    # temporary file so concurrent replacements cannot collide.
    temporary = STATUS_PATH.with_suffix(f".{os.getpid()}.{threading.get_ident()}.tmp")
    temporary.write_text(json.dumps(status, indent=2) + "\n", encoding="utf-8")
    if os.name != "nt":
        temporary.chmod(0o600)
    temporary.replace(STATUS_PATH)


def read_status() -> dict[str, Any] | None:
    try:
        value = json.loads(STATUS_PATH.read_text(encoding="utf-8"))
        return value if isinstance(value, dict) else None
    except (OSError, json.JSONDecodeError):
        return None


def snapshot_process_running(snapshot: dict[str, Any] | None) -> bool:
    try:
        process_id = int((snapshot or {}).get("process_id") or 0)
        return bool(psutil is not None and process_id > 0 and psutil.pid_exists(process_id))
    except (OSError, TypeError, ValueError):
        return False


def load_ui_state() -> dict[str, Any]:
    try:
        value = json.loads(UI_STATE_PATH.read_text(encoding="utf-8"))
        return value if isinstance(value, dict) else {}
    except (OSError, json.JSONDecodeError):
        return {}


def save_ui_state(state: dict[str, Any]) -> None:
    app_dir().mkdir(parents=True, exist_ok=True)
    temporary = UI_STATE_PATH.with_suffix(".tmp")
    temporary.write_text(json.dumps(state, indent=2) + "\n", encoding="utf-8")
    if os.name != "nt":
        temporary.chmod(0o600)
    temporary.replace(UI_STATE_PATH)


def request_external_check() -> None:
    app_dir().mkdir(parents=True, exist_ok=True)
    temporary = WAKE_PATH.with_suffix(".tmp")
    temporary.write_text(str(time.time_ns()), encoding="ascii")
    temporary.replace(WAKE_PATH)


class VaultUnavailable(RuntimeError):
    """The password lives in an OS credential vault that cannot be used right now."""


class _NoVault(Exception):
    """No usable credential vault backend exists in this session."""


VAULT_TIMEOUT_SECONDS = 60.0
VAULT_REPROBE_SECONDS = 10.0
VAULT_ABANDON_SECONDS = 600.0
_vault_state: dict[str, Any] = {"probed_at": float("-inf"), "worker": None, "started_at": 0.0}


def _is_linux() -> bool:
    return sys.platform.startswith("linux")


def _active_keyring():
    """Return a usable keyring backend or None.

    keyring caches its first backend detection for the life of the process.
    A service started before the desktop's Secret Service daemon would
    otherwise keep the fail backend forever, so Linux re-probes periodically.
    """
    if keyring is None:
        return None
    try:
        backend = keyring.get_keyring()
        if getattr(backend, "priority", 0) > 0:
            return backend
    except Exception:
        pass
    if not _is_linux():
        return None
    now = time.monotonic()
    if now - _vault_state["probed_at"] < VAULT_REPROBE_SECONDS:
        return None
    _vault_state["probed_at"] = now
    try:
        from keyring.backends import SecretService

        candidate = SecretService.Keyring()
        if candidate.priority > 0:
            keyring.set_keyring(candidate)
            return candidate
    except Exception:
        pass
    return None


def _with_vault(operation, timeout: float = VAULT_TIMEOUT_SECONDS):
    """Run operation(backend) with a deadline.

    Secret Service unlock prompts block without a timeout; running the call
    on a worker thread keeps the monitor loop alive while one is pending.
    """
    worker = _vault_state["worker"]
    if (
        worker is not None
        and worker.is_alive()
        and time.monotonic() - _vault_state["started_at"] < VAULT_ABANDON_SECONDS
    ):
        raise VaultUnavailable("The credential vault is still waiting for an earlier request; it may be locked.")
    # A request stuck for longer (an unlock prompt that never completes) is
    # abandoned so a recovered vault can be used again without a restart.
    outcome: dict[str, Any] = {}

    def target() -> None:
        try:
            backend = _active_keyring()
            if backend is None:
                outcome["missing"] = True
            else:
                outcome["value"] = operation(backend)
        except BaseException as exc:
            outcome["error"] = exc

    worker = threading.Thread(target=target, name="wifi-agent-vault", daemon=True)
    _vault_state["worker"] = worker
    _vault_state["started_at"] = time.monotonic()
    worker.start()
    worker.join(timeout)
    if worker.is_alive():
        raise VaultUnavailable(
            f"The credential vault did not answer within {int(timeout)} seconds; it may be locked."
        )
    if outcome.get("missing"):
        raise _NoVault()
    if "error" in outcome:
        raise outcome["error"]
    return outcome.get("value")


def _read_file_credentials() -> dict[str, str]:
    try:
        raw = json.loads(CREDENTIALS_PATH.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    accounts = raw.get("accounts") if isinstance(raw, dict) else None
    if not isinstance(accounts, dict):
        return {}
    result: dict[str, str] = {}
    for name, encoded in accounts.items():
        try:
            result[str(name)] = base64.b64decode(str(encoded).encode("ascii"), validate=True).decode("utf-8")
        except (ValueError, UnicodeError):
            continue
    return result


def _write_file_credentials(accounts: dict[str, str]) -> None:
    CREDENTIALS_PATH.parent.mkdir(parents=True, exist_ok=True)
    CREDENTIALS_PATH.parent.chmod(0o700)
    if not accounts:
        CREDENTIALS_PATH.unlink(missing_ok=True)
        return
    payload = {
        "format": 1,
        "note": "Base64 is an encoding, not encryption. This file is protected only by its permissions.",
        "accounts": {
            name: base64.b64encode(password.encode("utf-8")).decode("ascii")
            for name, password in accounts.items()
        },
    }
    temporary = CREDENTIALS_PATH.with_suffix(".tmp")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        handle.write(json.dumps(payload, indent=2) + "\n")
    temporary.chmod(0o600)
    temporary.replace(CREDENTIALS_PATH)


def _file_credential(username: str) -> str | None:
    """Linux fallback store, used only when no Secret Service vault exists."""
    if not _is_linux() or not CREDENTIALS_PATH.exists():
        return None
    try:
        if CREDENTIALS_PATH.stat().st_mode & 0o077:
            CREDENTIALS_PATH.chmod(0o600)
    except OSError:
        pass
    return _read_file_credentials().get(username) or None


def _forget_file_credentials(*usernames: str) -> None:
    if not _is_linux() or not CREDENTIALS_PATH.exists():
        return
    accounts = _read_file_credentials()
    if any(name in accounts for name in usernames):
        for name in usernames:
            accounts.pop(name, None)
        _write_file_credentials(accounts)


def credential_backend_ready() -> tuple[bool, str]:
    if keyring is None:
        return False, "The keyring package is not installed."
    try:
        return True, _with_vault(lambda backend: type(backend).__module__.removeprefix("keyring.backends."))
    except _NoVault:
        return False, "No usable operating-system credential vault was found."
    except Exception as exc:
        return False, str(exc)


def store_credentials(username: str, password: str, old_username: str = "") -> str:
    """Save the password and return the store used: "vault" or "file"."""

    def save(backend) -> None:
        backend.set_password(KEYRING_SERVICE, username, password)
        if old_username and old_username != username:
            try:
                backend.delete_password(KEYRING_SERVICE, old_username)
            except Exception:
                pass

    vault_error: BaseException | None = None
    try:
        _with_vault(save)
        _forget_file_credentials(username, old_username)
        return "vault"
    except _NoVault:
        pass
    except Exception as exc:
        vault_error = exc
    if _is_linux():
        accounts = _read_file_credentials()
        if old_username and old_username != username:
            accounts.pop(old_username, None)
        accounts[username] = password
        _write_file_credentials(accounts)
        return "file"
    detail = str(vault_error) if vault_error else "No usable operating-system credential vault was found."
    raise RuntimeError(
        f"The password could not be saved: {detail} "
        "Unlock Windows Credential Manager or the macOS Keychain and try again."
    )


def get_password(username: str, expected_store: str = "") -> str:
    """Return the saved password.

    expected_store is the store recorded at save time. Configurations from
    before 1.4.0 have none and always used the vault.
    """
    ensure_dependencies("keyring")
    if expected_store == "file":
        # The file holds the newest password when it was saved while the
        # vault was locked; an older vault copy must not override it.
        password = _file_credential(username)
        if password:
            return password
    vault_error: BaseException | None = None
    vault_exists = True
    try:
        password = _with_vault(lambda backend: backend.get_password(KEYRING_SERVICE, username))
        if password:
            return password
    except _NoVault:
        vault_exists = False
    except Exception as exc:
        vault_error = exc
    password = _file_credential(username)
    if password:
        return password
    if isinstance(vault_error, VaultUnavailable):
        raise vault_error
    if vault_error is not None:
        raise VaultUnavailable(f"The OS credential vault is unavailable: {vault_error}") from vault_error
    if not vault_exists and expected_store != "file":
        if _is_linux():
            raise VaultUnavailable(
                "The password vault (GNOME Keyring / KWallet Secret Service) is not running or is locked. "
                "Unlock it, or open WiFi Agent and enter the password again to keep it in a private file."
            )
        raise VaultUnavailable("No usable operating-system credential vault was found.")
    raise RuntimeError("No saved password was found. Open WiFi Agent and enter the password again.")


def active_interfaces() -> list[str]:
    """Return active, non-loopback interfaces that currently own an IPv4 address."""
    ensure_dependencies("psutil")
    try:
        stats = psutil.net_if_stats()
        address_map = psutil.net_if_addrs()
    except (OSError, PermissionError):
        return _fallback_active_interfaces()
    result: list[str] = []
    for name, addresses in address_map.items():
        if not stats.get(name) or not stats[name].isup:
            continue
        if any(a.family == socket.AF_INET and not a.address.startswith("127.") for a in addresses):
            result.append(name)
    return sorted(result, key=str.casefold)


def _fallback_active_interfaces() -> list[str]:
    """Best-effort fallback for restricted machines where psutil/netlink is blocked."""
    if sys.platform.startswith("linux"):
        result = []
        for interface_path in Path("/sys/class/net").glob("*"):
            try:
                if interface_path.name == "lo":
                    continue
                state = (interface_path / "operstate").read_text(encoding="ascii").strip()
                carrier_path = interface_path / "carrier"
                carrier = carrier_path.read_text(encoding="ascii").strip() if carrier_path.exists() else "1"
                if state == "up" and carrier == "1":
                    result.append(interface_path.name)
            except OSError:
                continue
        return sorted(result, key=str.casefold)

    if sys.platform == "darwin":
        try:
            names = subprocess.run(
                ["ifconfig", "-l"], check=True, capture_output=True, text=True, timeout=5
            ).stdout.split()
            active = []
            for name in names:
                detail = subprocess.run(
                    ["ifconfig", name], check=True, capture_output=True, text=True, timeout=5
                ).stdout
                if "status: active" in detail and " inet " in detail:
                    active.append(name)
            return sorted(active, key=str.casefold)
        except (OSError, subprocess.SubprocessError):
            return []

    if sys.platform == "win32":
        command = (
            "Get-NetIPConfiguration | Where-Object { $_.IPv4Address -and "
            "$_.NetAdapter.Status -eq 'Up' } | Select-Object -ExpandProperty InterfaceAlias"
        )
        try:
            output = subprocess.run(
                ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", command],
                check=True, capture_output=True, text=True, timeout=8, creationflags=WINDOWS_NO_WINDOW,
            ).stdout
            return sorted((line.strip() for line in output.splitlines() if line.strip()), key=str.casefold)
        except (OSError, subprocess.SubprocessError):
            return []
    return []


@lru_cache(maxsize=1)
def _mac_wireless_interfaces() -> frozenset[str]:
    if sys.platform != "darwin":
        return frozenset()
    try:
        output = subprocess.run(
            ["networksetup", "-listallhardwareports"],
            check=True, capture_output=True, text=True, timeout=8,
        ).stdout
    except (OSError, subprocess.SubprocessError):
        return frozenset()
    wireless: set[str] = set()
    hardware_port = ""
    for line in output.splitlines():
        if line.startswith("Hardware Port:"):
            hardware_port = line.partition(":")[2].strip().casefold()
        elif line.startswith("Device:") and any(word in hardware_port for word in ("wi-fi", "airport", "wireless")):
            wireless.add(line.partition(":")[2].strip())
    return frozenset(wireless)


def _looks_wired(name: str) -> bool:
    lower = name.casefold()
    excluded = (
        "wi-fi", "wifi", "wlan", "wireless", "airport", "loopback", "bluetooth",
        "docker", "veth", "virbr", "vmnet", "virtual", "tailscale", "utun", "tun", "tap",
    )
    if any(word in lower for word in excluded):
        return False
    if sys.platform == "darwin" and name in _mac_wireless_interfaces():
        return False
    if sys.platform.startswith("linux"):
        interface_path = Path("/sys/class/net") / name
        if (interface_path / "wireless").exists():
            return False
        # A physical/USB Ethernet interface has a device link. Some valid bonded
        # interfaces do not, so names commonly used for Ethernet remain accepted.
        if (interface_path / "device").exists():
            return True
        return lower.startswith(("eth", "en", "eno", "ens", "enp", "bond"))
    return True


def wired_interfaces(configured: str = "auto") -> list[str]:
    active = active_interfaces()
    if configured and configured != "auto":
        return [configured] if configured in active else []
    return [name for name in active if _looks_wired(name)]


def portal_port_open(host: str, port: int, timeout: float = 3.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


INTERNET_PROBES = (
    ("https://connectivitycheck.gstatic.com/generate_204", 204, None),
    ("http://www.msftconnecttest.com/connecttest.txt", 200, b"Microsoft Connect Test"),
    ("https://captive.apple.com/hotspot-detect.html", 200, b"Success"),
)


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, request, file_pointer, code, message, headers, new_url):
        return None


def internet_available(timeout: float = 5.0) -> bool:
    # Captive portals commonly return a redirect or a branded HTTP 200 page.
    # Refusing redirects and checking exact response fingerprints prevents both
    # from being mistaken for working internet access.
    opener = build_opener(_NoRedirect(), HTTPSHandler(context=ssl.create_default_context()))
    for url, expected_status, expected_body in INTERNET_PROBES:
        try:
            request = Request(url, headers={"User-Agent": f"{APP_NAME}/1.0"})
            with opener.open(request, timeout=timeout) as response:
                body = response.read(256)
                if response.status == expected_status and (
                    expected_body is None or expected_body in body
                ):
                    return True
        except (HTTPError, URLError, OSError, TimeoutError, ssl.SSLError):
            continue
    return False


class PortalResult(NamedTuple):
    """Outcome of a portal request.

    kind is one of: alive (session valid), expired (portal asks to log in
    again), rejected (credentials refused), denied (account refused for
    another reason, such as a quota), limit (maximum concurrent logins),
    network (transport failure), unknown (unrecognised reply).
    """

    ok: bool
    message: str
    kind: str = "unknown"


_LIMIT_WORDS = ("maximum login", "max login", "login limit")
_REJECTED_WORDS = (
    "password", "invalid user", "invalid credential", "could not log you on",
    "incorrect", "authentication failed", "wrong user",
)
_DENIED_WORDS = ("exceeded", "denied", "not allowed", "disabled", "locked", "blocked")
_EXPIRED_WORDS = ("login_again", "login again", "not logged", "logged out", "inactive", "expired", "dead")
_FAILURE_WORDS = ("fail", "invalid", "error", "could not")


class PortalClient:
    def __init__(self, config: dict[str, Any], password: str):
        self.username = str(config["username"])
        self.password = password
        self.scheme = str(config.get("portal_scheme", "https"))
        self.host = str(config["portal_host"])
        self.port = int(config["portal_port"])
        self.base_url = f"{self.scheme}://{_portal_authority(self.host, self.port)}"
        self.ssl_context = ssl.create_default_context()
        if config.get("allow_self_signed_portal", True):
            self.ssl_context.check_hostname = False
            self.ssl_context.verify_mode = ssl.CERT_NONE
        self.opener = build_opener(HTTPSHandler(context=self.ssl_context))
        self.unrecognised_replies: set[str] = set()

    def _request(self, request: Request, timeout: float = 10.0) -> str:
        with self.opener.open(request, timeout=timeout) as response:
            return response.read(64 * 1024).decode("utf-8", errors="replace")

    def _safe_message(self, message: str) -> str:
        value = message.replace(self.password, "[redacted]") if self.password else message
        return " ".join(value.split())[:300]

    @staticmethod
    def _response_summary(text: str) -> PortalResult:
        import xml.etree.ElementTree as ET

        fields = {"status": "", "message": "", "ack": ""}
        try:
            root = ET.fromstring(text)
            for element in root.iter():
                tag = element.tag.rsplit("}", 1)[-1].casefold() if isinstance(element.tag, str) else ""
                value = (element.text or "").strip()
                if tag in fields and not fields[tag]:
                    fields[tag] = value
        except ET.ParseError:
            pass
        status, message, ack = fields["status"], fields["message"], fields["ack"]
        combined = " ".join(part for part in (status, message) if part) or ack or "HTTP response received"
        lowered = combined.casefold()

        # Sophos/Cyberoam keep-alive replies: <ack>ack</ack> while the session
        # is valid and <ack>login_again</ack> once the portal has dropped it.
        if ack and not status and not message:
            if ack.casefold() in {"ack", "live", "ok"}:
                return PortalResult(True, ack, "alive")
            if any(word in ack.casefold() for word in _EXPIRED_WORDS):
                return PortalResult(False, ack, "expired")
            return PortalResult(False, ack, "unknown")

        for words, kind in (
            (_LIMIT_WORDS, "limit"),
            (_REJECTED_WORDS, "rejected"),
            (_DENIED_WORDS, "denied"),
            (_EXPIRED_WORDS, "expired"),
        ):
            if any(word in lowered for word in words):
                return PortalResult(False, combined, kind)
        failed = any(word in lowered for word in _FAILURE_WORDS)
        if status.upper() in {"ACK", "LIVE", "OK", "SUCCESS"} and not failed:
            return PortalResult(True, combined, "alive")
        if not status and message and not failed:
            return PortalResult(True, combined, "alive")
        return PortalResult(False, combined, "rejected" if status.upper() in {"ERROR", "FAIL", "FAILED"} else "unknown")

    def _summarise(self, text: str) -> PortalResult:
        result = self._response_summary(text)
        if result.kind == "unknown":
            # Keep a sanitised sample of replies the parser does not recognise
            # so a portal firmware difference can be diagnosed from the log.
            sample = self._safe_message(text)[:200]
            if sample not in self.unrecognised_replies and len(self.unrecognised_replies) < 20:
                self.unrecognised_replies.add(sample)
                logging.getLogger(APP_NAME).info("Unrecognised portal reply: %s", sample or "(empty)")
        return result._replace(message=self._safe_message(result.message))

    @staticmethod
    def _timestamp() -> str:
        return str(int(time.time() * 1000))

    def login(self) -> PortalResult:
        form = urlencode({
            "mode": "191",
            "username": self.username,
            "password": self.password,
            "a": self._timestamp(),
            "producttype": "0",
        }).encode("utf-8")
        request = Request(
            f"{self.base_url}/login.xml",
            data=form,
            headers={"Content-Type": "application/x-www-form-urlencoded", "User-Agent": f"{APP_NAME}/1.0"},
            method="POST",
        )
        try:
            return self._summarise(self._request(request))
        except (HTTPError, URLError, OSError, TimeoutError, ssl.SSLError) as exc:
            return PortalResult(False, self._safe_message(str(exc)), "network")

    def keep_alive(self) -> PortalResult:
        url = (
            f"{self.base_url}/live?mode=192&username={quote(self.username, safe='')}"
            f"&a={self._timestamp()}&producttype=0"
        )
        try:
            return self._summarise(self._request(Request(url, headers={"User-Agent": f"{APP_NAME}/1.0"}), 8))
        except (HTTPError, URLError, OSError, TimeoutError, ssl.SSLError) as exc:
            return PortalResult(False, self._safe_message(str(exc)), "network")


def build_logger(console: bool = True) -> logging.Logger:
    app_dir().mkdir(parents=True, exist_ok=True)
    logger = logging.getLogger(APP_NAME)
    logger.setLevel(logging.INFO)
    if logger.handlers:
        return logger
    formatter = logging.Formatter("%(asctime)s | %(levelname)s | %(message)s")
    file_handler = RotatingFileHandler(LOG_PATH, maxBytes=1_000_000, backupCount=3, encoding="utf-8")
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)
    if console:
        stream = logging.StreamHandler()
        stream.setFormatter(formatter)
        logger.addHandler(stream)
    return logger


@dataclass
class AgentSnapshot:
    phase: str = "starting"
    message: str = "Agent is starting"
    ethernet_connected: bool = False
    interfaces: tuple[str, ...] = ()
    portal_port_open: bool | None = None
    portal_authenticated: bool | None = None
    internet_available: bool | None = None
    paused: bool = False
    last_check_at: str | None = None
    last_login_at: str | None = None
    consecutive_login_failures: int = 0
    retry_in_seconds: int = 0
    process_id: int = 0
    started_at: str | None = None
    last_login_error: str | None = None
    last_login_error_kind: str | None = None
    session_lost_at: str | None = None
    last_recovery_seconds: int | None = None
    version: str = APP_VERSION


def sd_notify(message: str) -> bool:
    """Send a systemd service notification (READY, WATCHDOG, STATUS)."""
    address = os.environ.get("NOTIFY_SOCKET", "")
    if not address or not hasattr(socket, "AF_UNIX"):
        return False
    if address.startswith("@"):
        address = "\0" + address[1:]
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as notifier:
            notifier.connect(address)
            notifier.sendall(message.encode("utf-8", errors="replace"))
        return True
    except OSError:
        return False


class AlreadyRunning(RuntimeError):
    """Another WiFi Agent monitor holds the single-instance lock."""


class SingleInstance(AbstractContextManager):
    """A process-scoped lock that is released automatically after crashes."""

    def __init__(self) -> None:
        self._handle: Any = None
        self._kernel32: Any = None
        self._file: Any = None

    def __enter__(self):
        app_dir().mkdir(parents=True, exist_ok=True)
        if sys.platform == "win32":
            import ctypes
            from ctypes import wintypes

            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            kernel32.CreateMutexW.argtypes = (ctypes.c_void_p, wintypes.BOOL, wintypes.LPCWSTR)
            kernel32.CreateMutexW.restype = wintypes.HANDLE
            kernel32.CloseHandle.argtypes = (wintypes.HANDLE,)
            kernel32.CloseHandle.restype = wintypes.BOOL
            self._kernel32 = kernel32
            self._handle = kernel32.CreateMutexW(None, False, "Local\\WiFiAgent.Monitor")
            if not self._handle:
                raise RuntimeError("Could not create the Windows single-instance mutex.")
            if ctypes.get_last_error() == 183:  # ERROR_ALREADY_EXISTS
                kernel32.CloseHandle(self._handle)
                self._handle = None
                raise AlreadyRunning("WiFi Agent is already running.")
            return self

        import fcntl

        self._file = LOCK_PATH.open("a+", encoding="ascii")
        try:
            fcntl.flock(self._file.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            self._file.close()
            self._file = None
            raise AlreadyRunning("WiFi Agent is already running.") from exc
        self._file.seek(0)
        self._file.truncate()
        self._file.write(str(os.getpid()))
        self._file.flush()
        if os.name != "nt":
            LOCK_PATH.chmod(0o600)
        return self

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        if self._handle is not None:
            self._kernel32.CloseHandle(self._handle)
            self._handle = None
            self._kernel32 = None
        if self._file is not None:
            self._file.close()
            self._file = None


class AgentMonitor:
    """Resilient monitoring loop shared by the service, tray, and console modes."""

    def __init__(self, logger: logging.Logger | None = None, status_callback=None):
        self.logger = logger or build_logger(console=sys.stderr is not None and sys.stderr.isatty())
        self.status_callback = status_callback
        self.stop_event = threading.Event()
        self.wake_event = threading.Event()
        self.pause_event = threading.Event()
        self.snapshot = AgentSnapshot(process_id=os.getpid(), started_at=utc_now())
        self._snapshot_lock = threading.Lock()
        self._client: PortalClient | None = None
        self._config: dict[str, Any] | None = None
        self._config_signature = ""
        self._last_logged_state: tuple[Any, ...] | None = None
        self._login_failures = 0
        self._next_login_at = 0.0
        self._keepalive_failures = 0
        self._healthy = False
        self._lost_at_wall: float | None = None
        self._last_watchdog = float("-inf")
        self._network_signature: tuple[Any, ...] | None = None
        self._vault_failures = 0

    def current_snapshot(self) -> AgentSnapshot:
        with self._snapshot_lock:
            return AgentSnapshot(**asdict(self.snapshot))

    def _publish(self, **changes: Any) -> None:
        with self._snapshot_lock:
            previous_message = self.snapshot.message
            for key, value in changes.items():
                setattr(self.snapshot, key, value)
            payload = asdict(self.snapshot)
        try:
            write_status(payload)
        except OSError as exc:
            self.logger.debug("Could not write status file: %s", exc)
        if payload["message"] != previous_message:
            sd_notify(f"STATUS={payload['message'][:200]}")
        if self.status_callback:
            try:
                self.status_callback(self.current_snapshot())
            except Exception as exc:
                self.logger.debug("Status callback failed: %s", exc)

    def stop(self) -> None:
        self.stop_event.set()
        self.wake_event.set()

    def request_check(self) -> None:
        self.wake_event.set()

    def set_paused(self, paused: bool) -> None:
        if paused:
            self.pause_event.set()
        else:
            self.pause_event.clear()
        self._publish(paused=paused, phase="paused" if paused else "checking", message="Monitoring paused" if paused else "Monitoring resumed")
        self.wake_event.set()

    def _load_client(self) -> tuple[dict[str, Any], PortalClient]:
        config = validate_config(load_config(), require_username=True)
        signature = json.dumps(config, sort_keys=True, separators=(",", ":"))
        if signature != self._config_signature or self._client is None:
            password = get_password(str(config["username"]), str(config.get("credential_store", "")))
            self._client = PortalClient(config, password)
            self._config = config
            self._config_signature = signature
            self._login_failures = 0
            self._next_login_at = 0.0
            self.logger.info(
                "Configuration loaded; portal=%s interface=%s",
                self._client.base_url,
                config["network_interface"],
            )
        return config, self._client

    def _schedule_login_retry(self, config: dict[str, Any], kind: str = "unknown") -> int:
        self._login_failures += 1
        attempt = min(self._login_failures - 1, 8)
        if kind in {"rejected", "denied", "expired"}:
            # The portal refused these credentials; back off exponentially so
            # a wrong password cannot lock the account.
            base = max(30, int(config["check_interval_seconds"]))
            ceiling = int(config["login_backoff_max_seconds"])
            delay = min(ceiling, base * (2 ** attempt))
            delay = min(ceiling, max(30, int(delay * random.uniform(0.9, 1.1))))
        elif kind == "limit":
            # The previous session is still counted; it frees up quickly.
            delay = max(5, int(30 * random.uniform(0.9, 1.1)))
        else:
            # Timeouts and unrecognised replies are usually transient.
            delay = max(5, int(min(60, 10 * (2 ** min(attempt, 3))) * random.uniform(0.9, 1.1)))
        self._next_login_at = time.monotonic() + delay
        return delay

    def _reset_login_backoff(self) -> None:
        self._login_failures = 0
        self._next_login_at = 0.0

    def _needs_attention(self, phase: str, message: str) -> bool:
        if message != self.snapshot.message:
            label = "Credential vault problem" if phase == "vault-unavailable" else "Configuration/credential problem"
            self.logger.warning("%s: %s", label, message)
        self._healthy = False
        self._publish(
            phase=phase,
            message=message,
            ethernet_connected=False,
            interfaces=(),
            portal_port_open=None,
            portal_authenticated=None,
            internet_available=None,
            paused=False,
            last_check_at=utc_now(),
        )
        return False

    def check_once(self) -> bool:
        if self.pause_event.is_set():
            self._publish(phase="paused", message="Monitoring paused", paused=True)
            return False

        try:
            config, client = self._load_client()
        except VaultUnavailable as exc:
            self._vault_failures += 1
            return self._needs_attention("vault-unavailable", str(exc))
        except (OSError, RuntimeError, ValueError) as exc:
            self._vault_failures = 0
            return self._needs_attention("needs-setup", str(exc))
        self._vault_failures = 0

        interfaces = wired_interfaces(str(config["network_interface"]))
        ethernet = bool(interfaces)
        port_open = portal_port_open(client.host, client.port) if ethernet else None
        session = client.keep_alive() if ethernet and port_open else None
        session_kind = session.kind if session is not None else None
        # When the portal says the session is gone, log in straight away;
        # probing public sites first would only delay the recovery.
        online = internet_available() if ethernet and session_kind != "expired" else None
        portal_authenticated: bool | None = (
            True if session_kind == "alive" else False if session is not None else None
        )

        state = (tuple(interfaces), port_open, portal_authenticated, online)
        if state != self._last_logged_state:
            self.logger.info(
                "Status: ethernet=%s (%s), portal-port=%s, portal-session=%s, internet=%s",
                "connected" if ethernet else "disconnected",
                ", ".join(interfaces) if interfaces else "none",
                "open" if port_open is True else "closed/unreachable" if port_open is False else "not checked",
                "authenticated" if portal_authenticated is True else "not authenticated" if portal_authenticated is False else "not checked",
                "available" if online is True else "unavailable" if online is False else "not checked",
            )
            self._last_logged_state = state

        phase = "online" if online else "offline"
        message = "Internet available" if online else "Internet unavailable"
        retry_in = max(0, int(self._next_login_at - time.monotonic()))
        changes: dict[str, Any] = {}

        if ethernet and port_open and session_kind == "alive":
            self._reset_login_backoff()
            self._keepalive_failures = 0
            if online:
                phase = "online"
                message = "Portal session connected; internet available"
            else:
                phase = "connected"
                message = "Portal session connected; internet check is inconclusive"

        elif ethernet and port_open and online and session_kind != "expired":
            self._reset_login_backoff()
            self._keepalive_failures += 1
            message = "Internet available"
            if self._keepalive_failures == 1 or self._keepalive_failures % 5 == 0:
                self.logger.warning("Portal session check was not acknowledged: %s", session.message if session else "")

        elif ethernet and port_open:
            if session_kind == "expired" and self._healthy:
                self.logger.info("Portal session ended (%s); logging in again", session.message if session else "")
                if self._lost_at_wall is None:
                    self._lost_at_wall = time.time()
                    changes["session_lost_at"] = utc_now()
            elif session_kind == "expired":
                self.logger.info("Portal reports no active session; logging in")
            now = time.monotonic()
            if now >= self._next_login_at:
                self.logger.info("Ethernet and portal are reachable; attempting portal login")
                result = client.login()
                if result.ok:
                    self.logger.info("Portal login accepted: %s", result.message)
                    portal_authenticated = True
                    changes.update(last_login_at=utc_now(), last_login_error=None, last_login_error_kind=None)
                    if not self.stop_event.wait(3):
                        online = internet_available()
                    self._reset_login_backoff()
                    retry_in = 0
                    if online:
                        phase = "online"
                        message = "Portal session connected; internet available"
                        self.logger.info("Internet became available after portal login")
                    else:
                        phase = "connected"
                        message = "Portal session connected; internet check is inconclusive"
                        self.logger.info("Portal session is authenticated; public connectivity probes remain unavailable")
                else:
                    portal_authenticated = False
                    delay = self._schedule_login_retry(config, result.kind)
                    retry_in = delay
                    phase = "backoff"
                    message = {
                        "rejected": f"Portal rejected the username or password; retrying in {delay}s",
                        "denied": f"Portal refused the login; retrying in {delay}s",
                        "limit": f"Portal login limit reached; retrying in {delay}s",
                    }.get(result.kind, f"Login failed; retrying in {delay}s")
                    changes.update(last_login_error=result.message, last_login_error_kind=result.kind)
                    self.logger.warning("%s: %s", message, result.message)
            else:
                phase = "backoff"
                message = f"Waiting {retry_in}s before the next login attempt"
        elif ethernet and not port_open:
            message = (
                "Internet available; the login portal is not on this network"
                if online
                else "Ethernet connected; portal port is unreachable"
            )
            self._reset_login_backoff()
        else:
            message = "Waiting for the selected Ethernet interface"
            self._reset_login_backoff()

        if phase in {"online", "connected"}:
            if self._lost_at_wall is not None:
                seconds = max(0, int(time.time() - self._lost_at_wall))
                self.logger.info("Connection restored after %ss", seconds)
                changes.update(last_recovery_seconds=seconds, session_lost_at=None)
                self._lost_at_wall = None
            self._healthy = True
        else:
            if self._healthy and ethernet and self._lost_at_wall is None:
                self._lost_at_wall = time.time()
                changes["session_lost_at"] = utc_now()
            self._healthy = False

        self._publish(
            phase=phase,
            message=message,
            ethernet_connected=ethernet,
            interfaces=tuple(interfaces),
            portal_port_open=port_open,
            portal_authenticated=portal_authenticated,
            internet_available=online,
            paused=False,
            last_check_at=utc_now(),
            consecutive_login_failures=self._login_failures,
            retry_in_seconds=retry_in,
            **changes,
        )
        return bool(online or portal_authenticated)

    def _next_wait_seconds(self) -> float:
        interval = int((self._config or DEFAULT_CONFIG)["check_interval_seconds"])
        snapshot = self.current_snapshot()
        if snapshot.phase in HEALTHY_PHASES:
            return interval
        if snapshot.phase == "backoff" and snapshot.retry_in_seconds > 0:
            return max(DEGRADED_CHECK_SECONDS, min(interval, snapshot.retry_in_seconds))
        if snapshot.phase == "vault-unavailable":
            # Each attempt may show an unlock prompt; back off to 5 minutes.
            # Saving settings, Check now, resume, or a network change still
            # retry immediately.
            return min(300, DEGRADED_CHECK_SECONDS * 2 ** min(max(self._vault_failures - 1, 0), 5))
        return min(interval, DEGRADED_CHECK_SECONDS)

    def _watchdog_ping(self) -> None:
        now = time.monotonic()
        if now - self._last_watchdog >= 10:
            self._last_watchdog = now
            sd_notify("WATCHDOG=1")

    def _network_fingerprint(self) -> tuple[Any, ...] | None:
        """Return the interface selection plus wired interfaces and their IPv4 addresses."""
        if psutil is None:
            return None
        configured = str((self._config or DEFAULT_CONFIG).get("network_interface", "auto"))
        try:
            stats = psutil.net_if_stats()
            addresses = psutil.net_if_addrs()
        except (OSError, PermissionError):
            return None
        result = []
        for name in sorted(addresses):
            if configured != "auto" and name != configured:
                continue
            if not stats.get(name) or not stats[name].isup:
                continue
            if configured == "auto" and not _looks_wired(name):
                continue
            ipv4 = tuple(sorted(item.address for item in addresses[name] if item.family == socket.AF_INET))
            if ipv4:
                result.append((name, ipv4))
        return (configured, tuple(result))

    def _wait_for_next_check(self, seconds: float) -> None:
        deadline = time.monotonic() + seconds
        # Linux and macOS monotonic clocks stop while suspended, so a jump of
        # wall-clock time relative to them means the machine just resumed.
        clock_offset = time.time() - time.monotonic()
        next_network_check = time.monotonic() + 2
        while not self.stop_event.is_set():
            self._watchdog_ping()
            remaining = deadline - time.monotonic()
            if remaining <= 0 or self.wake_event.wait(min(1.0, remaining)):
                self.wake_event.clear()
                return
            if WAKE_PATH.exists():
                try:
                    WAKE_PATH.unlink()
                except OSError:
                    pass
                return
            if abs((time.time() - time.monotonic()) - clock_offset) > 15:
                self.logger.info("System resumed from sleep or the clock changed; checking now")
                self._reset_login_backoff()
                self._vault_failures = 0
                return
            if time.monotonic() >= next_network_check:
                next_network_check = time.monotonic() + 2
                fingerprint = self._network_fingerprint()
                if fingerprint is not None and fingerprint != self._network_signature:
                    # A new interface selection in the settings is not a network change.
                    changed = self._network_signature is not None and self._network_signature[0] == fingerprint[0]
                    self._network_signature = fingerprint
                    if changed:
                        self.logger.info("Wired network changed; checking now")
                        self._reset_login_backoff()
                        return

    def run(self, once: bool = False) -> int:
        self.logger.info("Agent monitor started (version %s)", APP_VERSION)
        sd_notify(f"READY=1\nSTATUS={self.snapshot.message}")
        self._network_signature = self._network_fingerprint()
        try:
            while not self.stop_event.is_set():
                self._watchdog_ping()
                try:
                    online = self.check_once()
                except Exception:
                    self.logger.exception("Unexpected monitor-cycle error; the agent will continue")
                    self._publish(phase="error", message="Unexpected monitoring error; see logs", last_check_at=utc_now())
                    online = False
                if once:
                    return 0 if online else 1
                self._wait_for_next_check(self._next_wait_seconds())
        finally:
            sd_notify("STOPPING=1")
            self.logger.info("Agent monitor stopped")
        return 0


class Notice(NamedTuple):
    kind: str
    summary: str
    body: str
    urgency: int = 1  # 0 low, 1 normal, 2 critical (freedesktop urgency levels)
    attention: bool = False  # surface the window if notifications cannot be shown


class NotificationPolicy:
    """Decide which status changes deserve a desktop notification.

    Each problem is announced once per incident, a recovery is announced
    only after a problem was announced, and short-lived vault or portal
    outages at login get a grace period instead of an immediate alarm.
    """

    VAULT_GRACE_SECONDS = 45
    UNREACHABLE_GRACE_SECONDS = 30

    def __init__(self, clock=time.monotonic):
        self._clock = clock
        self._last_login_at: str | None = None
        self._signed_in_before = False
        self._failures = 0
        self._announced: set[str] = set()
        self._problem_announced = False
        self._vault_since: float | None = None
        self._unreachable_since: float | None = None

    def _announce(self, notice: Notice) -> Notice | None:
        if notice.kind in self._announced:
            return None
        self._announced.add(notice.kind)
        self._problem_announced = True
        return notice

    def observe(self, snapshot: AgentSnapshot) -> Notice | None:
        now = self._clock()
        phase = snapshot.phase
        login_changed = bool(snapshot.last_login_at) and snapshot.last_login_at != self._last_login_at
        self._last_login_at = snapshot.last_login_at
        failures_started = snapshot.consecutive_login_failures > 0 and self._failures == 0
        self._failures = snapshot.consecutive_login_failures
        if phase != "vault-unavailable":
            self._vault_since = None
        if phase != "offline":
            self._unreachable_since = None

        if phase in {"online", "connected"}:
            recovery = snapshot.last_recovery_seconds
            had_problem = self._problem_announced
            self._announced.clear()
            self._problem_announced = False
            if login_changed:
                first = not self._signed_in_before
                self._signed_in_before = True
                if first and not had_problem:
                    return Notice("signed-in", "Signed in to the portal", "Internet access is ready.", 0)
                detail = f" after {recovery}s offline" if recovery is not None and recovery >= 2 else ""
                return Notice(
                    "signed-in",
                    "Signed back in automatically",
                    f"The portal ended your session; WiFi Agent logged you in again{detail}.",
                    0,
                )
            if had_problem:
                detail = f" after {recovery}s" if recovery is not None and recovery >= 2 else ""
                return Notice("recovered", "Connection restored", f"Internet access is working again{detail}.", 0)
            return None

        if phase == "vault-unavailable":
            self._vault_since = now if self._vault_since is None else self._vault_since
            if now - self._vault_since < self.VAULT_GRACE_SECONDS:
                return None
            return self._announce(Notice("vault", "Password vault unavailable", snapshot.message, 2, True))
        if phase == "needs-setup":
            return self._announce(Notice("setup", "WiFi Agent needs setup", snapshot.message, 2, True))
        if phase == "error":
            return self._announce(
                Notice("error", "WiFi Agent hit an unexpected error", "Monitoring continues. Open Diagnostics for details.")
            )
        if snapshot.consecutive_login_failures == 0:
            # A new failure streak (for example after a password change) is
            # announced again.
            self._announced -= {"login-failed", "password"}
        if phase == "backoff" and snapshot.last_login_error_kind == "rejected":
            return self._announce(Notice(
                "password",
                "Portal rejected your password",
                f"{snapshot.last_login_error or ''}\nOpen WiFi Agent to update the saved password.".strip(),
                2,
                True,
            ))
        if phase == "backoff" and failures_started:
            detail = snapshot.last_login_error or ""
            if snapshot.last_login_error_kind == "limit":
                return self._announce(Notice("login-failed", "Portal login limit reached", snapshot.message))
            return self._announce(Notice("login-failed", "Portal login failed", f"{detail}\n{snapshot.message}".strip()))
        if (
            phase == "offline"
            and snapshot.ethernet_connected
            and snapshot.portal_port_open is False
            and not snapshot.internet_available
        ):
            self._unreachable_since = now if self._unreachable_since is None else self._unreachable_since
            if now - self._unreachable_since >= self.UNREACHABLE_GRACE_SECONDS:
                return self._announce(Notice(
                    "portal-unreachable",
                    "Login portal unreachable",
                    "Ethernet is connected but the portal does not answer. WiFi Agent keeps trying.",
                ))
        return None


def _macos_notify(notice: Notice) -> None:
    script = (
        "on run argv",
        "display notification (item 3 of argv) with title (item 1 of argv) subtitle (item 2 of argv)",
        "end run",
    )
    command = ["osascript"]
    for line in script:
        command.extend(["-e", line])
    subprocess.Popen(
        [*command, APP_DISPLAY_NAME, notice.summary, notice.body],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


def _session_bus_address() -> str | None:
    address = os.environ.get("DBUS_SESSION_BUS_ADDRESS", "")
    if address:
        return address
    runtime = os.environ.get("XDG_RUNTIME_DIR") or (f"/run/user/{os.getuid()}" if hasattr(os, "getuid") else "")
    bus = Path(runtime) / "bus" if runtime else None
    if bus is not None and bus.exists():
        return f"unix:path={bus}"
    return None


_GRAPHICAL_VARIABLES = (
    "DISPLAY", "WAYLAND_DISPLAY", "XAUTHORITY", "XDG_CURRENT_DESKTOP", "XDG_SESSION_TYPE",
    "XDG_SESSION_DESKTOP", "DESKTOP_SESSION", "DBUS_SESSION_BUS_ADDRESS", "XDG_RUNTIME_DIR",
)


_USER_MANAGER_ENVIRONMENT: dict[str, Any] = {"at": float("-inf"), "values": {}}


def _user_manager_environment() -> dict[str, str]:
    """Graphical variables the desktop exported to the systemd user manager (cached 30 s)."""
    now = time.monotonic()
    if now - _USER_MANAGER_ENVIRONMENT["at"] < 30:
        return _USER_MANAGER_ENVIRONMENT["values"]
    values: dict[str, str] = {}
    if shutil.which("systemctl") is not None:
        try:
            output = subprocess.run(
                ["systemctl", "--user", "show-environment"],
                capture_output=True, text=True, timeout=5,
            ).stdout
        except (OSError, subprocess.SubprocessError):
            output = ""
        for line in output.splitlines():
            key, separator, value = line.partition("=")
            if separator and key in _GRAPHICAL_VARIABLES:
                values[key] = value
    _USER_MANAGER_ENVIRONMENT.update(at=now, values=values)
    return values


def _graphical_environment() -> dict[str, str]:
    """Return an environment that can open windows.

    The systemd user service often starts before the desktop exports
    DISPLAY/WAYLAND_DISPLAY to the user manager, so read them from there.
    """
    environment = dict(os.environ)
    if not _is_linux() or environment.get("DISPLAY") or environment.get("WAYLAND_DISPLAY"):
        return environment
    for key, value in _user_manager_environment().items():
        if not environment.get(key):
            environment[key] = value
    return environment


def _has_display(environment: dict[str, str]) -> bool:
    return bool(environment.get("DISPLAY") or environment.get("WAYLAND_DISPLAY"))


def _spawn_detached(command: list[str], *, cwd: str | None = None) -> None:
    """Start a GUI helper that outlives a restart of the background service."""
    environment = _graphical_environment()
    if _running_as_service() and shutil.which("systemd-run"):
        # Processes started by a systemd service live in its cgroup and are
        # killed when it restarts; a transient scope keeps the window open.
        command = ["systemd-run", "--user", "--scope", "--collect", "--quiet", "--", *command]
    subprocess.Popen(
        command,
        cwd=cwd,
        env=environment,
        start_new_session=True,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


# Linux tray icon (StatusNotifierItem + com.canonical.dbusmenu) and
# notifications, implemented directly on the session bus with jeepney so no
# GUI toolkit or display connection is needed inside the systemd service.

TRAY_COLORS = {
    "good": (52, 199, 89),
    "busy": (255, 159, 10),
    "bad": (255, 69, 58),
    "idle": (142, 142, 147),
}
TRAY_ICON_SIZES = (22, 32, 48)
SNI_INTERFACE = "org.kde.StatusNotifierItem"
SNI_PATH = "/StatusNotifierItem"
SNI_WATCHER = "org.kde.StatusNotifierWatcher"
DBUSMENU_INTERFACE = "com.canonical.dbusmenu"
DBUSMENU_PATH = "/MenuBar"
NOTIFICATIONS_NAME = "org.freedesktop.Notifications"
_PROPERTIES_INTERFACE = "org.freedesktop.DBus.Properties"
_INTROSPECTABLE_INTERFACE = "org.freedesktop.DBus.Introspectable"
_MENU_ACTIONS = {1: "open", 4: "check", 5: "toggle_pause", 6: "updates", 7: "diagnostics", 8: "logs", 10: "quit"}

_INTROSPECTION = {
    "/": """<!DOCTYPE node PUBLIC "-//freedesktop//DTD D-BUS Object Introspection 1.0//EN"
 "http://www.freedesktop.org/standards/dbus/1.0/introspect.dtd">
<node><node name="StatusNotifierItem"/><node name="MenuBar"/></node>""",
    SNI_PATH: """<!DOCTYPE node PUBLIC "-//freedesktop//DTD D-BUS Object Introspection 1.0//EN"
 "http://www.freedesktop.org/standards/dbus/1.0/introspect.dtd">
<node>
 <interface name="org.kde.StatusNotifierItem">
  <property name="Category" type="s" access="read"/>
  <property name="Id" type="s" access="read"/>
  <property name="Title" type="s" access="read"/>
  <property name="Status" type="s" access="read"/>
  <property name="WindowId" type="i" access="read"/>
  <property name="IconName" type="s" access="read"/>
  <property name="IconThemePath" type="s" access="read"/>
  <property name="IconPixmap" type="a(iiay)" access="read"/>
  <property name="OverlayIconName" type="s" access="read"/>
  <property name="OverlayIconPixmap" type="a(iiay)" access="read"/>
  <property name="AttentionIconName" type="s" access="read"/>
  <property name="AttentionIconPixmap" type="a(iiay)" access="read"/>
  <property name="AttentionMovieName" type="s" access="read"/>
  <property name="ToolTip" type="(sa(iiay)ss)" access="read"/>
  <property name="ItemIsMenu" type="b" access="read"/>
  <property name="Menu" type="o" access="read"/>
  <method name="ContextMenu"><arg name="x" type="i" direction="in"/><arg name="y" type="i" direction="in"/></method>
  <method name="Activate"><arg name="x" type="i" direction="in"/><arg name="y" type="i" direction="in"/></method>
  <method name="SecondaryActivate"><arg name="x" type="i" direction="in"/><arg name="y" type="i" direction="in"/></method>
  <method name="Scroll"><arg name="delta" type="i" direction="in"/><arg name="orientation" type="s" direction="in"/></method>
  <signal name="NewTitle"/>
  <signal name="NewIcon"/>
  <signal name="NewAttentionIcon"/>
  <signal name="NewOverlayIcon"/>
  <signal name="NewToolTip"/>
  <signal name="NewStatus"><arg name="status" type="s"/></signal>
 </interface>
 <interface name="org.freedesktop.DBus.Properties">
  <method name="Get"><arg type="s" direction="in"/><arg type="s" direction="in"/><arg type="v" direction="out"/></method>
  <method name="GetAll"><arg type="s" direction="in"/><arg type="a{sv}" direction="out"/></method>
 </interface>
 <interface name="org.freedesktop.DBus.Introspectable">
  <method name="Introspect"><arg type="s" direction="out"/></method>
 </interface>
</node>""",
    DBUSMENU_PATH: """<!DOCTYPE node PUBLIC "-//freedesktop//DTD D-BUS Object Introspection 1.0//EN"
 "http://www.freedesktop.org/standards/dbus/1.0/introspect.dtd">
<node>
 <interface name="com.canonical.dbusmenu">
  <property name="Version" type="u" access="read"/>
  <property name="TextDirection" type="s" access="read"/>
  <property name="Status" type="s" access="read"/>
  <property name="IconThemePath" type="as" access="read"/>
  <method name="GetLayout">
   <arg type="i" name="parentId" direction="in"/><arg type="i" name="recursionDepth" direction="in"/>
   <arg type="as" name="propertyNames" direction="in"/>
   <arg type="u" name="revision" direction="out"/><arg type="(ia{sv}av)" name="layout" direction="out"/>
  </method>
  <method name="GetGroupProperties">
   <arg type="ai" name="ids" direction="in"/><arg type="as" name="propertyNames" direction="in"/>
   <arg type="a(ia{sv})" name="properties" direction="out"/>
  </method>
  <method name="GetProperty">
   <arg type="i" name="id" direction="in"/><arg type="s" name="name" direction="in"/>
   <arg type="v" name="value" direction="out"/>
  </method>
  <method name="Event">
   <arg type="i" name="id" direction="in"/><arg type="s" name="eventId" direction="in"/>
   <arg type="v" name="data" direction="in"/><arg type="u" name="timestamp" direction="in"/>
  </method>
  <method name="EventGroup">
   <arg type="a(isvu)" name="events" direction="in"/><arg type="ai" name="idErrors" direction="out"/>
  </method>
  <method name="AboutToShow">
   <arg type="i" name="id" direction="in"/><arg type="b" name="needUpdate" direction="out"/>
  </method>
  <method name="AboutToShowGroup">
   <arg type="ai" name="ids" direction="in"/>
   <arg type="ai" name="updatesNeeded" direction="out"/><arg type="ai" name="idErrors" direction="out"/>
  </method>
  <signal name="ItemsPropertiesUpdated">
   <arg type="a(ia{sv})" name="updatedProps"/><arg type="a(ias)" name="removedProps"/>
  </signal>
  <signal name="LayoutUpdated"><arg type="u" name="revision"/><arg type="i" name="parent"/></signal>
 </interface>
 <interface name="org.freedesktop.DBus.Properties">
  <method name="Get"><arg type="s" direction="in"/><arg type="s" direction="in"/><arg type="v" direction="out"/></method>
  <method name="GetAll"><arg type="s" direction="in"/><arg type="a{sv}" direction="out"/></method>
 </interface>
 <interface name="org.freedesktop.DBus.Introspectable">
  <method name="Introspect"><arg type="s" direction="out"/></method>
 </interface>
</node>""",
}


def tray_tone(phase: str) -> str:
    if phase in {"online", "connected"}:
        return "good"
    if phase in ATTENTION_PHASES:
        return "bad"
    if phase == "paused":
        return "idle"
    return "busy"


@lru_cache(maxsize=32)
def wifi_icon_pixmap(size: int, rgb: tuple[int, int, int]) -> bytes:
    """Render a Wi-Fi glyph as ARGB32 in network byte order (not premultiplied)."""
    red, green, blue = rgb
    center_x, center_y = size / 2, size * 0.80
    dot_radius = size * 0.10
    radii = (size * 0.22, size * 0.40, size * 0.58)
    half_width = size * 0.055
    samples = 4
    pixels = bytearray()
    for y in range(size):
        for x in range(size):
            covered = 0
            for sample_y in range(samples):
                dy = center_y - (y + (sample_y + 0.5) / samples)
                for sample_x in range(samples):
                    dx = x + (sample_x + 0.5) / samples - center_x
                    distance = math.hypot(dx, dy)
                    if distance <= dot_radius or (
                        dy > 0 and abs(dx) <= dy and any(abs(distance - radius) <= half_width for radius in radii)
                    ):
                        covered += 1
            pixels += bytes((round(255 * covered / (samples * samples)), red, green, blue))
    return bytes(pixels)


class TrayMenuItem(NamedTuple):
    id: int
    label: str = ""
    enabled: bool = True
    separator: bool = False


def tray_menu_items(snapshot: AgentSnapshot, paused: bool) -> list[TrayMenuItem]:
    status = f"Status: {snapshot.message}"
    if len(status) > 80:
        status = status[:79] + "…"
    return [
        TrayMenuItem(1, "Open WiFi Agent"),
        TrayMenuItem(2, status, enabled=False),
        TrayMenuItem(3, separator=True),
        TrayMenuItem(4, "Check and log in now"),
        TrayMenuItem(5, "Resume monitoring" if paused else "Pause monitoring"),
        TrayMenuItem(6, "Check for updates"),
        TrayMenuItem(7, "View diagnostics"),
        TrayMenuItem(8, "Open logs"),
        TrayMenuItem(9, separator=True),
        TrayMenuItem(10, "Exit until next login"),
    ]


def dbusmenu_item_properties(item: TrayMenuItem, names=()) -> dict[str, tuple[str, Any]]:
    if item.separator:
        properties: dict[str, tuple[str, Any]] = {"type": ("s", "separator")}
    else:
        properties = {
            # dbusmenu treats "_" as a mnemonic marker; double it to show it.
            "label": ("s", item.label.replace("_", "__")),
            "enabled": ("b", item.enabled),
            "visible": ("b", True),
        }
    if names:
        properties = {name: value for name, value in properties.items() if name in names}
    return properties


def dbusmenu_layout(items: list[TrayMenuItem], parent_id: int = 0, depth: int = -1, names=()) -> tuple:
    if parent_id != 0:
        item = next((candidate for candidate in items if candidate.id == parent_id), None)
        if item is None:
            raise KeyError(parent_id)
        return (item.id, dbusmenu_item_properties(item, names), [])
    root = {"children-display": ("s", "submenu")}
    if names:
        root = {name: value for name, value in root.items() if name in names}
    children = [] if depth == 0 else [
        ("(ia{sv}av)", (item.id, dbusmenu_item_properties(item, names), [])) for item in items
    ]
    return (0, root, children)


def sni_properties(snapshot: AgentSnapshot) -> dict[str, tuple[str, Any]]:
    tone = tray_tone(snapshot.phase)
    icon = [(size, size, wifi_icon_pixmap(size, TRAY_COLORS[tone])) for size in TRAY_ICON_SIZES]
    attention = [(size, size, wifi_icon_pixmap(size, TRAY_COLORS["bad"])) for size in TRAY_ICON_SIZES]
    return {
        "Category": ("s", "SystemServices"),
        "Id": ("s", "wifi-agent"),
        "Title": ("s", APP_DISPLAY_NAME),
        # Never Passive: several hosts hide passive items entirely.
        "Status": ("s", "NeedsAttention" if tone == "bad" else "Active"),
        "WindowId": ("i", 0),
        # An empty icon name makes hosts use the colour-coded pixmap.
        "IconName": ("s", ""),
        "IconThemePath": ("s", ""),
        "IconPixmap": ("a(iiay)", icon),
        "OverlayIconName": ("s", ""),
        "OverlayIconPixmap": ("a(iiay)", []),
        "AttentionIconName": ("s", ""),
        "AttentionIconPixmap": ("a(iiay)", attention),
        "AttentionMovieName": ("s", ""),
        "ToolTip": ("(sa(iiay)ss)", ("", [], APP_DISPLAY_NAME, xml_escape(snapshot.message))),
        "ItemIsMenu": ("b", False),
        "Menu": ("o", DBUSMENU_PATH),
    }


class _DBusError(Exception):
    def __init__(self, name: str, text: str):
        super().__init__(text)
        self.name = name
        self.text = text


class TrayObjectServer:
    """Answer StatusNotifierItem and dbusmenu calls; no I/O of its own."""

    def __init__(self, actions: dict[str, Any], logger: logging.Logger | None = None):
        self.actions = actions
        self.logger = logger or logging.getLogger(APP_NAME)
        self.snapshot = AgentSnapshot()
        self.paused = False
        self.revision = 1

    def update(self, snapshot: AgentSnapshot, paused: bool) -> set[str]:
        changes: set[str] = set()
        if tray_tone(snapshot.phase) != tray_tone(self.snapshot.phase):
            changes |= {"icon", "status"}
        if snapshot.message != self.snapshot.message:
            changes |= {"tooltip", "menu"}
        if paused != self.paused:
            changes.add("menu")
        self.snapshot = snapshot
        self.paused = paused
        if "menu" in changes:
            self.revision += 1
        return changes

    def menu_items(self) -> list[TrayMenuItem]:
        return tray_menu_items(self.snapshot, self.paused)

    def run_action(self, name: str) -> None:
        action = self.actions.get(name)
        if action is None:
            return
        try:
            action()
        except Exception as exc:
            self.logger.warning("Tray action %s failed: %s", name, exc)

    def handle(self, message):
        from jeepney import MessageType, new_error
        from jeepney.low_level import HeaderFields, MessageFlag

        header = message.header
        if header.message_type != MessageType.method_call:
            return None
        path = header.fields.get(HeaderFields.path, "")
        interface = header.fields.get(HeaderFields.interface)
        member = header.fields.get(HeaderFields.member, "")
        try:
            reply = self._dispatch(message, path, interface, member)
        except _DBusError as exc:
            reply = new_error(message, exc.name, "s", (exc.text,))
        except Exception as exc:
            reply = new_error(message, "org.freedesktop.DBus.Error.Failed", "s", (str(exc),))
        if header.flags & MessageFlag.no_reply_expected:
            return None
        return reply

    def _properties(self, path: str) -> dict[str, dict[str, tuple[str, Any]]]:
        if path == SNI_PATH:
            return {SNI_INTERFACE: sni_properties(self.snapshot)}
        if path == DBUSMENU_PATH:
            return {DBUSMENU_INTERFACE: {
                "Version": ("u", 3),
                "TextDirection": ("s", "ltr"),
                "Status": ("s", "normal"),
                "IconThemePath": ("as", []),
            }}
        return {}

    def _dispatch(self, message, path: str, interface: str | None, member: str):
        from jeepney import new_method_return

        body = message.body
        if member == "Introspect" and interface in {_INTROSPECTABLE_INTERFACE, None}:
            return new_method_return(message, "s", (_INTROSPECTION.get(path, _INTROSPECTION["/"]),))
        if interface == "org.freedesktop.DBus.Peer" and member == "Ping":
            return new_method_return(message)
        if interface == _PROPERTIES_INTERFACE:
            properties = self._properties(path)
            if member == "GetAll":
                return new_method_return(message, "a{sv}", (properties.get(body[0], {}),))
            if member == "Get":
                value = properties.get(body[0], {}).get(body[1])
                if value is None:
                    raise _DBusError("org.freedesktop.DBus.Error.UnknownProperty", f"No property {body[1]}")
                return new_method_return(message, "v", (value,))
            if member == "Set":
                raise _DBusError("org.freedesktop.DBus.Error.PropertyReadOnly", "Properties are read-only")
        if path == SNI_PATH and interface in {SNI_INTERFACE, None}:
            if member == "Activate":
                self.run_action("open")
                return new_method_return(message)
            if member == "SecondaryActivate":
                self.run_action("check")
                return new_method_return(message)
            if member in {"ContextMenu", "Scroll", "ProvideXdgActivationToken"}:
                return new_method_return(message)
        if path == DBUSMENU_PATH and interface in {DBUSMENU_INTERFACE, None}:
            return self._dispatch_menu(message, member, body)
        raise _DBusError("org.freedesktop.DBus.Error.UnknownMethod", f"Unknown method {interface}.{member} on {path}")

    def _dispatch_menu(self, message, member: str, body: tuple):
        from jeepney import new_method_return

        items = self.menu_items()
        known = {item.id for item in items} | {0}
        if member == "GetLayout":
            parent_id, depth, names = body
            try:
                layout = dbusmenu_layout(items, parent_id, depth, names)
            except KeyError as exc:
                raise _DBusError("org.freedesktop.DBus.Error.InvalidArgs", f"Unknown menu item {parent_id}") from exc
            return new_method_return(message, "u(ia{sv}av)", (self.revision, layout))
        if member == "GetGroupProperties":
            ids, names = body
            result = [
                (item.id, dbusmenu_item_properties(item, names))
                for item in items
                if not ids or item.id in ids
            ]
            if 0 in ids:
                result.insert(0, (0, dbusmenu_layout([], 0, 0, names)[1]))
            return new_method_return(message, "a(ia{sv})", (result,))
        if member == "GetProperty":
            item_id, name = body
            item = next((candidate for candidate in items if candidate.id == item_id), None)
            properties = dbusmenu_item_properties(item) if item else dbusmenu_layout([], 0, 0)[1]
            if name not in properties:
                raise _DBusError("org.freedesktop.DBus.Error.InvalidArgs", f"Unknown property {name}")
            return new_method_return(message, "v", (properties[name],))
        if member == "Event":
            item_id, event_id = body[0], body[1]
            if event_id == "clicked" and item_id in _MENU_ACTIONS:
                self.run_action(_MENU_ACTIONS[item_id])
            return new_method_return(message)
        if member == "EventGroup":
            missing = []
            for item_id, event_id, _data, _timestamp in body[0]:
                if item_id not in known:
                    missing.append(item_id)
                elif event_id == "clicked" and item_id in _MENU_ACTIONS:
                    self.run_action(_MENU_ACTIONS[item_id])
            return new_method_return(message, "ai", (missing,))
        if member == "AboutToShow":
            return new_method_return(message, "b", (False,))
        if member == "AboutToShowGroup":
            return new_method_return(message, "aiai", ([], [item_id for item_id in body[0] if item_id not in known]))
        raise _DBusError("org.freedesktop.DBus.Error.UnknownMethod", f"Unknown dbusmenu method {member}")


class LinuxDesktopIntegration:
    """Tray icon and notifications for the Linux background service.

    The monitor thread only enqueues snapshots; one dispatcher thread owns
    the D-Bus connection, answers the panel, emits signals, and reconnects
    whenever the bus, panel, or notification daemon restarts.
    """

    ATTENTION_FALLBACK_SECONDS = 90

    def __init__(self, monitor: AgentMonitor, logger: logging.Logger):
        self.monitor = monitor
        self.logger = logger
        self.policy = NotificationPolicy()
        self.server = TrayObjectServer(
            {
                "open": lambda: spawn_setup_window(),
                "check": monitor.request_check,
                "toggle_pause": lambda: monitor.set_paused(not monitor.pause_event.is_set()),
                "updates": lambda: spawn_setup_window("overview", check_updates=True),
                "diagnostics": lambda: spawn_setup_window("diagnostics"),
                "logs": open_log_location,
                "quit": self._quit,
            },
            logger,
        )
        self.events: queue.Queue = queue.Queue()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._router: Any = None
        self._connection: Any = None
        self._name = f"org.kde.StatusNotifierItem-{os.getpid()}-1"
        self._notification_id = 0
        self._pending: list[tuple[Notice, float]] = []
        self._next_pending_retry = 0.0
        self._tray_registered = False
        self._reported_missing_tray = False

    @classmethod
    def maybe_create(cls, monitor: AgentMonitor, logger: logging.Logger) -> LinuxDesktopIntegration | None:
        if os.environ.get("WIFI_AGENT_TRAY", "1").strip() in {"0", "false", "no", "off"}:
            return None
        try:
            import jeepney.io.threading  # noqa: F401
        except ImportError:
            logger.info("Tray icon and notifications are disabled: the jeepney package is not installed")
            return None
        return cls(monitor, logger)

    def publish(self, snapshot: AgentSnapshot) -> None:
        self.events.put(("status", snapshot))

    def start(self) -> None:
        self._thread = threading.Thread(target=self._run, name="wifi-agent-tray", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        self.events.put(("stop", None))
        if self._thread is not None:
            self._thread.join(timeout=5)
        self._disconnect()

    def _quit(self) -> None:
        if _running_as_service() and shutil.which("systemctl"):
            # Stopping through systemd keeps Restart=always from reviving it;
            # the resulting SIGTERM stops the monitor cleanly.
            subprocess.Popen(
                ["systemctl", "--user", "stop", "--no-block", SYSTEMD_UNIT_NAME],
                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )
        else:
            self.monitor.stop()

    # Connection management -------------------------------------------------

    def _run(self) -> None:
        delay = 2.0
        while not self._stop.is_set():
            try:
                self._connect()
                delay = 2.0
                self._serve()
            except Exception as exc:
                self.logger.info("Desktop tray/notifications unavailable (%s); retrying in %ss", exc, int(delay))
            self._disconnect()
            if not self._stop.is_set():
                self._serve_offline(delay)
                delay = min(60.0, delay * 2)

    def _call(self, message, timeout: float = 5.0):
        from jeepney import MessageType

        reply = self._router.send_and_get_reply(message, timeout=timeout)
        if reply.header.message_type == MessageType.error:
            from jeepney.wrappers import DBusErrorResponse

            raise DBusErrorResponse(reply)
        return reply.body

    def _connect(self) -> None:
        from jeepney import MatchRule, message_bus
        from jeepney.io.threading import DBusRouter, open_dbus_connection

        address = _session_bus_address()
        if not address:
            raise RuntimeError("no D-Bus session bus")
        connection = open_dbus_connection(bus=address)
        router = DBusRouter(connection)
        self._connection, self._router = connection, router
        # Register every filter before asking the bus for anything, so the
        # receiver thread never sees the filter table change under it.
        router.filter(MatchRule(type="method_call"), queue=self.events)
        owner_rules = []
        for name in (SNI_WATCHER, NOTIFICATIONS_NAME):
            rule = MatchRule(
                type="signal",
                sender="org.freedesktop.DBus",
                interface="org.freedesktop.DBus",
                member="NameOwnerChanged",
                path="/org/freedesktop/DBus",
            )
            rule.add_arg_condition(0, name)
            router.filter(rule, queue=self.events)
            owner_rules.append(rule)
        for rule in owner_rules:
            self._call(message_bus.AddMatch(rule))
        self._call(message_bus.RequestName(self._name, 4))  # DBUS_NAME_FLAG_DO_NOT_QUEUE
        self._register_tray()
        self._retry_pending(now=True)

    def _disconnect(self) -> None:
        router, connection = self._router, self._connection
        self._router = self._connection = None
        self._tray_registered = False
        for closer in (router, connection):
            if closer is not None:
                try:
                    closer.close()
                except Exception:
                    pass

    def _register_tray(self) -> None:
        from jeepney import DBusAddress, message_bus, new_method_call
        from jeepney.low_level import MessageFlag

        if not self._call(message_bus.NameHasOwner(SNI_WATCHER))[0]:
            if not self._reported_missing_tray:
                self.logger.info("No system-tray host is running; notifications remain available")
                self._reported_missing_tray = True
            self._tray_registered = False
            return
        watcher = DBusAddress("/StatusNotifierWatcher", bus_name=SNI_WATCHER, interface=SNI_WATCHER)
        message = new_method_call(watcher, "RegisterStatusNotifierItem", "s", (self._name,))
        message.header.flags |= MessageFlag.no_auto_start
        try:
            self._call(message)
        except Exception as exc:
            self.logger.debug("Tray registration reply: %s", exc)
        self._tray_registered = True
        self._reported_missing_tray = False
        self.logger.info("Tray icon registered with the desktop panel")

    # Event handling ---------------------------------------------------------

    def _serve(self) -> None:
        from jeepney import message_bus

        next_health_check = time.monotonic() + 30
        while not self._stop.is_set():
            try:
                item = self.events.get(timeout=5)
            except queue.Empty:
                item = None
            if isinstance(item, tuple):
                if item[0] == "stop":
                    return
                self._apply_status(item[1])
            elif item is not None:
                self._handle_message(item)
            if time.monotonic() >= next_health_check:
                next_health_check = time.monotonic() + 30
                self._call(message_bus.GetId())  # raises once the bus connection is gone
            self._retry_pending()

    def _serve_offline(self, seconds: float) -> None:
        deadline = time.monotonic() + seconds
        while not self._stop.is_set():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return
            try:
                item = self.events.get(timeout=remaining)
            except queue.Empty:
                return
            if isinstance(item, tuple):
                if item[0] == "stop":
                    return
                self._apply_status(item[1])
            self._retry_pending()

    def _handle_message(self, message) -> None:
        from jeepney import MessageType

        if self._router is None:
            return
        if message.header.message_type == MessageType.signal:
            name, _old_owner, new_owner = message.body
            if new_owner and name == SNI_WATCHER:
                self._register_tray()
            elif new_owner and name == NOTIFICATIONS_NAME:
                self._retry_pending(now=True)
            elif not new_owner and name == SNI_WATCHER:
                self._tray_registered = False
            return
        reply = self.server.handle(message)
        if reply is not None:
            self._router.send(reply)

    def _emit(self, path: str, interface: str, member: str, signature: str | None = None, body: tuple = ()) -> None:
        from jeepney import DBusAddress, new_signal

        self._router.send(new_signal(DBusAddress(path, interface=interface), member, signature, body))

    def _apply_status(self, snapshot: AgentSnapshot) -> None:
        changes = self.server.update(snapshot, self.monitor.pause_event.is_set())
        if self._router is not None and self._tray_registered and changes:
            try:
                if "icon" in changes:
                    self._emit(SNI_PATH, SNI_INTERFACE, "NewIcon")
                    self._emit(SNI_PATH, SNI_INTERFACE, "NewAttentionIcon")
                if "status" in changes:
                    status = sni_properties(snapshot)["Status"][1]
                    self._emit(SNI_PATH, SNI_INTERFACE, "NewStatus", "s", (status,))
                if "tooltip" in changes:
                    self._emit(SNI_PATH, SNI_INTERFACE, "NewToolTip")
                if "menu" in changes:
                    self._emit(DBUSMENU_PATH, DBUSMENU_INTERFACE, "LayoutUpdated", "ui", (self.server.revision, 0))
            except Exception as exc:
                self.logger.debug("Could not update the tray icon: %s", exc)
        notice = self.policy.observe(snapshot)
        if notice is not None:
            self._deliver(notice)

    # Notifications ----------------------------------------------------------

    def _deliver(self, notice: Notice) -> None:
        if self._notify(notice):
            self._pending = [(item, since) for item, since in self._pending if item.kind != notice.kind]
            return
        self.logger.info("Notification queued (no notification service yet): %s — %s", notice.summary, notice.body)
        if notice.attention:
            self._pending = [(item, since) for item, since in self._pending if item.kind != notice.kind]
            self._pending.append((notice, time.monotonic()))

    def _notify(self, notice: Notice) -> bool:
        if self._router is None:
            return False
        from jeepney import DBusAddress, new_method_call
        from jeepney.low_level import MessageFlag

        environment = _graphical_environment()
        address = DBusAddress(
            "/org/freedesktop/Notifications", bus_name=NOTIFICATIONS_NAME, interface=NOTIFICATIONS_NAME
        )
        hints = {
            "urgency": ("y", notice.urgency),
            "category": ("s", "network"),
            "desktop-entry": ("s", "wifi-agent"),
        }
        icon = "network-error" if notice.urgency >= 2 else "network-wired"
        message = new_method_call(
            address,
            "Notify",
            "susssasa{sv}i",
            (APP_DISPLAY_NAME, self._notification_id, icon, notice.summary, notice.body, [], hints,
             6000 if notice.urgency == 0 else -1),
        )
        if not _has_display(environment):
            # Activating a notification daemon before the desktop exported
            # its display would start it without a screen to draw on.
            message.header.flags |= MessageFlag.no_auto_start
        try:
            self._notification_id = int(self._call(message)[0])
            return True
        except Exception as exc:
            self.logger.debug("Notification not delivered: %s", exc)
            return False

    def _retry_pending(self, *, now: bool = False) -> None:
        if not self._pending or (not now and time.monotonic() < self._next_pending_retry):
            return
        self._next_pending_retry = time.monotonic() + 15
        remaining = []
        for notice, since in self._pending:
            if self._notify(notice):
                continue
            if time.monotonic() - since >= self.ATTENTION_FALLBACK_SECONDS and _has_display(_graphical_environment()):
                # No notification daemon at all: show the window instead so
                # the problem is never silent.
                self.logger.warning("No notification service; opening WiFi Agent for: %s", notice.summary)
                try:
                    spawn_setup_window()
                except OSError as exc:
                    self.logger.warning("Could not open WiFi Agent: %s", exc)
                continue
            remaining.append((notice, since))
        self._pending = remaining


def _running_as_service() -> bool:
    """Return whether this process belongs to the WiFi Agent systemd unit."""
    if not _is_linux():
        return False
    try:
        lines = Path("/proc/self/cgroup").read_text(encoding="utf-8").splitlines()
    except OSError:
        return False
    return any(line.rstrip().endswith("/" + SYSTEMD_UNIT_NAME) for line in lines)


def _repair_startup_unit(logger: logging.Logger) -> None:
    """Move a service started from an older unit definition onto the current one."""
    if not _running_as_service() or not startup_unit_outdated():
        return
    try:
        _linux_unit_path().write_text(_linux_unit_text(_service_command()), encoding="utf-8")
        subprocess.run(["systemctl", "--user", "daemon-reload"], check=True, capture_output=True, text=True, timeout=30)
        logger.info("Updated the systemd user service definition; restarting onto it")
        subprocess.Popen(
            ["systemctl", "--user", "restart", "--no-block", SYSTEMD_UNIT_NAME],
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        logger.warning("Could not update the systemd user service definition: %s", exc)


def run_agent(once: bool = False, *, tray: bool = True) -> int:
    ensure_dependencies()
    monitor = AgentMonitor()
    integration = (
        LinuxDesktopIntegration.maybe_create(monitor, monitor.logger)
        if tray and not once and _is_linux()
        else None
    )
    try:
        with SingleInstance():
            # Start the tray only once the lock is held so a duplicate
            # instance never shows a second icon.
            if integration is not None:
                monitor.status_callback = integration.publish
                integration.start()
            if not once:
                _repair_startup_unit(monitor.logger)
            previous_handlers: dict[int, Any] = {}

            def stop_handler(signum, frame) -> None:
                monitor.stop()

            for signal_name in ("SIGINT", "SIGTERM"):
                signal_value = getattr(signal, signal_name, None)
                if signal_value is not None:
                    previous_handlers[signal_value] = signal.getsignal(signal_value)
                    signal.signal(signal_value, stop_handler)
            try:
                return monitor.run(once=once)
            finally:
                for signal_value, handler in previous_handlers.items():
                    signal.signal(signal_value, handler)
                if integration is not None:
                    integration.stop()
    except AlreadyRunning as exc:
        monitor.logger.info("Another WiFi Agent monitor is already running; this one exits")
        if sys.stderr is not None:
            print(f"Error: {exc}", file=sys.stderr)
        return EXIT_ALREADY_RUNNING


def open_log_location() -> None:
    app_dir().mkdir(parents=True, exist_ok=True)
    target = LOG_PATH if LOG_PATH.exists() else app_dir()
    if sys.platform == "win32":
        os.startfile(str(target))  # type: ignore[attr-defined]
    elif sys.platform == "darwin":
        subprocess.Popen(["open", str(target)], start_new_session=True)
    else:
        _spawn_detached(["xdg-open", str(target)])


def _application_command(*arguments: str) -> list[str]:
    """Return a command that works from source and from a frozen app bundle."""
    if getattr(sys, "frozen", False):
        return [str(Path(sys.executable).resolve()), *arguments]

    executable = Path(sys.executable)
    if sys.platform == "win32":
        pythonw = executable.with_name("pythonw.exe")
        if pythonw.exists():
            executable = pythonw
    return [str(executable), str(Path(__file__).resolve()), *arguments]


def _application_working_directory() -> Path:
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent


def spawn_setup_window(pane: str | None = None, *, check_updates: bool = False) -> None:
    command = _application_command("setup")
    if pane:
        command.extend(["--pane", pane])
    if check_updates:
        command.append("--check-updates")
    _spawn_detached(command, cwd=str(_application_working_directory()))


def _tray_image():
    from PIL import Image, ImageDraw

    image = Image.new("RGBA", (64, 64), (0, 0, 0, 0))
    draw = ImageDraw.Draw(image)
    if sys.platform == "darwin":
        # Monochrome template-style artwork follows the menu bar appearance.
        draw.arc((8, 5, 56, 53), 215, 325, fill="black", width=7)
        draw.arc((17, 17, 47, 47), 215, 325, fill="black", width=7)
        draw.ellipse((28, 40, 36, 48), fill="black")
    else:
        draw.rounded_rectangle((4, 4, 60, 60), radius=15, fill=(22, 101, 216, 255))
        draw.arc((14, 16, 50, 50), 215, 325, fill="white", width=5)
        draw.arc((21, 25, 43, 47), 215, 325, fill="white", width=5)
        draw.ellipse((29, 42, 35, 48), fill="white")
    return image


_MACOS_STATE: dict[str, Any] = {}


def _fourcc(code: bytes) -> int:
    return int.from_bytes(code, "big")


def _prepare_macos_menu_bar_app(open_settings) -> None:
    """Hide the Dock icon and open Settings when the app is launched again.

    The login item and the Settings window share one app bundle, so Finder,
    Launchpad, and Spotlight hand a second launch to this running menu-bar
    process as a "reopen" Apple event instead of starting a new process.
    Without a handler that launch shows nothing at all.
    """
    import AppKit
    import Foundation
    import objc
    from PyObjCTools import AppHelper

    _MACOS_STATE["open_settings"] = open_settings
    handler_class = _MACOS_STATE.get("handler_class")
    if handler_class is None:
        class WiFiAgentReopenHandler(Foundation.NSObject):
            @objc.typedSelector(b"v@:@@")
            def handleReopen_withReplyEvent_(self, event, reply):
                callback = _MACOS_STATE.get("open_settings")
                if callback is not None:
                    try:
                        callback()
                    except Exception:
                        pass

        handler_class = _MACOS_STATE["handler_class"] = WiFiAgentReopenHandler

    def install() -> None:
        AppKit.NSApplication.sharedApplication().setActivationPolicy_(
            AppKit.NSApplicationActivationPolicyAccessory
        )
        handler = handler_class.alloc().init()
        _MACOS_STATE["handler"] = handler
        AppKit.NSAppleEventManager.sharedAppleEventManager().setEventHandler_andSelector_forEventClass_andEventID_(
            handler, b"handleReopen:withReplyEvent:", _fourcc(b"aevt"), _fourcc(b"rapp")
        )

    # Installed after NSApplication finished launching so its own default
    # handlers do not replace this one.
    AppHelper.callAfter(install)


def run_tray() -> int:
    if _is_linux():
        # Linux shows its tray icon from the background service itself.
        return run_agent()
    if sys.platform not in {"win32", "darwin"}:
        raise RuntimeError("The menu-bar/tray interface is supported on macOS, Windows, and Linux.")
    ensure_dependencies()
    try:
        import pystray
    except ImportError as exc:
        installer = "install.cmd" if sys.platform == "win32" else "./install.sh"
        raise RuntimeError(f"Menu-bar dependencies are missing. Run {installer} again.") from exc

    logger = build_logger(console=False)
    monitor_holder: dict[str, AgentMonitor] = {}
    icon_holder: dict[str, Any] = {}
    policy = NotificationPolicy()

    def on_status(snapshot: AgentSnapshot) -> None:
        icon = icon_holder.get("icon")
        if icon is None:
            return
        icon.title = f"WiFi Agent — {snapshot.message}"[:127]
        try:
            icon.update_menu()
        except Exception:
            pass
        notice = policy.observe(snapshot)
        if notice is None:
            return
        try:
            if sys.platform == "darwin":
                _macos_notify(notice)
            elif getattr(icon, "HAS_NOTIFICATION", True):
                icon.notify(notice.body, notice.summary)
        except Exception as exc:
            logger.debug("Notification failed: %s", exc)

    monitor = AgentMonitor(logger=logger, status_callback=on_status)
    monitor_holder["monitor"] = monitor

    def snapshot() -> AgentSnapshot:
        return monitor_holder["monitor"].current_snapshot()

    def open_settings(icon, item) -> None:
        try:
            spawn_setup_window()
        except OSError as exc:
            if getattr(icon, "HAS_NOTIFICATION", True):
                icon.notify(str(exc), "Could not open settings")

    def open_diagnostics(icon, item) -> None:
        try:
            spawn_setup_window("diagnostics")
        except OSError as exc:
            if getattr(icon, "HAS_NOTIFICATION", True):
                icon.notify(str(exc), "Could not open diagnostics")

    def open_updates(icon, item) -> None:
        try:
            spawn_setup_window("overview", check_updates=True)
        except OSError as exc:
            if getattr(icon, "HAS_NOTIFICATION", True):
                icon.notify(str(exc), "Could not check for updates")

    def check_now(icon, item) -> None:
        monitor.request_check()
        try:
            if not getattr(icon, "HAS_NOTIFICATION", True):
                return
            icon.notify("A connectivity and portal check has been requested.", "WiFi Agent")
        except Exception:
            pass

    def toggle_pause(icon, item) -> None:
        monitor.set_paused(not monitor.pause_event.is_set())

    def pause_label(item) -> str:
        return "Resume monitoring" if monitor.pause_event.is_set() else "Pause monitoring"

    def status_label(item) -> str:
        return f"Status: {snapshot().message}"[:80]

    def open_logs(icon, item) -> None:
        try:
            open_log_location()
        except OSError as exc:
            if getattr(icon, "HAS_NOTIFICATION", True):
                icon.notify(str(exc), "Could not open logs")

    def quit_agent(icon, item) -> None:
        monitor.stop()
        icon.stop()

    is_macos = sys.platform == "darwin"
    pause_item = (
        pystray.MenuItem(
            "Pause Monitoring",
            toggle_pause,
            checked=lambda item: monitor.pause_event.is_set(),
        )
        if is_macos
        else pystray.MenuItem(pause_label, toggle_pause)
    )
    menu = pystray.Menu(
        pystray.MenuItem(
            "Open WiFi Agent Settings…" if is_macos else "Open WiFi Agent",
            open_settings,
            default=not is_macos,
        ),
        pystray.MenuItem(status_label, lambda icon, item: None, enabled=False),
        pystray.Menu.SEPARATOR,
        pystray.MenuItem("Check Now" if is_macos else "Check and log in now", check_now),
        pause_item,
        pystray.MenuItem("Check for Updates…" if is_macos else "Check for updates", open_updates),
        pystray.MenuItem("View Diagnostics…", open_diagnostics),
        pystray.MenuItem("Open Logs…" if is_macos else "Open logs", open_logs),
        pystray.Menu.SEPARATOR,
        pystray.MenuItem("Quit WiFi Agent" if is_macos else "Exit until next login", quit_agent),
    )
    icon = pystray.Icon(APP_NAME, _tray_image(), "WiFi Agent — starting", menu)
    icon_holder["icon"] = icon

    def tray_setup(running_icon) -> None:
        running_icon.visible = True
        if is_macos:
            try:
                _prepare_macos_menu_bar_app(lambda: open_settings(running_icon, None))
            except Exception as exc:
                logger.warning("Could not install the macOS reopen handler: %s", exc)

    with SingleInstance():
        worker = threading.Thread(target=monitor.run, name="wifi-agent-monitor", daemon=True)
        worker.start()
        try:
            icon.run(setup=tray_setup)
        finally:
            monitor.stop()
            worker.join(timeout=15)
    return 0


def _service_command() -> list[str]:
    mode = "tray" if sys.platform in {"win32", "darwin"} else "run"
    return _application_command(mode)


def _linux_unit_path() -> Path:
    return Path.home() / ".config" / "systemd" / "user" / SYSTEMD_UNIT_NAME


def _linux_unit_text(command: list[str]) -> str:
    quoted_command = " ".join(_systemd_quote(part) for part in command)
    # Skip, rather than restart-loop, when the program was uninstalled.
    conditions = "".join(
        f"ConditionPathExists={part.replace('%', '%%')}\n" for part in command[:2] if part.startswith("/")
    )
    return (
        "[Unit]\n"
        "Description=WiFi Agent captive-portal automation\n"
        "Documentation=https://github.com/akshajtiwari/Wifi-Agent\n"
        "StartLimitIntervalSec=0\n"
        f"{conditions}\n"
        "[Service]\n"
        "Type=notify\n"
        f"ExecStart={quoted_command}\n"
        "Restart=always\n"
        "RestartSec=5\n"
        f"RestartPreventExitStatus={EXIT_ALREADY_RUNNING}\n"
        "WatchdogSec=180\n"
        "TimeoutStopSec=15\n\n"
        "[Install]\n"
        "WantedBy=default.target\n"
    )


def startup_unit_outdated() -> bool:
    """Return whether the installed Linux unit differs from the current definition."""
    if not _is_linux():
        return False
    try:
        current = _linux_unit_path().read_text(encoding="utf-8")
    except OSError:
        return False
    return current != _linux_unit_text(_service_command())


def install_startup(*, require_credentials: bool = True) -> str:
    if (
        sys.platform == "darwin"
        and getattr(sys, "frozen", False)
        and str(Path(sys.executable).resolve()).startswith("/Volumes/")
    ):
        raise RuntimeError(
            "Move WiFi Agent to the Applications folder before enabling Install at Login."
        )
    if require_credentials:
        config = load_config()
        username = str(config.get("username", "")).strip()
        if not username:
            raise RuntimeError("Save credentials before installing the startup service.")
        # Refuse to install a service that is guaranteed to fail immediately.
        get_password(username, str(config.get("credential_store", "")))
    command = _service_command()
    app_dir().mkdir(parents=True, exist_ok=True)

    if sys.platform == "win32":
        account = getpass.getuser()
        domain = os.environ.get("USERDOMAIN", "").strip()
        if domain and "\\" not in account:
            account = f"{domain}\\{account}"
        task_xml = app_dir() / "startup-task.xml"
        arguments = subprocess.list2cmdline(command[1:])
        xml = f'''<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo><Description>Sophos/Cyberoam Ethernet auto-login</Description></RegistrationInfo>
  <Triggers><LogonTrigger><Enabled>true</Enabled><UserId>{xml_escape(account)}</UserId></LogonTrigger></Triggers>
  <Principals><Principal id="Author"><UserId>{xml_escape(account)}</UserId><LogonType>InteractiveToken</LogonType><RunLevel>LeastPrivilege</RunLevel></Principal></Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <StartWhenAvailable>true</StartWhenAvailable>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <RestartOnFailure><Interval>PT1M</Interval><Count>999</Count></RestartOnFailure>
  </Settings>
  <Actions Context="Author"><Exec>
    <Command>{xml_escape(command[0])}</Command>
    <Arguments>{xml_escape(arguments)}</Arguments>
    <WorkingDirectory>{xml_escape(str(_application_working_directory()))}</WorkingDirectory>
  </Exec></Actions>
</Task>
'''
        task_xml.write_text(xml, encoding="utf-16")
        try:
            subprocess.run(
                ["schtasks", "/Create", "/TN", APP_NAME, "/XML", str(task_xml), "/F"],
                check=True, capture_output=True, text=True, creationflags=WINDOWS_NO_WINDOW,
            )
        finally:
            task_xml.unlink(missing_ok=True)
        # Stop an older headless/tray version so the replacement starts now
        # instead of waiting for the next Windows sign-in.
        subprocess.run(
            ["schtasks", "/End", "/TN", APP_NAME],
            capture_output=True, text=True, creationflags=WINDOWS_NO_WINDOW,
        )
        subprocess.run(
            ["schtasks", "/Run", "/TN", APP_NAME],
            check=True, capture_output=True, text=True, creationflags=WINDOWS_NO_WINDOW,
        )
        return f"Windows startup task '{APP_NAME}' installed and started."

    if sys.platform == "darwin":
        target = Path.home() / "Library" / "LaunchAgents" / "com.local.wifi-agent.plist"
        target.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "Label": "com.local.wifi-agent",
            "ProgramArguments": command,
            "RunAtLoad": True,
            "KeepAlive": {"SuccessfulExit": False},
            "StandardOutPath": str(LOG_PATH),
            "StandardErrorPath": str(LOG_PATH),
        }
        with target.open("wb") as handle:
            plistlib.dump(payload, handle)
        domain = f"gui/{os.getuid()}"
        subprocess.run(["launchctl", "bootout", domain, str(target)], capture_output=True)
        subprocess.run(["launchctl", "bootstrap", domain, str(target)], check=True, capture_output=True, text=True)
        return f"macOS LaunchAgent installed at {target} and started."

    target = _linux_unit_path()
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(_linux_unit_text(command), encoding="utf-8")
    subprocess.run(["systemctl", "--user", "daemon-reload"], check=True, capture_output=True, text=True)
    subprocess.run(["systemctl", "--user", "enable", target.name], check=True, capture_output=True, text=True)
    subprocess.run(["systemctl", "--user", "restart", target.name], check=True, capture_output=True, text=True)
    return f"Linux systemd user service installed at {target} and started."


def _systemd_quote(value: str) -> str:
    escaped = value.replace("\\", "\\\\").replace('"', '\\"').replace("%", "%%")
    return '"' + escaped + '"'


def startup_is_installed() -> bool:
    if sys.platform == "win32":
        return subprocess.run(
            ["schtasks", "/Query", "/TN", APP_NAME],
            capture_output=True, text=True, creationflags=WINDOWS_NO_WINDOW,
        ).returncode == 0
    if sys.platform == "darwin":
        return (Path.home() / "Library" / "LaunchAgents" / "com.local.wifi-agent.plist").exists()
    return _linux_unit_path().exists()


def initial_setup_complete(config: dict[str, Any], startup_installed: bool | None = None) -> bool:
    """Return whether credentials and login-time monitoring are ready."""
    try:
        normalized = validate_config(config, require_username=True)
    except ValueError:
        return False
    if not (startup_is_installed() if startup_installed is None else startup_installed):
        return False
    try:
        get_password(str(normalized["username"]), str(normalized["credential_store"]))
    except (OSError, RuntimeError, KeyringError):
        return False
    return True


def uninstall_startup() -> str:
    if sys.platform == "win32":
        subprocess.run(
            ["schtasks", "/End", "/TN", APP_NAME],
            capture_output=True, text=True, creationflags=WINDOWS_NO_WINDOW,
        )
        result = subprocess.run(
            ["schtasks", "/Delete", "/TN", APP_NAME, "/F"],
            capture_output=True, text=True, creationflags=WINDOWS_NO_WINDOW,
        )
        if result.returncode != 0 and startup_is_installed():
            raise RuntimeError(result.stderr.strip() or result.stdout.strip() or "Could not remove the startup task.")
        return f"Windows startup task '{APP_NAME}' removed. Saved settings were kept."
    if sys.platform == "darwin":
        target = Path.home() / "Library" / "LaunchAgents" / "com.local.wifi-agent.plist"
        subprocess.run(["launchctl", "bootout", f"gui/{os.getuid()}", str(target)], capture_output=True)
        if target.exists():
            target.unlink()
        return "macOS LaunchAgent removed. Saved settings were kept."
    target = _linux_unit_path()
    subprocess.run(["systemctl", "--user", "disable", "--now", target.name], capture_output=True)
    if target.exists():
        target.unlink()
    subprocess.run(["systemctl", "--user", "daemon-reload"], capture_output=True)
    return "Linux systemd user service removed. Saved settings were kept."


def credential_store_description(store: str) -> str:
    if store == "file":
        return (
            "No system keyring is available, so the password is kept in a private file "
            f"readable only by you ({CREDENTIALS_PATH})."
        )
    return "Settings are stored locally; the password remains in the OS credential vault."


def show_setup_ui(initial_pane: str | None = None, *, check_updates_on_open: bool = False) -> int:
    ensure_dependencies()
    try:
        import tkinter as tk
        from tkinter import messagebox, scrolledtext, ttk
    except ImportError:
        print(
            "Tkinter is not installed. Install python3-tk (Debian/Ubuntu), tk (Arch), "
            "or python3-tkinter (Fedora), then retry.",
            file=sys.stderr,
        )
        return 2

    if sys.platform == "win32":
        try:
            import ctypes

            ctypes.windll.shcore.SetProcessDpiAwareness(1)
        except (AttributeError, OSError):
            pass

    configuration_warning = ""
    try:
        config = load_config()
    except (OSError, RuntimeError, ValueError) as exc:
        config = validate_config(DEFAULT_CONFIG)
        configuration_warning = f"The saved configuration could not be loaded and must be repaired: {exc}"

    startup_detected = startup_is_installed()
    setup_required = {"value": not initial_setup_complete(config, startup_detected)}

    root = tk.Tk()
    is_macos = sys.platform == "darwin"
    root.title("WiFi Agent Settings" if is_macos else "WiFi Agent")
    root.geometry("730x650" if is_macos else "780x700")
    if is_macos:
        # A settings window is pane-sized rather than a general resizable app
        # window, matching the platform's Settings convention.
        root.resizable(False, False)
    else:
        root.minsize(720, 620)

    def system_color(name: str, fallback: str) -> str:
        if not is_macos:
            return fallback
        try:
            root.winfo_rgb(name)
            return name
        except tk.TclError:
            return fallback

    colors = {
        "background": system_color("systemWindowBackgroundColor", "#ececec"),
        "surface": system_color("systemControlBackgroundColor", "#ffffff"),
        "primary": system_color("systemControlAccentColor", "#0a84ff"),
        "text": system_color("systemTextColor", "#1d1d1f"),
        "muted": system_color("systemSecondaryLabelColor", "#6e6e73"),
        "success": system_color("systemGreenColor", "#30d158"),
        "warning": system_color("systemOrangeColor", "#ff9f0a"),
        "danger": system_color("systemRedColor", "#ff453a"),
        "idle": system_color("systemGrayColor", "#8e8e93"),
    } if is_macos else {
        "background": "#f4f7fb",
        "surface": "#ffffff",
        "primary": "#1769d8",
        "text": "#172033",
        "muted": "#637083",
        "success": "#168553",
        "warning": "#c47a00",
        "danger": "#c43d4b",
        "idle": "#8591a3",
    }
    root.configure(background=colors["background"])
    style = ttk.Style(root)
    available_themes = style.theme_names()
    preferred_theme = "vista" if sys.platform == "win32" else "aqua" if sys.platform == "darwin" else "clam"
    if preferred_theme in available_themes:
        style.theme_use(preferred_theme)
    default_font = "Segoe UI" if sys.platform == "win32" else "Helvetica Neue" if is_macos else "Helvetica"
    style.configure("App.TFrame", background=colors["background"])
    style.configure("Surface.TFrame", background=colors["surface"])
    style.configure("Header.TLabel", background=colors["background"], foreground=colors["text"], font=(default_font, 18 if is_macos else 22, "bold"))
    style.configure("Subtitle.TLabel", background=colors["background"], foreground=colors["muted"], font=(default_font, 10))
    style.configure("CardTitle.TLabel", background=colors["surface"], foreground=colors["muted"], font=(default_font, 9, "bold"))
    style.configure("CardValue.TLabel", background=colors["surface"], foreground=colors["text"], font=(default_font, 13, "bold"))
    style.configure("StatusTitle.TLabel", background=colors["surface"], foreground=colors["text"], font=(default_font, 15, "bold"))
    style.configure("StatusText.TLabel", background=colors["surface"], foreground=colors["muted"], font=(default_font, 10))
    style.configure("Hint.TLabel", foreground=colors["muted"], font=(default_font, 9))
    style.configure("Accent.TButton", font=(default_font, 9, "bold"), padding=(12, 5) if is_macos else (13, 7))
    style.configure("Action.TButton", padding=(10, 5) if is_macos else (11, 7))
    style.configure("TNotebook", background=colors["background"], borderwidth=0)
    style.configure("TNotebook.Tab", padding=(20, 7) if is_macos else (18, 9), font=(default_font, 9, "bold"))

    if not is_macos:
        icon = tk.PhotoImage(width=32, height=32)
        icon.put(colors["primary"], to=(3, 3, 29, 29))
        icon.put("#ffffff", to=(9, 10, 23, 13))
        icon.put("#ffffff", to=(12, 16, 20, 19))
        icon.put("#ffffff", to=(15, 22, 18, 25))
        root.iconphoto(True, icon)

    main = ttk.Frame(root, style="App.TFrame", padding=(22, 14, 22, 18) if is_macos else (24, 18, 24, 20))
    main.pack(fill="both", expand=True)
    header = ttk.Frame(main, style="App.TFrame")
    header.pack(fill="x", pady=(0, 14))
    ttk.Label(header, text="WiFi Agent Settings" if is_macos else "WiFi Agent", style="Header.TLabel").pack(anchor="w")
    header_subtitle = tk.StringVar(
        value=(
            "Enter your portal credentials and finish initial setup to start monitoring"
            if setup_required["value"]
            else "Sophos/Cyberoam connectivity monitoring, secure login, and service management"
        )
    )
    ttk.Label(
        header,
        textvariable=header_subtitle,
        style="Subtitle.TLabel",
    ).pack(anchor="w", pady=(2, 0))

    notebook = ttk.Notebook(main)
    notebook.pack(fill="both", expand=True)
    overview_tab = ttk.Frame(notebook, style="App.TFrame", padding=(2, 16, 2, 2))
    settings_tab = ttk.Frame(notebook, style="App.TFrame", padding=(2, 16, 2, 2))
    diagnostics_tab = ttk.Frame(notebook, style="App.TFrame", padding=(2, 16, 2, 2))
    if setup_required["value"]:
        notebook.add(settings_tab, text="Initial Setup")
    else:
        notebook.add(overview_tab, text="General" if is_macos else "Overview")
        notebook.add(settings_tab, text="Connection" if is_macos else "Settings")
        notebook.add(diagnostics_tab, text="Diagnostics")

    username = tk.StringVar(value=str(config["username"]))
    password = tk.StringVar()
    scheme = tk.StringVar(value=str(config.get("portal_scheme", "https")))
    host = tk.StringVar(value=str(config["portal_host"]))
    port = tk.StringVar(value=str(config["portal_port"]))
    interval = tk.StringVar(value=str(config["check_interval_seconds"]))
    max_backoff = tk.StringVar(value=str(config["login_backoff_max_seconds"]))
    interface = tk.StringVar(value=str(config.get("network_interface", "auto")))
    insecure = tk.BooleanVar(value=bool(config.get("allow_self_signed_portal", True)))
    show_password = tk.BooleanVar(value=False)
    status_title = tk.StringVar(value="Loading agent status…")
    status_detail = tk.StringVar(value="Waiting for the first status snapshot")
    runtime_value = tk.StringVar(value="Checking…")
    startup_value = tk.StringVar(value="Checking…")
    ethernet_value = tk.StringVar(value="Not checked")
    portal_value = tk.StringVar(value="Not checked")
    internet_value = tk.StringVar(value="Not checked")
    last_check_value = tk.StringVar(value="Never")
    feedback_value = tk.StringVar(value=credential_store_description(str(config.get("credential_store", ""))))
    feedback_override_until = {"value": 0.0}
    startup_installed = {"value": startup_detected}
    agent_running = {"value": False}

    def startup_description(installed: bool) -> str:
        if is_macos:
            return "Available from the menu bar after login" if installed else "Not installed as a Login Item"
        if _is_linux():
            return (
                "Runs in the background from login (systemd user service)"
                if installed
                else "Not installed as a background service"
            )
        return "Starts automatically at user login" if installed else "Not installed at startup"

    # Overview status card.
    status_card = ttk.Frame(overview_tab, style="Surface.TFrame", padding=18)
    status_card.pack(fill="x", pady=(0, 12))
    status_dot = tk.Canvas(status_card, width=22, height=22, highlightthickness=0, background=colors["surface"])
    status_dot.pack(side="left", padx=(0, 12), anchor="n", pady=2)
    status_dot_id = status_dot.create_oval(3, 3, 19, 19, fill=colors["idle"], outline="")
    status_copy = ttk.Frame(status_card, style="Surface.TFrame")
    status_copy.pack(side="left", fill="x", expand=True)
    ttk.Label(status_copy, textvariable=status_title, style="StatusTitle.TLabel", wraplength=610).pack(anchor="w")
    ttk.Label(status_copy, textvariable=status_detail, style="StatusText.TLabel", wraplength=610).pack(anchor="w", pady=(3, 0))

    metrics = ttk.Frame(overview_tab, style="App.TFrame")
    metrics.pack(fill="x", pady=(0, 12))
    for column in range(3):
        metrics.columnconfigure(column, weight=1, uniform="metric")

    def metric_card(column: int, title: str, variable: tk.StringVar) -> None:
        card = ttk.Frame(metrics, style="Surface.TFrame", padding=14)
        card.grid(row=0, column=column, sticky="nsew", padx=(0 if column == 0 else 5, 0 if column == 2 else 5))
        ttk.Label(card, text=title.upper(), style="CardTitle.TLabel").pack(anchor="w")
        ttk.Label(card, textvariable=variable, style="CardValue.TLabel").pack(anchor="w", pady=(7, 0))

    metric_card(0, "Ethernet", ethernet_value)
    metric_card(1, "Portal session", portal_value)
    metric_card(2, "Internet", internet_value)

    service_card = ttk.Frame(overview_tab, style="Surface.TFrame", padding=18)
    service_card.pack(fill="x", pady=(0, 12))
    service_card.columnconfigure(0, weight=1)
    ttk.Label(service_card, text="AGENT & STARTUP", style="CardTitle.TLabel").grid(row=0, column=0, sticky="w")
    ttk.Label(service_card, textvariable=runtime_value, style="CardValue.TLabel").grid(row=1, column=0, sticky="w", pady=(7, 0))
    ttk.Label(service_card, textvariable=startup_value, style="StatusText.TLabel").grid(row=2, column=0, sticky="w", pady=(3, 0))
    ttk.Label(service_card, textvariable=last_check_value, style="StatusText.TLabel").grid(row=3, column=0, sticky="w", pady=(3, 0))
    service_actions = ttk.Frame(service_card, style="Surface.TFrame")
    service_actions.grid(row=0, column=1, rowspan=4, sticky="e")

    quick_actions = ttk.Frame(overview_tab, style="App.TFrame")
    quick_actions.pack(fill="x")

    # Settings tab. The canvas keeps every action reachable in a partial-height
    # Windows window while retaining the fixed Settings-window size on macOS.
    settings_canvas = tk.Canvas(
        settings_tab,
        background=colors["background"],
        borderwidth=0,
        highlightthickness=0,
    )
    settings_scrollbar = ttk.Scrollbar(settings_tab, orient="vertical", command=settings_canvas.yview)
    settings_canvas.configure(yscrollcommand=settings_scrollbar.set)
    settings_scrollbar.pack(side="right", fill="y")
    settings_canvas.pack(side="left", fill="both", expand=True)
    settings_content = ttk.Frame(settings_canvas, style="App.TFrame")
    settings_window = settings_canvas.create_window((0, 0), window=settings_content, anchor="nw")

    def resize_settings_content(event=None) -> None:
        settings_canvas.configure(scrollregion=settings_canvas.bbox("all"))
        settings_canvas.itemconfigure(settings_window, width=settings_canvas.winfo_width())

    settings_content.bind("<Configure>", resize_settings_content)
    settings_canvas.bind("<Configure>", resize_settings_content)

    def scroll_settings(event) -> str | None:
        if notebook.select() != str(settings_tab):
            return None
        if getattr(event, "num", None) == 4:
            units = -3
        elif getattr(event, "num", None) == 5:
            units = 3
        else:
            delta = int(getattr(event, "delta", 0))
            units = -max(-3, min(3, delta // 120 if abs(delta) >= 120 else delta))
        if units:
            settings_canvas.yview_scroll(units, "units")
        return "break"

    root.bind_all("<MouseWheel>", scroll_settings, add="+")
    root.bind_all("<Button-4>", scroll_settings, add="+")
    root.bind_all("<Button-5>", scroll_settings, add="+")

    account_group = ttk.LabelFrame(settings_content, text=" Account ", padding=14)
    account_group.pack(fill="x", pady=(0, 10))
    account_group.columnconfigure(1, weight=1)
    ttk.Label(account_group, text="Username / roll number").grid(row=0, column=0, sticky="w", padx=(0, 12), pady=5)
    ttk.Entry(account_group, textvariable=username).grid(row=0, column=1, columnspan=2, sticky="ew", pady=5)
    ttk.Label(account_group, text="Password").grid(row=1, column=0, sticky="w", padx=(0, 12), pady=5)
    password_entry = ttk.Entry(account_group, textvariable=password, show="•")
    password_entry.grid(row=1, column=1, sticky="ew", pady=5)

    def toggle_password_visibility() -> None:
        password_entry.configure(show="" if show_password.get() else "•")

    ttk.Checkbutton(
        account_group,
        text="Show",
        variable=show_password,
        command=toggle_password_visibility,
    ).grid(row=1, column=2, padx=(8, 0), pady=5)
    password_hint = tk.StringVar(
        value="Password is required for initial setup." if setup_required["value"] else "Leave blank to keep the saved credential."
    )
    ttk.Label(account_group, textvariable=password_hint, style="Hint.TLabel").grid(
        row=2, column=1, columnspan=2, sticky="w", pady=(0, 2)
    )

    portal_group = ttk.LabelFrame(settings_content, text=" Portal ", padding=14)
    portal_group.pack(fill="x", pady=(0, 10))
    portal_group.columnconfigure(1, weight=1)
    ttk.Label(portal_group, text="Protocol").grid(row=0, column=0, sticky="w", padx=(0, 12), pady=5)
    ttk.Combobox(portal_group, textvariable=scheme, values=("https", "http"), state="readonly", width=10).grid(
        row=0, column=1, sticky="w", pady=5
    )
    ttk.Label(portal_group, text="Host or IP").grid(row=1, column=0, sticky="w", padx=(0, 12), pady=5)
    ttk.Entry(portal_group, textvariable=host).grid(row=1, column=1, sticky="ew", pady=5)
    ttk.Label(portal_group, text="Port").grid(row=1, column=2, sticky="w", padx=(14, 6), pady=5)
    ttk.Entry(portal_group, textvariable=port, width=8).grid(row=1, column=3, sticky="w", pady=5)
    ttk.Checkbutton(
        portal_group,
        text="Allow the portal's self-signed HTTPS certificate",
        variable=insecure,
    ).grid(row=2, column=1, columnspan=3, sticky="w", pady=(7, 2))

    monitor_group = ttk.LabelFrame(settings_content, text=" Monitoring & retry ", padding=14)
    monitor_group.pack(fill="x", pady=(0, 10))
    monitor_group.columnconfigure(1, weight=1)
    ttk.Label(monitor_group, text="Network interface").grid(row=0, column=0, sticky="w", padx=(0, 12), pady=5)
    interface_box = ttk.Combobox(monitor_group, textvariable=interface, state="readonly")
    interface_box.grid(row=0, column=1, sticky="ew", pady=5)

    def refresh_interfaces() -> None:
        try:
            choices = ["auto"] + active_interfaces()
            if interface.get() not in choices:
                choices.append(interface.get())
            interface_box.configure(values=choices)
        except Exception as exc:
            messagebox.showerror("Could not list interfaces", str(exc))

    ttk.Button(monitor_group, text="Refresh", command=refresh_interfaces).grid(row=0, column=2, padx=(8, 0), pady=5)
    ttk.Label(monitor_group, text="Check interval").grid(row=1, column=0, sticky="w", padx=(0, 12), pady=5)
    ttk.Spinbox(monitor_group, from_=15, to=3600, increment=15, textvariable=interval, width=10).grid(
        row=1, column=1, sticky="w", pady=5
    )
    ttk.Label(monitor_group, text="seconds", style="Hint.TLabel").grid(row=1, column=1, sticky="w", padx=(82, 0), pady=5)
    ttk.Label(monitor_group, text="Maximum retry delay").grid(row=2, column=0, sticky="w", padx=(0, 12), pady=5)
    ttk.Spinbox(monitor_group, from_=30, to=3600, increment=30, textvariable=max_backoff, width=10).grid(
        row=2, column=1, sticky="w", pady=5
    )
    ttk.Label(monitor_group, text="seconds", style="Hint.TLabel").grid(row=2, column=1, sticky="w", padx=(82, 0), pady=5)
    ttk.Label(
        monitor_group,
        text="Auto selects an active physical Ethernet interface. Choose an adapter explicitly to override detection.",
        style="Hint.TLabel",
        wraplength=590,
    ).grid(row=3, column=0, columnspan=3, sticky="w", pady=(7, 0))
    refresh_interfaces()

    feedback = ttk.Frame(settings_content, style="Surface.TFrame", padding=(12, 9))
    feedback.pack(fill="x", pady=(0, 10))
    ttk.Label(feedback, textvariable=feedback_value, style="StatusText.TLabel", wraplength=650).pack(anchor="w")
    settings_actions = ttk.Frame(settings_content, style="App.TFrame")
    settings_actions.pack(fill="x", pady=(0, 2))

    # Diagnostics tab.
    diagnostic_header = ttk.Frame(diagnostics_tab, style="App.TFrame")
    diagnostic_header.pack(fill="x", pady=(0, 8))
    ttk.Label(
        diagnostic_header,
        text="Status snapshot and recent logs. Credentials are never included.",
        style="Subtitle.TLabel",
    ).pack(side="left")
    diagnostic_text = scrolledtext.ScrolledText(
        diagnostics_tab,
        height=22,
        wrap="word",
        font=("Consolas" if sys.platform == "win32" else "TkFixedFont", 9),
        background=colors["surface"] if is_macos else "#101722",
        foreground=colors["text"] if is_macos else "#dbe7f7",
        insertbackground=colors["text"] if is_macos else "#ffffff",
        selectbackground=colors["primary"],
        relief="sunken" if is_macos else "flat",
        padx=12,
        pady=12,
    )
    diagnostic_text.pack(fill="both", expand=True)
    diagnostic_actions = ttk.Frame(diagnostics_tab, style="App.TFrame")
    diagnostic_actions.pack(fill="x", pady=(10, 0))

    def candidate_config() -> dict[str, Any]:
        return validate_config(
            {
                **config,
                "username": username.get(),
                "portal_scheme": scheme.get(),
                "portal_host": host.get(),
                "portal_port": port.get(),
                "check_interval_seconds": interval.get(),
                "login_backoff_max_seconds": max_backoff.get(),
                "network_interface": interface.get(),
                "allow_self_signed_portal": insecure.get(),
            },
            require_username=True,
        )

    def set_feedback(message: str, *, seconds: int = 5) -> None:
        feedback_value.set(message)
        feedback_override_until["value"] = time.monotonic() + seconds

    def save() -> bool:
        new_password = password.get()
        try:
            normalized = candidate_config()
            new_username = str(normalized["username"])
            if not new_password:
                get_password(new_username, str(normalized["credential_store"]))
            if new_password:
                normalized["credential_store"] = store_credentials(
                    new_username, new_password, str(config.get("username", ""))
                )
            save_config(normalized)
            config.clear()
            config.update(normalized)
            password.set("")
            request_external_check()
            if normalized["credential_store"] == "file":
                set_feedback(
                    "Saved. No system keyring is available, so the password was stored in a private file "
                    "readable only by you. The running agent has been asked to reload.",
                    seconds=12,
                )
            else:
                set_feedback("Settings saved securely. The running agent has been asked to reload them.")
            return True
        except (OSError, ValueError, RuntimeError, KeyringError) as exc:
            messagebox.showerror("Could not save", str(exc))
            return False

    busy_buttons: list[Any] = []

    def set_busy(busy: bool) -> None:
        state = "disabled" if busy else "normal"
        for button in busy_buttons:
            button.configure(state=state)
        root.configure(cursor="watch" if busy else "")

    def run_background(work, on_success, title: str, *, show_errors: bool = True) -> None:
        set_busy(True)

        def worker() -> None:
            try:
                result = work()
                root.after(0, lambda: on_success(result))
            except Exception as exc:
                detail = exc.stderr.strip() if isinstance(exc, subprocess.CalledProcessError) and exc.stderr else str(exc)
                if show_errors:
                    root.after(0, lambda message=detail: messagebox.showerror(title, message))
            finally:
                root.after(0, lambda: set_busy(False))

        threading.Thread(target=worker, daemon=True).start()

    def install() -> None:
        if not save():
            return

        def installed(message: str) -> None:
            startup_installed["value"] = True
            startup_value.set(startup_description(True))
            set_feedback(message, seconds=8)
            if setup_required["value"]:
                setup_required["value"] = False
                notebook.forget(settings_tab)
                notebook.add(overview_tab, text="General" if is_macos else "Overview")
                notebook.add(settings_tab, text="Connection" if is_macos else "Settings")
                notebook.add(diagnostics_tab, text="Diagnostics")
                password_hint.set("Leave blank to keep the saved credential.")
                header_subtitle.set("Sophos/Cyberoam connectivity monitoring, secure login, and service management")
                notebook.select(overview_tab)
            messagebox.showinfo("Service installed", message)

        run_background(install_startup, installed, "Installation failed")

    def uninstall() -> None:
        if not messagebox.askyesno("Remove startup service", "Stop WiFi Agent and remove it from startup? Saved settings and credentials will be kept."):
            return
        def uninstalled(message: str) -> None:
            startup_installed["value"] = False
            startup_value.set(startup_description(False))
            set_feedback(message, seconds=8)
            messagebox.showinfo("Service removed", message)

        run_background(uninstall_startup, uninstalled, "Removal failed")

    def test_now() -> None:
        try:
            normalized = candidate_config()
        except (ValueError, RuntimeError) as exc:
            messagebox.showerror("Cannot test these settings", str(exc))
            return
        set_feedback("Testing the selected interface, portal port, and internet access…", seconds=20)

        def work() -> tuple[list[str], bool | None, bool | None]:
            wired = wired_interfaces(str(normalized["network_interface"]))
            open_ = portal_port_open(str(normalized["portal_host"]), int(normalized["portal_port"])) if wired else None
            online = internet_available() if wired else None
            return wired, open_, online

        def tested(result: tuple[list[str], bool | None, bool | None]) -> None:
            wired, open_, online = result
            ethernet_value.set("Connected" if wired else "Disconnected")
            portal_value.set("Reachable" if open_ is True else "Unreachable" if open_ is False else "Not checked")
            internet_value.set("Available" if online is True else "Unavailable" if online is False else "Not checked")
            set_feedback(
                f"Test complete — interface: {', '.join(wired) if wired else 'none'}; "
                f"portal: {portal_value.get().lower()}; internet: {internet_value.get().lower()}.",
                seconds=10,
            )

        run_background(work, tested, "Connection test failed")

    def check_now() -> None:
        if not agent_running["value"]:
            messagebox.showwarning("Agent is not running", "Install or start WiFi Agent before requesting an immediate check.")
            return
        request_external_check()
        set_feedback("Immediate check requested. Live status will update when the agent finishes.")

    def check_updates(interactive: bool = True) -> None:
        if sys.platform not in {"win32", "darwin"}:
            def release_checked(result: tuple[str, str] | None) -> None:
                if result is None:
                    if interactive:
                        messagebox.showinfo("No updates", f"WiFi Agent {APP_VERSION} is the latest version.")
                    return
                version, release_url = result
                if messagebox.askyesno(
                    "Update available",
                    f"WiFi Agent {version} is available.\n\n"
                    "Open the release page to download the package for your distribution?",
                ):
                    import webbrowser

                    webbrowser.open(release_url)

            run_background(check_for_release_page, release_checked, "Update check failed", show_errors=interactive)
            return

        def checked(update: UpdateInfo | None) -> None:
            if update is None:
                if interactive:
                    messagebox.showinfo("No updates", f"WiFi Agent {APP_VERSION} is the latest version.")
                return
            should_install = messagebox.askyesno(
                "Update available",
                f"WiFi Agent {update.version} is available.\n\n"
                "Download, verify, and install it now? Your credentials and settings will be kept.",
            )
            if not should_install:
                return

            def downloaded(installer: Path) -> None:
                def start_installation() -> None:
                    if sys.platform == "win32":
                        messagebox.showinfo(
                            "Installing update",
                            "WiFi Agent will close while the verified update installs, then restart in the notification area.",
                        )
                        install_downloaded_update(installer)
                        root.after(150, root.destroy)
                        return

                    def installed(_result: None) -> None:
                        root.destroy()

                    run_background(
                        lambda: install_downloaded_update(installer),
                        installed,
                        "Update installation failed",
                    )

                root.after(50, start_installation)

            root.after(
                50,
                lambda: run_background(
                    lambda: download_update(update),
                    downloaded,
                    "Update download failed",
                ),
            )

        run_background(
            check_for_update,
            checked,
            "Update check failed",
            show_errors=interactive,
        )

    def safe_open_logs() -> None:
        try:
            open_log_location()
        except OSError as exc:
            messagebox.showerror("Could not open logs", str(exc))

    def refresh_diagnostics() -> None:
        snapshot = read_status()
        sections = [
            "WIFI AGENT DIAGNOSTICS",
            "=" * 72,
            f"Generated: {utc_now()}",
            f"Platform: {sys.platform}",
            f"Python: {sys.version.split()[0]}",
            f"Version: {APP_VERSION}",
            f"Startup installed: {startup_installed['value']}",
            f"Password store: {config.get('credential_store') or 'vault'}",
            *[f"{key}: {value}" for key, value in desktop_integration_report().items()],
            f"Configuration: {CONFIG_PATH}",
            f"Log: {LOG_PATH}",
            "",
            "STATUS SNAPSHOT",
            "-" * 72,
            json.dumps(snapshot or {"message": "No status recorded"}, indent=2),
            "",
            "RECENT LOGS",
            "-" * 72,
        ]
        if LOG_PATH.exists():
            sections.extend(LOG_PATH.read_text(encoding="utf-8", errors="replace").splitlines()[-80:])
        else:
            sections.append("No log file has been created yet.")
        diagnostic_text.configure(state="normal")
        diagnostic_text.delete("1.0", "end")
        diagnostic_text.insert("1.0", "\n".join(sections))
        diagnostic_text.configure(state="disabled")

    def copy_diagnostics() -> None:
        root.clipboard_clear()
        root.clipboard_append(diagnostic_text.get("1.0", "end-1c"))
        set_feedback("Diagnostics copied to the clipboard.")

    def on_tab_changed(event=None) -> None:
        pane_by_widget = {
            str(overview_tab): "general" if is_macos else "overview",
            str(settings_tab): "connection" if is_macos else "settings",
            str(diagnostics_tab): "diagnostics",
        }
        selected_pane = pane_by_widget.get(notebook.select(), "general" if is_macos else "overview")
        try:
            save_ui_state({"last_pane": selected_pane})
        except OSError:
            pass
        if is_macos:
            pane_title = {"general": "General", "connection": "Connection", "diagnostics": "Diagnostics"}[selected_pane]
            root.title(f"WiFi Agent Settings — {pane_title}")
        if notebook.select() == str(diagnostics_tab):
            refresh_diagnostics()

    notebook.bind("<<NotebookTabChanged>>", on_tab_changed)

    def go_to_settings() -> None:
        notebook.select(settings_tab)

    # Wire actions after functions exist.
    install_button = ttk.Button(
        service_actions,
        text="Install at Login" if is_macos else "Install / repair",
        command=install,
        style="Action.TButton",
    )
    install_button.pack(side="left", padx=4)
    remove_button = ttk.Button(
        service_actions,
        text="Remove from Login" if is_macos else "Remove",
        command=uninstall,
        style="Action.TButton",
    )
    remove_button.pack(side="left", padx=4)
    check_button = ttk.Button(quick_actions, text="Check Now" if is_macos else "Check now", command=check_now, style="Accent.TButton")
    check_button.pack(side="left", padx=(0, 8))
    update_button = ttk.Button(
        quick_actions,
        text="Check for Updates…" if is_macos else "Check for updates",
        command=check_updates,
        style="Action.TButton",
    )
    update_button.pack(side="left", padx=4)
    ttk.Button(
        quick_actions,
        text="Connection Settings…" if is_macos else "Open settings",
        command=go_to_settings,
        style="Action.TButton",
    ).pack(side="left", padx=4)
    ttk.Button(
        quick_actions,
        text="Open Logs…" if is_macos else "Open logs",
        command=safe_open_logs,
        style="Action.TButton",
    ).pack(side="left", padx=4)

    test_button = ttk.Button(settings_actions, text="Test Connection" if is_macos else "Test connection", command=test_now, style="Action.TButton")
    test_button.pack(side="left")
    save_install_button = ttk.Button(
        settings_actions,
        text="Save & Install at Login" if is_macos else "Save & install",
        command=install,
        style="Accent.TButton",
    )
    save_install_button.pack(side="right")
    save_button = ttk.Button(settings_actions, text="Save" if is_macos else "Save settings", command=save, style="Action.TButton")
    save_button.pack(side="right", padx=(0, 8))

    ttk.Button(diagnostic_actions, text="Refresh", command=refresh_diagnostics, style="Action.TButton").pack(side="left")
    ttk.Button(diagnostic_actions, text="Copy", command=copy_diagnostics, style="Action.TButton").pack(side="left", padx=8)
    ttk.Button(
        diagnostic_actions,
        text="Open Log…" if is_macos else "Open log file",
        command=safe_open_logs,
        style="Action.TButton",
    ).pack(side="right")
    busy_buttons.extend(
        [install_button, remove_button, check_button, update_button, test_button, save_button, save_install_button]
    )

    remembered_pane = str(load_ui_state().get("last_pane", ""))
    requested_pane = (initial_pane or remembered_pane).casefold()
    if setup_required["value"]:
        notebook.select(settings_tab)
        root.after(100, password_entry.focus_set)
    elif requested_pane in {"settings", "connection"}:
        notebook.select(settings_tab)
    elif requested_pane == "diagnostics":
        notebook.select(diagnostics_tab)
    else:
        notebook.select(overview_tab)
    on_tab_changed()

    if is_macos:
        root.bind_all("<Command-s>", lambda event: (save(), "break")[1])
        root.bind_all("<Command-w>", lambda event: (root.destroy(), "break")[1])
        root.bind_all("<Command-comma>", lambda event: (go_to_settings(), "break")[1])

        def show_preferences() -> None:
            root.deiconify()
            root.lift()
            go_to_settings()

        root.createcommand("tk::mac::ShowPreferences", show_preferences)
    else:
        root.bind_all("<Control-s>", lambda event: (save(), "break")[1])

    def refresh_status() -> None:
        snapshot = read_status()
        if snapshot:
            checked = snapshot.get("last_check_at") or "not checked yet"
            try:
                process_id = int(snapshot.get("process_id") or 0)
            except (TypeError, ValueError):
                process_id = 0
            running = snapshot_process_running(snapshot)
            agent_running["value"] = running
            phase = str(snapshot.get("phase", "unknown"))
            status_title.set(str(snapshot.get("message", "Unknown")))
            status_detail.set(f"Phase: {phase} · Process ID: {process_id or 'unknown'}")
            runtime_value.set("Agent running" if running else "Agent not running")
            startup_value.set(startup_description(startup_installed["value"]))
            last_check_value.set(f"Last checked: {checked}")
            interfaces = snapshot.get("interfaces") or []
            ethernet_value.set("Connected" if snapshot.get("ethernet_connected") else "Disconnected")
            if interfaces:
                ethernet_value.set(f"Connected · {', '.join(str(value) for value in interfaces)}")
            port_state = snapshot.get("portal_port_open")
            authenticated = snapshot.get("portal_authenticated")
            portal_value.set(
                "Connected" if authenticated is True else
                "Reachable" if port_state is True else
                "Unreachable" if port_state is False else
                "Not checked"
            )
            internet_state = snapshot.get("internet_available")
            internet_value.set("Available" if internet_state is True else "Unavailable" if internet_state is False else "Not checked")
            dot_color = (
                colors["success"] if phase in {"online", "connected"} else
                colors["warning"] if phase in {"offline", "backoff", "paused"} else
                colors["danger"] if phase in ATTENTION_PHASES else
                colors["idle"]
            )
            status_dot.itemconfigure(status_dot_id, fill=dot_color)
            if time.monotonic() >= feedback_override_until["value"]:
                feedback_value.set(str(snapshot.get("message", "Status unavailable")))
        else:
            agent_running["value"] = False
            status_title.set("No status recorded")
            status_detail.set("Install or start WiFi Agent to begin monitoring.")
            runtime_value.set("Agent not running")
            startup_value.set(startup_description(startup_installed["value"]))
        root.after(2000, refresh_status)

    refresh_status()
    refresh_diagnostics()
    if check_updates_on_open and not setup_required["value"]:
        root.after(500, check_updates)
    elif (
        getattr(sys, "frozen", False)
        and sys.platform in {"win32", "darwin"}
        and not setup_required["value"]
    ):
        root.after(2500, lambda: check_updates(False))
    if configuration_warning:
        root.after(100, lambda: messagebox.showwarning("Configuration needs repair", configuration_warning))
    if startup_detected and startup_unit_outdated():
        # A service installed by an older version: move it to the current
        # definition (watchdog, restart policy) without asking.
        root.after(
            300,
            lambda: run_background(
                lambda: install_startup(require_credentials=False),
                lambda message: set_feedback("The background service was updated to the current version.", seconds=8),
                "Service update failed",
                show_errors=False,
            ),
        )

    root.mainloop()
    return 0


def desktop_integration_report() -> dict[str, str]:
    """Describe the Linux tray host and notification service for diagnostics."""
    if not _is_linux():
        return {}
    address = _session_bus_address()
    if not address:
        return {"Desktop session bus": "not found (tray icon and notifications unavailable)"}
    try:
        from jeepney import message_bus
        from jeepney.io.blocking import open_dbus_connection
    except ImportError:
        return {"Tray and notifications": "unavailable: the jeepney package is not installed"}
    try:
        with open_dbus_connection(bus=address) as connection:
            names = set(connection.send_and_get_reply(message_bus.ListNames(), timeout=5).body[0])
            activatable = set(connection.send_and_get_reply(message_bus.ListActivatableNames(), timeout=5).body[0])
    except Exception as exc:
        return {"Desktop session bus": f"unreachable ({exc})"}
    report = {
        "Tray host": "available" if SNI_WATCHER in names else (
            "not running; on GNOME enable the \"AppIndicator and KStatusNotifierItem Support\" extension"
        ),
        "Notification service": (
            "available" if NOTIFICATIONS_NAME in names
            else "starts on demand" if NOTIFICATIONS_NAME in activatable
            else "not found; problems will open the WiFi Agent window instead"
        ),
        "Secret Service vault": (
            "available" if "org.freedesktop.secrets" in names
            else "starts on demand" if "org.freedesktop.secrets" in activatable
            else "not found; passwords are kept in a private file"
        ),
    }
    return report


def print_status(*, json_output: bool = False, log_lines: int = 10) -> int:
    snapshot = read_status()
    running = snapshot_process_running(snapshot)
    if json_output:
        payload = snapshot or {"phase": "unknown", "message": "No status has been recorded"}
        payload = {**payload, "process_running": running, "startup_installed": startup_is_installed()}
        print(json.dumps(payload, indent=2))
    elif snapshot:
        print(f"Running:  {'yes' if running else 'no (status may be stale)'}")
        print(f"Startup:  {'installed' if startup_is_installed() else 'not installed'}")
        print(f"State:    {snapshot.get('phase', 'unknown')}")
        print(f"Message:  {snapshot.get('message', 'Unknown')}")
        print(f"Checked:  {snapshot.get('last_check_at') or 'never'}")
        print(f"Ethernet: {'connected' if snapshot.get('ethernet_connected') else 'disconnected'}")
        port = snapshot.get("portal_port_open")
        authenticated = snapshot.get("portal_authenticated")
        print(f"Portal:   {'connected' if authenticated is True else 'not connected' if authenticated is False else 'not checked'}")
        print(f"Port:     {'reachable' if port is True else 'unreachable' if port is False else 'not checked'}")
        online = snapshot.get("internet_available")
        print(f"Internet: {'available' if online is True else 'unavailable' if online is False else 'not checked'}")
    else:
        print("No agent status has been recorded yet.")

    if not json_output and log_lines > 0 and LOG_PATH.exists():
        print("\nRecent log entries:")
        lines = LOG_PATH.read_text(encoding="utf-8", errors="replace").splitlines()
        print("\n".join(lines[-log_lines:]))
    return 0 if snapshot else 1


def credential_location(username: str) -> str:
    """Return where the password is: "vault", "file", "missing", or a vault error."""
    vault_error = ""
    try:
        if _with_vault(lambda backend: backend.get_password(KEYRING_SERVICE, username)):
            return "vault"
    except _NoVault:
        pass
    except Exception as exc:
        vault_error = str(exc)
    if _file_credential(username):
        return "file"
    return f"vault unavailable: {vault_error}" if vault_error else "missing"


def run_doctor() -> int:
    dependencies = {"keyring": keyring is not None, "psutil": psutil is not None}
    if _is_linux():
        try:
            import jeepney  # noqa: F401

            dependencies["jeepney"] = True
        except ImportError:
            dependencies["jeepney"] = False
    report: dict[str, Any] = {
        "version": APP_VERSION,
        "python": sys.version.split()[0],
        "platform": sys.platform,
        "configuration_path": str(CONFIG_PATH),
        "log_path": str(LOG_PATH),
        "dependencies": dependencies,
        "startup_installed": startup_is_installed(),
    }
    if _is_linux() and report["startup_installed"]:
        report["startup_current"] = not startup_unit_outdated()
    healthy = bool(keyring is not None and psutil is not None)
    try:
        config = validate_config(load_config(), require_username=True)
        report["configuration"] = "valid"
        report["portal"] = f"{config['portal_scheme']}://{_portal_authority(str(config['portal_host']), int(config['portal_port']))}"
        report["selected_interface"] = config["network_interface"]
        if keyring is not None:
            ready, backend = credential_backend_ready()
            report["credential_vault"] = backend if ready else f"unavailable: {backend}"
            location = credential_location(str(config["username"]))
            report["credential_store"] = location
            report["credential_saved"] = location in {"vault", "file"}
            healthy = healthy and report["credential_saved"]
        else:
            healthy = False
    except (OSError, RuntimeError, ValueError, KeyringError) as exc:
        report["configuration"] = f"invalid: {exc}"
        healthy = False
    try:
        report["active_interfaces"] = active_interfaces() if psutil is not None else []
    except Exception as exc:
        report["active_interfaces_error"] = str(exc)
        healthy = False
    if _is_linux():
        report["desktop"] = desktop_integration_report()
    report["last_status"] = read_status()
    report["healthy"] = healthy
    print(json.dumps(report, indent=2))
    return 0 if healthy else 1


def _self_test_checks() -> None:
    ensure_dependencies()
    import tkinter

    if not tkinter.Tcl().eval("info patch"):
        raise RuntimeError("The bundled Tcl/Tk runtime did not initialize.")
    if sys.platform in {"win32", "darwin"}:
        from PIL import Image
        import pystray

        if Image.new("RGBA", (1, 1)).size != (1, 1) or not getattr(pystray, "Icon", None):
            raise RuntimeError("The bundled tray-image runtime did not initialize.")
        # tkinter.Tcl() never loads Tk itself; open and close a real window.
        window = tkinter.Tk()
        window.withdraw()
        window.update_idletasks()
        window.update()
        window.destroy()
        if _active_keyring() is None:
            raise RuntimeError("No credential vault backend was found in the packaged application.")
        if sys.platform == "darwin":
            import AppKit  # noqa: F401
            import Foundation  # noqa: F401
            import objc  # noqa: F401
            from PyObjCTools import AppHelper  # noqa: F401
        return
    import jeepney.io.blocking  # noqa: F401
    import jeepney.io.threading  # noqa: F401

    snapshot = AgentSnapshot(phase="online", message="Self-test")
    properties = sni_properties(snapshot)
    if len(properties["IconPixmap"][1][0][2]) != 22 * 22 * 4:
        raise RuntimeError("The tray icon renderer produced an invalid image.")
    dbusmenu_layout(tray_menu_items(snapshot, False))


def run_packaging_self_test(result_file: str | None = None) -> int:
    """Exercise the runtime the way a real launch does and report the result."""
    try:
        _self_test_checks()
        outcome, code = "ok", 0
    except BaseException as exc:
        outcome, code = "failed: " + "".join(traceback.format_exception(type(exc), exc, exc.__traceback__)), 1
    if result_file:
        Path(result_file).write_text(outcome + "\n", encoding="utf-8")
    if code and sys.stderr is not None:
        print(outcome, file=sys.stderr)
    return code


_FAULT_LOG: dict[str, Any] = {}


def _enable_fault_log() -> None:
    """Record hard crashes (segfaults, aborts) that bypass Python handlers."""
    try:
        app_dir().mkdir(parents=True, exist_ok=True)
        path = app_dir() / "fault.log"
        if path.exists() and path.stat().st_size > 512 * 1024:
            path.unlink()
        handle = path.open("a", encoding="utf-8")
        faulthandler.enable(file=handle)
        _FAULT_LOG["handle"] = handle
    except (OSError, RuntimeError, ValueError):
        pass


def _record_crash(detail: str) -> None:
    entry = f"{utc_now()} WiFi Agent {APP_VERSION} ({' '.join(sys.argv[1:]) or 'setup'})\n{detail.rstrip()}\n\n"
    targets = [CRASH_LOG_PATH]
    if sys.platform == "darwin":
        targets.append(Path.home() / "Library" / "Logs" / APP_NAME / "crash.log")
    for target in targets:
        try:
            target.parent.mkdir(parents=True, exist_ok=True)
            if target.exists() and target.stat().st_size > 512 * 1024:
                target.unlink()
            with target.open("a", encoding="utf-8") as handle:
                handle.write(entry)
        except OSError:
            pass


def _show_fatal_error(detail: str) -> None:
    """Show an error without relying on Tk, which may be what failed."""
    try:
        if sys.platform == "darwin":
            subprocess.Popen(
                [
                    "osascript",
                    "-e", "on run argv",
                    "-e", "display alert \"WiFi Agent could not start\" message (item 1 of argv) as critical",
                    "-e", "end run",
                    detail,
                ],
                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                start_new_session=True,
            )
        elif sys.platform == "win32":
            import ctypes

            ctypes.windll.user32.MessageBoxW(None, detail, APP_DISPLAY_NAME, 0x10)
        else:
            from tkinter import Tk, messagebox

            window = Tk()
            window.withdraw()
            messagebox.showerror(APP_DISPLAY_NAME, detail, parent=window)
            window.destroy()
    except Exception:
        pass


def _report_failure(detail: str, *, interactive: bool) -> None:
    has_terminal = bool(sys.stderr is not None and getattr(sys.stderr, "isatty", lambda: False)())
    if sys.stderr is not None:
        try:
            print(f"Error: {detail}", file=sys.stderr)
        except (OSError, ValueError):
            pass
    if getattr(sys, "frozen", False) or not has_terminal:
        _record_crash(detail)
    # A packaged app opened from Finder or Explorer has no console; without
    # a dialog a startup failure would look like the app never opened.
    if interactive and not has_terminal:
        _show_fatal_error(detail)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", action="version", version=f"{APP_DISPLAY_NAME} {APP_VERSION}")
    subparsers = parser.add_subparsers(dest="command")
    setup_parser = subparsers.add_parser("setup", help="open the credential/settings window")
    setup_parser.add_argument(
        "--pane",
        choices=("overview", "general", "settings", "connection", "diagnostics"),
        help="open a specific settings pane",
    )
    setup_parser.add_argument("--check-updates", action="store_true", help=argparse.SUPPRESS)
    run_parser = subparsers.add_parser("run", help="run the background monitor")
    run_parser.add_argument("--once", action="store_true", help="perform one status/login cycle")
    run_parser.add_argument("--no-tray", action="store_true", help="do not show a Linux tray icon or notifications")
    subparsers.add_parser("tray", help="run the monitor with its tray, menu-bar, or panel icon")
    subparsers.add_parser("check", help="ask a running agent to check immediately")
    install_parser = subparsers.add_parser("install", help="install and start the per-user startup service")
    install_parser.add_argument(
        "--repair", action="store_true", help="rewrite the startup service without checking credentials"
    )
    subparsers.add_parser("uninstall", help="remove the startup service (keep settings)")
    status_parser = subparsers.add_parser("status", help="show current state and recent logs")
    status_parser.add_argument("--json", action="store_true", help="print machine-readable status")
    status_parser.add_argument("--logs", type=int, default=10, help="number of recent log lines")
    subparsers.add_parser("doctor", help="validate configuration, vault, startup, and interfaces")
    subparsers.add_parser("open-logs", help="open the agent log location")
    self_test_parser = subparsers.add_parser("self-test", help=argparse.SUPPRESS)
    self_test_parser.add_argument("--result-file", help=argparse.SUPPRESS)
    return parser


def _dispatch(args: argparse.Namespace) -> int:
    if args.command in (None, "setup"):
        return show_setup_ui(
            getattr(args, "pane", None),
            check_updates_on_open=getattr(args, "check_updates", False),
        )
    if args.command == "run":
        return run_agent(args.once, tray=not args.no_tray)
    if args.command == "tray":
        return run_tray()
    if args.command == "check":
        request_external_check()
        print("Immediate check requested. Use 'status' to view the result.")
        return 0
    if args.command == "install":
        print(install_startup(require_credentials=not args.repair))
        return 0
    if args.command == "uninstall":
        print(uninstall_startup())
        return 0
    if args.command == "status":
        return print_status(json_output=args.json, log_lines=max(0, args.logs))
    if args.command == "doctor":
        return run_doctor()
    if args.command == "open-logs":
        open_log_location()
        return 0
    if args.command == "self-test":
        return run_packaging_self_test(args.result_file)
    return 0


def main() -> int:
    _enable_fault_log()
    args = _build_parser().parse_args()
    interactive = args.command not in {"run", "tray", "self-test"}
    try:
        return _dispatch(args)
    except (OSError, RuntimeError, ValueError, KeyringError, subprocess.CalledProcessError) as exc:
        detail = exc.stderr.strip() if isinstance(exc, subprocess.CalledProcessError) and exc.stderr else str(exc)
        _report_failure(detail, interactive=interactive)
        return 2
    except SystemExit as exc:
        if isinstance(exc.code, str):
            _report_failure(exc.code, interactive=interactive)
            return 2
        raise
    except KeyboardInterrupt:
        return 130
    except Exception:
        _record_crash(traceback.format_exc())
        _report_failure(
            f"WiFi Agent stopped because of an unexpected error. Details were saved to {CRASH_LOG_PATH}.",
            interactive=interactive,
        )
        return 70


if __name__ == "__main__":
    raise SystemExit(main())
