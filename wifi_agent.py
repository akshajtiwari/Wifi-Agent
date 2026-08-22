#!/usr/bin/env python3
"""WiFi Agent: cross-platform Sophos/Cyberoam captive-portal automation."""

from __future__ import annotations

import argparse
from contextlib import AbstractContextManager
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from functools import lru_cache
import getpass
from html import escape as xml_escape
import ipaddress
import json
import logging
from logging.handlers import RotatingFileHandler
import os
from pathlib import Path
import plistlib
import random
import re
import signal
import socket
import ssl
import subprocess
import sys
import threading
import time
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, quote
from urllib.request import HTTPRedirectHandler, HTTPSHandler, Request, build_opener

try:
    import keyring
    from keyring.errors import KeyringError, NoKeyringError
except ImportError:  # Helpful error before the installer has installed dependencies.
    keyring = None
    KeyringError = NoKeyringError = Exception

try:
    import psutil
except ImportError:
    psutil = None

APP_NAME = "WiFiAgent"
APP_DISPLAY_NAME = "WiFi Agent"
APP_VERSION = "1.1.0"
if getattr(sys, "frozen", False):
    try:
        from wifi_agent_build import BUILD_VERSION

        APP_VERSION = BUILD_VERSION
    except ImportError:
        pass
KEYRING_SERVICE = "WiFi Agent"
DEFAULT_CONFIG: dict[str, Any] = {
    "username": "",
    "portal_scheme": "https",
    "portal_host": "192.168.1.2",
    "portal_port": 8090,
    "check_interval_seconds": 45,
    "login_backoff_max_seconds": 600,
    "network_interface": "auto",
    "allow_self_signed_portal": True,
    "config_revision": 0,
}


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
WINDOWS_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)


def utc_now() -> str:
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


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

    return {
        "username": username,
        "portal_scheme": scheme,
        "portal_host": host,
        "portal_port": port,
        "check_interval_seconds": interval,
        "login_backoff_max_seconds": max_backoff,
        "network_interface": interface,
        "allow_self_signed_portal": bool(config.get("allow_self_signed_portal", True)),
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
    temporary = STATUS_PATH.with_suffix(".tmp")
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


def credential_backend_ready() -> tuple[bool, str]:
    if keyring is None:
        return False, "The keyring package is not installed."
    try:
        backend = keyring.get_keyring()
        priority = getattr(backend, "priority", 0)
        if priority <= 0:
            return False, "No usable operating-system credential vault was found."
        return True, backend.__class__.__name__
    except Exception as exc:
        return False, str(exc)


def store_credentials(username: str, password: str, old_username: str = "") -> None:
    ready, detail = credential_backend_ready()
    if not ready:
        raise RuntimeError(
            detail + " Install/unlock Windows Credential Manager, macOS Keychain, "
            "or a Linux Secret Service keyring and try again."
        )
    try:
        keyring.set_password(KEYRING_SERVICE, username, password)
        if old_username and old_username != username:
            try:
                keyring.delete_password(KEYRING_SERVICE, old_username)
            except KeyringError:
                pass
    except (KeyringError, NoKeyringError) as exc:
        raise RuntimeError(f"The password could not be saved in the OS credential vault: {exc}") from exc


def get_password(username: str) -> str:
    ensure_dependencies("keyring")
    try:
        password = keyring.get_password(KEYRING_SERVICE, username)
    except (KeyringError, NoKeyringError) as exc:
        raise RuntimeError(f"The OS credential vault is unavailable: {exc}") from exc
    if not password:
        raise RuntimeError("No saved password was found. Open setup and save the credentials again.")
    return password


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
        "cloudflare", "warp", "wireguard", "wintun", "zerotier", "nordlynx", "proton",
        "openvpn", "anyconnect", "cisco", "fortinet", "globalprotect", "secuextender",
        "hamachi", "hyper-v", "vethernet", "npcap", "pcap",
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

    def _request(self, request: Request, timeout: float = 10.0) -> str:
        with self.opener.open(request, timeout=timeout) as response:
            return response.read(64 * 1024).decode("utf-8", errors="replace")

    def _safe_message(self, message: str) -> str:
        value = message.replace(self.password, "[redacted]") if self.password else message
        return " ".join(value.split())[:300]

    @staticmethod
    def _response_summary(text: str) -> tuple[bool, str]:
        import xml.etree.ElementTree as ET

        status = ""
        message = ""
        ack = ""
        try:
            root = ET.fromstring(text)
            for element in root.iter():
                tag = element.tag.rsplit("}", 1)[-1].casefold() if isinstance(element.tag, str) else ""
                value = (element.text or "").strip()
                if tag == "status" and not status:
                    status = value
                elif tag == "message" and not message:
                    message = value
                elif tag == "ack" and not ack:
                    ack = value
                elif tag in {"state", "result"} and not status:
                    status = value
        except ET.ParseError:
            pass

        parts = []
        for part in (status, message, ack):
            if part and not any(part.casefold() == existing.casefold() for existing in parts):
                parts.append(part)
        combined = " ".join(parts) or "HTTP response received"

        status_upper = status.upper()
        ack_upper = ack.upper()

        is_positive_status = status_upper in {"ACK", "LIVE", "OK", "SUCCESS", "1"}
        is_positive_ack = ack_upper in {"ACK", "LIVE", "OK", "SUCCESS", "1"}
        is_explicit_negative = (
            status_upper in {"FAIL", "FAILED", "LOGIN", "NACK", "ERROR", "DENIED", "0", "OFF", "LIVE_OFF"}
            or ack_upper in {"FAIL", "FAILED", "LOGIN", "NACK", "ERROR", "DENIED", "0", "OFF", "LIVE_OFF"}
            or any(
                word in message.casefold()
                for word in ("invalid", "denied", "error", "fail", "maximum login", "logged off", "signed off", "live_off", "off")
            )
        )

        if is_explicit_negative:
            success = False
        elif is_positive_status or is_positive_ack:
            success = True
        elif not status and not ack and message and not any(
            word in message.casefold() for word in ("fail", "invalid", "denied", "error", "could not", "maximum login")
        ):
            success = True
        else:
            success = False

        return success, combined

    def login(self) -> tuple[bool, str]:
        form = urlencode({
            "mode": "191",
            "username": self.username,
            "password": self.password,
            "producttype": "0",
        }).encode("utf-8")
        request = Request(
            f"{self.base_url}/login.xml",
            data=form,
            headers={"Content-Type": "application/x-www-form-urlencoded", "User-Agent": f"{APP_NAME}/1.0"},
            method="POST",
        )
        try:
            success, message = self._response_summary(self._request(request))
            return success, self._safe_message(message)
        except (HTTPError, URLError, OSError, TimeoutError, ssl.SSLError) as exc:
            return False, str(exc)

    def keep_alive(self) -> tuple[bool, str]:
        url = f"{self.base_url}/live?mode=192&username={quote(self.username, safe='')}"
        try:
            success, message = self._response_summary(
                self._request(Request(url, headers={"User-Agent": f"{APP_NAME}/1.0"}), 8)
            )
            return success, self._safe_message(message)
        except (HTTPError, URLError, OSError, TimeoutError, ssl.SSLError) as exc:
            return False, str(exc)


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
    internet_available: bool | None = None
    paused: bool = False
    last_check_at: str | None = None
    last_login_at: str | None = None
    consecutive_login_failures: int = 0
    retry_in_seconds: int = 0
    process_id: int = 0
    started_at: str | None = None


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
                raise RuntimeError("WiFi Agent is already running.")
            return self

        import fcntl

        self._file = LOCK_PATH.open("a+", encoding="ascii")
        try:
            fcntl.flock(self._file.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            self._file.close()
            self._file = None
            raise RuntimeError("WiFi Agent is already running.") from exc
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
    """Resilient monitoring loop shared by console and Windows tray modes."""

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

    def current_snapshot(self) -> AgentSnapshot:
        with self._snapshot_lock:
            return AgentSnapshot(**asdict(self.snapshot))

    def _publish(self, **changes: Any) -> None:
        with self._snapshot_lock:
            for key, value in changes.items():
                setattr(self.snapshot, key, value)
            payload = asdict(self.snapshot)
        try:
            write_status(payload)
        except OSError as exc:
            self.logger.debug("Could not write status file: %s", exc)
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
            password = get_password(str(config["username"]))
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

    def _schedule_login_retry(self, config: dict[str, Any]) -> int:
        self._login_failures += 1
        base = max(30, int(config["check_interval_seconds"]))
        ceiling = int(config["login_backoff_max_seconds"])
        delay = min(ceiling, base * (2 ** min(self._login_failures - 1, 8)))
        delay = min(ceiling, max(30, int(delay * random.uniform(0.9, 1.1))))
        self._next_login_at = time.monotonic() + delay
        return delay

    def _reset_login_backoff(self) -> None:
        self._login_failures = 0
        self._next_login_at = 0.0

    def check_once(self) -> bool:
        if self.pause_event.is_set():
            self._publish(phase="paused", message="Monitoring paused", paused=True)
            return False

        try:
            config, client = self._load_client()
        except (OSError, RuntimeError, ValueError) as exc:
            message = str(exc)
            if message != self.snapshot.message:
                self.logger.warning("Configuration/credential problem: %s", message)
            self._publish(
                phase="needs-setup",
                message=message,
                ethernet_connected=False,
                interfaces=(),
                portal_port_open=None,
                internet_available=None,
                last_check_at=utc_now(),
            )
            return False

        interfaces = wired_interfaces(str(config["network_interface"]))
        ethernet = bool(interfaces)
        port_open = portal_port_open(client.host, client.port) if ethernet else None
        online = internet_available() if ethernet else None
        state = (tuple(interfaces), port_open, online)
        if state != self._last_logged_state:
            self.logger.info(
                "Status: ethernet=%s (%s), portal-port=%s, internet=%s",
                "connected" if ethernet else "disconnected",
                ", ".join(interfaces) if interfaces else "none",
                "open" if port_open is True else "closed/unreachable" if port_open is False else "not checked",
                "available" if online is True else "unavailable" if online is False else "not checked",
            )
            self._last_logged_state = state

        phase = "online" if online else "offline"
        message = "Internet available" if online else "Internet unavailable"
        retry_in = max(0, int(self._next_login_at - time.monotonic()))

        if ethernet and port_open and online:
            ok, keepalive_message = client.keep_alive()
            if ok:
                self._keepalive_failures = 0
                self._reset_login_backoff()
            else:
                self._keepalive_failures += 1
                session_expired = any(
                    word in keepalive_message.casefold()
                    for word in ("login", "fail", "nack", "expired", "denied", "invalid", "signed off", "logged off", "live_off", "off", "inactive")
                )
                if session_expired or self._keepalive_failures >= 2:
                    now = time.monotonic()
                    if now >= self._next_login_at:
                        self.logger.info(
                            "Portal keep-alive indicates session is inactive (%s); attempting portal login",
                            keepalive_message,
                        )
                        ok_login, login_msg = client.login()
                        if ok_login:
                            self.logger.info("Portal login accepted: %s", login_msg)
                            self._publish(last_login_at=utc_now())
                            self._keepalive_failures = 0
                            self._reset_login_backoff()
                            if not self.stop_event.wait(3):
                                online = internet_available()
                            phase = "online" if online else "offline"
                            message = "Login succeeded; session refreshed" if online else "Login accepted; verifying internet"
                        else:
                            delay = self._schedule_login_retry(config)
                            retry_in = delay
                            message = f"Portal re-login failed; retrying in {delay}s"
                            self.logger.warning("%s: %s", message, login_msg)
                    else:
                        phase = "backoff"
                        message = f"Waiting {retry_in}s before re-login"
                elif self._keepalive_failures == 1 or self._keepalive_failures % 5 == 0:
                    self.logger.warning("Portal keep-alive was not acknowledged: %s", keepalive_message)

        elif ethernet and port_open and not online:
            now = time.monotonic()
            if now >= self._next_login_at:
                self.logger.info("Ethernet and portal are reachable; attempting portal login")
                ok, login_message = client.login()
                if ok:
                    self.logger.info("Portal login accepted: %s", login_message)
                    self._publish(last_login_at=utc_now())
                    if not self.stop_event.wait(3):
                        online = internet_available()
                    if online:
                        self._reset_login_backoff()
                        phase = "online"
                        message = "Login succeeded; internet available"
                        self.logger.info("Internet became available after portal login")
                    else:
                        delay = self._schedule_login_retry(config)
                        retry_in = delay
                        message = f"Login accepted but internet is unavailable; retrying in {delay}s"
                        self.logger.warning(message)
                else:
                    delay = self._schedule_login_retry(config)
                    retry_in = delay
                    message = f"Login failed; retrying in {delay}s"
                    self.logger.warning("%s: %s", message, login_message)
            else:
                phase = "backoff"
                message = f"Waiting {retry_in}s before the next login attempt"
        elif ethernet and not port_open:
            message = "Ethernet connected; portal port is unreachable"
            self._reset_login_backoff()
        else:
            message = "Waiting for the selected Ethernet interface"
            self._reset_login_backoff()

        self._publish(
            phase=phase,
            message=message,
            ethernet_connected=ethernet,
            interfaces=tuple(interfaces),
            portal_port_open=port_open,
            internet_available=online,
            paused=False,
            last_check_at=utc_now(),
            consecutive_login_failures=self._login_failures,
            retry_in_seconds=retry_in,
        )
        return bool(online)

    def run(self, once: bool = False) -> int:
        self.logger.info("Agent monitor started")
        try:
            while not self.stop_event.is_set():
                try:
                    online = self.check_once()
                except Exception:
                    self.logger.exception("Unexpected monitor-cycle error; the agent will continue")
                    self._publish(phase="error", message="Unexpected monitoring error; see logs", last_check_at=utc_now())
                    online = False
                if once:
                    return 0 if online else 1
                interval = int((self._config or DEFAULT_CONFIG)["check_interval_seconds"])
                deadline = time.monotonic() + interval
                while not self.stop_event.is_set():
                    remaining = deadline - time.monotonic()
                    if remaining <= 0 or self.wake_event.wait(min(1.0, remaining)):
                        self.wake_event.clear()
                        break
                    if WAKE_PATH.exists():
                        try:
                            WAKE_PATH.unlink()
                        except OSError:
                            pass
                        break
        finally:
            self.logger.info("Agent monitor stopped")
        return 0


def run_agent(once: bool = False) -> int:
    ensure_dependencies()
    monitor = AgentMonitor()
    with SingleInstance():
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


def open_log_location() -> None:
    app_dir().mkdir(parents=True, exist_ok=True)
    target = LOG_PATH if LOG_PATH.exists() else app_dir()
    if sys.platform == "win32":
        os.startfile(str(target))  # type: ignore[attr-defined]
    elif sys.platform == "darwin":
        subprocess.Popen(["open", str(target)], start_new_session=True)
    else:
        subprocess.Popen(["xdg-open", str(target)], start_new_session=True)


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


def spawn_setup_window(pane: str | None = None) -> None:
    command = _application_command("setup")
    if pane:
        command.extend(["--pane", pane])
    subprocess.Popen(
        command,
        cwd=str(_application_working_directory()),
        start_new_session=True,
    )


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


def run_tray() -> int:
    if sys.platform not in {"win32", "darwin"}:
        raise RuntimeError("The menu-bar/tray interface is supported on macOS and Windows.")
    ensure_dependencies()
    try:
        import pystray
    except ImportError as exc:
        installer = "install.cmd" if sys.platform == "win32" else "./install.sh"
        raise RuntimeError(f"Menu-bar dependencies are missing. Run {installer} again.") from exc

    logger = build_logger(console=False)
    monitor_holder: dict[str, AgentMonitor] = {}
    icon_holder: dict[str, Any] = {}
    last_phase = {"value": ""}

    def on_status(snapshot: AgentSnapshot) -> None:
        icon = icon_holder.get("icon")
        if icon is None:
            return
        icon.title = f"WiFi Agent — {snapshot.message}"[:127]
        try:
            icon.update_menu()
        except Exception:
            pass
        if (
            snapshot.phase in {"needs-setup", "error"}
            and snapshot.phase != last_phase["value"]
            and getattr(icon, "HAS_NOTIFICATION", True)
        ):
            try:
                icon.notify(snapshot.message, "WiFi Agent needs attention")
            except Exception:
                pass
        last_phase["value"] = snapshot.phase

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
        pystray.MenuItem("View Diagnostics…", open_diagnostics),
        pystray.MenuItem("Open Logs…" if is_macos else "Open logs", open_logs),
        pystray.Menu.SEPARATOR,
        pystray.MenuItem("Quit WiFi Agent" if is_macos else "Exit until next login", quit_agent),
    )
    icon = pystray.Icon(APP_NAME, _tray_image(), "WiFi Agent — starting", menu)
    icon_holder["icon"] = icon

    with SingleInstance():
        worker = threading.Thread(target=monitor.run, name="wifi-agent-monitor", daemon=True)
        worker.start()
        try:
            icon.run()
        finally:
            monitor.stop()
            worker.join(timeout=15)
    return 0


def _service_command() -> list[str]:
    mode = "tray" if sys.platform in {"win32", "darwin"} else "run"
    return _application_command(mode)


def install_startup() -> str:
    if (
        sys.platform == "darwin"
        and getattr(sys, "frozen", False)
        and (
            str(Path(sys.executable).resolve()).startswith("/Volumes/")
            or Path(sys.executable).as_posix().startswith("/Volumes/")
            or any(part.casefold() == "volumes" for part in Path(sys.executable).parts)
        )
    ):
        raise RuntimeError(
            "Move WiFi Agent to the Applications folder before enabling Install at Login."
        )
    username = str(load_config().get("username", "")).strip()
    if not username:
        raise RuntimeError("Save credentials before installing the startup service.")
    # Refuse to install a service that is guaranteed to fail immediately.
    get_password(username)
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
        uid = getattr(os, "getuid", lambda: 501)()
        domain = f"gui/{uid}"
        subprocess.run(["launchctl", "bootout", domain, str(target)], capture_output=True)
        subprocess.run(["launchctl", "bootstrap", domain, str(target)], check=True, capture_output=True, text=True)
        return f"macOS LaunchAgent installed at {target} and started."

    target = Path.home() / ".config" / "systemd" / "user" / "wifi-agent.service"
    target.parent.mkdir(parents=True, exist_ok=True)
    quoted_command = " ".join(_systemd_quote(part) for part in command)
    target.write_text(
        "[Unit]\n"
        "Description=WiFi Agent captive-portal automation\n"
        "After=network-online.target\n\n"
        "[Service]\n"
        f"ExecStart={quoted_command}\n"
        "Restart=on-failure\n"
        "RestartSec=10\n\n"
        "[Install]\n"
        "WantedBy=default.target\n",
        encoding="utf-8",
    )
    subprocess.run(["systemctl", "--user", "daemon-reload"], check=True, capture_output=True, text=True)
    subprocess.run(["systemctl", "--user", "enable", target.name], check=True, capture_output=True, text=True)
    subprocess.run(["systemctl", "--user", "restart", target.name], check=True, capture_output=True, text=True)
    return f"Linux systemd user service installed at {target} and started."


def _systemd_quote(value: str) -> str:
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def startup_is_installed() -> bool:
    if sys.platform == "win32":
        return subprocess.run(
            ["schtasks", "/Query", "/TN", APP_NAME],
            capture_output=True, text=True, creationflags=WINDOWS_NO_WINDOW,
        ).returncode == 0
    if sys.platform == "darwin":
        return (Path.home() / "Library" / "LaunchAgents" / "com.local.wifi-agent.plist").exists()
    return (Path.home() / ".config" / "systemd" / "user" / "wifi-agent.service").exists()


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
        uid = getattr(os, "getuid", lambda: 501)()
        subprocess.run(["launchctl", "bootout", f"gui/{uid}", str(target)], capture_output=True)
        if target.exists():
            target.unlink()
        return "macOS LaunchAgent removed. Saved settings were kept."
    target = Path.home() / ".config" / "systemd" / "user" / "wifi-agent.service"
    subprocess.run(["systemctl", "--user", "disable", "--now", target.name], capture_output=True)
    if target.exists():
        target.unlink()
    subprocess.run(["systemctl", "--user", "daemon-reload"], capture_output=True)
    return "Linux systemd user service removed. Saved settings were kept."


def show_setup_ui(initial_pane: str | None = None) -> int:
    ensure_dependencies()
    try:
        import tkinter as tk
        from tkinter import messagebox, scrolledtext, ttk
    except ImportError:
        print("Tkinter is not installed. On Debian/Ubuntu, install python3-tk, then retry.", file=sys.stderr)
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
    ttk.Label(
        header,
        text="Sophos/Cyberoam connectivity monitoring, secure login, and service management",
        style="Subtitle.TLabel",
    ).pack(anchor="w", pady=(2, 0))

    notebook = ttk.Notebook(main)
    notebook.pack(fill="both", expand=True)
    overview_tab = ttk.Frame(notebook, style="App.TFrame", padding=(2, 16, 2, 2))
    settings_tab = ttk.Frame(notebook, style="App.TFrame", padding=(2, 16, 2, 2))
    diagnostics_tab = ttk.Frame(notebook, style="App.TFrame", padding=(2, 16, 2, 2))
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
    feedback_value = tk.StringVar(value="Settings are stored locally; the password remains in the OS credential vault.")
    feedback_override_until = {"value": 0.0}
    startup_installed = {"value": startup_is_installed()}
    agent_running = {"value": False}

    def startup_description(installed: bool) -> str:
        if is_macos:
            return "Available from the menu bar after login" if installed else "Not installed as a Login Item"
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
    metric_card(1, "Portal port", portal_value)
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

    # Settings tab.
    account_group = ttk.LabelFrame(settings_tab, text=" Account ", padding=14)
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
    ttk.Label(account_group, text="Leave blank to keep the saved credential.", style="Hint.TLabel").grid(
        row=2, column=1, columnspan=2, sticky="w", pady=(0, 2)
    )

    portal_group = ttk.LabelFrame(settings_tab, text=" Portal ", padding=14)
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

    monitor_group = ttk.LabelFrame(settings_tab, text=" Monitoring & retry ", padding=14)
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

    feedback = ttk.Frame(settings_tab, style="Surface.TFrame", padding=(12, 9))
    feedback.pack(fill="x", pady=(0, 10))
    ttk.Label(feedback, textvariable=feedback_value, style="StatusText.TLabel", wraplength=650).pack(anchor="w")
    settings_actions = ttk.Frame(settings_tab, style="App.TFrame")
    settings_actions.pack(fill="x")

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
                get_password(new_username)
            if new_password:
                store_credentials(new_username, new_password, str(config.get("username", "")))
            save_config(normalized)
            config.clear()
            config.update(normalized)
            password.set("")
            request_external_check()
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

    def run_background(work, on_success, title: str) -> None:
        set_busy(True)

        def worker() -> None:
            try:
                result = work()
                root.after(0, lambda: on_success(result))
            except Exception as exc:
                detail = exc.stderr.strip() if isinstance(exc, subprocess.CalledProcessError) and exc.stderr else str(exc)
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
            portal_value.set("Open" if open_ is True else "Unreachable" if open_ is False else "Not checked")
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
            f"Startup installed: {startup_installed['value']}",
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
    busy_buttons.extend([install_button, remove_button, check_button, test_button, save_button, save_install_button])

    remembered_pane = str(load_ui_state().get("last_pane", ""))
    requested_pane = (initial_pane or remembered_pane).casefold()
    if requested_pane in {"settings", "connection"}:
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
            portal_value.set("Open" if port_state is True else "Unreachable" if port_state is False else "Not checked")
            internet_state = snapshot.get("internet_available")
            internet_value.set("Available" if internet_state is True else "Unavailable" if internet_state is False else "Not checked")
            dot_color = (
                colors["success"] if phase == "online" else
                colors["warning"] if phase in {"offline", "backoff", "paused"} else
                colors["danger"] if phase in {"error", "needs-setup"} else
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
    if configuration_warning:
        root.after(100, lambda: messagebox.showwarning("Configuration needs repair", configuration_warning))

    root.mainloop()
    return 0


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
        print(f"Portal:   {'open' if port is True else 'unreachable' if port is False else 'not checked'}")
        online = snapshot.get("internet_available")
        print(f"Internet: {'available' if online is True else 'unavailable' if online is False else 'not checked'}")
    else:
        print("No agent status has been recorded yet.")

    if not json_output and log_lines > 0 and LOG_PATH.exists():
        print("\nRecent log entries:")
        lines = LOG_PATH.read_text(encoding="utf-8", errors="replace").splitlines()
        print("\n".join(lines[-log_lines:]))
    return 0 if snapshot else 1


def run_doctor() -> int:
    report: dict[str, Any] = {
        "python": sys.version.split()[0],
        "platform": sys.platform,
        "configuration_path": str(CONFIG_PATH),
        "log_path": str(LOG_PATH),
        "dependencies": {"keyring": keyring is not None, "psutil": psutil is not None},
        "startup_installed": startup_is_installed(),
    }
    healthy = bool(keyring is not None and psutil is not None)
    try:
        config = validate_config(load_config(), require_username=True)
        report["configuration"] = "valid"
        report["portal"] = f"{config['portal_scheme']}://{_portal_authority(str(config['portal_host']), int(config['portal_port']))}"
        report["selected_interface"] = config["network_interface"]
        if keyring is not None:
            ready, backend = credential_backend_ready()
            report["credential_vault"] = backend if ready else f"unavailable: {backend}"
            healthy = healthy and ready
            if ready:
                report["credential_saved"] = bool(keyring.get_password(KEYRING_SERVICE, str(config["username"])))
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
    report["last_status"] = read_status()
    report["healthy"] = healthy
    print(json.dumps(report, indent=2))
    return 0 if healthy else 1


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", action="version", version=f"{APP_DISPLAY_NAME} {APP_VERSION}")
    subparsers = parser.add_subparsers(dest="command")
    setup_parser = subparsers.add_parser("setup", help="open the credential/settings window")
    setup_parser.add_argument(
        "--pane",
        choices=("overview", "general", "settings", "connection", "diagnostics"),
        help="open a specific settings pane",
    )
    run_parser = subparsers.add_parser("run", help="run the background monitor")
    run_parser.add_argument("--once", action="store_true", help="perform one status/login cycle")
    subparsers.add_parser("tray", help="run the macOS menu-bar or Windows notification-area manager")
    subparsers.add_parser("check", help="ask a running agent to check immediately")
    subparsers.add_parser("install", help="install and start the per-user startup service")
    subparsers.add_parser("uninstall", help="remove the startup service (keep settings)")
    status_parser = subparsers.add_parser("status", help="show current state and recent logs")
    status_parser.add_argument("--json", action="store_true", help="print machine-readable status")
    status_parser.add_argument("--logs", type=int, default=10, help="number of recent log lines")
    subparsers.add_parser("doctor", help="validate configuration, vault, startup, and interfaces")
    subparsers.add_parser("open-logs", help="open the agent log location")
    args = parser.parse_args()

    try:
        if args.command in (None, "setup"):
            return show_setup_ui(getattr(args, "pane", None))
        if args.command == "run":
            return run_agent(args.once)
        if args.command == "tray":
            return run_tray()
        if args.command == "check":
            request_external_check()
            print("Immediate check requested. Use 'status' to view the result.")
            return 0
        if args.command == "install":
            print(install_startup())
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
    except (OSError, RuntimeError, ValueError, KeyringError, subprocess.CalledProcessError) as exc:
        detail = exc.stderr.strip() if isinstance(exc, subprocess.CalledProcessError) and exc.stderr else str(exc)
        if sys.stderr is not None:
            print(f"Error: {detail}", file=sys.stderr)
        elif getattr(sys, "frozen", False) and sys.platform in {"win32", "darwin"}:
            try:
                from tkinter import messagebox

                messagebox.showerror(APP_DISPLAY_NAME, detail)
            except Exception:
                pass
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
