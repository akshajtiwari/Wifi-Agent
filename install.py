#!/usr/bin/env python3
"""Install/update the private runtime and dispatch a management command."""

from pathlib import Path
import hashlib
import os
import shutil
import subprocess
import sys
import venv


APP_NAME = "WiFiAgent"


def runtime_dir() -> Path:
    if sys.platform == "win32":
        base = Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local"))
    elif sys.platform == "darwin":
        base = Path.home() / "Library" / "Application Support"
    else:
        base = Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local" / "share"))
    return base / APP_NAME / "runtime"


def main() -> int:
    if sys.version_info < (3, 10):
        print("Python 3.10 or newer is required.", file=sys.stderr)
        return 2
    source = Path(__file__).resolve().parent
    runtime = runtime_dir()
    runtime.mkdir(parents=True, exist_ok=True)
    installed_script = runtime / "wifi_agent.py"
    installed_requirements = runtime / "requirements.txt"
    previous_code = installed_script.read_bytes() if installed_script.exists() else b""
    shutil.copy2(source / "wifi_agent.py", installed_script)
    shutil.copy2(source / "requirements.txt", installed_requirements)
    code_changed = previous_code != installed_script.read_bytes()

    environment = runtime / ".venv"
    if not environment.exists():
        print("Creating the local Python environment…")
        venv.EnvBuilder(with_pip=True).create(environment)
    if os.name == "nt":
        python = environment / "Scripts" / "python.exe"
    else:
        python = environment / "bin" / "python"
    requirement_hash = hashlib.sha256(installed_requirements.read_bytes()).hexdigest()
    marker = runtime / ".requirements-installed"
    if not marker.exists() or marker.read_text(encoding="ascii", errors="ignore") != requirement_hash:
        print("Installing/updating required packages…")
        subprocess.run(
            [str(python), "-m", "pip", "install", "--disable-pip-version-check", "-r", str(installed_requirements)],
            check=True,
        )
        marker.write_text(requirement_hash, encoding="ascii")

    command = sys.argv[1:] or ["setup"]
    if code_changed and previous_code and command[0] not in {"install", "uninstall"}:
        restart_running_agent()
    return subprocess.call([str(python), str(installed_script), *command])


def restart_running_agent() -> None:
    """Move an already-running background agent onto the updated code."""
    if sys.platform.startswith("linux"):
        unit = Path.home() / ".config" / "systemd" / "user" / "wifi-agent.service"
        if unit.exists() and shutil.which("systemctl"):
            print("Restarting the background service with the updated code…")
            subprocess.run(["systemctl", "--user", "try-restart", unit.name], check=False)
    elif sys.platform == "darwin":
        agent = Path.home() / "Library" / "LaunchAgents" / "com.local.wifi-agent.plist"
        if agent.exists():
            print("Restarting the menu-bar agent with the updated code…")
            subprocess.run(["launchctl", "kickstart", "-k", f"gui/{os.getuid()}/com.local.wifi-agent"], check=False)


if __name__ == "__main__":
    raise SystemExit(main())
