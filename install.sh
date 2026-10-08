#!/bin/sh
# Source installer for Linux and macOS. On Linux it first installs the
# system packages Python needs (venv and Tk) with the distribution's package
# manager, then builds the private runtime and runs a management command.
set -eu
cd "$(dirname "$0")"

run_as_root() {
    if [ "$(id -u)" -eq 0 ]; then
        "$@"
    elif command -v sudo >/dev/null 2>&1; then
        sudo "$@"
    else
        echo "Run as root: $*" >&2
        exit 1
    fi
}

install_linux_prerequisites() {
    if command -v python3 >/dev/null 2>&1 && python3 -c 'import ensurepip, tkinter, venv' >/dev/null 2>&1; then
        return 0
    fi
    ID=""
    ID_LIKE=""
    if [ -r /etc/os-release ]; then
        # shellcheck source=/dev/null
        . /etc/os-release
    fi
    case " $ID $ID_LIKE " in
        *" arch "*) manager=pacman packages="python tk" ;;
        *" debian "* | *" ubuntu "*) manager=apt packages="python3 python3-venv python3-tk" ;;
        *" fedora "* | *" rhel "*) manager=dnf packages="python3 python3-tkinter" ;;
        *" suse "* | *" opensuse "*) manager=zypper packages="python3 python3-tk" ;;
        *)
            echo "Install Python 3.10 or newer with its venv module and Tk, then run this again." >&2
            exit 1
            ;;
    esac
    echo "WiFi Agent needs these system packages: $packages"
    if [ -t 0 ]; then
        printf "Install them now with %s? [Y/n] " "$manager"
        read -r answer
        case "$answer" in
            [Nn]*) exit 1 ;;
        esac
    fi
    # shellcheck disable=SC2086 # package lists are intentionally split
    case "$manager" in
        pacman) run_as_root pacman -S --needed --noconfirm $packages ;;
        apt) run_as_root apt-get update && run_as_root apt-get install -y $packages ;;
        dnf) run_as_root dnf install -y $packages ;;
        zypper) run_as_root zypper --non-interactive install $packages ;;
    esac
}

if [ "$(uname -s)" = "Linux" ]; then
    install_linux_prerequisites
fi
exec python3 install.py "$@"
