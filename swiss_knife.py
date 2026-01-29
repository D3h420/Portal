#!/usr/bin/env python3

"""
Simple launcher that combines the existing attacks into one menu (Airgeddon style).
Each choice runs a separate script and returns to the menu when it exits.
"""

import os
import signal
import subprocess
import sys
import shutil
import platform
from typing import Dict, List

COLOR_ENABLED = sys.stdout.isatty()
COLOR_RESET = "\033[0m" if COLOR_ENABLED else ""
COLOR_HEADER = "\033[36m" if COLOR_ENABLED else ""
COLOR_HIGHLIGHT = "\033[35m" if COLOR_ENABLED else ""
COLOR_SUCCESS = "\033[32m" if COLOR_ENABLED else ""
COLOR_ERROR = "\033[31m" if COLOR_ENABLED else ""
COLOR_DIM = "\033[90m" if COLOR_ENABLED else ""
STYLE_BOLD = "\033[1m" if COLOR_ENABLED else ""


def color_text(text: str, color: str) -> str:
    return f"{color}{text}{COLOR_RESET}" if color else text


def style(text: str, *styles: str) -> str:
    prefix = "".join(s for s in styles if s)
    return f"{prefix}{text}{COLOR_RESET}" if prefix else text


ASCII_HEADER = r"""
██╗      █████╗ ██████╗ ███████╗
██║     ██╔══██╗██╔══██╗██╔════╝
██║     ███████║██████╔╝███████╗
██║     ██╔══██║██╔══██╗╚════██║
███████╗██║  ██║██████╔╝███████║
╚══════╝╚═╝  ╚═╝╚═════╝ ╚══════╝

wireless swiss knife
"""

MAIN_MENU: Dict[str, Dict[str, str]] = {
    "1": {"name": "Recon", "action": "recon"},
    "2": {"name": "Attacks", "action": "attacks"},
    "3": {"name": "Exit", "action": "exit"},
}

ATTACKS_MENU: Dict[str, Dict[str, str]] = {
    "basic": {"name": "-BASIC-", "separator": True},
    "1": {"name": "Deauth", "file": os.path.join("modules", "deauth.py")},
    "2": {"name": "Portal", "file": os.path.join("modules", "portal.py")},
    "3": {"name": "Evil Twin", "file": os.path.join("modules", "twins.py")},
    "4": {"name": "Handshaker (under construction)", "file": os.path.join("modules", "handshaker.py")},
    "5": {"name": "Karma (under construction)", "file": "", "disabled": True},
    "mitm": {"name": "-MITM-", "separator": True},
    "6": {"name": "HTTP Sniffer", "file": os.path.join("modules", "http_sniffer.py")},
    "7": {"name": "ARP Spoof", "file": os.path.join("modules", "arp_spoof.py")},
    "spacer": {"name": "", "separator": True},
    "8": {"name": "Back", "file": ""},
}

RECON_SCRIPT = os.path.join("modules", "recon.py")

REQUIRED_TOOLS: List[str] = [
    "iw",
    "ip",
    "ethtool",
    "aireplay-ng",
    "hostapd",
    "dnsmasq",
    "iptables",
]

PACKAGE_MAPS = {
    "apt": {
        "aireplay-ng": "aircrack-ng",
        "ip": "iproute2",
    },
    "apt-get": {
        "aireplay-ng": "aircrack-ng",
        "ip": "iproute2",
    },
    "dnf": {
        "aireplay-ng": "aircrack-ng",
        "ip": "iproute",
    },
    "yum": {
        "aireplay-ng": "aircrack-ng",
        "ip": "iproute",
    },
    "pacman": {
        "aireplay-ng": "aircrack-ng",
        "ip": "iproute2",
    },
    "zypper": {
        "aireplay-ng": "aircrack-ng",
        "ip": "iproute2",
    },
}


def base_dir() -> str:
    return os.path.dirname(os.path.abspath(__file__))


def print_banner() -> None:
    print(color_text(ASCII_HEADER, COLOR_HEADER))
    print()


def extended_path_env() -> str:
    extra_paths = ["/sbin", "/usr/sbin", "/usr/local/sbin"]
    env_path = os.environ.get("PATH", "")
    return os.pathsep.join([env_path, *extra_paths])


def tool_exists(tool: str) -> bool:
    return shutil.which(tool, path=extended_path_env()) is not None


def detect_package_manager() -> str:
    if platform.system() == "Darwin":
        return "brew" if shutil.which("brew") else ""

    for candidate in ["apt-get", "apt", "dnf", "yum", "pacman", "zypper", "apk"]:
        if shutil.which(candidate):
            return candidate
    return ""


def package_names(package_manager: str, tools: List[str]) -> List[str]:
    mapping = PACKAGE_MAPS.get(package_manager, {})
    resolved = []
    for tool in tools:
        package = mapping.get(tool, tool)
        if package not in resolved:
            resolved.append(package)
    return resolved


def install_missing_tools(missing: List[str]) -> bool:
    if platform.system() == "Darwin":
        print(color_text("Automatic installation is not supported on macOS. Please install the missing tools manually (e.g., via Homebrew).\n", COLOR_HIGHLIGHT))
        return False

    package_manager = detect_package_manager()
    if not package_manager:
        print(color_text("No supported package manager found; please install tools manually.\n", COLOR_HIGHLIGHT))
        return False

    packages = package_names(package_manager, missing)

    if package_manager in ("apt", "apt-get"):
        cmd = [package_manager, "install", "-y", *packages]
    elif package_manager in ("dnf", "yum"):
        cmd = [package_manager, "install", "-y", *packages]
    elif package_manager == "pacman":
        cmd = ["pacman", "-S", "--noconfirm", "--needed", *packages]
    elif package_manager == "zypper":
        cmd = ["zypper", "--non-interactive", "install", *packages]
    elif package_manager == "apk":
        cmd = ["apk", "add", *packages]
    else:
        print(color_text(f"Unsupported package manager '{package_manager}'. Please install tools manually.\n", COLOR_HIGHLIGHT))
        return False

    print(style(f"Installing missing tools via {package_manager}...", STYLE_BOLD))
    result = subprocess.run(cmd)
    if result.returncode != 0:
        print(color_text("Automatic installation failed. Please install the remaining tools manually.\n", COLOR_HIGHLIGHT))
        return False

    return True


def prompt_yes_no(message: str, default_yes: bool = True) -> bool:
    try:
        response = input(style(message, STYLE_BOLD)).strip().lower()
    except EOFError:
        return default_yes

    if not response:
        return default_yes
    return response in ("y", "yes")


def report_dependencies() -> List[str]:
    missing = []
    print_banner()
    print(style("Dependency check:", STYLE_BOLD))

    for tool in REQUIRED_TOOLS:
        if tool_exists(tool):
            status = color_text("OK", COLOR_SUCCESS)
        else:
            status = color_text("missing", COLOR_ERROR)
            missing.append(tool)
        print(f"- {tool.ljust(12)} {status}")

    print()
    return missing


def ensure_dependencies(is_root: bool) -> None:
    missing = report_dependencies()
    if not missing:
        print(color_text("All required tools are available.\n", COLOR_SUCCESS))
        return

    if not is_root:
        print(color_text("Run as root to allow automatic installation of missing tools.\n", COLOR_HIGHLIGHT))
        return

    if not prompt_yes_no("Install missing tools now? [Y/n]: "):
        print(color_text("Proceeding without installation may lead to runtime failures.\n", COLOR_HIGHLIGHT))
        return

    installed = install_missing_tools(missing)
    if installed:
        report_dependencies()
    else:
        print(color_text("Could not install all tools automatically. Please handle manually.\n", COLOR_HIGHLIGHT))


def script_path(filename: str) -> str:
    return os.path.join(base_dir(), filename)


def print_header(title: str, menu: Dict[str, Dict[str, str]]) -> None:
    print(color_text(ASCII_HEADER, COLOR_HEADER))
    print(style(title, STYLE_BOLD))
    print()
    for key, meta in menu.items():
        if meta.get("separator"):
            name = meta.get("name", "")
            if name:
                print(f"  {color_text(name, COLOR_DIM)}")
            else:
                print()
            continue
        label = f"[{key}] {meta['name']}"
        color = COLOR_DIM if meta.get("disabled") else meta.get("color", COLOR_HIGHLIGHT)
        print(f"  {color_text(label, color)}")
    print()


def run_child(script_file: str) -> None:
    abs_path = script_path(script_file)
    if not os.path.isfile(abs_path):
        print(color_text(f"File not found: {abs_path}", COLOR_HIGHLIGHT))
        return

    cmd = [sys.executable or "python3", abs_path]
    print(style(f"Starting {script_file}...\n", STYLE_BOLD))

    # Let the child handle its own Ctrl+C; the parent just waits.
    previous_handler = signal.signal(signal.SIGINT, signal.SIG_IGN)
    try:
        subprocess.run(cmd)
    finally:
        signal.signal(signal.SIGINT, previous_handler)
    print(style("\nDone. Press Enter to return to the menu.", STYLE_BOLD))
    try:
        input()
    except EOFError:
        pass


def attacks_menu() -> None:
    while True:
        print_header("Attacks:", ATTACKS_MENU)
        choice = input(style("Your choice (1-8): ", STYLE_BOLD)).strip()

        if choice not in ATTACKS_MENU or ATTACKS_MENU[choice].get("separator"):
            print(color_text("Invalid choice, try again.\n", COLOR_HIGHLIGHT))
            continue

        if choice == "8":
            break

        if ATTACKS_MENU[choice].get("disabled"):
            print(color_text("Coming soon.", COLOR_HIGHLIGHT))
            continue

        run_child(ATTACKS_MENU[choice]["file"])


def main() -> None:
    is_root = os.geteuid() == 0
    ensure_dependencies(is_root)

    if not is_root:
        print(color_text("This launcher must be run as root.", COLOR_HIGHLIGHT))
        sys.exit(1)

    while True:
        print_header("Main menu:", MAIN_MENU)
        choice = input(style("Your choice (1-3): ", STYLE_BOLD)).strip()

        if choice not in MAIN_MENU:
            print(color_text("Invalid choice, try again.\n", COLOR_HIGHLIGHT))
            continue

        if choice == "3":
            print(style("Exiting. See you!", COLOR_SUCCESS, STYLE_BOLD))
            break

        if choice == "1":
            run_child(RECON_SCRIPT)
            continue

        if choice == "2":
            attacks_menu()
            continue


if __name__ == "__main__":
    main()
