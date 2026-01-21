#!/usr/bin/env python3

"""
Simple launcher that combines the existing attacks into one menu (Airgeddon style).
Each choice runs a separate script and returns to the menu when it exits.
"""

import os
import signal
import subprocess
import sys
from typing import Dict

COLOR_ENABLED = sys.stdout.isatty()
COLOR_RESET = "\033[0m" if COLOR_ENABLED else ""
COLOR_HEADER = "\033[36m" if COLOR_ENABLED else ""
COLOR_HIGHLIGHT = "\033[35m" if COLOR_ENABLED else ""
COLOR_SUCCESS = "\033[32m" if COLOR_ENABLED else ""
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
    "1": {"name": "Deauth", "file": os.path.join("modules", "deauth.py")},
    "2": {"name": "Portal", "file": os.path.join("modules", "portal.py")},
    "3": {"name": "Evil Twin", "file": os.path.join("modules", "twins.py")},
    "4": {"name": "Back", "file": ""},
}

RECON_MENU: Dict[str, Dict[str, str]] = {
    "1": {"name": "Wireless Recon", "file": os.path.join("modules", "recon.py")},
    "2": {"name": "Back", "file": ""},
}


def base_dir() -> str:
    return os.path.dirname(os.path.abspath(__file__))


def script_path(filename: str) -> str:
    return os.path.join(base_dir(), filename)


def print_header(title: str, menu: Dict[str, Dict[str, str]]) -> None:
    print(color_text(ASCII_HEADER, COLOR_HEADER))
    print(style(title, STYLE_BOLD))
    print()
    for key, meta in menu.items():
        label = f"[{key}] {meta['name']}"
        print(f"  {color_text(label, COLOR_HIGHLIGHT)}")
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


def recon_menu() -> None:
    while True:
        print_header("Recon:", RECON_MENU)
        choice = input(style("Your choice (1-2): ", STYLE_BOLD)).strip()

        if choice not in RECON_MENU:
            print(color_text("Invalid choice, try again.\n", COLOR_HIGHLIGHT))
            continue

        if choice == "2":
            break
        run_child(RECON_MENU[choice]["file"])


def attacks_menu() -> None:
    while True:
        print_header("Attacks:", ATTACKS_MENU)
        choice = input(style("Your choice (1-4): ", STYLE_BOLD)).strip()

        if choice not in ATTACKS_MENU:
            print(color_text("Invalid choice, try again.\n", COLOR_HIGHLIGHT))
            continue

        if choice == "4":
            break

        run_child(ATTACKS_MENU[choice]["file"])


def main() -> None:
    if os.geteuid() != 0:
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
            recon_menu()
            continue

        if choice == "2":
            attacks_menu()
            continue


if __name__ == "__main__":
    main()
