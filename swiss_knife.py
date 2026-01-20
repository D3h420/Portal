#!/usr/bin/env python3

"""
Prosty launcher łączący trzy istniejące ataki w jedno menu (styl Airgeddon).
Każdy wybór odpala osobny skrypt i po jego zakończeniu wraca do menu.
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
   ___       __         __            __
  / _ )___  / /__ _____/ /_____ _____/ /__
 / _  / _ \/ / _ `/ __/  '_/ -_) __/  '_/
/____/\___/_/\_,_/\__/_/\_\\__/_/ /_/\_\

   WiFi Swiss Knife
"""

SCRIPT_MAP: Dict[str, Dict[str, str]] = {
    "1": {"name": "Deauth", "file": "deauth.py", "desc": "Ciągły deauth na wybraną sieć"},
    "2": {"name": "Portal", "file": "portal.py", "desc": "Captive portal z fałszywym AP"},
    "3": {"name": "Evil Twin", "file": "twins.py", "desc": "Evil twin + deauth + harvest"},
    "4": {"name": "Exit", "file": "", "desc": "Zakończ działanie menu"},
}


def base_dir() -> str:
    return os.path.dirname(os.path.abspath(__file__))


def script_path(filename: str) -> str:
    return os.path.join(base_dir(), filename)


def print_header() -> None:
    print(color_text(ASCII_HEADER, COLOR_HEADER))
    print(style("Wybierz atak do uruchomienia:", STYLE_BOLD))
    print()
    for key, meta in SCRIPT_MAP.items():
        label = f"[{key}] {meta['name']}"
        print(f"  {color_text(label, COLOR_HIGHLIGHT)} - {meta['desc']}")
    print()


def run_child(script_file: str) -> None:
    abs_path = script_path(script_file)
    if not os.path.isfile(abs_path):
        print(color_text(f"Nie znaleziono pliku: {abs_path}", COLOR_HIGHLIGHT))
        return

    cmd = [sys.executable or "python3", abs_path]
    print(style(f"Uruchamiam {script_file}...\n", STYLE_BOLD))

    # Pozwól dziecku obsłużyć własne Ctrl+C; rodzic po prostu czeka.
    previous_handler = signal.signal(signal.SIGINT, signal.SIG_IGN)
    try:
        subprocess.run(cmd)
    finally:
        signal.signal(signal.SIGINT, previous_handler)
    print(style("\nZakończono. Naciśnij Enter, aby wrócić do menu.", STYLE_BOLD))
    try:
        input()
    except EOFError:
        pass


def main() -> None:
    if os.geteuid() != 0:
        print(color_text("Ten launcher wymaga uruchomienia jako root.", COLOR_HIGHLIGHT))
        sys.exit(1)

    while True:
        print_header()
        choice = input(style("Twój wybór (1-4): ", STYLE_BOLD)).strip()

        if choice not in SCRIPT_MAP:
            print(color_text("Nieprawidłowy wybór, spróbuj ponownie.\n", COLOR_HIGHLIGHT))
            continue

        if choice == "4":
            print(style("Kończę pracę. Do zobaczenia!", COLOR_SUCCESS, STYLE_BOLD))
            break

        run_child(SCRIPT_MAP[choice]["file"])


if __name__ == "__main__":
    main()
