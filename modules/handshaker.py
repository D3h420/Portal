#!/usr/bin/env python3

import os
import sys
import time
import subprocess
import threading
import logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set

logging.basicConfig(level=logging.INFO, format="%(message)s")

COLOR_ENABLED = sys.stdout.isatty()
COLOR_RESET = "\033[0m" if COLOR_ENABLED else ""
COLOR_HEADER = "\033[36m" if COLOR_ENABLED else ""
COLOR_HIGHLIGHT = "\033[35m" if COLOR_ENABLED else ""
COLOR_SUCCESS = "\033[32m" if COLOR_ENABLED else ""
COLOR_ERROR = "\033[31m" if COLOR_ENABLED else ""
COLOR_DIM = "\033[90m" if COLOR_ENABLED else ""
STYLE_BOLD = "\033[1m" if COLOR_ENABLED else ""

DEFAULT_MONITOR_CHANNELS = (
    list(range(1, 15))
    + [
        36,
        40,
        44,
        48,
        52,
        56,
        60,
        64,
        100,
        104,
        108,
        112,
        116,
        120,
        124,
        128,
        132,
        136,
        140,
        144,
        149,
        153,
        157,
        161,
        165,
    ]
)
DEFAULT_HOP_INTERVAL = 0.8
DEFAULT_UPDATE_INTERVAL = 0.5

try:
    from scapy.all import AsyncSniffer, Dot11, Dot11Beacon, Dot11Elt, Dot11ProbeResp  # type: ignore
    from scapy.error import Scapy_Exception  # type: ignore
    SCAPY_AVAILABLE = True
except Exception:
    SCAPY_AVAILABLE = False
    Scapy_Exception = Exception  # type: ignore


def color_text(text: str, color: str) -> str:
    return f"{color}{text}{COLOR_RESET}" if color else text


def style(text: str, *styles: str) -> str:
    prefix = "".join(s for s in styles if s)
    return f"{prefix}{text}{COLOR_RESET}" if prefix else text


def list_network_interfaces() -> List[str]:
    interfaces: List[str] = []
    ip_link = subprocess.run(["ip", "-o", "link", "show"], stdout=subprocess.PIPE, text=True, check=False)
    for line in ip_link.stdout.splitlines():
        if ": " in line:
            name = line.split(": ", 1)[1].split(":", 1)[0]
            if name and name != "lo":
                interfaces.append(name)
    return interfaces


def get_interface_chipset(interface: str) -> str:
    try:
        result = subprocess.run(
            ["ethtool", "-i", interface],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            check=False,
        )
    except FileNotFoundError:
        return "unknown"

    if result.returncode != 0:
        return "unknown"

    driver = None
    bus_info = None
    for line in result.stdout.splitlines():
        if line.startswith("driver:"):
            driver = line.split(":", 1)[1].strip()
        if line.startswith("bus-info:"):
            bus_info = line.split(":", 1)[1].strip()

    if driver and bus_info and bus_info != "":
        return f"{driver} ({bus_info})"
    if driver:
        return driver
    return "unknown"


def select_interface(interfaces: List[str]) -> str:
    if not interfaces:
        logging.error("No network interfaces found.")
        sys.exit(1)

    logging.info("")
    logging.info(style("Available interfaces:", STYLE_BOLD))
    for index, name in enumerate(interfaces, start=1):
        chipset = get_interface_chipset(name)
        label = f"{index}) {name} -"
        logging.info("  %s %s", color_text(label, COLOR_HIGHLIGHT), chipset)

    while True:
        choice = input(f"{style('Select interface', STYLE_BOLD)} (number or name): ").strip()
        if not choice:
            logging.warning("Please select an interface.")
            continue
        if choice.isdigit():
            idx = int(choice)
            if 1 <= idx <= len(interfaces):
                return interfaces[idx - 1]
        if choice in interfaces:
            return choice
        logging.warning("Invalid selection. Try again.")


def get_interface_mode(interface: str) -> Optional[str]:
    result = subprocess.run(
        ["iw", "dev", interface, "info"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        return None
    for raw_line in result.stdout.splitlines():
        line = raw_line.strip()
        if line.startswith("type "):
            parts = line.split()
            if len(parts) >= 2:
                return parts[1]
    return None


def set_interface_type(interface: str, mode: str) -> bool:
    try:
        subprocess.run(["ip", "link", "set", interface, "down"], check=False, stderr=subprocess.DEVNULL)
        result = subprocess.run(
            ["iw", "dev", interface, "set", "type", mode],
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        if result.returncode != 0:
            logging.error("Failed to set %s mode: %s", mode, result.stderr.strip() or "unknown error")
            return False
        subprocess.run(["ip", "link", "set", interface, "up"], check=False, stderr=subprocess.DEVNULL)
        time.sleep(0.5)
        return True
    except Exception as exc:
        logging.error("Failed to set %s mode: %s", mode, exc)
        return False


def restore_managed_mode(interface: str) -> None:
    try:
        subprocess.run(["ip", "link", "set", interface, "down"], check=False, stderr=subprocess.DEVNULL)
        subprocess.run(["iw", "dev", interface, "set", "type", "managed"], check=False, stderr=subprocess.DEVNULL)
        subprocess.run(["ip", "link", "set", interface, "up"], check=False, stderr=subprocess.DEVNULL)
    except Exception:
        pass


def prompt_int(prompt: str, default: int, minimum: int = 1) -> int:
    raw = input(prompt).strip()
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError:
        return default
    if value < minimum:
        return minimum
    return value


def build_box(lines: List[str]) -> str:
    width = max(len(line) for line in lines)
    border = "+" + "-" * (width + 2) + "+"
    body = [f"| {line.ljust(width)} |" for line in lines]
    return "\n".join([border, *body, border])


def display_scan_live(
    networks: int,
    clients: int,
    interface: str,
    status: str,
    remaining: int,
) -> None:
    lines = [
        f"Handshaker scan on {interface}",
        f"Networks: {networks}",
        f"Clients:  {clients}",
        f"Status:   {status.upper()}",
        f"Time left: {remaining}s",
    ]
    output = build_box(lines)
    if COLOR_ENABLED:
        sys.stdout.write("\033[2J\033[H" + output + "\n")
    else:
        sys.stdout.write(output + "\n")
    sys.stdout.flush()


def format_ssid(ssid: str, max_len: int = 24) -> str:
    if not ssid:
        return "<hidden>"
    cleaned = " ".join(ssid.split())
    if not cleaned:
        return "<hidden>"
    if len(cleaned) <= max_len:
        return cleaned
    return cleaned[: max_len - 3].rstrip() + "..."


def extract_ssid(packet) -> str:
    if not packet.haslayer(Dot11Elt):
        return "<hidden>"
    elt = packet[Dot11Elt]
    while isinstance(elt, Dot11Elt):
        if elt.ID == 0:
            ssid_bytes = elt.info or b""
            if not ssid_bytes or b"\x00" in ssid_bytes:
                return "<hidden>"
            try:
                return ssid_bytes.decode("utf-8")
            except UnicodeDecodeError:
                return "<non-printable>"
        elt = elt.payload
    return "<hidden>"


def parse_rsn_akm_suites(info: bytes) -> List[int]:
    if len(info) < 8:
        return []
    idx = 0
    idx += 2
    idx += 4
    if idx + 2 > len(info):
        return []
    pairwise_count = int.from_bytes(info[idx:idx + 2], "little")
    idx += 2 + pairwise_count * 4
    if idx + 2 > len(info):
        return []
    akm_count = int.from_bytes(info[idx:idx + 2], "little")
    idx += 2
    akm_types: List[int] = []
    for _ in range(akm_count):
        if idx + 4 > len(info):
            break
        akm_types.append(info[idx + 3])
        idx += 4
    return akm_types


def extract_security(packet) -> str:
    privacy = False
    wpa = False
    rsn = False
    wpa3 = False
    if packet.haslayer(Dot11Beacon):
        cap_info = packet.sprintf("%Dot11Beacon.cap%")
    else:
        cap_info = packet.sprintf("%Dot11ProbeResp.cap%")
    if "privacy" in cap_info:
        privacy = True
    elt = packet[Dot11Elt] if packet.haslayer(Dot11Elt) else None
    while isinstance(elt, Dot11Elt):
        if elt.ID == 48:
            rsn = True
            akm_types = parse_rsn_akm_suites(elt.info or b"")
            if any(akm in (8, 9) for akm in akm_types):
                wpa3 = True
        elif elt.ID == 221 and elt.info.startswith(b"\x00P\xf2\x01\x01\x00"):
            wpa = True
        elt = elt.payload
    if rsn:
        return "WPA3" if wpa3 else "WPA2"
    if wpa:
        return "WPA"
    if privacy:
        return "WEP"
    return "OPEN"


def is_unicast(mac_address: Optional[str]) -> bool:
    if not is_valid_mac(mac_address):
        return False
    try:
        first_octet = int(mac_address.split(":")[0], 16)
    except (ValueError, IndexError):
        return False
    return (first_octet & 1) == 0


def is_valid_mac(mac_address: Optional[str]) -> bool:
    if not mac_address:
        return False
    lower = mac_address.lower()
    if lower in ("ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00"):
        return False
    if lower.startswith(("01:00:5e", "01:80:c2", "33:33")):
        return False
    if len(lower.split(":")) != 6:
        return False
    return True


@dataclass
class AccessPoint:
    ssid: str
    bssid: str
    security: str
    clients: Set[str] = field(default_factory=set)

    def update_security(self, new_security: str) -> None:
        priority = {"OPEN": 0, "WEP": 1, "WPA": 2, "WPA2": 3, "WPA3": 4}
        if priority.get(new_security, -1) > priority.get(self.security, -1):
            self.security = new_security


def channel_hopper(interface: str, channels: List[int], interval: float, stop_event: threading.Event) -> None:
    if not channels:
        return
    while not stop_event.is_set():
        for channel in channels:
            if stop_event.is_set():
                break
            subprocess.run(
                ["iw", "dev", interface, "set", "channel", str(channel)],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
            )
            time.sleep(interval)


def scan_networks(
    interface: str,
    duration_seconds: int,
    channels: List[int],
    hop_interval: float,
    update_interval: float,
) -> Dict[str, AccessPoint]:
    aps: Dict[str, AccessPoint] = {}
    aps_lock = threading.Lock()

    def handle_packet(packet) -> None:
        if not packet.haslayer(Dot11):
            return

        if packet.haslayer(Dot11Beacon) or packet.haslayer(Dot11ProbeResp):
            bssid = packet[Dot11].addr3
            if not bssid or not is_valid_mac(bssid):
                return
            ssid = extract_ssid(packet)
            security = extract_security(packet)
            with aps_lock:
                ap = aps.get(bssid)
                if ap is None:
                    aps[bssid] = AccessPoint(
                        ssid=ssid,
                        bssid=bssid,
                        security=security,
                    )
                else:
                    if ap.ssid == "<hidden>" and ssid != "<hidden>":
                        ap.ssid = ssid
                    ap.update_security(security)

        sender = packet.addr2
        receiver = packet.addr1
        with aps_lock:
            if sender in aps and is_unicast(receiver):
                aps[sender].clients.add(receiver)
            if receiver in aps and is_unicast(sender):
                aps[receiver].clients.add(sender)

    sniffer: Optional[AsyncSniffer] = None
    status = "starting"
    last_restart = 0.0
    last_error = ""
    restart_delay = 1.0

    def start_sniffer() -> None:
        nonlocal sniffer, status, last_restart, last_error
        now = time.time()
        if now - last_restart < restart_delay:
            status = "restarting"
            return
        last_restart = now
        try:
            sniffer = AsyncSniffer(iface=interface, prn=handle_packet, store=False)
            sniffer.start()
            status = "running"
        except Exception as exc:
            status = "error"
            error_text = str(exc)
            if error_text != last_error:
                logging.error("Sniffer failed to start: %s", exc)
                last_error = error_text
            sniffer = None

    start_sniffer()

    stop_event = threading.Event()
    hopper_thread: Optional[threading.Thread] = None
    if channels:
        hopper_thread = threading.Thread(
            target=channel_hopper, args=(interface, channels, hop_interval, stop_event), daemon=True
        )
        hopper_thread.start()

    end_time = time.time() + max(1, duration_seconds)
    while time.time() < end_time:
        if sniffer is None or not getattr(sniffer, "running", False):
            start_sniffer()
        with aps_lock:
            networks = len(aps)
            clients = sum(len(ap.clients) for ap in aps.values())
        remaining = max(0, int(end_time - time.time()))
        display_scan_live(networks, clients, interface, status, remaining)
        time.sleep(max(0.2, update_interval))

    stop_event.set()
    try:
        if sniffer and getattr(sniffer, "running", False):
            sniffer.stop()
    except Scapy_Exception:
        pass

    if hopper_thread:
        hopper_thread.join(timeout=2)

    return aps


def format_network_lines(aps: Dict[str, AccessPoint]) -> List[str]:
    if not aps:
        return [color_text("No networks found.", COLOR_ERROR)]

    def sort_key(ap: AccessPoint) -> int:
        return len(ap.clients)

    sorted_aps = sorted(aps.values(), key=sort_key, reverse=True)
    lines: List[str] = [style("Observed networks:", STYLE_BOLD)]
    for index, ap in enumerate(sorted_aps, start=1):
        if ap.security == "WPA2":
            color = COLOR_SUCCESS
        elif ap.security == "WPA3":
            color = COLOR_ERROR
        else:
            color = COLOR_DIM
        label = f"{index}) {format_ssid(ap.ssid)}"
        details = f"{ap.security} | clients {len(ap.clients)}"
        lines.append(f"  {color_text(label, color)} {details}")
    return lines


def main() -> None:
    logging.info(color_text("Handshaker", COLOR_HEADER))
    logging.info("Passive scan (attack under construction)")
    logging.info("")

    if os.geteuid() != 0:
        logging.error("This script must be run as root!")
        sys.exit(1)

    if not SCAPY_AVAILABLE:
        logging.error("Scapy is not installed. Install with: pip3 install scapy")
        sys.exit(1)

    required_tools = ["iw", "ip", "ethtool"]
    for tool in required_tools:
        if subprocess.run(["which", tool], stdout=subprocess.DEVNULL).returncode != 0:
            logging.error("Required tool '%s' not found!", tool)
            sys.exit(1)

    logging.info(style("Disclaimer:", STYLE_BOLD))
    logging.info(
        "Attack under construction. No deauth or handshake capture is performed."
    )

    interfaces = list_network_interfaces()
    interface = select_interface(interfaces)

    original_mode = get_interface_mode(interface)
    if original_mode != "monitor":
        logging.info("")
        input(f"{style('Press Enter', STYLE_BOLD)} to switch {interface} to monitor mode...")
        if not set_interface_type(interface, "monitor"):
            logging.error("Failed to enable monitor mode on %s.", interface)
            sys.exit(1)

    logging.info("")
    duration = prompt_int(
        f"{style('Scan duration', STYLE_BOLD)} in seconds "
        f"({style('Enter', STYLE_BOLD)} for {style('15', COLOR_SUCCESS, STYLE_BOLD)}): ",
        default=15,
    )
    logging.info("")
    input(f"{style('Press Enter', STYLE_BOLD)} to start scanning on {interface}...")
    aps = scan_networks(
        interface,
        duration,
        channels=DEFAULT_MONITOR_CHANNELS,
        hop_interval=DEFAULT_HOP_INTERVAL,
        update_interval=DEFAULT_UPDATE_INTERVAL,
    )

    logging.info("")
    for line in format_network_lines(aps):
        logging.info("%s", line)

    if original_mode and original_mode != "monitor":
        restore_managed_mode(interface)

    input(style("Press Enter to return.", STYLE_BOLD))


if __name__ == "__main__":
    main()
