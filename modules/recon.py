#!/usr/bin/env python3

import os
import sys
import time
import subprocess
import threading
import logging
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Set, Tuple

logging.basicConfig(level=logging.INFO, format="%(message)s")

COLOR_ENABLED = sys.stdout.isatty()
COLOR_RESET = "\033[0m" if COLOR_ENABLED else ""
COLOR_HEADER = "\033[36m" if COLOR_ENABLED else ""
COLOR_HIGHLIGHT = "\033[35m" if COLOR_ENABLED else ""
COLOR_SUCCESS = "\033[32m" if COLOR_ENABLED else ""
COLOR_WARNING = "\033[33m" if COLOR_ENABLED else ""
STYLE_BOLD = "\033[1m" if COLOR_ENABLED else ""

MODULE_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(MODULE_DIR)
DEFAULT_VENDOR_DB = os.environ.get(
    "SWISSKNIFE_VENDOR_DB", os.path.join(MODULE_DIR, "oui.txt")
)
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
DEFAULT_LIVE_UPDATE_INTERVAL = 0.5

try:
    from scapy.all import Dot11, Dot11Beacon, Dot11Elt, Dot11ProbeReq, Dot11ProbeResp, sniff  # type: ignore
    SCAPY_AVAILABLE = True
except Exception:
    SCAPY_AVAILABLE = False


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


def is_monitor_mode(interface: str) -> bool:
    return get_interface_mode(interface) == "monitor"


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


def freq_to_channel(freq: float) -> Optional[int]:
    if 2412 <= freq <= 2472:
        return int((freq - 2407) // 5)
    if freq == 2484:
        return 14
    if 5000 <= freq <= 5825:
        return int((freq - 5000) // 5)
    return None


def channel_to_freq_mhz(channel: Optional[int]) -> Optional[int]:
    if channel is None:
        return None
    if channel == 14:
        return 2484
    if 1 <= channel <= 13:
        return 2407 + channel * 5
    if 32 <= channel <= 196:
        return 5000 + channel * 5
    return None


def parse_channel_value(text: str) -> Optional[int]:
    try:
        return int(text)
    except (TypeError, ValueError):
        return None


def parse_freq_value(text: str) -> Optional[float]:
    try:
        value = float(text)
    except (TypeError, ValueError):
        return None
    if value > 100000:
        value /= 1000.0
    return value


def normalize_mac_prefix(text: str) -> Optional[str]:
    if not text:
        return None
    cleaned = text.replace(":", "").replace("-", "").strip().upper()
    if len(cleaned) < 6:
        return None
    return cleaned[:6]


def load_vendor_db(path: str) -> Dict[str, str]:
    if not path or not os.path.isfile(path):
        return {}
    vendors: Dict[str, str] = {}
    with open(path, "r", encoding="utf-8", errors="ignore") as handle:
        for raw_line in handle:
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            if "|" in line:
                parts = [part.strip() for part in line.split("|")]
                if len(parts) >= 2:
                    prefix = normalize_mac_prefix(parts[0])
                    vendor = parts[1]
                else:
                    continue
            else:
                tokens = line.split(None, 1)
                prefix = normalize_mac_prefix(tokens[0]) if tokens else None
                vendor = tokens[1].strip() if len(tokens) > 1 else ""
            if prefix:
                vendors[prefix] = vendor
    return vendors


def lookup_vendor(mac_address: Optional[str], vendors: Dict[str, str]) -> Optional[str]:
    if not mac_address or not vendors:
        return None
    prefix = normalize_mac_prefix(mac_address)
    if not prefix:
        return None
    vendor = vendors.get(prefix)
    if vendor:
        return vendor
    return None


def shorten_vendor(vendor: Optional[str], max_len: int = 22) -> Optional[str]:
    if not vendor:
        return None
    cleaned = " ".join(vendor.split())
    if len(cleaned) <= max_len:
        return cleaned
    return cleaned[: max_len - 3].rstrip() + "..."


def finalize_encryption(privacy: bool, wpa: bool, wpa2: bool, wps: bool) -> str:
    if wpa2:
        encryption = "WPA2"
    elif wpa:
        encryption = "WPA"
    elif privacy:
        encryption = "WEP"
    else:
        encryption = "OPEN"
    if encryption != "WEP" and wps:
        encryption = f"{encryption}/WPS"
    return encryption


def scan_wireless_networks_iw(
    interface: str,
    duration_seconds: int = 15,
    show_progress: bool = False,
) -> List[Dict[str, Optional[str]]]:
    def run_scan() -> subprocess.CompletedProcess:
        return subprocess.run(
            ["iw", "dev", interface, "scan"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )

    end_time = time.time() + max(1, duration_seconds)
    networks: Dict[str, Dict[str, Optional[str]]] = {}
    last_remaining = None
    while time.time() < end_time:
        if show_progress and COLOR_ENABLED:
            remaining = max(0, int(end_time - time.time()))
            if remaining != last_remaining:
                last_remaining = remaining
                message = (
                    f"{style('Scanning', STYLE_BOLD)}... "
                    f"{style(str(remaining), COLOR_SUCCESS, STYLE_BOLD)}s remaining"
                )
                sys.stdout.write("\r" + message)
                sys.stdout.flush()
        try:
            result = run_scan()
        except FileNotFoundError:
            logging.error("Required tool 'iw' not found!")
            if show_progress and COLOR_ENABLED:
                sys.stdout.write("\n")
            return []

        if result.returncode != 0 and is_monitor_mode(interface):
            if set_interface_type(interface, "managed"):
                result = run_scan()
                if not set_interface_type(interface, "monitor"):
                    logging.error("Failed to restore monitor mode after scan.")

        if result.returncode != 0:
            logging.error("Wireless scan failed: %s", result.stderr.strip() or "unknown error")
            if show_progress and COLOR_ENABLED:
                sys.stdout.write("\n")
            return []

        current: Dict[str, Optional[str]] = {
            "bssid": None,
            "ssid": None,
            "signal": None,
            "channel": None,
            "encryption": None,
            "wps": None,
        }
        privacy = False
        wpa = False
        wpa2 = False
        wps = False

        def finalize_current() -> None:
            nonlocal current, privacy, wpa, wpa2, wps
            if current.get("bssid"):
                encryption = finalize_encryption(privacy, wpa, wpa2, wps)
                current["encryption"] = encryption
                current["wps"] = "yes" if wps else "no"
                existing = networks.get(current["bssid"])
                if existing is None or (
                    current.get("signal") is not None
                    and (existing.get("signal") is None or current["signal"] > existing["signal"])
                ):
                    networks[current["bssid"]] = current
            current = {
                "bssid": None,
                "ssid": None,
                "signal": None,
                "channel": None,
                "encryption": None,
                "wps": None,
            }
            privacy = False
            wpa = False
            wpa2 = False
            wps = False

        for raw_line in result.stdout.splitlines():
            line = raw_line.strip()
            if line.startswith("BSS "):
                finalize_current()
                current["bssid"] = line.split()[1].split("(")[0]
                continue
            if line.startswith("freq:"):
                parts = line.split()
                freq_val = parse_freq_value(parts[1]) if len(parts) > 1 else None
                current["channel"] = freq_to_channel(freq_val) if freq_val is not None else None
                continue
            if line.startswith("DS Parameter set:"):
                parts = line.split()
                if len(parts) >= 4 and parts[-2] == "channel":
                    channel_val = parse_channel_value(parts[-1])
                    if channel_val is not None:
                        current["channel"] = channel_val
                continue
            if line.startswith("* primary channel:"):
                parts = line.split(":")
                if len(parts) == 2:
                    channel_val = parse_channel_value(parts[1].strip())
                    if channel_val is not None:
                        current["channel"] = channel_val
                continue
            if line.startswith("signal:"):
                parts = line.split()
                try:
                    current["signal"] = float(parts[1])
                except (IndexError, ValueError):
                    current["signal"] = None
                continue
            if line.startswith("capability:") and "Privacy" in line:
                privacy = True
                continue
            if line.startswith("RSN:"):
                wpa2 = True
                continue
            if line.startswith("WPA:"):
                wpa = True
                continue
            if "WPS" in line:
                wps = True
                continue
            if line.startswith("SSID:"):
                ssid_val = line.split(":", 1)[1].strip()
                current["ssid"] = ssid_val if ssid_val else "<hidden>"
                continue

        finalize_current()

        time.sleep(0.2)

    if show_progress and COLOR_ENABLED:
        sys.stdout.write("\n")

    sorted_networks = sorted(
        networks.values(),
        key=lambda item: item["signal"] if item["signal"] is not None else -1000,
        reverse=True,
    )
    return sorted_networks


def display_iw_results(networks: List[Dict[str, Optional[str]]], vendors: Dict[str, str]) -> None:
    if not networks:
        logging.warning("No networks found.")
        return

    logging.info("")
    logging.info(style("Available networks:", STYLE_BOLD))
    for index, net in enumerate(networks, start=1):
        signal = f"{net['signal']:.1f} dBm" if net["signal"] is not None else "signal ?"
        channel = f"ch {net['channel']}" if net["channel"] else "ch ?"
        encryption = net.get("encryption") or "UNKNOWN"
        bssid = net.get("bssid") or "??"
        ssid = net.get("ssid") or "<hidden>"
        vendor = lookup_vendor(bssid, vendors)
        vendor_label = f" | {vendor}" if vendor else ""
        label = f"{index}) {ssid} ({bssid}) -"
        logging.info(
            "  %s %s | %s | %s%s",
            color_text(label, COLOR_HIGHLIGHT),
            channel,
            encryption,
            signal,
            vendor_label,
        )


def parse_channels(text: str) -> List[int]:
    if not text:
        return []
    text = text.strip()
    channels: List[int] = []
    for part in text.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            start_str, end_str = part.split("-", 1)
            try:
                start = int(start_str)
                end = int(end_str)
            except ValueError:
                continue
            for ch in range(min(start, end), max(start, end) + 1):
                channels.append(ch)
        else:
            try:
                channels.append(int(part))
            except ValueError:
                continue
    return sorted(set(channels))


def get_rssi(packet) -> Optional[int]:
    if hasattr(packet, "dBm_AntSignal"):
        try:
            return int(packet.dBm_AntSignal)
        except Exception:
            return None
    raw = getattr(packet, "notdecoded", None)
    if raw:
        try:
            return -(256 - max(raw[-4], raw[-2]))
        except Exception:
            return None
    return None


def rssi_to_quality(rssi: Optional[int]) -> Optional[int]:
    if rssi is None:
        return None
    if rssi >= -50:
        return 100
    value = 2 * (rssi + 100)
    if value < 0:
        return 0
    if value > 100:
        return 100
    return value


def extract_ssid(packet) -> Tuple[str, bool]:
    if not packet.haslayer(Dot11Elt):
        return "<hidden>", True
    elt = packet[Dot11Elt]
    while isinstance(elt, Dot11Elt):
        if elt.ID == 0:
            ssid_bytes = elt.info or b""
            if not ssid_bytes or b"\x00" in ssid_bytes:
                return "<hidden>", True
            try:
                return ssid_bytes.decode("utf-8"), False
            except UnicodeDecodeError:
                return "<non-printable>", False
        elt = elt.payload
    return "<hidden>", True


def extract_channel(packet) -> Optional[int]:
    if not packet.haslayer(Dot11Elt):
        return None
    elt = packet[Dot11Elt]
    while isinstance(elt, Dot11Elt):
        if elt.ID in (3, 61) and elt.info:
            try:
                return int(elt.info[0])
            except Exception:
                return None
        elt = elt.payload
    return None


def extract_encryption(packet) -> str:
    privacy = False
    wpa = False
    wpa2 = False
    wps = False
    if packet.haslayer(Dot11Beacon):
        cap_info = packet.sprintf("%Dot11Beacon.cap%")
    else:
        cap_info = packet.sprintf("%Dot11ProbeResp.cap%")
    if "privacy" in cap_info:
        privacy = True
    elt = packet[Dot11Elt] if packet.haslayer(Dot11Elt) else None
    while isinstance(elt, Dot11Elt):
        if elt.ID == 48:
            wpa2 = True
        elif elt.ID == 221 and elt.info.startswith(b"\x00P\xf2\x01\x01\x00"):
            wpa = True
        if elt.ID == 221 and elt.info.startswith(b"\x00P\xf2\x04"):
            wps = True
        elt = elt.payload
    return finalize_encryption(privacy, wpa, wpa2, wps)


def is_unicast(mac_address: Optional[str]) -> bool:
    if not mac_address:
        return False
    if mac_address.lower() == "ff:ff:ff:ff:ff:ff":
        return False
    try:
        first_octet = int(mac_address.split(":")[0], 16)
    except (ValueError, IndexError):
        return False
    return (first_octet & 1) == 0


@dataclass
class AccessPoint:
    ssid: str
    bssid: str
    channel: Optional[int]
    frequency: Optional[int]
    encryption: str
    rssi: Optional[int]
    signal: Optional[int]
    clients: Set[str] = field(default_factory=set)

    def update_signal(self, new_rssi: Optional[int]) -> None:
        new_signal = rssi_to_quality(new_rssi)
        if new_signal is None:
            return
        if self.signal is None or new_signal > self.signal + 5:
            self.signal = new_signal
            self.rssi = new_rssi


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


def scan_wireless_networks_scapy(
    interface: str,
    duration_seconds: int,
    channels: List[int],
    hop_interval: float,
    update_interval: float = DEFAULT_LIVE_UPDATE_INTERVAL,
    on_update: Optional[Callable[[Dict[str, "AccessPoint"], int], None]] = None,
) -> Dict[str, AccessPoint]:
    aps: Dict[str, AccessPoint] = {}
    aps_lock = threading.Lock()

    def handle_packet(packet) -> None:
        if not packet.haslayer(Dot11):
            return

        if packet.haslayer(Dot11Beacon) or packet.haslayer(Dot11ProbeResp):
            bssid = packet[Dot11].addr3
            if not bssid:
                return
            ssid, _hidden = extract_ssid(packet)
            channel = extract_channel(packet)
            frequency = channel_to_freq_mhz(channel)
            encryption = extract_encryption(packet)
            rssi = get_rssi(packet)
            signal = rssi_to_quality(rssi)

            with aps_lock:
                ap = aps.get(bssid)
                if ap is None:
                    aps[bssid] = AccessPoint(
                        ssid=ssid,
                        bssid=bssid,
                        channel=channel,
                        frequency=frequency,
                        encryption=encryption,
                        rssi=rssi,
                        signal=signal,
                    )
                else:
                    if ap.ssid == "<hidden>" and ssid != "<hidden>":
                        ap.ssid = ssid
                    if channel and not ap.channel:
                        ap.channel = channel
                    if frequency and not ap.frequency:
                        ap.frequency = frequency
                    if encryption and encryption != ap.encryption:
                        ap.encryption = encryption
                    ap.update_signal(rssi)

        sender = packet.addr2
        receiver = packet.addr1
        with aps_lock:
            if sender in aps and is_unicast(receiver):
                aps[sender].clients.add(receiver)
            if receiver in aps and is_unicast(sender):
                aps[receiver].clients.add(sender)

    stop_event = threading.Event()
    hopper_thread: Optional[threading.Thread] = None
    if channels:
        hopper_thread = threading.Thread(
            target=channel_hopper, args=(interface, channels, hop_interval, stop_event), daemon=True
        )
        hopper_thread.start()

    sniff_thread = threading.Thread(
        target=sniff,
        kwargs={"iface": interface, "prn": handle_packet, "store": False, "timeout": duration_seconds},
        daemon=True,
    )
    sniff_thread.start()

    end_time = time.time() + max(1, duration_seconds)
    while time.time() < end_time:
        if on_update:
            with aps_lock:
                snapshot = {
                    bssid: AccessPoint(
                        ssid=ap.ssid,
                        bssid=ap.bssid,
                        channel=ap.channel,
                        frequency=ap.frequency,
                        encryption=ap.encryption,
                        rssi=ap.rssi,
                        signal=ap.signal,
                        clients=set(ap.clients),
                    )
                    for bssid, ap in aps.items()
                }
            remaining = max(0, int(end_time - time.time()))
            on_update(snapshot, remaining)
        time.sleep(max(0.2, update_interval))

    sniff_thread.join(timeout=2)

    stop_event.set()
    if hopper_thread:
        hopper_thread.join(timeout=2)

    return aps


def format_scapy_results_lines(aps: Dict[str, AccessPoint], vendors: Dict[str, str]) -> List[str]:
    if not aps:
        return [color_text("No access points found.", COLOR_WARNING)]

    sorted_aps = sorted(
        aps.values(),
        key=lambda ap: ap.signal if ap.signal is not None else -1,
        reverse=True,
    )

    lines: List[str] = [style("Observed access points:", STYLE_BOLD)]
    for index, ap in enumerate(sorted_aps, start=1):
        channel = f"ch {ap.channel}" if ap.channel else "ch ?"
        rssi = f"{ap.rssi} dBm" if ap.rssi is not None else "rssi ?"
        clients = f"clients {len(ap.clients)}"
        vendor = shorten_vendor(lookup_vendor(ap.bssid, vendors))
        label = f"{index}) {ap.ssid} ({ap.bssid}) -"
        details = f"{channel} | {ap.encryption} | {rssi} | {clients}"
        if vendor:
            details += f" | {vendor}"
        lines.append(f"  {color_text(label, COLOR_HIGHLIGHT)} {details}")

    return lines


def display_scapy_results(aps: Dict[str, AccessPoint], vendors: Dict[str, str]) -> None:
    lines = format_scapy_results_lines(aps, vendors)
    logging.info("")
    for line in lines:
        logging.info("%s", line)


def display_scapy_live_update(
    aps: Dict[str, AccessPoint],
    vendors: Dict[str, str],
    remaining: int,
    interface: str,
) -> None:
    header = style(f"Scaner on {interface}", STYLE_BOLD)
    progress = (
        f"{style('Scanning', STYLE_BOLD)}... "
        f"{style(str(remaining), COLOR_SUCCESS, STYLE_BOLD)}s remaining"
    )
    lines = [header, progress, ""]
    lines.extend(format_scapy_results_lines(aps, vendors))
    output = "\n".join(lines)
    if COLOR_ENABLED:
        sys.stdout.write("\033[2J\033[H" + output + "\n")
    else:
        sys.stdout.write(output + "\n")
    sys.stdout.flush()


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


def prompt_float(prompt: str, default: float, minimum: float = 0.2) -> float:
    raw = input(prompt).strip()
    if not raw:
        return default
    try:
        value = float(raw)
    except ValueError:
        return default
    if value < minimum:
        return minimum
    return value


def format_client_list(clients: Set[str], max_items: int = 3) -> str:
    if not clients:
        return ""
    sorted_clients = sorted(clients)
    if len(sorted_clients) <= max_items:
        return ", ".join(sorted_clients)
    remaining = len(sorted_clients) - max_items
    shown = ", ".join(sorted_clients[:max_items])
    return f"{shown} +{remaining}"


def display_sniffer_live(packet_count: int, remaining: int, interface: str) -> None:
    header = style(f"Sniffer on {interface}", STYLE_BOLD)
    progress = (
        f"{style('Listening', STYLE_BOLD)}... "
        f"{style(str(remaining), COLOR_SUCCESS, STYLE_BOLD)}s remaining"
    )
    count_line = f"{style('Packets', STYLE_BOLD)}: {style(str(packet_count), COLOR_SUCCESS, STYLE_BOLD)}"
    output = "\n".join([header, progress, count_line])
    if COLOR_ENABLED:
        sys.stdout.write("\033[2J\033[H" + output + "\n")
    else:
        sys.stdout.write(output + "\n")
    sys.stdout.flush()


def format_sniffer_networks_lines(aps: Dict[str, AccessPoint], vendors: Dict[str, str]) -> List[str]:
    if not aps:
        return [color_text("No networks found.", COLOR_WARNING)]

    sorted_aps = sorted(
        aps.values(),
        key=lambda ap: (len(ap.clients), ap.signal if ap.signal is not None else -1),
        reverse=True,
    )

    lines: List[str] = [style("Observed networks:", STYLE_BOLD)]
    for index, ap in enumerate(sorted_aps, start=1):
        channel = f"ch {ap.channel}" if ap.channel else "ch ?"
        rssi = f"{ap.rssi} dBm" if ap.rssi is not None else "rssi ?"
        client_count = len(ap.clients)
        client_list = format_client_list(ap.clients)
        client_label = f"clients {client_count}"
        if client_list:
            client_label += f" ({client_list})"
        vendor = shorten_vendor(lookup_vendor(ap.bssid, vendors))
        label = f"{index}) {ap.ssid} ({ap.bssid}) -"
        details = f"{channel} | {ap.encryption} | {rssi} | {client_label}"
        if vendor:
            details += f" | {vendor}"
        lines.append(f"  {color_text(label, COLOR_HIGHLIGHT)} {details}")
    return lines


def format_probe_lines(probe_counts: Dict[str, int]) -> List[str]:
    if not probe_counts:
        return [color_text("No probe requests observed.", COLOR_WARNING)]

    lines: List[str] = [style("Observed probes:", STYLE_BOLD)]
    for ssid, count in sorted(probe_counts.items(), key=lambda item: item[1], reverse=True)[:10]:
        lines.append(f"  {color_text(ssid, COLOR_HIGHLIGHT)} - {count}")
    return lines


def run_sniffer(
    interface: str,
    duration_seconds: int,
    channels: Optional[List[int]] = None,
    hop_interval: float = DEFAULT_HOP_INTERVAL,
    update_interval: float = 1.0,
) -> Tuple[Dict[str, AccessPoint], Dict[str, int], int]:
    aps: Dict[str, AccessPoint] = {}
    probe_counts: Dict[str, int] = {}
    packet_count = 0
    aps_lock = threading.Lock()

    def handle_packet(packet) -> None:
        nonlocal packet_count
        with aps_lock:
            packet_count += 1

        if not packet.haslayer(Dot11):
            return

        if packet.haslayer(Dot11Beacon) or packet.haslayer(Dot11ProbeResp):
            bssid = packet[Dot11].addr3
            if not bssid:
                return
            ssid, _hidden = extract_ssid(packet)
            channel = extract_channel(packet)
            frequency = channel_to_freq_mhz(channel)
            encryption = extract_encryption(packet)
            rssi = get_rssi(packet)
            signal = rssi_to_quality(rssi)

            with aps_lock:
                ap = aps.get(bssid)
                if ap is None:
                    aps[bssid] = AccessPoint(
                        ssid=ssid,
                        bssid=bssid,
                        channel=channel,
                        frequency=frequency,
                        encryption=encryption,
                        rssi=rssi,
                        signal=signal,
                    )
                else:
                    if ap.ssid == "<hidden>" and ssid != "<hidden>":
                        ap.ssid = ssid
                    if channel and not ap.channel:
                        ap.channel = channel
                    if frequency and not ap.frequency:
                        ap.frequency = frequency
                    if encryption and encryption != ap.encryption:
                        ap.encryption = encryption
                    ap.update_signal(rssi)

        if packet.haslayer(Dot11ProbeReq):
            ssid, hidden = extract_ssid(packet)
            if not hidden and ssid not in ("<hidden>", "<non-printable>"):
                with aps_lock:
                    probe_counts[ssid] = probe_counts.get(ssid, 0) + 1

        sender = packet.addr2
        receiver = packet.addr1
        with aps_lock:
            if sender in aps and is_unicast(receiver):
                aps[sender].clients.add(receiver)
            if receiver in aps and is_unicast(sender):
                aps[receiver].clients.add(sender)

    sniff_thread = threading.Thread(
        target=sniff,
        kwargs={"iface": interface, "prn": handle_packet, "store": False, "timeout": duration_seconds},
        daemon=True,
    )
    stop_event = threading.Event()
    hopper_thread: Optional[threading.Thread] = None
    if channels:
        hopper_thread = threading.Thread(
            target=channel_hopper, args=(interface, channels, hop_interval, stop_event), daemon=True
        )
        hopper_thread.start()

    sniff_thread.start()

    end_time = time.time() + max(1, duration_seconds)
    while time.time() < end_time:
        with aps_lock:
            current_count = packet_count
        remaining = max(0, int(end_time - time.time()))
        display_sniffer_live(current_count, remaining, interface)
        time.sleep(max(0.2, update_interval))

    sniff_thread.join(timeout=2)
    stop_event.set()
    if hopper_thread:
        hopper_thread.join(timeout=2)

    return aps, probe_counts, packet_count


def recon_menu(vendors: Dict[str, str]) -> None:
    while True:
        logging.info("")
        logging.info(style("Recon menu:", STYLE_BOLD))
        if SCAPY_AVAILABLE:
            logging.info("  %s", color_text("[1] Scaner (scapy)", COLOR_HIGHLIGHT))
            logging.info("  %s", color_text("[2] Sniffer (scapy)", COLOR_HIGHLIGHT))
        else:
            logging.info("  %s", color_text("[1] Scaner (scapy) [missing]", COLOR_WARNING))
            logging.info("  %s", color_text("[2] Sniffer (scapy) [missing]", COLOR_WARNING))
        logging.info("  %s", color_text("[3] Back", COLOR_HIGHLIGHT))

        choice = input(style("Your choice (1-3): ", STYLE_BOLD)).strip()
        if choice == "3":
            return

        if choice == "1":
            if not SCAPY_AVAILABLE:
                logging.warning("Scapy is not installed. Install with: pip3 install scapy")
                continue

            interfaces = list_network_interfaces()
            interface = select_interface(interfaces)

            original_mode = get_interface_mode(interface)
            if original_mode != "monitor":
                logging.info("")
                input(f"{style('Press Enter', STYLE_BOLD)} to switch {interface} to monitor mode...")
                if not set_interface_type(interface, "monitor"):
                    logging.error("Failed to enable monitor mode on %s.", interface)
                    continue

            logging.info("")
            duration = prompt_int(
                f"{style('Scan duration', STYLE_BOLD)} in seconds "
                f"({style('Enter', STYLE_BOLD)} for {style('12', COLOR_SUCCESS, STYLE_BOLD)}): ",
                default=12,
            )

            logging.info("")
            input(f"{style('Press Enter', STYLE_BOLD)} to start scaner on {interface}...")
            live_update = lambda snapshot, remaining: display_scapy_live_update(
                snapshot, vendors, remaining, interface
            )
            aps = scan_wireless_networks_scapy(
                interface,
                duration,
                DEFAULT_MONITOR_CHANNELS,
                DEFAULT_HOP_INTERVAL,
                update_interval=DEFAULT_LIVE_UPDATE_INTERVAL,
                on_update=live_update,
            )
            display_scapy_results(aps, vendors)

            if original_mode and original_mode != "monitor":
                restore_managed_mode(interface)
            input(style("Press Enter to return.", STYLE_BOLD))
            continue

        if choice == "2":
            if not SCAPY_AVAILABLE:
                logging.warning("Scapy is not installed. Install with: pip3 install scapy")
                continue

            interfaces = list_network_interfaces()
            interface = select_interface(interfaces)

            original_mode = get_interface_mode(interface)
            if original_mode != "monitor":
                logging.info("")
                input(f"{style('Press Enter', STYLE_BOLD)} to switch {interface} to monitor mode...")
                if not set_interface_type(interface, "monitor"):
                    logging.error("Failed to enable monitor mode on %s.", interface)
                    continue

            logging.info("")
            duration = prompt_int(
                f"{style('Sniffer duration', STYLE_BOLD)} in seconds "
                f"({style('Enter', STYLE_BOLD)} for {style('15', COLOR_SUCCESS, STYLE_BOLD)}): ",
                default=15,
            )

            logging.info("")
            input(f"{style('Press Enter', STYLE_BOLD)} to start sniffer on {interface}...")
            aps, probes, packet_count = run_sniffer(
                interface,
                duration,
                channels=DEFAULT_MONITOR_CHANNELS,
                hop_interval=DEFAULT_HOP_INTERVAL,
            )

            logging.info("")
            logging.info(style(f"Total packets captured: {packet_count}", STYLE_BOLD))
            for line in format_sniffer_networks_lines(aps, vendors):
                logging.info("%s", line)
            logging.info("")
            for line in format_probe_lines(probes):
                logging.info("%s", line)

            if original_mode and original_mode != "monitor":
                restore_managed_mode(interface)
            input(style("Press Enter to return.", STYLE_BOLD))
            continue

        logging.warning("Invalid choice.")


def main() -> None:
    logging.info(color_text("Recon Toolkit", COLOR_HEADER))
    logging.info("Passive wireless discovery and inventory")
    logging.info("")

    if os.geteuid() != 0:
        logging.error("This script must be run as root!")
        sys.exit(1)

    required_tools = ["iw", "ip", "ethtool"]
    for tool in required_tools:
        if subprocess.run(["which", tool], stdout=subprocess.DEVNULL).returncode != 0:
            logging.error("Required tool '%s' not found!", tool)
            sys.exit(1)

    vendors = load_vendor_db(DEFAULT_VENDOR_DB)
    if not vendors:
        logging.info(
            "Vendor lookup: disabled (set SWISSKNIFE_VENDOR_DB or add data/oui.txt)."
        )
    else:
        logging.info("Vendor lookup: enabled (%d entries).", len(vendors))

    recon_menu(vendors)


if __name__ == "__main__":
    main()
