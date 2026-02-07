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
MONITOR_SETTLE_SECONDS = 2.0

try:
    from scapy.all import AsyncSniffer, Dot11, Dot11Beacon, Dot11Elt, Dot11ProbeResp  # type: ignore
    from scapy.error import Scapy_Exception  # type: ignore
    from scapy.layers.eap import EAPOL  # type: ignore
    from scapy.utils import PcapWriter  # type: ignore
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


def extract_channel(packet) -> Optional[int]:
    # Try to learn the AP's primary channel from beacon/probe response IEs.
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


def sanitize_filename_component(value: str, fallback: str = "unknown") -> str:
    cleaned = " ".join(value.split())
    cleaned = re.sub(r"\s+", "_", cleaned)
    cleaned = re.sub(r"[^A-Za-z0-9._-]", "", cleaned)
    if not cleaned:
        return fallback
    return cleaned[:48]


def set_interface_channel(interface: str, channel: int) -> bool:
    result = subprocess.run(
        ["iw", "dev", interface, "set", "channel", str(channel)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        logging.error("Failed to set channel %s: %s", channel, result.stderr.strip() or "unknown error")
        return False
    time.sleep(0.2)
    return True


def packet_matches_bssid(packet, bssid: str) -> bool:
    if not packet.haslayer(Dot11):
        return False
    dot11 = packet[Dot11]
    return bssid in (dot11.addr1, dot11.addr2, dot11.addr3)


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
    channel: Optional[int] = None
    clients: Set[str] = field(default_factory=set)

    def update_security(self, new_security: str) -> None:
        priority = {"OPEN": 0, "WEP": 1, "WPA": 2, "WPA2": 3, "WPA3": 4}
        if priority.get(new_security, -1) > priority.get(self.security, -1):
            self.security = new_security

    def update_channel(self, new_channel: Optional[int]) -> None:
        if new_channel is None:
            return
        if self.channel is None:
            self.channel = new_channel


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

        # Beacons / probe responses announce AP presence and parameters.
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
                    aps[bssid] = AccessPoint(
                        ssid=ssid,
                        bssid=bssid,
                        security=security,
                        channel=channel,
                    )
                else:
                    if ap.ssid == "<hidden>" and ssid != "<hidden>":
                        ap.ssid = ssid
                    ap.update_security(security)
                    ap.update_channel(channel)

        # Infer clients by observing traffic to/from known BSSIDs.
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
        # Channel hopping increases discovery coverage during the scan.
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


def sorted_access_points(aps: Dict[str, AccessPoint]) -> List[AccessPoint]:
    return sorted(aps.values(), key=lambda ap: len(ap.clients), reverse=True)


def format_network_lines(sorted_aps: List[AccessPoint]) -> List[str]:
    if not sorted_aps:
        return [color_text("No networks found.", COLOR_ERROR)]

    lines: List[str] = [style("Observed networks (sorted by clients):", STYLE_BOLD)]
    for index, ap in enumerate(sorted_aps, start=1):
        if ap.security == "WPA2":
            color = COLOR_SUCCESS
        elif ap.security == "WPA3":
            color = COLOR_ERROR
        else:
            color = COLOR_DIM
        ssid_label = format_ssid(ap.ssid)
        channel_label = str(ap.channel) if ap.channel else "?"
        label = f"{index}) {ssid_label}"
        details = f"{ap.bssid} | ch {channel_label} | {ap.security} | clients {len(ap.clients)}"
        lines.append(f"  {color_text(label, color)} {details}")
    return lines


def select_access_point(sorted_aps: List[AccessPoint]) -> Optional[AccessPoint]:
    if not sorted_aps:
        return None
    while True:
        choice = input(
            f"{style('Select target AP', STYLE_BOLD)} (number, or 'q' to quit): "
        ).strip().lower()
        if choice in ("q", "quit", "exit"):
            return None
        if choice.isdigit():
            idx = int(choice)
            if 1 <= idx <= len(sorted_aps):
                return sorted_aps[idx - 1]
        logging.warning("Invalid selection. Try again.")


def display_capture_live(
    interface: str,
    ap: AccessPoint,
    elapsed: int,
    duration: int,
    total_packets: int,
    eapol_packets: int,
    target_eapol_packets: int,
    status: str,
) -> None:
    if duration > 0:
        time_label = f"{elapsed}s / {duration}s"
    else:
        time_label = f"{elapsed}s / until Ctrl+C"

    lines = [
        f"Passive capture on {interface}",
        f"Target: {format_ssid(ap.ssid)} ({ap.bssid})",
        f"Channel: {ap.channel if ap.channel else 'unknown'}",
        f"Elapsed: {time_label}",
        f"Packets: {total_packets}",
        f"EAPOL (all): {eapol_packets}",
        f"EAPOL (target): {target_eapol_packets}",
        f"Status: {status.upper()}",
    ]
    output = build_box(lines)
    if COLOR_ENABLED:
        sys.stdout.write("\033[2J\033[H" + output + "\n")
    else:
        sys.stdout.write(output + "\n")
    sys.stdout.flush()


def capture_passive(
    interface: str,
    ap: AccessPoint,
    duration_seconds: int,
    output_dir: str,
) -> Optional[Dict[str, object]]:
    os.makedirs(output_dir, exist_ok=True)
    bssid_label = sanitize_filename_component(ap.bssid.replace(":", "-"), "unknown_bssid")
    ssid_label = sanitize_filename_component(ap.ssid, "hidden")
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_path = os.path.join(output_dir, f"handshake_{bssid_label}_{ssid_label}_{timestamp}.pcap")

    total_packets = 0
    eapol_packets = 0
    target_eapol_packets = 0
    stats_lock = threading.Lock()

    def handle_packet(packet) -> None:
        nonlocal total_packets, eapol_packets, target_eapol_packets
        if not packet.haslayer(Dot11):
            return
        # Write every observed 802.11 frame on the channel to the pcap file.
        try:
            writer.write(packet)
        except Exception as exc:
            logging.error("Failed to write packet: %s", exc)
        with stats_lock:
            total_packets += 1
            # Count EAPOL frames (WPA/WPA2 4-way handshake traffic).
            if packet.haslayer(EAPOL):
                eapol_packets += 1
                if packet_matches_bssid(packet, ap.bssid):
                    target_eapol_packets += 1

    writer: Optional[PcapWriter] = None
    sniffer: Optional[AsyncSniffer] = None
    try:
        writer = PcapWriter(output_path, append=False, sync=True)
    except Exception as exc:
        logging.error("Failed to open capture file: %s", exc)
        return None

    try:
        # Passive sniffing only; no packets are sent.
        sniffer = AsyncSniffer(iface=interface, prn=handle_packet, store=False)
        sniffer.start()
    except Exception as exc:
        logging.error("Failed to start passive capture: %s", exc)
        try:
            writer.close()
        except Exception:
            pass
        return None

    start_time = time.time()
    interrupted = False
    try:
        while True:
            elapsed = int(time.time() - start_time)
            done = duration_seconds > 0 and elapsed >= duration_seconds
            status = "finished" if done else "running"
            with stats_lock:
                total = total_packets
                eapol = eapol_packets
                target_eapol = target_eapol_packets
            display_capture_live(
                interface=interface,
                ap=ap,
                elapsed=elapsed,
                duration=duration_seconds,
                total_packets=total,
                eapol_packets=eapol,
                target_eapol_packets=target_eapol,
                status=status,
            )
            if done:
                break
            time.sleep(1)
    except KeyboardInterrupt:
        interrupted = True
    finally:
        try:
            if sniffer and getattr(sniffer, "running", False):
                sniffer.stop()
        except Scapy_Exception:
            pass
        try:
            if writer:
                writer.close()
        except Exception:
            pass

    with stats_lock:
        summary = {
            "path": output_path,
            "total_packets": total_packets,
            "eapol_packets": eapol_packets,
            "target_eapol_packets": target_eapol_packets,
            "elapsed": int(time.time() - start_time),
            "interrupted": interrupted,
        }
    return summary


def main() -> None:
    logging.info(color_text("Handshaker", COLOR_HEADER))
    logging.info("Passive Wi-Fi scan and handshake capture (educational)")
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
        "This tool is 100% passive and only observes Wi-Fi traffic."
    )
    logging.info(
        "Use it only on networks you own or have explicit permission to monitor."
    )

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

        sorted_aps = sorted_access_points(aps)
        logging.info("")
        for line in format_network_lines(sorted_aps):
            logging.info("%s", line)

        if not sorted_aps:
            logging.info("")
            logging.info("No networks discovered. Exiting.")
            return

        logging.info("")
        target_ap = select_access_point(sorted_aps)
        if target_ap is None:
            logging.info("No target selected. Exiting.")
            return

        if target_ap.channel:
            logging.info(
                "Locking interface %s to channel %s for passive capture.", interface, target_ap.channel
            )
            if not set_interface_channel(interface, target_ap.channel):
                logging.warning("Could not lock to channel %s. Continuing anyway.", target_ap.channel)
        else:
            logging.warning(
                "Channel for selected AP is unknown. Capture will remain on the current channel."
            )

        logging.info("")
        capture_duration = prompt_int(
            f"{style('Capture duration', STYLE_BOLD)} in seconds "
            f"({style('Enter', STYLE_BOLD)} for {style('60', COLOR_SUCCESS, STYLE_BOLD)}, "
            f"{style('0', COLOR_SUCCESS, STYLE_BOLD)} = until Ctrl+C): ",
            default=60,
            minimum=0,
        )
        logging.info("")
        input(f"{style('Press Enter', STYLE_BOLD)} to start passive capture...")
        logging.info(
            "Capturing passively. Handshakes appear only when clients reconnect naturally."
        )

        output_dir = os.path.join(os.getcwd(), "logs", "handshakes")
        summary = capture_passive(
            interface=interface,
            ap=target_ap,
            duration_seconds=capture_duration,
            output_dir=output_dir,
        )

        if summary is None:
            logging.error("Capture failed.")
            return

        logging.info("")
        logging.info(style("Capture summary:", STYLE_BOLD))
        logging.info("  File:   %s", summary["path"])
        logging.info("  Total packets: %s", summary["total_packets"])
        logging.info("  EAPOL packets (all): %s", summary["eapol_packets"])
        logging.info("  EAPOL packets (target): %s", summary["target_eapol_packets"])
        if summary["interrupted"]:
            logging.info("  Note: capture interrupted by user.")
        logging.info("")
        logging.info(
            "Open the capture in Wireshark and filter for 'eapol' to inspect 4-way handshakes."
        )
    finally:
        if changed_to_monitor or (original_mode and original_mode != "monitor"):
            restore_managed_mode(interface)

    input(style("Press Enter to return.", STYLE_BOLD))


if __name__ == "__main__":
    main()
