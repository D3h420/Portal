#!/usr/bin/env python3

import os
import sys
import time
import socket
import threading
import subprocess
import logging
from dataclasses import dataclass, field
from datetime import datetime
from collections import Counter, defaultdict
from getpass import getpass
from typing import Dict, List, Optional

logging.basicConfig(level=logging.INFO, format="%(message)s")

COLOR_ENABLED = sys.stdout.isatty()
COLOR_RESET = "\033[0m" if COLOR_ENABLED else ""
COLOR_HEADER = "\033[36m" if COLOR_ENABLED else ""
COLOR_HIGHLIGHT = "\033[35m" if COLOR_ENABLED else ""
COLOR_SUCCESS = "\033[32m" if COLOR_ENABLED else ""
COLOR_WARNING = "\033[33m" if COLOR_ENABLED else ""
COLOR_DIM = "\033[90m" if COLOR_ENABLED else ""
STYLE_BOLD = "\033[1m" if COLOR_ENABLED else ""

SCAN_BUSY_RETRY_DELAY = 0.8
SCAN_COMMAND_TIMEOUT = 4.0
DEFAULT_SCAN_SECONDS = 12

MODULE_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(MODULE_DIR)
LOG_DIR = os.path.join(PROJECT_ROOT, "log")

FILTER_SUFFIXES = (
    "local",
    "lan",
    "arpa",
    "in-addr.arpa",
)

try:
    from scapy.all import AsyncSniffer  # type: ignore
    from scapy.layers.dns import DNS, DNSQR  # type: ignore
    from scapy.layers.inet import IP  # type: ignore
    from scapy.layers.inet6 import IPv6  # type: ignore
    SCAPY_AVAILABLE = True
except Exception:
    SCAPY_AVAILABLE = False
    AsyncSniffer = None  # type: ignore
    DNS = DNSQR = IP = IPv6 = object  # type: ignore


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


def is_monitor_mode(interface: str) -> bool:
    result = subprocess.run(
        ["iw", "dev", interface, "info"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        return False
    for raw_line in result.stdout.splitlines():
        line = raw_line.strip()
        if line.startswith("type "):
            parts = line.split()
            return len(parts) >= 2 and parts[1] == "monitor"
    return False


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


def is_scan_busy_error(stderr: str) -> bool:
    if not stderr:
        return False
    lower = stderr.lower()
    return "resource busy" in lower or "device or resource busy" in lower or "(-16)" in lower


def scan_wireless_networks(
    interface: str,
    duration_seconds: int = DEFAULT_SCAN_SECONDS,
    show_progress: bool = False,
) -> List[Dict[str, Optional[str]]]:
    def run_scan(timeout_seconds: float) -> subprocess.CompletedProcess:
        return subprocess.run(
            ["iw", "dev", interface, "scan"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout_seconds,
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
            remaining_time = end_time - time.time()
            if remaining_time <= 0:
                break
            timeout_seconds = max(1.0, min(SCAN_COMMAND_TIMEOUT, remaining_time))
            result = run_scan(timeout_seconds)
        except FileNotFoundError:
            logging.error("Required tool 'iw' not found!")
            if show_progress and COLOR_ENABLED:
                sys.stdout.write("\n")
            return []
        except subprocess.TimeoutExpired:
            time.sleep(0.2)
            continue

        if result.returncode != 0 and is_monitor_mode(interface):
            if set_interface_type(interface, "managed"):
                remaining_time = end_time - time.time()
                if remaining_time <= 0:
                    break
                timeout_seconds = max(1.0, min(SCAN_COMMAND_TIMEOUT, remaining_time))
                result = run_scan(timeout_seconds)
                set_interface_type(interface, "monitor")

        if result.returncode != 0:
            err_text = result.stderr.strip()
            if is_scan_busy_error(err_text):
                time.sleep(SCAN_BUSY_RETRY_DELAY)
                continue
            logging.error("Wireless scan failed: %s", err_text or "unknown error")
            if show_progress and COLOR_ENABLED:
                sys.stdout.write("\n")
            return []

        current_signal: Optional[float] = None
        for raw_line in result.stdout.splitlines():
            line = raw_line.strip()
            if line.startswith("BSS "):
                current_signal = None
                continue
            if line.startswith("signal:"):
                parts = line.split()
                try:
                    current_signal = float(parts[1])
                except (IndexError, ValueError):
                    current_signal = None
                continue
            if line.startswith("SSID:"):
                ssid = line.split(":", 1)[1].strip()
                if not ssid:
                    continue
                existing = networks.get(ssid)
                if existing is None or (
                    current_signal is not None
                    and (existing.get("signal") is None or current_signal > existing["signal"])
                ):
                    networks[ssid] = {"ssid": ssid, "signal": current_signal}

        time.sleep(0.2)

    if show_progress and COLOR_ENABLED:
        sys.stdout.write("\n")

    return sorted(
        networks.values(),
        key=lambda item: item["signal"] if item["signal"] is not None else -1000,
        reverse=True,
    )


def prompt_manual_ssid() -> str:
    while True:
        manual = input(f"{style('Enter SSID', STYLE_BOLD)}: ").strip()
        if manual:
            return manual
        logging.warning("SSID cannot be empty.")


def select_network_ssid(interface: str, duration_seconds: int) -> str:
    while True:
        networks = scan_wireless_networks(interface, duration_seconds, show_progress=True)
        if not networks:
            logging.warning("No networks found during scan.")
            choice = input(
                f"{style('Rescan', STYLE_BOLD)} (R), "
                f"{style('Manual SSID', STYLE_BOLD)} (M), "
                f"or {style('Exit', STYLE_BOLD)} (E): "
            ).strip().lower()
            if choice == "r":
                continue
            if choice == "m":
                return prompt_manual_ssid()
            sys.exit(1)

        logging.info("")
        logging.info(style("Available networks:", STYLE_BOLD))
        for index, network in enumerate(networks, start=1):
            signal = (
                f"{network['signal']:.1f} dBm"
                if network["signal"] is not None
                else "signal unknown"
            )
            label = f"{index}) {network['ssid']} -"
            logging.info("  %s %s", color_text(label, COLOR_HIGHLIGHT), signal)

        choice = input(
            f"{style('Select network', STYLE_BOLD)} (number, R to rescan, M for manual): "
        ).strip().lower()
        if choice == "r":
            continue
        if choice == "m":
            return prompt_manual_ssid()
        if choice.isdigit():
            idx = int(choice)
            if 1 <= idx <= len(networks):
                return networks[idx - 1]["ssid"]
        logging.warning("Invalid selection. Try again.")


def prompt_password(ssid: str) -> str:
    while True:
        try:
            password = getpass(f"{style('Enter password', STYLE_BOLD)} for {ssid} (leave blank if open): ")
        except (EOFError, KeyboardInterrupt):
            return ""
        if password or password == "":
            return password


def normalize_domain(domain: str) -> str:
    return domain.strip().rstrip(".").lower()


def should_skip_domain(domain: str) -> bool:
    if not domain:
        return True
    for suffix in FILTER_SUFFIXES:
        if domain == suffix or domain.endswith(f".{suffix}"):
            return True
    return False


def resolve_device_name(ip_addr: str) -> str:
    try:
        hostname = socket.gethostbyaddr(ip_addr)[0]
        if hostname:
            return hostname.split(".")[0]
    except Exception:
        pass
    if ":" in ip_addr:
        return f"client_{ip_addr.split(':')[-1]}"
    if "." in ip_addr:
        return f"client_{ip_addr.split('.')[-1]}"
    return ip_addr


@dataclass
class DNSQuery:
    timestamp: str
    ip: str
    device: str
    domain: str


@dataclass
class DNSSniffState:
    queries: List[DNSQuery] = field(default_factory=list)
    device_names: Dict[str, str] = field(default_factory=dict)
    device_counts: Counter = field(default_factory=Counter)
    domain_counts: Counter = field(default_factory=Counter)


def show_live_header(interface: str, ssid: str) -> None:
    logging.info("")
    logging.info(style("DNS Sniff - Live View", STYLE_BOLD))
    logging.info("Interface: %s", style(interface, COLOR_SUCCESS, STYLE_BOLD))
    logging.info("Target SSID: %s", style(ssid, COLOR_SUCCESS, STYLE_BOLD))
    logging.info("%s", color_text("Press Enter to stop.", COLOR_DIM))
    logging.info("")


def handle_dns_packet(packet, state: DNSSniffState, state_lock: threading.Lock) -> None:
    try:
        if not packet.haslayer(DNSQR) or not packet.haslayer(DNS):
            return
        dns_layer = packet[DNS]
        if dns_layer.qr != 0:
            return
        domain_raw = packet[DNSQR].qname
        if not domain_raw:
            return
        domain = normalize_domain(domain_raw.decode("utf-8", errors="ignore"))
        if should_skip_domain(domain):
            return

        ip_addr = None
        if packet.haslayer(IP):
            ip_addr = packet[IP].src
        elif packet.haslayer(IPv6):
            ip_addr = packet[IPv6].src
        if not ip_addr:
            return

        with state_lock:
            device_name = state.device_names.get(ip_addr)
            if not device_name:
                device_name = resolve_device_name(ip_addr)
                state.device_names[ip_addr] = device_name

            device_label = f"{device_name} ({ip_addr})"
            timestamp = datetime.now().strftime("%H:%M:%S")
            state.queries.append(DNSQuery(timestamp=timestamp, ip=ip_addr, device=device_label, domain=domain))
            state.device_counts[device_label] += 1
            state.domain_counts[domain] += 1

        label = f"{device_label:30}"
        print(f"[{timestamp}] {label} -> {domain}", flush=True)
    except Exception:
        return


def run_dns_sniffer(interface: str, ssid: str) -> DNSSniffState:
    state = DNSSniffState()
    state_lock = threading.Lock()
    stop_event = threading.Event()

    def wait_for_stop() -> None:
        try:
            input()
        except EOFError:
            pass
        stop_event.set()

    stopper = threading.Thread(target=wait_for_stop, daemon=True)
    stopper.start()

    def packet_handler(packet) -> None:
        handle_dns_packet(packet, state, state_lock)

    show_live_header(interface, ssid)

    try:
        sniffer = AsyncSniffer(
            iface=interface,
            prn=packet_handler,
            store=False,
            filter="udp port 53 or tcp port 53",
        )
        sniffer.start()
    except Exception as exc:
        logging.warning("BPF filter failed (%s). Falling back to unfiltered capture.", exc)
        try:
            sniffer = AsyncSniffer(
                iface=interface,
                prn=packet_handler,
                store=False,
            )
            sniffer.start()
        except Exception as fallback_exc:
            logging.error("Failed to start sniffer: %s", fallback_exc)
            stop_event.set()
            return state

    while not stop_event.is_set():
        time.sleep(0.2)

    try:
        if sniffer and getattr(sniffer, "running", False):
            sniffer.stop()
    except Exception:
        pass

    stopper.join(timeout=1)
    return state


def show_summary(state: DNSSniffState, ssid: str) -> None:
    logging.info("")
    logging.info(style("DNS Sniff Summary", STYLE_BOLD))
    logging.info("Target SSID: %s", style(ssid, COLOR_SUCCESS, STYLE_BOLD))

    if not state.queries:
        logging.info("No DNS queries captured.")
        return

    device_data: Dict[str, List[str]] = defaultdict(list)
    for query in state.queries:
        device_data[query.device].append(query.domain)

    logging.info("Captured queries: %s", color_text(str(len(state.queries)), COLOR_SUCCESS))
    logging.info("Active devices: %s", color_text(str(len(device_data)), COLOR_SUCCESS))
    logging.info("")
    logging.info(style("Traffic by device:", STYLE_BOLD))

    for device, domains in sorted(device_data.items()):
        domain_counts = Counter(domains)
        top_domains = domain_counts.most_common(5)
        logging.info("  %s", color_text(device, COLOR_HIGHLIGHT))
        logging.info("    Queries: %d", len(domains))
        logging.info("    Unique domains: %d", len(set(domains)))
        if top_domains:
            logging.info("    Top domains:")
            for domain, count in top_domains:
                logging.info("      - %s (%dx)", domain, count)

    save_log(state, ssid)


def save_log(state: DNSSniffState, ssid: str) -> None:
    if not state.queries:
        return

    os.makedirs(LOG_DIR, exist_ok=True)
    filename = f"dns_sniff_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
    filepath = os.path.join(LOG_DIR, filename)

    with open(filepath, "w", encoding="utf-8") as log_file:
        log_file.write("DNS Sniff - Log\n")
        log_file.write("=" * 60 + "\n\n")
        log_file.write(f"Session time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        log_file.write(f"Target SSID: {ssid}\n")
        log_file.write(f"Total queries: {len(state.queries)}\n\n")
        for query in state.queries:
            log_file.write(f"[{query.timestamp}] {query.device:20} -> {query.domain}\n")

    logging.info("")
    logging.info("Log saved to: %s", color_text(filepath, COLOR_SUCCESS))


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


def run_dns_session() -> None:
    interfaces = list_network_interfaces()
    interface = select_interface(interfaces)

    logging.info("")
    while True:
        method = input(
            f"{style('SSID source', STYLE_BOLD)} - "
            f"{style('Scan', STYLE_BOLD)} (S) or {style('Manual', STYLE_BOLD)} (M): "
        ).strip().lower()
        if method in {"s", "scan", ""}:
            scan_seconds = prompt_int(
                f"{style('Scan duration', STYLE_BOLD)} in seconds "
                f"({style('Enter', STYLE_BOLD)} for {style(str(DEFAULT_SCAN_SECONDS), COLOR_SUCCESS, STYLE_BOLD)}): ",
                default=DEFAULT_SCAN_SECONDS,
            )
            input(f"{style('Press Enter', STYLE_BOLD)} to scan networks on {interface}...")
            ssid = select_network_ssid(interface, scan_seconds)
            break
        if method in {"m", "manual"}:
            ssid = prompt_manual_ssid()
            break
        logging.warning("Please enter S or M.")

    _password = prompt_password(ssid)
    del _password

    logging.info("")
    input(f"{style('Press Enter', STYLE_BOLD)} to start DNS sniffing on {interface}...")
    state = run_dns_sniffer(interface, ssid)
    show_summary(state, ssid)


def main() -> None:
    logging.info(color_text("DNS Sniff", COLOR_HEADER))
    logging.info("Live DNS visibility for local clients")
    logging.info("")

    if os.geteuid() != 0:
        logging.error("This script must be run as root!")
        sys.exit(1)

    if not SCAPY_AVAILABLE:
        logging.error("Scapy is not installed. Install with: pip3 install scapy")
        sys.exit(1)

    required_tools = ["iw", "ip", "ethtool"]
    missing = []
    for tool in required_tools:
        if subprocess.run(["which", tool], stdout=subprocess.DEVNULL).returncode != 0:
            missing.append(tool)

    if missing:
        logging.error("Missing required tools: %s", ", ".join(missing))
        sys.exit(1)

    try:
        run_dns_session()
    except KeyboardInterrupt:
        logging.info("\n")
        logging.info(color_text("Sniffer stopped by user.", COLOR_WARNING))


if __name__ == "__main__":
    main()
