#!/usr/bin/env python3
"""
Tor IP Suite - Streamlined Tool for Ethical Hacking
A comprehensive suite for anonymity, security testing, and network analysis through Tor
"""

import os
import sys
import time
import json
import signal
import random
import argparse
import platform
import subprocess
import threading
import socket
import re
import ssl
from datetime import datetime, timedelta
from urllib.parse import urlparse
from collections import Counter

VERSION = "3.5.0"

# ANSI colors for terminal output
COLORS = {
    "RED": "\033[91m",
    "GREEN": "\033[92m",
    "YELLOW": "\033[93m",
    "BLUE": "\033[94m",
    "PURPLE": "\033[95m",
    "CYAN": "\033[96m",
    "RESET": "\033[0m",
    "BOLD": "\033[1m",
}

# Handle dependencies
packages_missing = False
try:
    import requests
except ImportError:
    packages_missing = True
try:
    import stem
    from stem import Signal
    from stem.control import Controller
except ImportError:
    packages_missing = True

# Check for missing packages
if packages_missing:
    print(f"{COLORS['RED']}[!] Required packages are missing.{COLORS['RESET']}")
    print(f"{COLORS['YELLOW']}Please install the required packages using:{COLORS['RESET']}")
    print("\n    pip install requests stem PySocks\n")
    print("Or activate the virtual environment:")
    print(f"\n    source {os.path.join(os.path.dirname(os.path.abspath(__file__)), 'venv/bin/activate')}\n")
    sys.exit(1)

# Default port configurations
DEFAULT_SOCKS_PORT = 9050
DEFAULT_CTRL_PORT = 9051

# Path to store Tor password hash
TOR_PASSWORD_FILE = os.path.join(os.path.expanduser("~"), ".tor-password-hash")

# Paths
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(SCRIPT_DIR, "data")
IP_HISTORY_FILE = os.path.join(DATA_DIR, "ip_history.json")
SECURITY_REPORT_DIR = os.path.join(DATA_DIR, "security_reports")

# Create necessary directories
os.makedirs(DATA_DIR, exist_ok=True)
os.makedirs(SECURITY_REPORT_DIR, exist_ok=True)

# Import security tools
try:
    from tor_security_tools import perform_security_scan, scan_target_ports
    SECURITY_TOOLS_AVAILABLE = True
except ImportError:
    SECURITY_TOOLS_AVAILABLE = False

# Global variables
ip_changer_thread = None
ip_monitor_thread = None
security_scan_thread = None
stop_threads = False
current_ip = "Unknown"
ip_changes = 0
ip_history = []

#
# Utility Functions
#

def colorize(text, color):
    """Add color to terminal output"""
    if os.environ.get("NO_COLOR") or not sys.stdout.isatty():
        return text
    return f"{COLORS.get(color.upper(), '')}{text}{COLORS.get('RESET', '')}"

def info(message):
    """Print informational message"""
    print(colorize(f"[*] {message}", "BLUE"))

def success(message):
    """Print success message"""
    print(colorize(f"[+] {message}", "GREEN"))

def warning(message):
    """Print warning message"""
    print(colorize(f"[!] {message}", "YELLOW"))

def error(message):
    """Print error message"""
    print(colorize(f"[-] {message}", "RED"))

def setup_tor_password():
    """Set up Tor with password authentication"""
    # Generate a random password
    password = ''.join(random.choices('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789', k=16))
    
    try:
        # Generate password hash
        result = subprocess.run(
            ["tor", "--hash-password", password],
            capture_output=True,
            text=True,
            check=True
        )
        
        # Extract hash from output
        hash_lines = result.stdout.strip().split('\n')
        password_hash = next((line for line in hash_lines if line.startswith('16:')), None)
        
        if not password_hash:
            error("Failed to generate Tor password hash")
            return None, None
        
        # Save password and hash to file
        with open(TOR_PASSWORD_FILE, 'w') as f:
            f.write(f"HashedControlPassword {password_hash}\n")
            f.write(f"# Plaintext password (for script use only): {password}\n")
        
        os.chmod(TOR_PASSWORD_FILE, 0o600)  # Make file only readable by owner
        
        info(f"Tor password hash saved to {TOR_PASSWORD_FILE}")
        info("Add the 'HashedControlPassword' line to your torrc file")
        
        return password, password_hash
    except Exception as e:
        error(f"Error setting up Tor password: {e}")
        return None, None

def restart_tor_service():
    """Attempt to restart the Tor service"""
    try:
        if platform.system() == "Linux":
            warning("Attempting to restart Tor service")
            if os.path.exists("/bin/systemctl") or os.path.exists("/usr/bin/systemctl"):
                result = subprocess.run(
                    ["sudo", "systemctl", "restart", "tor"], 
                    capture_output=True, 
                    text=True
                )
                if result.returncode == 0:
                    success("Successfully restarted Tor service via systemctl")
                    time.sleep(5)  # Give Tor time to initialize
                    return True
            elif os.path.exists("/etc/init.d/tor"):
                result = subprocess.run(
                    ["sudo", "/etc/init.d/tor", "restart"], 
                    capture_output=True, 
                    text=True
                )
                if result.returncode == 0:
                    success("Successfully restarted Tor service via init.d")
                    time.sleep(5)
                    return True
            else:
                # Kill and restart Tor as a last resort
                subprocess.run(["sudo", "pkill", "tor"], capture_output=True)
                time.sleep(1)
                subprocess.Popen(["tor"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                time.sleep(7)  # Give more time to initialize
                return True
    except Exception as e:
        error(f"Failed to restart Tor service: {e}")
    return False

def clear_screen():
    """Clear the terminal screen"""
    os.system('cls' if os.name == 'nt' else 'clear')

def print_header(title):
    """Print a formatted header"""
    print(colorize("=" * 60, "CYAN"))
    print(colorize(f"  {title}", "BOLD"))
    print(colorize("=" * 60, "CYAN"))

def get_tor_session():
    """Create a requests session that routes through Tor"""
    session = requests.session()
    
    # Configure session with shorter timeouts
    session.proxies = {
        'http': f'socks5h://127.0.0.1:{DEFAULT_SOCKS_PORT}',
        'https': f'socks5h://127.0.0.1:{DEFAULT_SOCKS_PORT}'
    }
    
    # Configure shorter timeouts to avoid long hanging connections
    session.timeout = 5
    
    # Disable SSL verification if needed (only for testing)
    # session.verify = False
    
    return session

def is_tor_running():
    """Check if Tor is running and properly connected"""
    try:
        # First check if SOCKS port is open
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)  # 2 second timeout
        result = sock.connect_ex(('127.0.0.1', DEFAULT_SOCKS_PORT))
        sock.close()
        
        if result != 0:
            return False
            
        # Test connection with multiple sites
        with get_tor_session() as session:
            # Try multiple IP checking services with shorter timeouts
            services = [
                "https://api.ipify.org",
                "https://icanhazip.com",
                "https://ident.me",
                "https://check.torproject.org"
            ]
            
            for service in services:
                try:
                    response = session.get(service, timeout=5)  # Shorter timeout
                    if response.status_code == 200:
                        # If we get a response from any service, Tor is working
                        if service == "https://check.torproject.org" and "Congratulations" in response.text:
                            success("Confirmed Tor connection via check.torproject.org")
                            return True
                        elif service != "https://check.torproject.org":
                            # We got a response from an IP service, which is good enough
                            success(f"Confirmed Tor connection via {service}")
                            return True
                except Exception as e:
                    warning(f"Failed to connect to {service}: {str(e)}")
                    continue
            
            # If we've tried all services and none worked, check if we can at least get an IP
            try:
                ip = get_current_ip()
                if ip and ip != "Unknown":
                    success(f"Confirmed Tor connection (IP: {ip})")
                    return True
            except Exception:
                pass
                
            warning("Connected to Tor proxy but could not confirm external connectivity")
            return False
    except Exception as e:
        warning(f"Tor check error: {str(e)}")
        return False

#
# Tor IP Management
#

def get_current_ip():
    """Get current IP address through Tor"""
    global current_ip
    
    try:
        with get_tor_session() as session:
            # Try multiple IP checking services
            services = [
                "https://api.ipify.org",
                "https://icanhazip.com",
                "https://ident.me"
            ]
            
            for service in services:
                try:
                    response = session.get(service, timeout=10)
                    if response.status_code == 200:
                        current_ip = response.text.strip()
                        return current_ip
                except:
                    continue
    except Exception as e:
        error(f"Error getting IP: {e}")
    
    return None

def get_ip_details(ip=None):
    """Get detailed information about the current IP"""
    if not ip:
        ip = get_current_ip()
        if not ip:
            return None
    
    # Try multiple geolocation services
    services = [
        # Format: (URL format string, response handler function)
        (f"https://ipapi.co/{ip}/json/", lambda r: r.json()),
        (f"https://ipinfo.io/{ip}/json", lambda r: r.json()),
        (f"https://freegeoip.app/json/{ip}", lambda r: r.json()),
        (f"https://extreme-ip-lookup.com/json/{ip}", lambda r: r.json())
    ]
    
    for service_url, handler in services:
        try:
            with get_tor_session() as session:
                response = session.get(service_url, timeout=5)  # Shorter timeout
                if response.status_code == 200:
                    data = handler(response)
                    
                    # Normalize response data to a common format
                    ip_details = {
                        "ip": ip,
                        "country": data.get("country_name", data.get("country", "Unknown")),
                        "country_code": data.get("country_code", data.get("countryCode", "Unknown")),
                        "region": data.get("region", data.get("regionName", data.get("region_name", "Unknown"))),
                        "city": data.get("city", "Unknown"),
                        "isp": data.get("org", data.get("isp", "Unknown")),
                        "latitude": data.get("latitude", data.get("lat", 0)),
                        "longitude": data.get("longitude", data.get("lon", 0)),
                        "timezone": data.get("timezone", data.get("timeZone", "Unknown")),
                        "source": service_url
                    }
                    return ip_details
        except Exception as e:
            warning(f"Failed to get IP details from {service_url}: {e}")
    
    # Fallback: Create basic info if all services fail
    warning("All geolocation services failed, using basic info only")
    return {
        "ip": ip,
        "country": "Unknown", 
        "country_code": "XX",
        "region": "Unknown",
        "city": "Unknown",
        "isp": "Unknown",
        "source": "local"
    }

def change_ip():
    """Request a new Tor circuit to change IP"""
    original_ip = get_current_ip()
    
    # Method 1: Use the control port with authentication
    try:
        with Controller.from_port(port=DEFAULT_CTRL_PORT) as controller:
            # Try all authentication methods one by one
            auth_methods = [
                lambda: controller.authenticate(),  # No password
                lambda: controller.authenticate(""),  # Empty password
                lambda: controller.authenticate("password"),  # Common password
                # Try to read cookie file with different methods
                lambda: controller.authenticate(path="/var/run/tor/control.authcookie"),
                lambda: controller.authenticate(path="/var/lib/tor/control.authcookie"),
                lambda: controller.authenticate(path="/run/tor/control.authcookie"),
                # Try with cookie file but different permission handling
                lambda: controller.authenticate(
                    cookie_path="/run/tor/control.authcookie",
                    chroot_path=None
                )
            ]
            
            # Try all authentication methods
            auth_success = False
            for auth_method in auth_methods:
                try:
                    auth_method()
                    auth_success = True
                    break
                except Exception:
                    continue
            
            if not auth_success:
                raise Exception("All authentication methods failed")
                
            try:
                # Try to send the NEWNYM signal directly
                controller.signal(Signal.NEWNYM)
                success("Successfully requested new Tor circuit")
                
                # Verify IP actually changed
                time.sleep(3)  # Give Tor time to establish a new circuit
                new_ip = get_current_ip()
                if new_ip and new_ip != original_ip:
                    success(f"IP changed: {original_ip} -> {new_ip}")
                    return True
                else:
                    warning("Signal sent but IP didn't change, trying other methods")
            except Exception as e:
                warning(f"NEWNYM signal failed: {e}")
                # If signal fails, try a different approach
                try:
                    # Try a lower-level command that bypasses signal() method
                    response = controller.msg("SIGNAL NEWNYM")
                    if response.is_ok():
                        success("Successfully requested new circuit via direct command")
                        time.sleep(3)
                        new_ip = get_current_ip()
                        if new_ip and new_ip != original_ip:
                            success(f"IP changed: {original_ip} -> {new_ip}")
                            return True
                except Exception as e:
                    warning(f"Direct SIGNAL command failed: {e}")
    except Exception as e:
        warning(f"Control port method failed: {e}")
    
    # Method 2: Try using saved passwords
    try:
        if os.path.exists(TOR_PASSWORD_FILE):
            with open(TOR_PASSWORD_FILE, 'r') as f:
                for line in f:
                    if line.startswith('# Plaintext password'):
                        plaintext_password = line.split(':')[1].strip()
                        try:
                            with Controller.from_port(port=DEFAULT_CTRL_PORT) as controller:
                                controller.authenticate(password=plaintext_password)
                                controller.signal(Signal.NEWNYM)
                                success("Successfully requested new Tor circuit using saved password")
                                time.sleep(3)
                                new_ip = get_current_ip()
                                if new_ip and new_ip != original_ip:
                                    return True
                        except Exception:
                            pass
    except Exception:
        pass
    
    # Method 3: As a last resort, restart Tor
    warning("Control port methods failed, restarting Tor service")
    if restart_tor_service():
        success("Successfully restarted Tor service")
        time.sleep(5)  # Give Tor time to restart
        
        # Verify IP actually changed
        new_ip = get_current_ip()
        if new_ip and new_ip != original_ip:
            success(f"IP changed after restart: {original_ip} -> {new_ip}")
            return True
        else:
            warning("Restarted Tor but IP didn't change")
    
    # If we get here, all methods failed
    error("All methods to change IP failed")
    return False

def check_current_ip():
    """Display current IP information"""
    print_header("Current Tor IP Information")
    
    ip = get_current_ip()
    if not ip:
        error("Failed to get current IP. Check if Tor is running.")
        return
    
    success(f"Current Tor IP: {ip}")
    
    # Get additional details
    details = get_ip_details(ip)
    if details:
        print(f"Country: {details.get('country', 'Unknown')} ({details.get('country_code', 'Unknown')})")
        print(f"Region: {details.get('region', 'Unknown')}")
        print(f"City: {details.get('city', 'Unknown')}")
        print(f"ISP: {details.get('isp', 'Unknown')}")
        if details.get('source') != 'local':
            print(f"Source: {details.get('source', 'Unknown')}")
        
        # Save to history
        record_ip(details)
    else:
        print("Could not retrieve detailed information")
        # Save basic info to history
        record_ip({"ip": ip, "country": "Unknown", "country_code": "XX", "region": "Unknown", 
                   "city": "Unknown", "isp": "Unknown", "timestamp": datetime.now().isoformat()})

def record_ip(ip_data):
    """Record IP data to history"""
    global ip_history
    
    if not ip_data:
        return
    
    # Create record
    record = {
        "timestamp": ip_data.get("timestamp") or datetime.now().isoformat(),
        "ip": ip_data.get("ip", "Unknown"),
        "country": ip_data.get("country", ip_data.get("country_name", "Unknown")),
        "country_code": ip_data.get("country_code", "Unknown"),
        "region": ip_data.get("region", "Unknown"),
        "city": ip_data.get("city", "Unknown"),
        "isp": ip_data.get("isp", ip_data.get("org", "Unknown")),
    }
    
    # Add to history
    ip_history.append(record)
    
    # Save history to file
    try:
        with open(IP_HISTORY_FILE, 'w') as f:
            json.dump(ip_history, f, indent=2)
    except Exception as e:
        error(f"Failed to save IP history: {e}")
        
    return record

def load_ip_history():
    """Load IP history from file"""
    global ip_history
    
    if os.path.exists(IP_HISTORY_FILE):
        try:
            with open(IP_HISTORY_FILE, 'r') as f:
                ip_history = json.load(f)
        except Exception as e:
            error(f"Failed to load IP history: {e}")
            ip_history = []

def generate_ip_stats(days=7):
    """Generate and display IP statistics"""
    print_header("Tor IP Statistics")
    
    if not ip_history:
        error("No IP history available")
        return
    
    # Filter by date if requested
    filtered_history = ip_history
    if days > 0:
        cutoff_date = (datetime.now() - timedelta(days=days)).isoformat()
        filtered_history = [entry for entry in ip_history if entry["timestamp"] >= cutoff_date]
    
    # Basic stats
    total_ips = len(filtered_history)
    unique_ips = len(set(entry["ip"] for entry in filtered_history))
    countries = Counter(entry["country"] for entry in filtered_history)
    isps = Counter(entry["isp"] for entry in filtered_history)
    
    print(f"Period: {days} days" if days > 0 else "All time")
    print(f"Total IP changes: {total_ips}")
    print(f"Unique IPs: {unique_ips} ({unique_ips/total_ips*100:.1f}%)")
    
    # Top countries
    print("\nTop 5 Countries:")
    for country, count in countries.most_common(5):
        print(f"- {country}: {count} ({count/total_ips*100:.1f}%)")
    
    # Top ISPs
    print("\nTop 5 ISPs:")
    for isp, count in isps.most_common(5):
        print(f"- {isp}: {count} ({count/total_ips*100:.1f}%)")

#
# Thread Management
#

def start_ip_changer_thread(interval_min=30, interval_max=60):
    """Start IP changer in background thread"""
    global ip_changer_thread, stop_threads
    
    if ip_changer_thread and ip_changer_thread.is_alive():
        warning("IP changer is already running")
        return False
    
    if not is_tor_running():
        error("Tor is not running properly")
        return False
    
    stop_threads = False
    
    def run_changer():
        global ip_changes
        
        info(f"Starting IP changer (interval: {interval_min}-{interval_max}s)")
        info("Press Ctrl+C in the main menu to stop")
        
        while not stop_threads:
            # Change IP
            if change_ip():
                time.sleep(5)  # Give Tor time to establish circuit
                new_ip = get_current_ip()
                
                if new_ip:
                    ip_details = get_ip_details(new_ip)
                    if ip_details:
                        record_ip(ip_details)
                        ip_changes += 1
                        success(f"New IP: {new_ip} ({ip_details.get('country_name', 'Unknown')})")
            
            # Random interval
            interval = random.randint(interval_min, interval_max)
            info(f"Next change in {interval}s")
            
            # Wait for next change
            for _ in range(interval):
                if stop_threads:
                    break
                time.sleep(1)
    
    ip_changer_thread = threading.Thread(target=run_changer)
    ip_changer_thread.daemon = True
    ip_changer_thread.start()
    
    success("IP changer started in background")
    return True

def stop_ip_changer_thread():
    """Stop IP changer thread"""
    global ip_changer_thread, stop_threads
    
    if not ip_changer_thread or not ip_changer_thread.is_alive():
        warning("IP changer is not running")
        return False
    
    stop_threads = True
    ip_changer_thread.join(timeout=5)
    
    if ip_changer_thread.is_alive():
        error("Failed to stop IP changer thread")
        return False
    
    success("IP changer stopped")
    return True

def start_ip_monitor_thread():
    """Start IP monitor in background thread"""
    global ip_monitor_thread, stop_threads
    
    if ip_monitor_thread and ip_monitor_thread.is_alive():
        warning("IP monitor is already running")
        return False
    
    stop_threads = False
    
    def run_monitor():
        info("Starting IP monitor")
        last_ip = None
        
        while not stop_threads:
            try:
                current = get_current_ip()
                
                if current and current != last_ip:
                    if last_ip:
                        success(f"IP changed: {last_ip} -> {current}")
                    else:
                        success(f"Initial IP: {current}")
                    
                    ip_details = get_ip_details(current)
                    if ip_details:
                        country_info = f" ({ip_details.get('country', 'Unknown')})"
                        success(f"New IP location{country_info}")
                        record = record_ip(ip_details)
                    else:
                        # Record basic info if details not available
                        record = record_ip({"ip": current, "timestamp": datetime.now().isoformat()})
                    
                    last_ip = current
                
                # Check every 30 seconds - more responsive
                for _ in range(30):
                    if stop_threads:
                        break
                    time.sleep(1)
            except Exception as e:
                warning(f"Monitor error: {e}")
                # Continue monitoring despite errors
                time.sleep(10)
    
    ip_monitor_thread = threading.Thread(target=run_monitor)
    ip_monitor_thread.daemon = True
    ip_monitor_thread.start()
    
    success("IP monitor started in background")
    return True

def stop_ip_monitor_thread():
    """Stop IP monitor thread"""
    global ip_monitor_thread, stop_threads
    
    if not ip_monitor_thread or not ip_monitor_thread.is_alive():
        warning("IP monitor is not running")
        return False
    
    stop_threads = True
    ip_monitor_thread.join(timeout=5)
    
    if ip_monitor_thread.is_alive():
        error("Failed to stop IP monitor thread")
        return False
    
    success("IP monitor stopped")
    return True

def start_security_scan(target_url=None):
    """Start security scan in background thread"""
    global security_scan_thread, stop_threads
    
    if not SECURITY_TOOLS_AVAILABLE:
        error("Security tools not available")
        return False
    
    if security_scan_thread and security_scan_thread.is_alive():
        warning("Security scan is already running")
        return False
    
    stop_threads = False
    
    if not target_url:
        target_url = input(colorize("Enter target URL to scan: ", "YELLOW"))
    
    def run_scan():
        info(f"Starting security scan for {target_url}")
        results = perform_security_scan(target_url)
        
        if results:
            success(f"Security scan completed for {target_url}")
            # Print summary
            print("\nSecurity Scan Summary:")
            print(f"Target: {results.get('target')}")
            print(f"Status Code: {results.get('status_code')}")
            print(f"Security Headers: {len(results.get('security_headers', {}).get('present', []))} present, {len(results.get('security_headers', {}).get('missing', []))} missing")
            print(f"Findings: {len(results.get('findings', []))}")
    
    security_scan_thread = threading.Thread(target=run_scan)
    security_scan_thread.daemon = True
    security_scan_thread.start()
    
    success("Security scan started in background")
    return True

def stop_security_scan_thread():
    """Stop security scan thread"""
    global security_scan_thread, stop_threads
    
    if not security_scan_thread or not security_scan_thread.is_alive():
        warning("Security scan is not running")
        return False
    
    stop_threads = True
    security_scan_thread.join(timeout=5)
    
    if security_scan_thread.is_alive():
        error("Failed to stop security scan thread")
        return False
    
    success("Security scan stopped")
    return True

def stop_all_threads():
    """Stop all background threads"""
    stopped_changer = stop_ip_changer_thread()
    stopped_monitor = stop_ip_monitor_thread()
    stopped_scan = stop_security_scan_thread()
    
    return stopped_changer or stopped_monitor or stopped_scan

#
# Security Functions
#

def show_security_menu():
    """Display security tools menu"""
    while True:
        clear_screen()
        print_header("Security Tools Menu")
        
        if not SECURITY_TOOLS_AVAILABLE:
            error("Security tools not available")
            print("Make sure security_tools.py is in the same directory.")
            input(colorize("\nPress Enter to return to main menu...", "GREEN"))
            return
        
        print(colorize("1. Website Security Scan", "BLUE"))
        print(colorize("2. Port Scanner", "BLUE"))
        print(colorize("3. View Security Reports", "BLUE"))
        print(colorize("0. Return to Main Menu", "RED"))
        print()
        
        choice = input(colorize("Enter your choice: ", "YELLOW"))
        
        if choice == "1":
            target_url = input(colorize("Enter target URL to scan: ", "YELLOW"))
            if target_url:
                results = perform_security_scan(target_url)
                if results:
                    success(f"Security scan completed for {target_url}")
                    # Print findings
                    if results.get('findings'):
                        print("\nFindings:")
                        for finding in results.get('findings'):
                            severity = finding.get('severity', 'info')
                            color = "RED" if severity == "high" else "YELLOW" if severity == "medium" else "BLUE"
                            print(f"- {colorize(finding.get('title', 'Unknown'), color)}")
                            print(f"  {finding.get('description', '')}")
            input(colorize("\nPress Enter to continue...", "GREEN"))
        
        elif choice == "2":
            target = input(colorize("Enter target (IP/hostname): ", "YELLOW"))
            if target:
                port_range = input(colorize("Enter port range (e.g. 1-1000) or leave blank for common ports: ", "YELLOW"))
                results = scan_target_ports(target, port_range)
                
                if results:
                    success(f"Scan completed for {target}")
                    print("\nOpen ports:")
                    if results.get('open_ports'):
                        for port, service in results.get('open_ports').items():
                            print(f"- {port}/tcp: {service}")
                    else:
                        print("No open ports found.")
            input(colorize("\nPress Enter to continue...", "GREEN"))
        
        elif choice == "3":
            reports = []
            for filename in os.listdir(SECURITY_REPORT_DIR):
                if filename.endswith(".json"):
                    filepath = os.path.join(SECURITY_REPORT_DIR, filename)
                    try:
                        with open(filepath, 'r') as f:
                            data = json.load(f)
                        reports.append({
                            "name": filename,
                            "target": data.get("target", "Unknown"),
                            "date": data.get("timestamp", "Unknown"),
                            "path": filepath
                        })
                    except:
                        pass
            
            if not reports:
                info("No security reports found.")
            else:
                print(f"Found {len(reports)} security reports:")
                for i, report in enumerate(reports, 1):
                    print(f"{i}. {report['target']} - {report['date']}")
                
                report_choice = input(colorize("\nEnter report number to view (or 0 to return): ", "YELLOW"))
                if report_choice.isdigit() and int(report_choice) > 0 and int(report_choice) <= len(reports):
                    report_index = int(report_choice) - 1
                    with open(reports[report_index]['path'], 'r') as f:
                        data = json.load(f)
                    
                    print(f"\nTarget: {data.get('target')}")
                    print(f"Date: {data.get('timestamp')}")
                    print(f"Status Code: {data.get('status_code')}")
                    
                    if data.get('findings'):
                        print("\nFindings:")
                        for finding in data.get('findings'):
                            severity = finding.get('severity', 'info')
                            color = "RED" if severity == "high" else "YELLOW" if severity == "medium" else "BLUE"
                            print(f"- {colorize(finding.get('title', 'Unknown'), color)}")
                            print(f"  {finding.get('description', '')}")
            
            input(colorize("\nPress Enter to continue...", "GREEN"))
        
        elif choice == "0":
            return

#
# Interactive Menu
#

def show_main_menu():
    """Display the main interactive menu"""
    global current_ip, ip_changes
    
    # Load IP history
    load_ip_history()
    
    while True:
        clear_screen()
        print_header(f"Tor IP Suite v{VERSION}")
        
        # Status
        changer_running = ip_changer_thread and ip_changer_thread.is_alive()
        monitor_running = ip_monitor_thread and ip_monitor_thread.is_alive()
        
        if changer_running:
            print(colorize("● IP Changer is running", "GREEN"))
        else:
            print(colorize("○ IP Changer is not running", "RED"))
        
        if monitor_running:
            print(colorize("● IP Monitor is running", "GREEN"))
        else:
            print(colorize("○ IP Monitor is not running", "RED"))
        
        print(colorize(f"● Current IP: {current_ip}", "CYAN"))
        print(colorize(f"● IP Changes: {ip_changes}", "CYAN"))
        print()
        
        # Menu options
        print(colorize("1. Start IP Changer", "BLUE"))
        print(colorize("2. Stop IP Changer", "BLUE"))
        print(colorize("3. Check Current IP", "BLUE"))
        print(colorize("4. Start IP Monitor", "BLUE"))
        print(colorize("5. Stop IP Monitor", "BLUE"))
        print(colorize("6. View IP Statistics", "BLUE"))
        print(colorize("7. Start Both IP Changer and Monitor", "BLUE"))
        print(colorize("8. Configure Tor Authentication", "BLUE"))
        print(colorize("S. Security Tools", "PURPLE"))
        print(colorize("0. Exit", "RED"))
        print()
        
        try:
            choice = input(colorize("Enter your choice: ", "YELLOW"))
            
            if choice == "1":
                if not changer_running:
                    interval_min = int(input(colorize("Enter minimum interval in seconds [30]: ", "YELLOW")) or "30")
                    interval_max = int(input(colorize("Enter maximum interval in seconds [60]: ", "YELLOW")) or "60")
                    start_ip_changer_thread(interval_min, interval_max)
                else:
                    warning("IP changer is already running")
                input(colorize("Press Enter to continue...", "GREEN"))
            
            elif choice == "2":
                stop_ip_changer_thread()
                input(colorize("Press Enter to continue...", "GREEN"))
            
            elif choice == "3":
                check_current_ip()
                input(colorize("Press Enter to continue...", "GREEN"))
            
            elif choice == "4":
                start_ip_monitor_thread()
                input(colorize("Press Enter to continue...", "GREEN"))
            
            elif choice == "5":
                stop_ip_monitor_thread()
                input(colorize("Press Enter to continue...", "GREEN"))
            
            elif choice == "6":
                days = int(input(colorize("Enter number of days to analyze (0 for all time): ", "YELLOW")) or "7")
                generate_ip_stats(days=days)
                input(colorize("Press Enter to continue...", "GREEN"))
            
            elif choice == "7":
                if not changer_running:
                    start_ip_changer_thread()
                if not monitor_running:
                    start_ip_monitor_thread()
                input(colorize("Press Enter to continue...", "GREEN"))
                
            elif choice == "8":
                print_header("Tor Authentication Configuration")
                print("This will help configure Tor for password authentication.")
                print("This is useful if you're having permission issues.")
                confirm = input(colorize("Generate a new Tor password? (y/n): ", "YELLOW")).lower()
                if confirm == "y":
                    password, password_hash = setup_tor_password()
                    if password and password_hash:
                        print("\nTo configure Tor, add the following to /etc/tor/torrc:")
                        print(colorize(f"HashedControlPassword {password_hash}", "CYAN"))
                        print("\nThen restart Tor with: sudo systemctl restart tor")
                        print(f"Your plaintext password is: {colorize(password, 'GREEN')}")
                        print("Remember this password for authentication.")
                        print("You can also find this information in:", colorize(TOR_PASSWORD_FILE, "YELLOW"))
                input(colorize("Press Enter to continue...", "GREEN"))
            
            elif choice.upper() == "S":
                show_security_menu()
            
            elif choice == "0":
                if changer_running or monitor_running:
                    confirm = input(colorize("Stop all threads before exiting? (y/n): ", "YELLOW")).lower()
                    if confirm == "y":
                        stop_all_threads()
                print(colorize("Goodbye!", "GREEN"))
                break
            
        except ValueError:
            error("Invalid input")
            input(colorize("Press Enter to continue...", "GREEN"))
        except KeyboardInterrupt:
            print("\n")
            if changer_running or monitor_running:
                confirm = input(colorize("Stop all threads before exiting? (y/n): ", "YELLOW")).lower()
                if confirm == "y":
                    stop_all_threads()
            print(colorize("Goodbye!", "GREEN"))
            break

#
# Main Function
#

def main():
    """Main function"""
    parser = argparse.ArgumentParser(description=f"Tor IP Suite v{VERSION} - A tool for ethical hackers")
    
    parser.add_argument("--check", action="store_true", help="Check current Tor IP")
    parser.add_argument("--change", action="store_true", help="Change Tor IP once")
    parser.add_argument("--interval", type=str, help="IP change interval in seconds (format: MIN-MAX)")
    parser.add_argument("--stats", action="store_true", help="View IP statistics")
    parser.add_argument("--days", type=int, default=7, help="Number of days for statistics")
    parser.add_argument("--scan", type=str, help="URL to scan for security issues")
    parser.add_argument("--configure-tor", action="store_true", help="Configure Tor authentication")
    
    args = parser.parse_args()
    
    # Check if Tor is running first
    if not is_tor_running():
        error("Tor is not running or configured properly")
        print("\nAttempting to restart Tor service...")
        
        if restart_tor_service():
            # Try again after restart
            if is_tor_running():
                success("Tor is now running correctly")
            else:
                warning("Tor is running but may have connectivity issues")
                print("\nTroubleshooting steps:")
                print("1. Check if Tor is installed: sudo apt install tor")
                print("2. Verify Tor is running: systemctl status tor")
                print("3. Check if the SOCKS port is open: ss -tunlp | grep 9050")
                print("4. Check if your network allows Tor connections")
                print("\nIf problems persist, try:")
                print("- Restart Tor: sudo systemctl restart tor")
                print("- Check Tor logs: sudo journalctl -u tor@default")
                print("- Configure Tor by running: ./tor_ip_changer.py --configure-tor")
                
                # Ask if user wants to continue anyway
                response = input(colorize("Continue anyway with limited functionality? (y/n): ", "YELLOW"))
                if response.lower() != 'y':
                    return 1
        else:
            print("\nTroubleshooting steps:")
            print("1. Check if Tor is installed: sudo apt install tor")
            print("2. Start the Tor service: sudo systemctl start tor")
            print("3. Verify Tor is running: systemctl status tor")
            print("4. Check if the SOCKS port is open: ss -tunlp | grep 9050")
            print("\nIf problems persist, try:")
            print("- Restart Tor: sudo systemctl restart tor")
            print("- Check Tor logs: sudo journalctl -u tor@default")
            return 1
    
    # Process command line args
    if args.configure_tor:
        print_header("Tor Authentication Configuration")
        password, password_hash = setup_tor_password()
        if password and password_hash:
            print("\nTo configure Tor, add the following to /etc/tor/torrc:")
            print(colorize(f"HashedControlPassword {password_hash}", "CYAN"))
            print("\nThen restart Tor with: sudo systemctl restart tor")
            print(f"Your plaintext password is: {colorize(password, 'GREEN')}")
            return 0
    elif args.check:
        check_current_ip()
    elif args.change:
        if change_ip():
            time.sleep(5)
            check_current_ip()
    elif args.interval:
        try:
            if "-" in args.interval:
                min_interval, max_interval = map(int, args.interval.split("-"))
            else:
                min_interval = max_interval = int(args.interval)
            
            start_ip_changer_thread(interval_min=min_interval, interval_max=max_interval)
            input(colorize("Press Ctrl+C to stop...", "GREEN"))
        except KeyboardInterrupt:
            stop_ip_changer_thread()
    elif args.stats:
        load_ip_history()
        generate_ip_stats(days=args.days)
    elif args.scan:
        if SECURITY_TOOLS_AVAILABLE:
            perform_security_scan(args.scan)
        else:
            error("Security tools not available")
    else:
        # Show interactive menu
        show_main_menu()
    
    return 0

if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\nOperation cancelled by user")
        sys.exit(1)
