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
    "WHITE": "\033[97m",
    "ENDC": "\033[0m"
}

# Import optional libraries
try:
    import requests
    from stem import Signal
    from stem.control import Controller
    TOR_AVAILABLE = True
except ImportError:
    TOR_AVAILABLE = False

try:
    import tor_security_tools as security_tools
    SECURITY_TOOLS_AVAILABLE = True
except ImportError:
    SECURITY_TOOLS_AVAILABLE = False

# Defaults
DEFAULT_SOCKS_PORT = 9050
DEFAULT_CTRL_PORT = 9051
TOR_PASSWORD_FILE = os.path.expanduser("~/.tor_password")
IP_HISTORY_FILE = os.path.expanduser("~/.tor_ip_history.json")
SECURITY_REPORT_DIR = os.path.join(os.path.expanduser("~"), ".tor_security_reports")

# Threading flags
stop_threads = False
ip_changer_thread = None
ip_monitor_thread = None

# Stats
ip_changes = 0
current_ip = None
ip_history = []

#
# Utility Functions
#

def colorize(text, color_name):
    """Apply ANSI color to text"""
    return f"{COLORS[color_name]}{text}{COLORS['ENDC']}"

def success(message):
    """Print a success message"""
    print(f"[{colorize('+', 'GREEN')}] {message}")

def error(message):
    """Print an error message"""
    print(f"[{colorize('!', 'RED')}] {message}")

def warning(message):
    """Print a warning message"""
    print(f"[{colorize('!', 'YELLOW')}] {message}")

def info(message):
    """Print an info message"""
    print(f"[{colorize('*', 'BLUE')}] {message}")

def setup_tor_password():
    """Generate and save a Tor control port password"""
    try:
        if not os.path.exists(os.path.dirname(TOR_PASSWORD_FILE)):
            os.makedirs(os.path.dirname(TOR_PASSWORD_FILE))
        
        # Generate a random password
        password = ''.join(random.choice('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789') for _ in range(16))
        
        # Get the hashed version
        process = subprocess.run(
            ["tor", "--hash-password", password], 
            capture_output=True, 
            text=True
        )
        
        if process.returncode != 0:
            error(f"Error generating password hash: {process.stderr}")
            return None, None
        
        password_hash = process.stdout.strip()
        
        # Save both plain and hashed password to file
        with open(TOR_PASSWORD_FILE, 'w') as f:
            f.write(f"# Tor control port password configuration\n")
            f.write(f"# Generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"# Plaintext password: {password}\n")
            f.write(f"HashedControlPassword {password_hash}\n")
        
        os.chmod(TOR_PASSWORD_FILE, 0o600)  # Make file readable only by owner
        success(f"Saved Tor authentication details to {TOR_PASSWORD_FILE}")
        
        return password, password_hash
    except Exception as e:
        error(f"Error setting up Tor password: {e}")
        return None, None

def kill_tor_using_processes():
    """Kill any processes that might be using Tor sockets"""
    try:
        # Find processes using Tor ports
        warning("Finding and killing processes using Tor ports")
        
        # Check processes using SOCKS port
        try:
            # List processes using port 9050
            lsof_result = subprocess.run(
                ["sudo", "lsof", "-i", f":{DEFAULT_SOCKS_PORT}"], 
                capture_output=True, 
                text=True
            )
            
            # Extract PIDs from lsof output
            if lsof_result.stdout:
                pid_pattern = re.compile(r'\s+(\d+)\s+')
                pids = pid_pattern.findall(lsof_result.stdout)
                
                # Kill each process using the port
                for pid in pids:
                    if pid.isdigit() and int(pid) > 1:  # Don't kill system processes
                        subprocess.run(["sudo", "kill", "-9", pid], capture_output=True)
                        warning(f"Killed process {pid} using Tor SOCKS port")
        except Exception as e:
            warning(f"Error checking SOCKS port: {e}")
        
        # Check processes using control port
        try:
            # List processes using port 9051
            lsof_result = subprocess.run(
                ["sudo", "lsof", "-i", f":{DEFAULT_CTRL_PORT}"], 
                capture_output=True, 
                text=True
            )
            
            # Extract PIDs from lsof output
            if lsof_result.stdout:
                pid_pattern = re.compile(r'\s+(\d+)\s+')
                pids = pid_pattern.findall(lsof_result.stdout)
                
                # Kill each process using the port
                for pid in pids:
                    if pid.isdigit() and int(pid) > 1:  # Don't kill system processes
                        subprocess.run(["sudo", "kill", "-9", pid], capture_output=True)
                        warning(f"Killed process {pid} using Tor control port")
        except Exception as e:
            warning(f"Error checking control port: {e}")
            
        # Give processes time to terminate
        time.sleep(1)
    except Exception as e:
        warning(f"Error killing Tor-using processes: {e}")

def restart_tor_service():
    """Attempt to restart the Tor service"""
    try:
        if platform.system() == "Linux":
            warning("Attempting to restart Tor service")
            
            # First, kill any processes using Tor ports
            kill_tor_using_processes()
            
            # Then, try to stop any existing Tor processes
            warning("Stopping all Tor processes")
            try:
                # Kill all Tor processes by their name
                subprocess.run(["sudo", "pkill", "-f", "tor"], capture_output=True)
                # Give some time for processes to terminate
                time.sleep(2)
                
                # Check if any tor processes are still running
                ps_result = subprocess.run(["ps", "aux"], capture_output=True, text=True)
                if "tor" in ps_result.stdout:
                    # Force kill any remaining tor processes
                    subprocess.run(["sudo", "pkill", "-9", "-f", "tor"], capture_output=True)
                    time.sleep(1)
            except Exception as e:
                warning(f"Error stopping Tor processes: {e}")
            
            # Now, try to start Tor service with systemd
            if os.path.exists("/bin/systemctl") or os.path.exists("/usr/bin/systemctl"):
                # Start fresh with systemctl
                result = subprocess.run(
                    ["sudo", "systemctl", "restart", "tor"], 
                    capture_output=True, 
                    text=True
                )
                if result.returncode == 0:
                    success("Successfully restarted Tor service via systemctl")
                    # Give Tor more time to initialize properly
                    time.sleep(7)
                    return True
                else:
                    warning(f"systemctl restart failed: {result.stderr}")
            
            # If systemctl didn't work, try init.d script
            elif os.path.exists("/etc/init.d/tor"):
                result = subprocess.run(
                    ["sudo", "/etc/init.d/tor", "restart"], 
                    capture_output=True, 
                    text=True
                )
                if result.returncode == 0:
                    success("Successfully restarted Tor service via init.d")
                    time.sleep(7)
                    return True
                else:
                    warning(f"init.d restart failed: {result.stderr}")
            
            # As a last resort, start Tor directly
            else:
                try:
                    # Kill any remaining tor processes just to be sure
                    subprocess.run(["sudo", "pkill", "-9", "-f", "tor"], capture_output=True)
                    time.sleep(1)
                    
                    # Start tor in the background
                    success("Starting Tor manually")
                    subprocess.Popen(["tor"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    time.sleep(10)  # Give more time to initialize
                    
                    # Check if it's running
                    if socket.socket().connect_ex(('127.0.0.1', DEFAULT_SOCKS_PORT)) == 0:
                        success("Tor started successfully")
                        return True
                    else:
                        warning("Tor failed to start properly")
                except Exception as e:
                    error(f"Failed to start Tor manually: {e}")
    except Exception as e:
        error(f"Failed to restart Tor service: {e}")
    
    return False

def clear_screen():
    """Clear the terminal screen"""
    os.system('cls' if os.name == 'nt' else 'clear')

def print_header(title):
    """Print a formatted header"""
    print(colorize("=" * 60, "CYAN"))
    print(colorize(f"  {title}", "CYAN"))
    print(colorize("=" * 60, "CYAN"))

def load_ip_history():
    """Load IP history from file"""
    global ip_history
    try:
        if os.path.exists(IP_HISTORY_FILE):
            with open(IP_HISTORY_FILE, 'r') as f:
                ip_history = json.load(f)
    except Exception as e:
        warning(f"Error loading IP history: {e}")
        ip_history = []

def save_ip_history():
    """Save IP history to file"""
    try:
        if not os.path.exists(os.path.dirname(IP_HISTORY_FILE)):
            os.makedirs(os.path.dirname(IP_HISTORY_FILE))
        with open(IP_HISTORY_FILE, 'w') as f:
            json.dump(ip_history, f, indent=2)
    except Exception as e:
        warning(f"Error saving IP history: {e}")

def record_ip(ip):
    """Record IP change to history"""
    global ip_history
    if not ip:
        return
    
    try:
        details = get_ip_details(ip)
        ip_data = {
            "ip": ip,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "country": details.get("country", "Unknown"),
            "country_code": details.get("country_code", "Unknown"),
            "region": details.get("region", "Unknown"),
            "city": details.get("city", "Unknown"),
            "isp": details.get("isp", "Unknown")
        }
        ip_history.append(ip_data)
        save_ip_history()
    except Exception as e:
        warning(f"Error recording IP history: {e}")

#
# Tor Functions
#

def is_tor_running():
    """Check if Tor is running"""
    try:
        # Method 1: Try to connect to the Tor SOCKS port
        s = socket.socket()
        result = s.connect_ex(('127.0.0.1', DEFAULT_SOCKS_PORT))
        s.close()
        if result == 0:
            # Verify we can make a connection through Tor
            try:
                with get_tor_session() as session:
                    response = session.get("https://api.ipify.org", timeout=10)
                    if response.status_code == 200:
                        success(f"Confirmed Tor connection via https://api.ipify.org")
                        return True
            except Exception as e:
                warning(f"Tor SOCKS port is open but connection failed: {e}")
        
        # If we get here, we couldn't connect to Tor or couldn't use it successfully
        return False
    except Exception as e:
        warning(f"Error checking Tor status: {e}")
        return False

def control_port_auth_with_cookie():
    """Authenticate to Tor control port with cookie"""
    try:
        with Controller.from_port(port=DEFAULT_CTRL_PORT) as controller:
            # Try all available cookie paths
            cookie_paths = [
                "/var/run/tor/control.authcookie",
                "/var/lib/tor/control.authcookie",
                "/run/tor/control.authcookie"
            ]
            
            for path in cookie_paths:
                try:
                    controller.authenticate(path=path)
                    return True
                except Exception:
                    continue
            
            # Try with explicit chroot path
            try:
                controller.authenticate(cookie_path="/run/tor/control.authcookie", chroot_path=None)
                return True
            except Exception:
                pass
            
            return False
    except Exception:
        return False

def control_port_auth_with_password():
    """Authenticate to Tor control port with password"""
    try:
        with Controller.from_port(port=DEFAULT_CTRL_PORT) as controller:
            # Try default/empty password
            try:
                controller.authenticate("")
                return True
            except Exception:
                pass
            
            # Try common password
            try:
                controller.authenticate("password")
                return True
            except Exception:
                pass
            
            # Try password from file
            if os.path.exists(TOR_PASSWORD_FILE):
                with open(TOR_PASSWORD_FILE, 'r') as f:
                    for line in f:
                        if line.startswith('# Plaintext password'):
                            try:
                                password = line.split(':')[1].strip()
                                controller.authenticate(password=password)
                                return True
                            except Exception:
                                pass
            
            return False
    except Exception:
        return False

def socket_auth_with_cookie():
    """Authenticate to Tor via socket with cookie"""
    try:
        socket_path = None
        # Find socket path
        for path in ["/var/run/tor/control", "/run/tor/control"]:
            if os.path.exists(path):
                socket_path = path
                break
        
        if not socket_path:
            return False
        
        with Controller.from_socket_file(path=socket_path) as controller:
            # Try all available cookie paths
            cookie_paths = [
                "/var/run/tor/control.authcookie",
                "/var/lib/tor/control.authcookie",
                "/run/tor/control.authcookie"
            ]
            
            for path in cookie_paths:
                try:
                    controller.authenticate(path=path)
                    return True
                except Exception:
                    continue
            
            return False
    except Exception:
        return False

def socket_auth_with_password():
    """Authenticate to Tor via socket with password"""
    try:
        socket_path = None
        # Find socket path
        for path in ["/var/run/tor/control", "/run/tor/control"]:
            if os.path.exists(path):
                socket_path = path
                break
        
        if not socket_path:
            return False
        
        with Controller.from_socket_file(path=socket_path) as controller:
            # Try default/empty password
            try:
                controller.authenticate("")
                return True
            except Exception:
                pass
            
            # Try common password
            try:
                controller.authenticate("password")
                return True
            except Exception:
                pass
            
            # Try password from file
            if os.path.exists(TOR_PASSWORD_FILE):
                with open(TOR_PASSWORD_FILE, 'r') as f:
                    for line in f:
                        if line.startswith('# Plaintext password'):
                            try:
                                password = line.split(':')[1].strip()
                                controller.authenticate(password=password)
                                return True
                            except Exception:
                                pass
            
            return False
    except Exception:
        return False

def get_tor_session():
    """Create a requests session that routes through Tor"""
    session = requests.session()
    # Tor uses the 9050 port as the default socks port
    session.proxies = {
        'http': f'socks5h://127.0.0.1:{DEFAULT_SOCKS_PORT}',
        'https': f'socks5h://127.0.0.1:{DEFAULT_SOCKS_PORT}'
    }
    return session

def get_current_ip():
    """Get the current Tor exit node IP"""
    try:
        with get_tor_session() as session:
            # Try multiple IP services
            services = [
                "https://api.ipify.org",
                "https://icanhazip.com",
                "https://ident.me",
                "https://ipecho.net/plain"
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

def clean_restart_tor():
    """Completely reset Tor for a clean start - kill all processes and restart fresh"""
    warning("Performing complete Tor reset")
    
    # Stop all threads first
    stop_ip_changer_thread()
    stop_ip_monitor_thread()
    time.sleep(1)
    
    # Kill any processes using Tor ports
    kill_tor_using_processes()
    
    # Stop the Tor service
    try:
        warning("Stopping Tor service")
        if os.path.exists("/bin/systemctl") or os.path.exists("/usr/bin/systemctl"):
            subprocess.run(["sudo", "systemctl", "stop", "tor"], capture_output=True)
        elif os.path.exists("/etc/init.d/tor"):
            subprocess.run(["sudo", "/etc/init.d/tor", "stop"], capture_output=True)
    except Exception as e:
        warning(f"Error stopping Tor service: {e}")
    
    # Kill all Tor processes to be absolutely sure
    try:
        subprocess.run(["sudo", "pkill", "-f", "tor"], capture_output=True)
        time.sleep(1)
        subprocess.run(["sudo", "pkill", "-9", "-f", "tor"], capture_output=True)
        time.sleep(1)
    except Exception as e:
        warning(f"Error killing Tor processes: {e}")
    
    # Clear any Tor cache/temp files if needed
    try:
        cache_dirs = [
            "/var/lib/tor/cached-certs",
            "/var/lib/tor/cached-descriptors",
            "/var/lib/tor/cached-descriptors.new",
            "/var/lib/tor/cached-microdesc-consensus",
            "/var/lib/tor/cached-microdescs",
            "/var/lib/tor/cached-microdescs.new",
            "/var/lib/tor/state",
        ]
        
        for cache_file in cache_dirs:
            if os.path.exists(cache_file):
                try:
                    subprocess.run(["sudo", "rm", "-f", cache_file], capture_output=True)
                except Exception:
                    pass
    except Exception as e:
        warning(f"Error clearing Tor cache: {e}")
    
    # Start Tor fresh
    try:
        success("Starting fresh Tor instance")
        if os.path.exists("/bin/systemctl") or os.path.exists("/usr/bin/systemctl"):
            subprocess.run(["sudo", "systemctl", "start", "tor"], capture_output=True)
        elif os.path.exists("/etc/init.d/tor"):
            subprocess.run(["sudo", "/etc/init.d/tor", "start"], capture_output=True)
        else:
            # Start tor directly as a last resort
            subprocess.Popen(["tor"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        
        # Give Tor time to initialize
        time.sleep(10)
        
        # Check if Tor is running
        if is_tor_running():
            success("Tor has been completely reset and is now running")
            # Check for new IP
            new_ip = check_current_ip()
            if new_ip:
                success(f"New IP after reset: {new_ip}")
            return True
        else:
            error("Tor failed to start after reset")
            return False
    except Exception as e:
        error(f"Error starting Tor after reset: {e}")
        return False

def change_ip():
    """Change the Tor exit node IP address"""
    global ip_changes, current_ip
    success_msg = None
    old_ip = current_ip or get_current_ip()
    
    if not is_tor_running():
        warning("Tor is not running, attempting to restart")
        restart_tor_service()
        if not is_tor_running():
            error("Tor service couldn't be started. Please check Tor installation.")
            return False
    
    # Try changing the circuit using the controller
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
            
            # Try signal method first
            try:
                controller.signal(Signal.NEWNYM)
                success_msg = "Successfully changed Tor circuit via SIGNAL"
            except Exception as e:
                if "unrecognized status code: 514" in str(e):
                    # If signal fails with code 514, try using the direct protocol command
                    try:
                        controller._handler.send("SIGNAL NEWNYM\r\n")
                        response = controller._handler.recv()
                        if "250" in response:
                            success_msg = "Successfully changed Tor circuit via direct command"
                        else:
                            raise Exception(f"Direct command failed: {response}")
                    except Exception as direct_err:
                        warning(f"Direct command failed: {direct_err}")
                        raise
                else:
                    raise
    except Exception as e:
        warning(f"Control port method failed: {e}")
        # Try restarting as a last resort
        warning("Control port methods failed, restarting Tor service")
        if restart_tor_service():
            success_msg = "Successfully changed IP by restarting Tor service"
        else:
            # Last resort - clean restart
            warning("Regular restart failed, trying clean restart")
            if clean_restart_tor():
                success_msg = "Successfully changed IP with clean Tor restart"
            else:
                error("Failed to change Tor circuit via any method")
                return False
    
    # Give the network time to update
    time.sleep(5)
    
    # Verify IP change
    try:
        new_ip = check_current_ip()
        if new_ip:
            if new_ip != old_ip:
                ip_changes += 1
                current_ip = new_ip
                details = get_ip_details(new_ip)
                location = f"{details.get('city', '')}, {details.get('country', '')}" if details.get('city') and details.get('country') else details.get('country', 'Unknown')
                success(f"New IP: {new_ip} ({location})")
                if success_msg:
                    success(success_msg)
                record_ip(new_ip)
                return True
            else:
                warning(f"IP didn't change ({new_ip}), trying again...")
                # Try one more time with a clean restart
                if clean_restart_tor():
                    new_ip = check_current_ip()
                    if new_ip and new_ip != old_ip:
                        ip_changes += 1
                        current_ip = new_ip
                        details = get_ip_details(new_ip)
                        location = f"{details.get('city', '')}, {details.get('country', '')}" if details.get('city') and details.get('country') else details.get('country', 'Unknown')
                        success(f"New IP after clean restart: {new_ip} ({location})")
                        record_ip(new_ip)
                        return True
                    else:
                        warning(f"IP still didn't change after clean restart: {new_ip}")
                        return False
        else:
            warning("Failed to verify new IP")
            return False
    except Exception as e:
        error(f"Error verifying IP change: {e}")
        return False

def check_current_ip():
    """Check and display current IP address with location info"""
    global current_ip
    try:
        ip = get_current_ip()
        if ip:
            current_ip = ip
            details = get_ip_details(ip)
            location = f"{details.get('city', '')}, {details.get('country', '')}" if details.get('city') and details.get('country') else details.get('country', 'Unknown')
            
            if details.get('isp') and details.get('isp') != 'Unknown':
                success(f"Current Tor exit IP: {ip} ({location}) via {details.get('isp')}")
            else:
                success(f"Current Tor exit IP: {ip} ({location})")
            
            return ip
        else:
            error("Failed to get current IP. Check your Tor connection.")
            return None
    except Exception as e:
        error(f"Error checking IP: {e}")
        return None

def ip_changer_loop(interval_min, interval_max):
    """Continuously change IP in a background thread"""
    global stop_threads
    
    try:
        initial_ip = check_current_ip()
        if initial_ip:
            success(f"Initial IP: {initial_ip}")
        
        while not stop_threads:
            if change_ip():
                # Random interval between changes
                interval = random.randint(interval_min, interval_max)
                info(f"Next change in {interval}s")
                
                # Check for stop signal every second
                for _ in range(interval):
                    if stop_threads:
                        break
                    time.sleep(1)
            else:
                # If change failed, wait a bit and try again
                for _ in range(15):  # Wait 15 seconds before retry
                    if stop_threads:
                        break
                    time.sleep(1)
    except Exception as e:
        error(f"Error in IP changer thread: {e}")

def monitor_ip_loop():
    """Monitor IP changes in background thread"""
    global stop_threads, current_ip
    
    try:
        last_ip = get_current_ip()
        last_check = datetime.now()
        current_ip = last_ip
        
        while not stop_threads:
            time.sleep(30)  # Check every 30 seconds
            
            try:
                new_ip = get_current_ip()
                if new_ip and new_ip != last_ip:
                    # IP has changed
                    details = get_ip_details(new_ip)
                    location = f"{details.get('city', '')}, {details.get('country', '')}" if details.get('city') and details.get('country') else details.get('country', 'Unknown')
                    success(f"IP changed: {last_ip} -> {new_ip} ({location})")
                    last_ip = new_ip
                    current_ip = new_ip
                    record_ip(new_ip)
            except Exception as e:
                warning(f"Error in IP monitor: {e}")
    except Exception as e:
        error(f"Error in IP monitor thread: {e}")

#
# IP Statistics
#

def generate_ip_stats(days=7):
    """Generate and display IP change statistics"""
    if not ip_history:
        warning("No IP history found")
        return
    
    # Filter by date if requested
    filtered_history = ip_history
    if days > 0:
        cutoff_date = datetime.now() - timedelta(days=days)
        cutoff_str = cutoff_date.strftime("%Y-%m-%d %H:%M:%S")
        filtered_history = [entry for entry in ip_history if entry["timestamp"] >= cutoff_str]
    
    total_ips = len(filtered_history)
    if total_ips == 0:
        warning(f"No IP changes found in the last {days} days")
        return
    
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
    
    # Reset flag and start thread
    stop_threads = False
    ip_changer_thread = threading.Thread(
        target=ip_changer_loop,
        args=(interval_min, interval_max),
        daemon=True
    )
    
    info(f"Starting IP changer (interval: {interval_min}-{interval_max}s)")
    ip_changer_thread.start()
    success("IP changer started in background")
    info("Press Ctrl+C in the main menu to stop")
    
    return True

def stop_ip_changer_thread():
    """Stop the IP changer thread"""
    global ip_changer_thread, stop_threads
    
    if ip_changer_thread and ip_changer_thread.is_alive():
        info("Stopping IP changer...")
        stop_threads = True
        ip_changer_thread.join(2)  # Wait up to 2 seconds
        success("IP changer stopped")
        return True
    else:
        warning("IP changer is not running")
        return False

def start_ip_monitor_thread():
    """Start IP monitor in background thread"""
    global ip_monitor_thread, stop_threads
    
    if ip_monitor_thread and ip_monitor_thread.is_alive():
        warning("IP monitor is already running")
        return False
    
    if not is_tor_running():
        error("Tor is not running properly")
        return False
    
    # Reset flag and start thread
    stop_threads = False
    ip_monitor_thread = threading.Thread(
        target=monitor_ip_loop,
        daemon=True
    )
    
    info("Starting IP monitor")
    ip_monitor_thread.start()
    success("IP monitor started in background")
    
    return True

def stop_ip_monitor_thread():
    """Stop the IP monitor thread"""
    global ip_monitor_thread, stop_threads
    
    if ip_monitor_thread and ip_monitor_thread.is_alive():
        info("Stopping IP monitor...")
        stop_threads = True
        ip_monitor_thread.join(2)  # Wait up to 2 seconds
        success("IP monitor stopped")
        return True
    else:
        warning("IP monitor is not running")
        return False

#
# Security Tools
#

def scan_target_security(url):
    """Scan a target URL for security issues"""
    if not SECURITY_TOOLS_AVAILABLE:
        error("Security tools module not available")
        return None
    
    try:
        info(f"Scanning {url} for security issues...")
        # Validate URL
        parsed_url = urlparse(url)
        if not parsed_url.scheme or not parsed_url.netloc:
            error("Invalid URL. Please include the protocol (e.g., http:// or https://)")
            return None
        
        # Perform scan through Tor
        scan_results = security_tools.scan_target(url, use_tor=True)
        
        # Save results
        if not os.path.exists(SECURITY_REPORT_DIR):
            os.makedirs(SECURITY_REPORT_DIR)
        
        report_file = os.path.join(
            SECURITY_REPORT_DIR, 
            f"scan_{parsed_url.netloc}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        )
        
        with open(report_file, 'w') as f:
            json.dump(scan_results, f, indent=2)
        
        success(f"Scan completed. Report saved to {report_file}")
        return scan_results
    except Exception as e:
        error(f"Error during security scan: {e}")
        return None

def scan_target_ports(target, port_range=None):
    """Scan a target for open ports"""
    if not SECURITY_TOOLS_AVAILABLE:
        error("Security tools module not available")
        return None
    
    try:
        if port_range:
            info(f"Scanning {target} on ports {port_range}...")
        else:
            info(f"Scanning {target} on common ports...")
        
        # Perform port scan through Tor
        scan_results = security_tools.port_scan(target, port_range, use_tor=True)
        
        # Save results
        if not os.path.exists(SECURITY_REPORT_DIR):
            os.makedirs(SECURITY_REPORT_DIR)
        
        report_file = os.path.join(
            SECURITY_REPORT_DIR, 
            f"portscan_{target}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        )
        
        with open(report_file, 'w') as f:
            json.dump(scan_results, f, indent=2)
        
        success(f"Port scan completed. Report saved to {report_file}")
        return scan_results
    except Exception as e:
        error(f"Error during port scan: {e}")
        return None

def perform_security_scan(url):
    """Perform a security scan and display results"""
    results = scan_target_security(url)
    if results:
        print("\nSecurity Scan Results:")
        
        # Summary
        print(f"Target: {results.get('target', 'Unknown')}")
        print(f"Scan date: {results.get('timestamp', 'Unknown')}")
        print(f"Risk level: {results.get('risk_level', 'Unknown')}")
        
        # Findings
        if results.get('findings'):
            print("\nFindings:")
            for finding in results.get('findings'):
                severity = finding.get('severity', 'info')
                color = "RED" if severity == "high" else "YELLOW" if severity == "medium" else "BLUE"
                print(f"- {colorize(finding.get('title', 'Unknown'), color)}")
                print(f"  {finding.get('description', '')}")
                if finding.get('recommendation'):
                    print(f"  Recommendation: {finding.get('recommendation')}")
        else:
            print("\nNo security issues found.")
    
    input(colorize("\nPress Enter to continue...", "GREEN"))

#
# Interactive Menu
#

def show_security_menu():
    """Display the security tools menu"""
    while True:
        clear_screen()
        print_header("Tor Security Tools")
        
        print(colorize("1. Security Scan", "BLUE"))
        print(colorize("2. Port Scan", "BLUE"))
        print(colorize("3. View Reports", "BLUE"))
        print(colorize("0. Back to Main Menu", "RED"))
        print()
        
        choice = input(colorize("Enter your choice: ", "YELLOW"))
        
        if choice == "0":
            break
        
        elif choice == "1":
            target_url = input(colorize("Enter target URL to scan: ", "YELLOW"))
            if target_url:
                results = scan_target_security(target_url)
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
                    except Exception:
                        pass
            
            if reports:
                print("\nAvailable Reports:")
                for i, report in enumerate(reports, 1):
                    print(f"{i}. {report['target']} - {report['date']}")
                
                report_choice = input(colorize("\nEnter report number to view (or 0 to cancel): ", "YELLOW"))
                if report_choice.isdigit() and 1 <= int(report_choice) <= len(reports):
                    report_idx = int(report_choice) - 1
                    try:
                        with open(reports[report_idx]["path"], 'r') as f:
                            data = json.load(f)
                        
                        print(f"\nReport for {data.get('target', 'Unknown')}")
                        print(f"Date: {data.get('timestamp', 'Unknown')}")
                        
                        if 'findings' in data:
                            print("\nFindings:")
                            for finding in data['findings']:
                                severity = finding.get('severity', 'info')
                                color = "RED" if severity == "high" else "YELLOW" if severity == "medium" else "BLUE"
                                print(f"- {colorize(finding.get('title', 'Unknown'), color)}")
                                print(f"  {finding.get('description', '')}")
                        elif 'open_ports' in data:
                            print("\nOpen ports:")
                            for port, service in data['open_ports'].items():
                                print(f"- {port}/tcp: {service}")
                    except Exception as e:
                        error(f"Error reading report: {e}")
            else:
                print("No reports found.")
            
            input(colorize("\nPress Enter to continue...", "GREEN"))

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
        print(colorize("9. Clean Restart Tor (Kill All Processes)", "BLUE"))
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
                if not is_tor_running():
                    error("Tor is not running properly")
                    if restart_tor_service():
                        success("Tor service restarted")
                
                interval_min = int(input(colorize("Enter minimum interval in seconds [30]: ", "YELLOW")) or "30")
                interval_max = int(input(colorize("Enter maximum interval in seconds [60]: ", "YELLOW")) or "60")
                
                start_ip_changer_thread(interval_min, interval_max)
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
            
            elif choice == "9":
                print_header("Clean Tor Restart")
                print("This will completely reset Tor by:")
                print("1. Stopping all running threads")
                print("2. Killing any processes using Tor ports")
                print("3. Stopping the Tor service")
                print("4. Killing all Tor processes")
                print("5. Starting a fresh Tor instance")
                
                confirm = input(colorize("Do you want to proceed with the complete Tor reset? (y/n): ", "YELLOW")).lower()
                if confirm == "y":
                    if clean_restart_tor():
                        success("Tor has been completely reset and is running with a fresh IP")
                    else:
                        error("Failed to reset Tor properly. Try manually with 'sudo systemctl restart tor'")
                input(colorize("Press Enter to continue...", "GREEN"))
            
            elif choice.upper() == "S":
                show_security_menu()
            
            elif choice == "0":
                # Clean exit
                stop_ip_changer_thread()
                stop_ip_monitor_thread()
                clear_screen()
                success("Thank you for using Tor IP Suite!")
                return
            
        except KeyboardInterrupt:
            # Handle Ctrl+C in menu
            print("\nOperation cancelled")
            stop_ip_changer_thread()
            stop_ip_monitor_thread()
            input(colorize("Press Enter to continue...", "GREEN"))
        except Exception as e:
            error(f"Error: {e}")
            input(colorize("Press Enter to continue...", "GREEN"))

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
    parser.add_argument("--clean-restart", action="store_true", help="Completely reset Tor service")
    
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
                    error("Exiting due to Tor connectivity issues")
                    return 1
        else:
            warning("Failed to restart Tor service. Attempting clean restart...")
            if clean_restart_tor():
                success("Tor has been completely reset and is now running")
            else:
                error("Failed to start Tor service")
                print("\nTry manually with: sudo systemctl restart tor")
                print("If that doesn't work, check Tor is installed: sudo apt install tor")
                return 1
    
    # Handle command line arguments
    if args.configure_tor:
        print_header("Tor Authentication Configuration")
        password, password_hash = setup_tor_password()
        if password and password_hash:
            print("\nTo configure Tor, add the following to /etc/tor/torrc:")
            print(colorize(f"HashedControlPassword {password_hash}", "CYAN"))
            print("\nThen restart Tor with: sudo systemctl restart tor")
            print(f"Your plaintext password is: {colorize(password, 'GREEN')}")
            return 0
    elif args.clean_restart:
        if clean_restart_tor():
            success("Tor has been completely reset and is now running")
            return 0
        else:
            error("Failed to reset Tor")
            return 1
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
