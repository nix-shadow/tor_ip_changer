#!/usr/bin/env python3
"""
Tor IP Changer
This script changes your IP address regularly using the Tor network.

Features:
- Auto-detects and auto-installs required packages
- Automatically configures Tor service if needed
- Falls back to user-space Tor if system Tor isn't accessible
- Changes IP address every 5-10 seconds (respecting Tor's rate limits)
- Provides real-time feedback on IP changes
"""

import os
import sys
import time
import random
import signal
import subprocess
import importlib.util
import platform
import re
import shutil
import argparse
import textwrap
from pathlib import Path

# Try importing required packages
try:
    import requests
    import stem
    from stem import Signal
    from stem.control import Controller
except ImportError:
    print("[!] Missing required packages. Installing...")
    subprocess.check_call([
        sys.executable, "-m", "pip", "install", 
        "--quiet", "--disable-pip-version-check", 
        "requests", "stem", "PySocks"
    ])
    print("[+] Required packages installed successfully")
    import requests
    import stem
    from stem import Signal
    from stem.control import Controller

# ANSI colors for terminal output
COLORS = {
    "RED": "\033[91m",
    "GREEN": "\033[92m",
    "YELLOW": "\033[93m",
    "BLUE": "\033[94m",
    "PURPLE": "\033[95m",
    "CYAN": "\033[96m",
    "WHITE": "\033[97m",
    "RESET": "\033[0m",
    "BOLD": "\033[1m",
}

# Default port configurations
DEFAULT_SYS_SOCKS_PORT = 9050
DEFAULT_SYS_CTRL_PORT = 9051
DEFAULT_USER_SOCKS_PORT = 9150
DEFAULT_USER_CTRL_PORT = 9151

def colorize(text, color):
    """Add color to terminal output if supported"""
    if os.environ.get("NO_COLOR") or not sys.stdout.isatty():
        return text
    color_code = COLORS.get(color.upper(), "")
    return f"{color_code}{text}{COLORS['RESET']}"

def info(msg):
    """Print an informational message"""
    print(colorize(f"[*] {msg}", "BLUE"))

def success(msg):
    """Print a success message"""
    print(colorize(f"[+] {msg}", "GREEN"))

def warning(msg):
    """Print a warning message"""
    print(colorize(f"[!] {msg}", "YELLOW"))

def error(msg):
    """Print an error message"""
    print(colorize(f"[!] {msg}", "RED"))

def check_dependencies():
    """Check and install required dependencies"""
    packages_to_install = []
    
    # Check Python packages
    required_packages = ["requests", "stem"]
    for package in required_packages:
        if importlib.util.find_spec(package.lower()) is None:
            packages_to_install.append(package)
    
    if packages_to_install:
        info(f"Installing required Python packages: {', '.join(packages_to_install)}")
        try:
            subprocess.check_call([
                sys.executable, "-m", "pip", "install", "--quiet", "--disable-pip-version-check", 
                *packages_to_install
            ])
            success("Required Python packages installed successfully")
        except subprocess.CalledProcessError as e:
            error(f"Failed to install Python packages: {e}")
            info("Please run manually: pip install requests stem PySocks")
            return False
    
    # Check for Tor
    if not shutil.which("tor"):
        error("Tor is not installed")
        if platform.system() == "Linux":
            # Try to detect Linux distribution
            distro = "unknown"
            if os.path.exists("/etc/os-release"):
                with open("/etc/os-release") as f:
                    for line in f:
                        if line.startswith("ID="):
                            distro = line.split("=")[1].strip().strip('"')
                            break
            
            if distro in ["debian", "ubuntu", "kali"]:
                info("Attempting to install Tor...")
                try:
                    subprocess.check_call(["sudo", "apt-get", "update", "-qq"])
                    subprocess.check_call(["sudo", "apt-get", "install", "-y", "tor"])
                    success("Tor installed successfully")
                except subprocess.CalledProcessError:
                    error("Failed to install Tor. Please install it manually.")
                    info("For Debian/Ubuntu/Kali: sudo apt-get install tor")
                    return False
            else:
                info(f"Please install Tor for your {distro} distribution")
                return False
        else:
            info("Please install Tor for your operating system")
            return False
    
    return True

def is_tor_service_active():
    """Check if Tor service is active (Linux only)"""
    if platform.system() != "Linux":
        return False
    
    try:
        result = subprocess.run(
            ["systemctl", "is-active", "tor"], 
            capture_output=True, 
            text=True,
            check=False
        )
        return result.stdout.strip() == "active"
    except (subprocess.SubprocessError, FileNotFoundError):
        return False

def is_port_listening(port):
    """Check if a port is open and listening"""
    try:
        if platform.system() == "Linux":
            cmd = ["ss", "-tln"]
        elif platform.system() == "Darwin":  # macOS
            cmd = ["netstat", "-an"]
        else:  # Windows or other
            cmd = ["netstat", "-an"]
        
        result = subprocess.run(cmd, capture_output=True, text=True, check=False)
        pattern = fr"(127\.0\.0\.1|localhost)[\:\.]{port}\b"
        return bool(re.search(pattern, result.stdout))
    except Exception:
        return False

def configure_tor_if_needed():
    """Configure Tor if needed and return success status"""
    # Only for Linux systems
    if platform.system() != "Linux":
        return True
    
    # Find torrc
    tor_config_path = "/etc/tor/torrc"
    if not os.path.exists(tor_config_path):
        warning(f"Could not locate Tor configuration at {tor_config_path}")
        return False
    
    # Check if Tor is already properly configured
    needed_settings = [
        "ControlPort 9051",
        "CookieAuthentication 1"
    ]
    
    missing_settings = []
    try:
        with open(tor_config_path, 'r') as f:
            content = f.read()
            for setting in needed_settings:
                if not re.search(rf"^\s*{re.escape(setting)}", content, re.MULTILINE):
                    missing_settings.append(setting)
    except Exception as e:
        error(f"Error reading Tor config: {e}")
        return False
    
    if not missing_settings:
        return True
    
    # Needs configuration changes
    info(f"Tor configuration at {tor_config_path} needs updates")
    try:
        # Make backup
        backup_path = f"{tor_config_path}.backup.{int(time.time())}"
        shutil.copy2(tor_config_path, backup_path)
        success(f"Created backup at {backup_path}")
        
        # Add needed settings
        with open(tor_config_path, 'a') as f:
            f.write("\n# Added by Tor IP Changer\n")
            for setting in missing_settings:
                f.write(f"{setting}\n")
        
        success("Updated Tor configuration")
        
        # Restart Tor service
        info("Restarting Tor service...")
        try:
            subprocess.run(["sudo", "systemctl", "restart", "tor"], check=True)
            success("Tor service restarted")
            time.sleep(3)  # Give Tor time to start up
            return True
        except subprocess.CalledProcessError:
            error("Failed to restart Tor service. You may need to restart it manually.")
            info("Run: sudo systemctl restart tor")
            return False
    except Exception as e:
        error(f"Failed to update Tor configuration: {e}")
        return False

class TorIpChanger:
    def __init__(self, min_interval=5, max_interval=10,
                 socks_port=None, control_port=None, user_tor=False):
        # Enforce Tor's ~10s NEWNYM rate limit to avoid ignored signals
        self.min_interval = max(10, int(min_interval))
        self.max_interval = max(self.min_interval, int(max_interval))

        self.control_port = control_port or DEFAULT_SYS_CTRL_PORT
        self.socks_port = socks_port or DEFAULT_SYS_SOCKS_PORT
        self.tor_proxy = {
            'http': f'socks5h://127.0.0.1:{self.socks_port}',
            'https': f'socks5h://127.0.0.1:{self.socks_port}',
        }

        self.running = True
        self.change_count = 0
        self.last_newnym_ts = 0.0
        self.force_user_tor = user_tor

        # User-space tor management
        self._tor_proc = None
        self._tor_data_dir = Path(__file__).parent.joinpath(".tor-data")

    def setup_signal_handling(self):
        """Setup signal handling for clean exit"""
        signal.signal(signal.SIGINT, self.exit_gracefully)
        signal.signal(signal.SIGTERM, self.exit_gracefully)

    def exit_gracefully(self, signum, frame):
        """Handle exit signals gracefully"""
        print("\n[!] Stopping IP changer...")
        self.running = False

    def get_current_ip(self):
        """Get the current public IP address"""
        urls = [
            'https://api.ipify.org',
            'https://ifconfig.me/ip',
            'https://icanhazip.com',
            'https://ident.me',
        ]
        
        for url in urls:
            try:
                response = requests.get(url, proxies=self.tor_proxy, timeout=20)
                if response.status_code == 200:
                    ip = response.text.strip()
                    if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", ip):
                        return ip
            except requests.RequestException:
                continue
        
        error("Failed to get current IP address from any service")
        return "Unknown"

    def change_ip(self):
        """Change the IP address by sending NEWNYM signal to Tor"""
        try:
            # Respect Tor's minimum interval between NEWNYM requests
            now = time.time()
            since_last = now - self.last_newnym_ts
            if since_last < 10:
                wait = 10 - since_last
                if wait > 0:
                    info(f"Waiting {wait:.1f}s to respect Tor's NEWNYM rate limit...")
                    time.sleep(wait)

            with Controller.from_port(port=self.control_port) as controller:
                # Try cookie authentication first (default for system Tor)
                try:
                    controller.authenticate()
                except stem.connection.AuthenticationFailure:
                    # For user Tor instances, look for a cookie file in our data directory
                    cookie_file = self._tor_data_dir / "control_auth_cookie"
                    if cookie_file.exists():
                        controller.authenticate(cookie_path=str(cookie_file))
                    else:
                        raise
                
                controller.signal(Signal.NEWNYM)
                self.last_newnym_ts = time.time()
                success("Requested new Tor circuit (NEWNYM)")
                return True
        except stem.SocketError as e:
            error(f"Error connecting to Tor controller: {e}")
            warning("Make sure Tor is running and ControlPort is enabled")
            return False
        except stem.connection.AuthenticationFailure:
            error("Authentication failed - check your Tor configuration")
            return False
        except Exception as e:
            error(f"Unexpected error changing Tor circuit: {e}")
            return False

    def start_user_tor(self):
        """Start a local Tor instance for this user"""
        info("Launching a local Tor instance (no sudo required)...")
        tor_cmd = [
            "tor",
            "--RunAsDaemon", "0",
            "--SocksPort", f"127.0.0.1:{DEFAULT_USER_SOCKS_PORT}",
            "--ControlPort", f"127.0.0.1:{DEFAULT_USER_CTRL_PORT}",
            "--CookieAuthentication", "1",
            "--CookieAuthFileGroupReadable", "1",
            "--DataDirectory", str(self._tor_data_dir),
        ]

        try:
            self._tor_data_dir.mkdir(parents=True, exist_ok=True)
            # Start tor and give it a moment to bootstrap
            self._tor_proc = subprocess.Popen(
                tor_cmd, 
                stdout=subprocess.PIPE, 
                stderr=subprocess.STDOUT, 
                text=True
            )
            
            # Wait up to ~30 seconds for ports to open
            for i in range(60):
                time.sleep(0.5)
                if i % 10 == 0 and i > 0:
                    info(f"Waiting for Tor to bootstrap ({i//2}s)...")
                
                if (is_port_listening(DEFAULT_USER_SOCKS_PORT) and 
                    is_port_listening(DEFAULT_USER_CTRL_PORT)):
                    break
            else:
                error("Failed to launch local Tor instance (ports didn't open)")
                self._cleanup_tor()
                return False

            self.socks_port = DEFAULT_USER_SOCKS_PORT
            self.control_port = DEFAULT_USER_CTRL_PORT
            self.tor_proxy = {
                'http': f'socks5h://127.0.0.1:{self.socks_port}',
                'https': f'socks5h://127.0.0.1:{self.socks_port}',
            }
            success(f"Local Tor instance is running on 127.0.0.1:{self.socks_port} (SOCKS) and 127.0.0.1:{self.control_port} (Control)")
            return True
        except FileNotFoundError:
            error("'tor' command not found. Please install Tor.")
            return False
        except Exception as e:
            error(f"Error launching local Tor: {e}")
            return False

    def ensure_tor_running(self):
        """Ensure Tor control is available; else launch a local Tor instance.

        Preference order:
        1) Use system Tor if both SocksPort and ControlPort are available (9050/9051)
        2) Otherwise, start a user-space Tor on alternate ports (9150/9151)
        """
        # First check if system tor is active and ports are listening
        sys_active = is_tor_service_active()
        
        sys_socks_ok = is_port_listening(DEFAULT_SYS_SOCKS_PORT)
        sys_ctrl_ok = is_port_listening(DEFAULT_SYS_CTRL_PORT)

        if sys_active and sys_socks_ok and sys_ctrl_ok:
            # Use system ports, but verify we can authenticate
            self.socks_port = DEFAULT_SYS_SOCKS_PORT
            self.control_port = DEFAULT_SYS_CTRL_PORT
            self.tor_proxy = {
                'http': f'socks5h://127.0.0.1:{self.socks_port}',
                'https': f'socks5h://127.0.0.1:{self.socks_port}',
            }
            try:
                with Controller.from_port(port=self.control_port) as controller:
                    controller.authenticate()  # cookie auth expected
                print("[*] Using system Tor (ports 9050/9051)")
                return True
            except stem.connection.AuthenticationFailure:
                print("[!] System Tor control port is not accessible to this user (cookie auth failed). Falling back to a local Tor instance.")
                # Fall through to local launch
            except Exception as e:
                print(f"[!] Failed to verify system Tor control port: {e}. Falling back to a local Tor instance.")

        # Try to start a local tor instance for this user
        print("[*] Launching a local Tor instance (no sudo required)...")
        tor_cmd = [
            "tor",
            "--RunAsDaemon", "0",
            "--SocksPort", f"127.0.0.1:{DEFAULT_USER_SOCKS_PORT}",
            "--ControlPort", f"127.0.0.1:{DEFAULT_USER_CTRL_PORT}",
            "--CookieAuthentication", "1",
            "--CookieAuthFileGroupReadable", "1",
            "--DataDirectory", str(self._tor_data_dir),
        ]

        try:
            self._tor_data_dir.mkdir(parents=True, exist_ok=True)
            # Start tor and give it a moment to bootstrap
            self._tor_proc = subprocess.Popen(tor_cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            # Wait up to ~25 seconds for ports to open
            for _ in range(50):
                time.sleep(0.5)
                if is_port_listening(DEFAULT_USER_SOCKS_PORT) and is_port_listening(DEFAULT_USER_CTRL_PORT):
                    break
            else:
                print("[!] Failed to launch local Tor instance (ports didn't open)")
                return False

            self.socks_port = DEFAULT_USER_SOCKS_PORT
            self.control_port = DEFAULT_USER_CTRL_PORT
            self.tor_proxy = {
                'http': f'socks5h://127.0.0.1:{self.socks_port}',
                'https': f'socks5h://127.0.0.1:{self.socks_port}',
            }
            print("[+] Local Tor instance is running on 127.0.0.1:9150 (SOCKS) and 127.0.0.1:9151 (Control)")
            return True
        except FileNotFoundError:
            print("[!] 'tor' command not found. Please install Tor or run the setup script.")
            return False
        except Exception as e:
            print(f"[!] Error launching local Tor: {e}")
            return False

    def _cleanup_tor(self):
        """Stop local Tor instance if we started one."""
        if self._tor_proc and self._tor_proc.poll() is None:
            try:
                self._tor_proc.terminate()
                try:
                    self._tor_proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    self._tor_proc.kill()
            except Exception:
                pass

    def run(self):
        """Run the IP changer loop"""
        self.setup_signal_handling()
        
        if not self.ensure_tor_running():
            print("[!] Cannot proceed without Tor service")
            return

        print("[*] Starting Tor IP Changer")
        print("[*] Press Ctrl+C to stop")
        if self.min_interval < 10:
            print("[!] Note: Tor rate-limits NEWNYM to ~10s. Enforcing 10s minimum between changes.")
        
        initial_ip = self.get_current_ip()
        print(f"[*] Initial IP address: {initial_ip}")
        
        while self.running:
            try:
                # Random interval between changes
                interval = random.uniform(self.min_interval, self.max_interval)
                print(f"[*] Waiting {interval:.1f} seconds before next change...")
                time.sleep(interval)
                
                if self.change_ip():
                    time.sleep(1)  # Brief pause to allow circuit change to take effect
                    new_ip = self.get_current_ip()
                    self.change_count += 1
                    print(f"[+] New IP address: {new_ip} (Change #{self.change_count})")
            except Exception as e:
                print(f"[!] Unexpected error: {e}")
                time.sleep(5)  # Wait a bit before retrying
        
        print(f"[*] IP address changed {self.change_count} times. Exiting.")
        self._cleanup_tor()

if __name__ == "__main__":
    print("="*50)
    print("Tor IP Changer - Change your IP every ~10 seconds")
    print("="*50)
    
    changer = TorIpChanger()
    changer.run()
