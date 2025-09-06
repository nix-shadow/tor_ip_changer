#!/usr/bin/env python3
"""
Tor IP Suite - Streamlined Tool for IP Changing through Tor
A simplified tool for anonymity and IP rotation through Tor
"""

import os
import sys
import time
import json
import signal
import random
import platform
import subprocess
import threading
import socket
import requests
import argparse
from datetime import datetime, timedelta
from collections import Counter
from stem import Signal
from stem.control import Controller

VERSION = "4.0.0"

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

# Configuration
DEFAULT_SOCKS_PORT = 9050
DEFAULT_CTRL_PORT = 9051
IP_HISTORY_FILE = os.path.expanduser("~/.tor_ip_history.json")

# Global variables
stop_threads = False
ip_changer_thread = None
ip_monitor_thread = None
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

def clear_screen():
    """Clear the terminal screen"""
    os.system('cls' if os.name == 'nt' else 'clear')

def print_header(title):
    """Print a formatted header"""
    print(colorize("=" * 60, "CYAN"))
    print(colorize(f"  {title}", "CYAN"))
    print(colorize("=" * 60, "CYAN"))

#
# IP History Functions
#

def load_ip_history():
    """Load IP history from file"""
    global ip_history
    try:
        if os.path.exists(IP_HISTORY_FILE):
            with open(IP_HISTORY_FILE, 'r') as f:
                ip_history = json.load(f)
    except Exception as e:
        warning(f"Failed to load IP history: {e}")

def save_ip_history():
    """Save IP history to file"""
    try:
        with open(IP_HISTORY_FILE, 'w') as f:
            json.dump(ip_history, f, indent=2)
    except Exception as e:
        warning(f"Failed to save IP history: {e}")

def record_ip(ip):
    """Record an IP change in history"""
    global ip_history
    try:
        # Get basic IP details
        details = get_ip_details(ip)
        
        # Create history entry
        entry = {
            "ip": ip,
            "timestamp": datetime.now().isoformat(),
            "country": details.get("country", "Unknown"),
            "country_code": details.get("country_code", "XX"),
            "region": details.get("region", "Unknown"),
            "city": details.get("city", "Unknown"),
            "isp": details.get("isp", "Unknown")
        }
        
        # Add to history and save
        ip_history.append(entry)
        save_ip_history()
    except Exception as e:
        warning(f"Failed to record IP: {e}")

#
# Tor Functions
#

def get_tor_session():
    """Create a requests session that routes through Tor"""
    session = requests.session()
    # Tor uses the 9050 port as the default socks port
    session.proxies = {
        'http': f'socks5h://127.0.0.1:{DEFAULT_SOCKS_PORT}',
        'https': f'socks5h://127.0.0.1:{DEFAULT_SOCKS_PORT}'
    }
    return session

def is_tor_running():
    """Check if Tor is running"""
    try:
        # Try to connect to the Tor SOCKS port
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
        
        return False
    except Exception as e:
        warning(f"Error checking Tor status: {e}")
        return False

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
        f"https://ipapi.co/{ip}/json/",
        f"https://ipinfo.io/{ip}/json",
        f"https://freegeoip.app/json/{ip}",
        f"https://extreme-ip-lookup.com/json/{ip}"
    ]
    
    for service_url in services:
        try:
            with get_tor_session() as session:
                response = session.get(service_url, timeout=5)
                if response.status_code == 200:
                    data = response.json()
                    
                    # Normalize response data to a common format
                    ip_details = {
                        "ip": ip,
                        "country": data.get("country_name", data.get("country", "Unknown")),
                        "country_code": data.get("country_code", data.get("countryCode", "XX")),
                        "region": data.get("region", data.get("regionName", data.get("region_name", "Unknown"))),
                        "city": data.get("city", "Unknown"),
                        "isp": data.get("org", data.get("isp", "Unknown")),
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

def restart_tor_service():
    """Restart the Tor service - safer approach"""
    try:
        if platform.system() == "Linux":
            warning("Attempting to restart Tor service")
            
            # ONLY restart the Tor service using systemctl - DO NOT kill processes directly
            if os.path.exists("/bin/systemctl") or os.path.exists("/usr/bin/systemctl"):
                result = subprocess.run(
                    ["sudo", "systemctl", "restart", "tor.service"], 
                    capture_output=True, 
                    text=True
                )
                if result.returncode == 0:
                    success("Successfully restarted Tor service via systemctl")
                    time.sleep(7)  # Give Tor time to initialize
                    return True
                else:
                    warning(f"systemctl restart failed: {result.stderr}")
            
            # Try init.d if systemd is not available
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
            
            # As a last resort, only if the user confirms
            else:
                warning("Could not find systemd or init.d service for Tor")
                warning("Manual Tor restart might be needed")
                return False
    except Exception as e:
        error(f"Failed to restart Tor service: {e}")
    
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
            success(f"Current IP: {ip} ({location})")
            return ip
        else:
            error("Failed to get current IP. Check Tor connection.")
            return None
    except Exception as e:
        error(f"Error checking IP: {e}")
        return None

def change_ip():
    """Change the Tor exit node IP address - safer approach"""
    global ip_changes, current_ip
    old_ip = current_ip or get_current_ip()
    
    # Check if Tor is running
    if not is_tor_running():
        warning("Tor is not running, attempting to restart")
        restart_tor_service()
        if not is_tor_running():
            error("Tor service couldn't be started. Please check Tor installation.")
            return False
    
    # Try to change the circuit using the controller
    success_msg = None
    try:
        with Controller.from_port(port=DEFAULT_CTRL_PORT) as controller:
            # Simple authentication approach
            try:
                # Try with no password first
                controller.authenticate()
            except Exception:
                try:
                    # Try with cookie authentication
                    controller.authenticate(path="/run/tor/control.authcookie")
                except Exception:
                    # Just restart the service if authentication fails
                    raise Exception("Authentication failed")
            
            # Try to send the NEWNYM signal
            try:
                controller.signal(Signal.NEWNYM)
                success_msg = "Successfully changed Tor circuit"
            except Exception as e:
                if "unrecognized status code: 514" in str(e):
                    # Try direct command if signal fails
                    controller._handler.send("SIGNAL NEWNYM\r\n")
                    response = controller._handler.recv()
                    if "250" in response:
                        success_msg = "Successfully changed Tor circuit via direct command"
                    else:
                        raise Exception(f"Direct command failed: {response}")
                else:
                    raise
    except Exception as e:
        warning(f"Controller method failed: {e}")
        # Restart Tor service as fallback
        warning("Restarting Tor service to change IP")
        if restart_tor_service():
            success_msg = "Changed IP by restarting Tor service"
        else:
            error("Failed to change Tor circuit or restart service")
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
                warning(f"IP didn't change ({new_ip}), trying again with service restart")
                # Try restarting the service if IP didn't change
                if restart_tor_service():
                    time.sleep(5)
                    new_ip = check_current_ip()
                    if new_ip and new_ip != old_ip:
                        ip_changes += 1
                        current_ip = new_ip
                        details = get_ip_details(new_ip)
                        location = f"{details.get('city', '')}, {details.get('country', '')}" if details.get('city') and details.get('country') else details.get('country', 'Unknown')
                        success(f"New IP after restart: {new_ip} ({location})")
                        record_ip(new_ip)
                        return True
                    else:
                        warning(f"IP still didn't change after restart: {new_ip}")
                        return False
        else:
            warning("Failed to verify new IP")
            return False
    except Exception as e:
        error(f"Error verifying IP change: {e}")
        return False

#
# Thread Functions
#

def ip_changer_worker(interval_min, interval_max):
    """Background worker for changing IP at intervals"""
    global stop_threads
    
    while not stop_threads:
        if change_ip():
            # Random interval for next change
            interval = random.randint(interval_min, interval_max)
            info(f"Next change in {interval}s")
            
            # Wait for the interval, checking for stop signal
            wait_start = time.time()
            while time.time() - wait_start < interval and not stop_threads:
                time.sleep(0.5)
        else:
            # If change failed, wait a bit and try again
            time.sleep(5)

def ip_monitor_worker():
    """Background worker for monitoring IP changes"""
    global stop_threads, current_ip
    
    # Initial IP check
    current_ip = current_ip or get_current_ip()
    if current_ip:
        success(f"Initial IP: {current_ip}")
    
    last_ip = current_ip
    
    while not stop_threads:
        try:
            ip = get_current_ip()
            if ip and ip != last_ip:
                details = get_ip_details(ip)
                location = f"{details.get('city', '')}, {details.get('country', '')}" if details.get('city') and details.get('country') else details.get('country', 'Unknown')
                success(f"New IP detected: {ip} ({location})")
                current_ip = ip
                last_ip = ip
                record_ip(ip)
        except Exception as e:
            warning(f"Error in IP monitor: {e}")
        
        # Check every 30 seconds
        time.sleep(30)

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
    info(f"Starting IP changer (interval: {interval_min}-{interval_max}s)")
    ip_changer_thread = threading.Thread(
        target=ip_changer_worker,
        args=(interval_min, interval_max),
        daemon=True
    )
    ip_changer_thread.start()
    success("IP changer started in background")
    info("Press Ctrl+C in the main menu to stop")
    return True

def stop_ip_changer_thread():
    """Stop the IP changer thread"""
    global ip_changer_thread, stop_threads
    
    if not ip_changer_thread or not ip_changer_thread.is_alive():
        warning("IP changer is not running")
        return False
    
    info("Stopping IP changer...")
    stop_threads = True
    ip_changer_thread.join(timeout=2)
    ip_changer_thread = None
    success("IP changer stopped")
    return True

def start_ip_monitor_thread():
    """Start IP monitor in background thread"""
    global ip_monitor_thread, stop_threads
    
    if ip_monitor_thread and ip_monitor_thread.is_alive():
        warning("IP monitor is already running")
        return False
    
    if not is_tor_running():
        error("Tor is not running properly")
        return False
    
    stop_threads = False
    info("Starting IP monitor")
    ip_monitor_thread = threading.Thread(
        target=ip_monitor_worker,
        daemon=True
    )
    ip_monitor_thread.start()
    success("IP monitor started in background")
    return True

def stop_ip_monitor_thread():
    """Stop the IP monitor thread"""
    global ip_monitor_thread, stop_threads
    
    if not ip_monitor_thread or not ip_monitor_thread.is_alive():
        warning("IP monitor is not running")
        return False
    
    info("Stopping IP monitor...")
    stop_threads = True
    ip_monitor_thread.join(timeout=2)
    ip_monitor_thread = None
    success("IP monitor stopped")
    return True

#
# Statistics Functions
#

def generate_ip_stats(days=7):
    """Generate and display IP statistics"""
    global ip_history
    
    if not ip_history:
        error("No IP history available")
        return
    
    # Filter by date if specified
    filtered_history = ip_history
    if days > 0:
        cutoff_date = datetime.now() - timedelta(days=days)
        filtered_history = [
            entry for entry in ip_history 
            if datetime.fromisoformat(entry["timestamp"]) > cutoff_date
        ]
    
    if not filtered_history:
        error(f"No IP history available for the last {days} days")
        return
    
    # Generate statistics
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
        
        print(colorize(f"● Current IP: {current_ip or 'Unknown'}", "CYAN"))
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
        print(colorize("8. Safely Restart Tor Service", "BLUE"))
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
                if not changer_running and not monitor_running:
                    interval_min = int(input(colorize("Enter minimum interval in seconds [30]: ", "YELLOW")) or "30")
                    interval_max = int(input(colorize("Enter maximum interval in seconds [60]: ", "YELLOW")) or "60")
                    
                    # Start both services
                    if start_ip_changer_thread(interval_min, interval_max):
                        start_ip_monitor_thread()
                else:
                    if changer_running:
                        warning("IP changer is already running")
                    if monitor_running:
                        warning("IP monitor is already running")
                input(colorize("Press Enter to continue...", "GREEN"))
            
            elif choice == "8":
                print_header("Tor Service Restart")
                print("This will safely restart the Tor service only, without affecting other processes.")
                confirm = input(colorize("Safely restart Tor service? (y/n): ", "YELLOW")).lower()
                if confirm == "y":
                    if restart_tor_service():
                        success("Tor service has been safely restarted")
                        check_current_ip()
                    else:
                        error("Failed to restart Tor service")
                input(colorize("Press Enter to continue...", "GREEN"))
            
            elif choice == "0":
                # Stop background threads before exiting
                stop_threads = True
                if ip_changer_thread and ip_changer_thread.is_alive():
                    ip_changer_thread.join(timeout=1)
                if ip_monitor_thread and ip_monitor_thread.is_alive():
                    ip_monitor_thread.join(timeout=1)
                break
            
            else:
                warning("Invalid choice")
                input(colorize("Press Enter to continue...", "GREEN"))
        
        except KeyboardInterrupt:
            # Handle Ctrl+C in the menu
            stop_threads = True
            if ip_changer_thread and ip_changer_thread.is_alive():
                ip_changer_thread.join(timeout=1)
            if ip_monitor_thread and ip_monitor_thread.is_alive():
                ip_monitor_thread.join(timeout=1)
            break
        except Exception as e:
            error(f"An error occurred: {e}")
            input(colorize("Press Enter to continue...", "GREEN"))

#
# Main Function
#

def main():
    """Main function"""
    parser = argparse.ArgumentParser(description=f"Tor IP Suite v{VERSION} - A tool for IP changing through Tor")
    
    parser.add_argument("--check", action="store_true", help="Check current Tor IP")
    parser.add_argument("--change", action="store_true", help="Change Tor IP once")
    parser.add_argument("--interval", type=str, help="IP change interval in seconds (format: MIN-MAX)")
    parser.add_argument("--stats", action="store_true", help="View IP statistics")
    parser.add_argument("--days", type=int, default=7, help="Number of days for statistics")
    
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
                
                # Ask if user wants to continue anyway
                response = input(colorize("Continue anyway with limited functionality? (y/n): ", "YELLOW"))
                if response.lower() != 'y':
                    return 1
        else:
            error("Failed to restart Tor service")
            print("\nPlease make sure Tor is installed and properly configured:")
            print("  sudo apt install tor")
            print("  sudo systemctl start tor")
            print("  sudo systemctl enable tor")
            return 1
    
    # Process command line arguments
    if args.check:
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
