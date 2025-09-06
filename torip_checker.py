#!/usr/bin/env python3
"""
Enhanced Tor IP Checker - Get your current Tor IP details
This script checks your current Tor IP and provides detailed information.
Run this alongside the main IP changer script.
"""

import os
import sys
import json
import argparse
import textwrap
import subprocess
from datetime import datetime

# Try importing required packages
try:
    import requests
except ImportError:
    print("[!] Missing required packages. Installing...")
    subprocess.check_call([
        sys.executable, "-m", "pip", "install", 
        "--quiet", "--disable-pip-version-check", 
        "requests"
    ])
    print("[+] Required packages installed successfully")
    import requests

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

def colorize(text, color):
    """Add color to terminal output if supported"""
    if os.environ.get("NO_COLOR") or not sys.stdout.isatty():
        return text
    color_code = COLORS.get(color.upper(), "")
    return f"{color_code}{text}{COLORS['RESET']}"

def get_tor_ip():
    """Get current Tor IP and details"""
    proxy = {
        'http': 'socks5h://127.0.0.1:9050',
        'https': 'socks5h://127.0.0.1:9050',
    }
    
    # Try backup ports if primary fails
    backup_ports = [9150, 9050]
    
    for port in backup_ports:
        try:
            proxy = {
                'http': f'socks5h://127.0.0.1:{port}',
                'https': f'socks5h://127.0.0.1:{port}',
            }
            
            # Get basic IP info
            ip_response = requests.get('https://api.ipify.org', proxies=proxy, timeout=10)
            if ip_response.status_code == 200:
                ip = ip_response.text.strip()
                print(colorize(f"[+] Current Tor IP: {ip}", "GREEN"))
                
                # Get detailed IP info
                try:
                    details_response = requests.get(f'https://ipinfo.io/{ip}/json', proxies=proxy, timeout=10)
                    if details_response.status_code == 200:
                        details = details_response.json()
                        
                        # Format and display the details
                        print(colorize("============ IP Details ============", "BLUE"))
                        print(colorize(f"Country: {details.get('country', 'Unknown')}", "CYAN"))
                        print(colorize(f"Region: {details.get('region', 'Unknown')}", "CYAN"))
                        print(colorize(f"City: {details.get('city', 'Unknown')}", "CYAN"))
                        
                        if 'loc' in details:
                            print(colorize(f"Location: {details['loc']}", "CYAN"))
                            
                        print(colorize(f"ISP/Org: {details.get('org', 'Unknown')}", "CYAN"))
                        print(colorize(f"Timezone: {details.get('timezone', 'Unknown')}", "CYAN"))
                        print(colorize("===================================", "BLUE"))
                        
                        # Save to history file
                        save_to_history(ip, details)
                        
                        return True
                except Exception as e:
                    print(colorize(f"[!] Could not get IP details: {e}", "YELLOW"))
                    return True
                
                return True
        except Exception:
            if port == backup_ports[-1]:
                print(colorize("[!] Failed to connect to Tor. Is Tor running?", "RED"))
                print(colorize("    Try starting the IP changer first.", "YELLOW"))
            continue
    
    return False

def save_to_history(ip, details):
    """Save IP change to history file"""
    history_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "ip_history")
    
    # Create directory if it doesn't exist
    if not os.path.exists(history_dir):
        os.makedirs(history_dir)
    
    # Create a record with timestamp
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    record = {
        "timestamp": timestamp,
        "ip": ip,
        **details
    }
    
    # Save to daily file
    daily_file = os.path.join(history_dir, f"{datetime.now().strftime('%Y-%m-%d')}.json")
    
    try:
        # Read existing records if file exists
        if os.path.exists(daily_file):
            with open(daily_file, 'r') as f:
                try:
                    records = json.load(f)
                except json.JSONDecodeError:
                    records = []
        else:
            records = []
        
        # Append new record
        records.append(record)
        
        # Write back to file
        with open(daily_file, 'w') as f:
            json.dump(records, f, indent=2)
            
        print(colorize(f"[+] IP record saved to {daily_file}", "GREEN"))
    except Exception as e:
        print(colorize(f"[!] Could not save to history: {e}", "YELLOW"))

def parse_arguments():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        description="Tor IP Checker - Get your current Tor IP details",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""
        Examples:
          python torip_checker.py    # Check current Tor IP
        """)
    )
    
    return parser.parse_args()

def main():
    """Main function"""
    # Print welcome message
    print(colorize("="*60, "BLUE"))
    print(colorize("Tor IP Checker - Get your current Tor IP details", "GREEN"))
    print(colorize("="*60, "BLUE"))
    
    # Parse arguments
    parse_arguments()
    
    # Get Tor IP
    get_tor_ip()
    
    return 0

if __name__ == "__main__":
    sys.exit(main())
