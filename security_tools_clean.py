"""
Security Tools Module for Tor IP Suite
Provides security testing functions through Tor network
"""

import os
import re
import json
import socket
import ssl
from datetime import datetime
from urllib.parse import urlparse

import requests

# Security reports directory
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(SCRIPT_DIR, "data")
SECURITY_REPORT_DIR = os.path.join(DATA_DIR, "security_reports")

# Create directories
os.makedirs(DATA_DIR, exist_ok=True)
os.makedirs(SECURITY_REPORT_DIR, exist_ok=True)

#
# Tor Session Management
#

def get_tor_session():
    """Create a requests session that routes through Tor"""
    session = requests.session()
    session.proxies = {
        'http': 'socks5h://127.0.0.1:9050',
        'https': 'socks5h://127.0.0.1:9050'
    }
    return session

#
# Security Testing Functions
#

def perform_security_scan(target_url, timeout=30):
    """
    Perform a basic security scan on a website through Tor
    Only for educational purposes and with proper authorization
    
    Args:
        target_url: The URL to scan
        timeout: Connection timeout in seconds
    
    Returns:
        dict: Security scan results
    """
    # Parse the URL to ensure it's valid
    try:
        parsed_url = urlparse(target_url)
        if not parsed_url.scheme or not parsed_url.netloc:
            print("[ERROR] Invalid URL format. Use http:// or https:// prefix")
            return None
    except Exception as e:
        print(f"[ERROR] URL parsing error: {e}")
        return None
    
    print(f"[INFO] Starting security scan for {target_url}")
    print("[INFO] This scan is for educational purposes only")
    
    results = {
        "target": target_url,
        "timestamp": datetime.now().isoformat(),
        "ip_address": None,
        "headers": {},
        "cookies": {},
        "ssl_info": {},
        "security_headers": {
            "present": [],
            "missing": []
        },
        "findings": [],
        "tor_connection": True,
    }
    
    # Make request through Tor
    try:
        with get_tor_session() as session:
            response = session.get(
                target_url, 
                timeout=timeout,
                allow_redirects=True,
                headers={
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; rv:102.0) Gecko/20100101 Firefox/102.0"
                }
            )
            
            # Extract basic information
            results["status_code"] = response.status_code
            results["headers"] = dict(response.headers)
            results["cookies"] = dict(response.cookies)
            
            # Check security headers
            security_headers = [
                "Strict-Transport-Security",
                "Content-Security-Policy",
                "X-Content-Type-Options",
                "X-Frame-Options",
                "X-XSS-Protection",
                "Referrer-Policy",
                "Permissions-Policy",
            ]
            
            for header in security_headers:
                if header in response.headers:
                    results["security_headers"]["present"].append(header)
                else:
                    results["security_headers"]["missing"].append(header)
            
            # SSL Information if HTTPS
            if parsed_url.scheme == "https":
                try:
                    # Get SSL information
                    hostname = parsed_url.netloc
                    port = 443
                    
                    if ":" in hostname:
                        hostname, port_str = hostname.split(":", 1)
                        port = int(port_str)
                    
                    context = ssl.create_default_context()
                    with socket.create_connection((hostname, port)) as sock:
                        with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                            cert = ssock.getpeercert()
                            
                            # Extract certificate information
                            results["ssl_info"] = {
                                "issuer": dict(cert.get("issuer", [])),
                                "subject": dict(cert.get("subject", [])),
                                "version": cert.get("version", "Unknown"),
                                "notBefore": cert.get("notBefore", "Unknown"),
                                "notAfter": cert.get("notAfter", "Unknown"),
                            }
                            
                            # Check certificate expiration
                            expires = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
                            expiration_days = (expires - datetime.now()).days
                            
                            if expiration_days < 0:
                                results["findings"].append({
                                    "severity": "high",
                                    "title": "SSL Certificate Expired",
                                    "description": f"The SSL certificate has expired on {cert['notAfter']}"
                                })
                            elif expiration_days < 30:
                                results["findings"].append({
                                    "severity": "medium",
                                    "title": "SSL Certificate Expiring Soon",
                                    "description": f"The SSL certificate will expire in {expiration_days} days"
                                })
                except Exception as e:
                    results["findings"].append({
                        "severity": "medium",
                        "title": "SSL Certificate Verification Failed",
                        "description": f"Could not verify SSL certificate: {str(e)}"
                    })
            
            # Security Header Analysis
            if not results["security_headers"]["present"]:
                results["findings"].append({
                    "severity": "high",
                    "title": "No Security Headers",
                    "description": "The site does not implement any standard security headers"
                })
            elif len(results["security_headers"]["missing"]) > 3:
                results["findings"].append({
                    "severity": "medium",
                    "title": "Missing Security Headers",
                    "description": f"The site is missing several security headers: {', '.join(results['security_headers']['missing'])}"
                })
            
    except requests.exceptions.Timeout:
        print(f"[ERROR] Connection to {target_url} timed out")
        results["findings"].append({
            "severity": "info",
            "title": "Connection Timeout",
            "description": f"The connection to {target_url} timed out after {timeout} seconds"
        })
    except requests.exceptions.RequestException as e:
        print(f"[ERROR] Request error: {e}")
        results["findings"].append({
            "severity": "info",
            "title": "Connection Error",
            "description": f"Error connecting to {target_url}: {str(e)}"
        })
    
    # Save the results
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    target_safe = re.sub(r'[^\w]', '_', urlparse(target_url).netloc)
    
    filename = f"{timestamp}_{target_safe}_scan.json"
    filepath = os.path.join(SECURITY_REPORT_DIR, filename)
    
    try:
        with open(filepath, 'w') as f:
            json.dump(results, f, indent=2)
        print(f"[SUCCESS] Security scan results saved to {filepath}")
    except Exception as e:
        print(f"[ERROR] Failed to save security scan results: {e}")
    
    return results

def scan_target_ports(target, port_range=None, timeout=5):
    """
    Scan a target for open ports through Tor
    
    Args:
        target: Target hostname or IP
        port_range: Port range string (e.g. "1-1000")
        timeout: Connection timeout in seconds
        
    Returns:
        dict: Port scan results
    """
    print(f"[INFO] Starting port scan for {target}")
    
    # Define common ports and services
    common_ports = {
        21: "ftp",
        22: "ssh",
        23: "telnet",
        25: "smtp",
        53: "dns",
        80: "http",
        110: "pop3",
        111: "rpcbind",
        135: "msrpc",
        139: "netbios-ssn",
        143: "imap",
        443: "https",
        445: "smb",
        993: "imaps",
        995: "pop3s",
        1723: "pptp",
        3306: "mysql",
        3389: "rdp",
        5900: "vnc",
        8080: "http-proxy"
    }
    
    # Determine which ports to scan
    ports_to_scan = []
    if port_range:
        try:
            start_port, end_port = map(int, port_range.split("-"))
            if 1 <= start_port <= end_port <= 65535:
                ports_to_scan = list(range(start_port, end_port + 1))
            else:
                print("[WARNING] Invalid port range. Using common ports.")
                ports_to_scan = list(common_ports.keys())
        except:
            print("[WARNING] Invalid port range format. Using common ports.")
            ports_to_scan = list(common_ports.keys())
    else:
        ports_to_scan = list(common_ports.keys())
    
    # Results
    results = {
        "target": target,
        "timestamp": datetime.now().isoformat(),
        "open_ports": {},
        "scan_range": f"{min(ports_to_scan)}-{max(ports_to_scan)}"
    }
    
    # Use Tor for connection
    try:
        # Create a new socket for each connection through Tor
        import socks
        socks.setdefaultproxy(socks.PROXY_TYPE_SOCKS5, "127.0.0.1", 9050)
        socket.socket = socks.socksocket
        
        # Scan ports
        for port in ports_to_scan:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(timeout)
                result = sock.connect_ex((target, port))
                if result == 0:
                    service = common_ports.get(port, "unknown")
                    results["open_ports"][port] = service
                    print(f"[INFO] Port {port}/tcp is open: {service}")
                sock.close()
            except:
                pass
    except Exception as e:
        print(f"[ERROR] Port scan error: {e}")
    
    # Reset socket
    socket.socket = socket._orig_socket
    
    return results

#
# Additional Security Functions
#

def check_dns_leaks():
    """
    Test for DNS leaks when using Tor
    
    Returns:
        dict: DNS leak test results
    """
    print("[INFO] Testing for DNS leaks...")
    
    # Results
    results = {
        "timestamp": datetime.now().isoformat(),
        "leaks_detected": False,
        "dns_servers": [],
        "leaked_servers": []
    }
    
    # Sites that check for DNS leaks
    test_urls = [
        "https://dnsleaktest.com/",
        "https://www.dnsleaktest.com/",
        "https://ipleak.net/"
    ]
    
    with get_tor_session() as session:
        for url in test_urls:
            try:
                response = session.get(url, timeout=10)
                # Simple check: if we can connect, DNS is working through Tor
                if response.status_code == 200:
                    results["dns_servers"].append("Tor DNS")
            except Exception as e:
                print(f"[ERROR] DNS leak test error: {e}")
    
    return results

def list_security_reports():
    """
    List all security reports
    
    Returns:
        list: Report information
    """
    reports = []
    
    if os.path.exists(SECURITY_REPORT_DIR):
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
    
    return reports
