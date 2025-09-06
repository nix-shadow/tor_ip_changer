#!/bin/bash
# Tor IP Suite - Launcher Script
# A streamlined launcher for the Tor IP Suite

# Get script directory
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ANSI colors
BLUE='\033[0;34m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Print header
echo -e "${BLUE}============================================================${NC}"
echo -e "${GREEN}Tor IP Suite - Ethical Hacking & Security Tools${NC}"
echo -e "${BLUE}============================================================${NC}"
echo

# Check Python version
python3 --version >/dev/null 2>&1
if [ $? -ne 0 ]; then
    echo -e "${RED}[!] Python 3 is required but not installed.${NC}"
    exit 1
fi

# Check for Tor system package
if ! command -v tor > /dev/null; then
    echo -e "${RED}[!] Tor is not installed. Attempting to install...${NC}"
    if command -v apt-get > /dev/null; then
        sudo apt-get update && sudo apt-get install -y tor
    elif command -v dnf > /dev/null; then
        sudo dnf install -y tor
    elif command -v pacman > /dev/null; then
        sudo pacman -S --noconfirm tor
    else
        echo -e "${RED}[!] Could not install Tor automatically. Please install it manually.${NC}"
        exit 1
    fi
fi

# Check for lsof command
if ! command -v lsof > /dev/null; then
    echo -e "${YELLOW}[*] lsof command not found. Attempting to install...${NC}"
    if command -v apt-get > /dev/null; then
        sudo apt-get update && sudo apt-get install -y lsof
    elif command -v dnf > /dev/null; then
        sudo dnf install -y lsof
    elif command -v pacman > /dev/null; then
        sudo pacman -S --noconfirm lsof
    else
        echo -e "${YELLOW}[*] Could not install lsof automatically. Some functionality may be limited.${NC}"
    fi
fi

# Check for Tor service
echo -e "${YELLOW}[*] Checking Tor service...${NC}"
curl --socks5 127.0.0.1:9050 --socks5-hostname 127.0.0.1:9050 -s https://check.torproject.org > /dev/null
if [ $? -ne 0 ]; then
    echo -e "${RED}[!] Tor doesn't seem to be running properly.${NC}"
    echo -e "${YELLOW}[*] Attempting to start Tor service...${NC}"
    
    # Try systemd
    if command -v systemctl > /dev/null; then
        sudo systemctl start tor
    # Try service
    elif command -v service > /dev/null; then
        sudo service tor start
    # Try direct tor command
    elif command -v tor > /dev/null; then
        tor &
        sleep 5
    else
        echo -e "${RED}[!] Could not start Tor. Please start it manually.${NC}"
        echo -e "${YELLOW}[*] Running Tor IP Suite in limited mode (some features may not work).${NC}"
    fi
    
    # Check again
    curl --socks5 127.0.0.1:9050 --socks5-hostname 127.0.0.1:9050 -s https://check.torproject.org > /dev/null
    if [ $? -ne 0 ]; then
        echo -e "${RED}[!] Tor is still not running properly. Limited functionality available.${NC}"
        read -p "Do you want to continue anyway? (y/n): " response
        if [[ "$response" != "y" ]]; then
            exit 1
        fi
    fi
fi

echo -e "${GREEN}[+] Tor service is running properly.${NC}"

# Create necessary directories
mkdir -p "$DIR/data/security_reports"
mkdir -p "$DIR/.tor-data"

# Check script permissions
if [ ! -x "$DIR/tor_ip_changer.py" ]; then
    echo -e "${YELLOW}[*] Making script executable...${NC}"
    chmod +x "$DIR/tor_ip_changer.py"
fi

if [ ! -x "$DIR/tor_security_tools.py" ]; then
    echo -e "${YELLOW}[*] Making security tools executable...${NC}"
    chmod +x "$DIR/tor_security_tools.py"
fi

# Check for Python dependencies
PYTHON_DEPS=("requests" "stem" "socks" "urllib3")
MISSING_DEPS=()

for dep in "${PYTHON_DEPS[@]}"; do
    python3 -c "import $dep" 2>/dev/null
    if [ $? -ne 0 ]; then
        MISSING_DEPS+=("$dep")
    fi
done

if [ ${#MISSING_DEPS[@]} -gt 0 ]; then
    echo -e "${YELLOW}[*] Installing missing Python dependencies: ${MISSING_DEPS[*]}${NC}"
    pip3 install --quiet --disable-pip-version-check "${MISSING_DEPS[@]}"
fi

# Forward arguments to the Python script
echo -e "${GREEN}[+] Launching Tor IP Suite...${NC}"
python3 "$DIR/tor_ip_changer.py" "$@"
