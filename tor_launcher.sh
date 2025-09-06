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

# Check if Tor is installed
if ! command -v tor &> /dev/null; then
    echo -e "${RED}[!] Tor is not installed.${NC}"
    echo -e "${YELLOW}[*] Installing Tor...${NC}"
    sudo apt update && sudo apt install -y tor
fi

# Check for Tor service
echo -e "${YELLOW}[*] Checking Tor service...${NC}"
curl --socks5 127.0.0.1:9050 --socks5-hostname 127.0.0.1:9050 -s https://check.torproject.org > /dev/null
if [ $? -ne 0 ]; then
    echo -e "${RED}[!] Tor doesn't seem to be running properly.${NC}"
    echo -e "${YELLOW}[*] Attempting to start Tor service...${NC}"
    
    # Try systemd
    if command -v systemctl > /dev/null; then
        sudo systemctl restart tor
        sleep 3 # Give Tor time to initialize
    # Try service
    elif command -v service > /dev/null; then
        sudo service tor restart
        sleep 3 # Give Tor time to initialize
    # Try direct tor command
    elif command -v tor > /dev/null; then
        sudo pkill tor &>/dev/null
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
PYTHON_DEPS=("requests" "stem" "socks")
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

# Check if virtual environment exists
VENV_PATH="$DIR/venv"
if [ -d "$VENV_PATH" ]; then
    echo -e "${YELLOW}[*] Activating virtual environment...${NC}"
    source "$VENV_PATH/bin/activate"
fi

# Run the script
python3 "$DIR/tor_ip_changer.py" "$@"

# Deactivate virtual environment if it was activated
if [ -n "$VIRTUAL_ENV" ]; then
    deactivate 2>/dev/null
fi
