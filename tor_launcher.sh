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

# Function to configure Tor for better permissions
configure_tor() {
    echo -e "${YELLOW}[*] Configuring Tor for better permissions...${NC}"
    
    # Check if torrc exists
    TORRC_PATH="/etc/tor/torrc"
    if [ ! -f "$TORRC_PATH" ]; then
        echo -e "${RED}[!] Tor configuration file not found.${NC}"
        return 1
    fi
    
    # Check if control port is already configured
    grep -q "ControlPort 9051" "$TORRC_PATH"
    if [ $? -ne 0 ]; then
        echo -e "${YELLOW}[*] Adding ControlPort configuration...${NC}"
        echo "ControlPort 9051" | sudo tee -a "$TORRC_PATH" > /dev/null
        MODIFIED=1
    fi
    
    # Check if cookie authentication is configured
    grep -q "CookieAuthentication 1" "$TORRC_PATH"
    if [ $? -ne 0 ]; then
        echo -e "${YELLOW}[*] Enabling cookie authentication...${NC}"
        echo "CookieAuthentication 1" | sudo tee -a "$TORRC_PATH" > /dev/null
        MODIFIED=1
    fi
    
    # Check if cookie file is readable
    grep -q "CookieAuthFileGroupReadable 1" "$TORRC_PATH"
    if [ $? -ne 0 ]; then
        echo -e "${YELLOW}[*] Making cookie file group readable...${NC}"
        echo "CookieAuthFileGroupReadable 1" | sudo tee -a "$TORRC_PATH" > /dev/null
        MODIFIED=1
    fi
    
    # Add current user to the Tor group
    if [ -n "$(getent group debian-tor)" ]; then
        echo -e "${YELLOW}[*] Adding user to tor group...${NC}"
        sudo usermod -a -G debian-tor "$(whoami)"
        MODIFIED=1
    fi
    
    # If we modified the config, restart Tor
    if [ -n "$MODIFIED" ]; then
        echo -e "${YELLOW}[*] Restarting Tor service to apply new configuration...${NC}"
        sudo systemctl restart tor
        sleep 3
    fi
}

# Check for Tor service
echo -e "${YELLOW}[*] Checking Tor service...${NC}"

# First check the port is open
if nc -z 127.0.0.1 9050 2>/dev/null; then
    echo -e "${GREEN}[+] Tor SOCKS port is open.${NC}"
    
    # Try a direct connection to an IP service
    TOR_IP=$(curl --socks5 127.0.0.1:9050 --socks5-hostname 127.0.0.1:9050 -s -m 5 https://api.ipify.org 2>/dev/null)
    
    if [ -n "$TOR_IP" ]; then
        echo -e "${GREEN}[+] Tor service is working. Current Tor IP: ${TOR_IP}${NC}"
        
        # Configure Tor for better permissions if needed
        read -p "Do you want to configure Tor for better permissions? (y/n): " response
        if [[ "$response" == "y" ]]; then
            configure_tor
        fi
    else
        # Try another service
        TOR_IP=$(curl --socks5 127.0.0.1:9050 --socks5-hostname 127.0.0.1:9050 -s -m 5 https://icanhazip.com 2>/dev/null)
        
        if [ -n "$TOR_IP" ]; then
            echo -e "${GREEN}[+] Tor service is working. Current Tor IP: ${TOR_IP}${NC}"
            
            # Configure Tor for better permissions if needed
            read -p "Do you want to configure Tor for better permissions? (y/n): " response
            if [[ "$response" == "y" ]]; then
                configure_tor
            fi
        else
            echo -e "${RED}[!] Tor doesn't seem to be routing traffic properly.${NC}"
            echo -e "${YELLOW}[*] Attempting to restart Tor service...${NC}"
            
            # Try systemd
            if command -v systemctl > /dev/null; then
                sudo systemctl restart tor
                sleep 5 # Give Tor more time to initialize
            # Try service
            elif command -v service > /dev/null; then
                sudo service tor restart
                sleep 5 # Give Tor more time to initialize
            # Try direct tor command
            elif command -v tor > /dev/null; then
                sudo pkill tor &>/dev/null
                tor &
                sleep 7
            else
                echo -e "${RED}[!] Could not restart Tor. Please start it manually.${NC}"
                echo -e "${YELLOW}[*] Running Tor IP Suite in limited mode (some features may not work).${NC}"
            fi
            
            # Check again with another service
            TOR_IP=$(curl --socks5 127.0.0.1:9050 --socks5-hostname 127.0.0.1:9050 -s -m 5 https://icanhazip.com 2>/dev/null)
            if [ -n "$TOR_IP" ]; then
                echo -e "${GREEN}[+] Tor service is now working. Current Tor IP: ${TOR_IP}${NC}"
                
                # Configure Tor for better permissions if needed
                read -p "Do you want to configure Tor for better permissions? (y/n): " response
                if [[ "$response" == "y" ]]; then
                    configure_tor
                fi
            else
                echo -e "${RED}[!] Tor is still not routing traffic properly. Limited functionality available.${NC}"
                read -p "Do you want to continue anyway? (y/n): " response
                if [[ "$response" != "y" ]]; then
                    exit 1
                fi
            fi
        fi
    fi
else
    echo -e "${RED}[!] Tor SOCKS port is not open.${NC}"
    echo -e "${YELLOW}[*] Attempting to start Tor service...${NC}"
    
    # Try systemd
    if command -v systemctl > /dev/null; then
        sudo systemctl restart tor
        sleep 5 # Give Tor more time to initialize
    # Try service
    elif command -v service > /dev/null; then
        sudo service tor restart
        sleep 5
    # Try direct tor command
    elif command -v tor > /dev/null; then
        sudo pkill tor &>/dev/null
        tor &
        sleep 7
    else
        echo -e "${RED}[!] Could not start Tor. Please start it manually.${NC}"
        echo -e "${YELLOW}[*] Running Tor IP Suite in limited mode (some features may not work).${NC}"
    fi
    
    # Check again
    if nc -z 127.0.0.1 9050 2>/dev/null; then
        TOR_IP=$(curl --socks5 127.0.0.1:9050 --socks5-hostname 127.0.0.1:9050 -s -m 5 https://api.ipify.org 2>/dev/null)
        if [ -n "$TOR_IP" ]; then
            echo -e "${GREEN}[+] Tor service is now working. Current Tor IP: ${TOR_IP}${NC}"
            
            # Configure Tor for better permissions if needed
            read -p "Do you want to configure Tor for better permissions? (y/n): " response
            if [[ "$response" == "y" ]]; then
                configure_tor
            fi
        else
            echo -e "${RED}[!] Tor is not routing traffic properly. Limited functionality available.${NC}"
            read -p "Do you want to continue anyway? (y/n): " response
            if [[ "$response" != "y" ]]; then
                exit 1
            fi
        fi
    else
        echo -e "${RED}[!] Tor SOCKS port is still not open. Limited functionality available.${NC}"
        read -p "Do you want to continue anyway? (y/n): " response
        if [[ "$response" != "y" ]]; then
            exit 1
        fi
    fi
fi

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
