#!/bin/bash
# Tor IP Monitor - Monitor Tor IP changes in real-time
# This script provides a real-time display of Tor IP changes

# ANSI colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Get script directory
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Welcome message
echo -e "${BLUE}============================================================${NC}"
echo -e "${GREEN}Tor IP Monitor - Track your Tor IP changes in real-time${NC}"
echo -e "${BLUE}============================================================${NC}"

# Check if the IP changer is already running
if ! pgrep -f "tor_ip_changer.py" > /dev/null; then
    echo -e "${YELLOW}[!] IP Changer doesn't appear to be running.${NC}"
    echo -e "${YELLOW}[!] Starting it in the background...${NC}"
    
    # Start the IP changer in the background
    "$DIR/tor_launcher.sh" --user-tor &
    IP_CHANGER_PID=$!
    
    # Give it a moment to start
    sleep 5
    echo -e "${GREEN}[+] IP Changer started in the background.${NC}"
else
    echo -e "${GREEN}[+] IP Changer is already running.${NC}"
fi

# Function to display the current time
show_time() {
    echo -e "${PURPLE}[$(date '+%Y-%m-%d %H:%M:%S')]${NC} $1"
}

# Function to get current Tor IP
get_tor_ip() {
    # Try different ports in case user-space Tor is used
    for PORT in 9050 9150; do
        IP=$(curl --silent --socks5-hostname 127.0.0.1:$PORT https://api.ipify.org 2>/dev/null)
        if [[ ! -z "$IP" ]]; then
            echo "$IP"
            return 0
        fi
    done
    
    echo "Unknown"
    return 1
}

# Start monitoring loop
echo -e "${CYAN}[*] Starting IP monitoring (Press Ctrl+C to stop)...${NC}"
echo -e "${CYAN}[*] Checking IP every 3 seconds...${NC}"

LAST_IP=""
CHANGES=0
START_TIME=$(date +%s)

while true; do
    CURRENT_IP=$(get_tor_ip)
    
    # Check if IP has changed
    if [[ "$CURRENT_IP" != "$LAST_IP" && "$CURRENT_IP" != "Unknown" ]]; then
        if [[ -z "$LAST_IP" ]]; then
            show_time "${GREEN}[+] Initial IP: ${CYAN}$CURRENT_IP${NC}"
        else
            CHANGES=$((CHANGES+1))
            show_time "${GREEN}[+] IP Changed (${YELLOW}#$CHANGES${GREEN}): ${CYAN}$CURRENT_IP${NC}"
        fi
        LAST_IP="$CURRENT_IP"
    elif [[ "$CURRENT_IP" == "Unknown" ]]; then
        show_time "${RED}[!] Could not determine current IP${NC}"
    fi
    
    # Calculate runtime
    CURRENT_TIME=$(date +%s)
    RUNTIME=$((CURRENT_TIME - START_TIME))
    MINUTES=$((RUNTIME / 60))
    SECONDS=$((RUNTIME % 60))
    
    # Show runtime and statistics in the terminal title
    if [[ $CHANGES -gt 0 ]]; then
        RATE=$(echo "scale=2; $CHANGES / ($RUNTIME / 60)" | bc 2>/dev/null)
        if [[ -z "$RATE" ]]; then
            RATE="0.00"
        fi
        echo -ne "\033]0;Tor Monitor: ${MINUTES}m${SECONDS}s | ${CHANGES} changes | ${RATE} changes/min\007"
    else
        echo -ne "\033]0;Tor Monitor: ${MINUTES}m${SECONDS}s | No changes yet\007"
    fi
    
    sleep 3
done

# Cleanup function
cleanup() {
    echo -e "\n${YELLOW}[!] Stopping IP monitor...${NC}"
    
    # If we started the IP changer, stop it
    if [[ ! -z "$IP_CHANGER_PID" ]]; then
        echo -e "${YELLOW}[!] Stopping background IP changer...${NC}"
        kill -TERM $IP_CHANGER_PID 2>/dev/null
    fi
    
    echo -e "${GREEN}[+] Monitoring stopped after ${YELLOW}$CHANGES${GREEN} IP changes.${NC}"
    exit 0
}

# Set up cleanup on exit
trap cleanup INT TERM
