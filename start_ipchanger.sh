#!/bin/bash
# Tor IP Changer - Wrapper Script

# Terminal colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}============================================================${NC}"
echo -e "${GREEN}Tor IP Changer - Automatically change your IP via Tor${NC}"
echo -e "${BLUE}============================================================${NC}"

# Get script directory
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Check if python3 is installed
if ! command -v python3 &> /dev/null; then
    echo -e "${RED}[!] Python 3 is not installed. Please install it.${NC}"
    exit 1
fi

# Make the Python script executable
chmod +x "$DIR/torip_changer.py"

# Collect command line arguments to pass through to Python script
ARGS=""
while [[ $# -gt 0 ]]; do
    # Handle spaces in arguments properly
    ARGS="$ARGS \"$1\""
    shift
done

# Run the main Python script with any passed arguments
echo -e "${GREEN}[+] Starting Tor IP Changer...${NC}"
eval "python3 \"$DIR/torip_changer.py\" $ARGS"
