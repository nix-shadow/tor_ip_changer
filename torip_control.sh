#!/bin/bash
# Tor IP Control Panel
# This script provides a menu-based interface for the Tor IP Changer suite

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

# Make scripts executable
chmod +x "$DIR/tor_ip_changer.py" "$DIR/tor_launcher.sh" "$DIR/torip_checker.py" "$DIR/torip_stats.py" "$DIR/torip_monitor.sh"

# Function to display the header
show_header() {
    clear
    echo -e "${BLUE}============================================================${NC}"
    echo -e "${GREEN}Tor IP Changer - Control Panel${NC}"
    echo -e "${BLUE}============================================================${NC}"
    echo ""
}

# Function to check if a process is running
is_running() {
    pgrep -f "$1" >/dev/null
    return $?
}

# Main menu function
show_menu() {
    show_header
    
    # Check status of IP changer
    if is_running "torip_changer.py"; then
        echo -e "${GREEN}● IP Changer is running${NC}"
    else
        echo -e "${RED}○ IP Changer is not running${NC}"
    fi
    
    # Check status of IP monitor
    if is_running "torip_monitor.sh"; then
        echo -e "${GREEN}● IP Monitor is running${NC}"
    else
        echo -e "${RED}○ IP Monitor is not running${NC}"
    fi
    
    echo ""
    echo -e "${CYAN}1. Start IP Changer${NC} (Changes IP every 10 seconds)"
    echo -e "${CYAN}2. Start IP Changer (with options)${NC}"
    echo -e "${CYAN}3. Stop IP Changer${NC}"
    echo -e "${CYAN}4. Check Current Tor IP${NC} (Show detailed IP info)"
    echo -e "${CYAN}5. Start IP Monitor${NC} (Track IP changes in real-time)"
    echo -e "${CYAN}6. View IP Statistics${NC} (Last 7 days)"
    echo -e "${CYAN}7. View IP Statistics (with options)${NC}"
    echo -e "${CYAN}8. View Documentation${NC}"
    echo -e "${CYAN}9. Exit${NC}"
    echo ""
    
    read -p "Enter your choice: " choice
    
    case $choice in
        1) start_ip_changer ;;
        2) start_ip_changer_options ;;
        3) stop_ip_changer ;;
        4) check_current_ip ;;
        5) start_ip_monitor ;;
        6) view_ip_stats ;;
        7) view_ip_stats_options ;;
        8) view_documentation ;;
        9) exit 0 ;;
        *) 
            echo -e "${YELLOW}Invalid option. Press Enter to continue...${NC}"
            read
            show_menu
            ;;
    esac
}

# Function to start the IP changer
start_ip_changer() {
    show_header
    echo -e "${BLUE}[*] Starting Tor IP Changer...${NC}"
    
    if is_running "torip_changer.py"; then
        echo -e "${YELLOW}[!] IP Changer is already running.${NC}"
    else
        "$DIR/start_ipchanger.sh" &
        disown
        sleep 2
        echo -e "${GREEN}[+] IP Changer started successfully.${NC}"
    fi
    
    echo ""
    read -p "Press Enter to continue..."
    show_menu
}

# Function to start the IP changer with options
start_ip_changer_options() {
    show_header
    echo -e "${BLUE}[*] Start IP Changer with Options${NC}"
    echo ""
    
    # Option for interval
    read -p "Enter interval between changes (format: MIN-MAX seconds, e.g., 10-15): " interval
    
    # Option for user-tor
    read -p "Force user-space Tor? (y/n): " user_tor
    user_tor_flag=""
    if [[ "$user_tor" == "y" || "$user_tor" == "Y" ]]; then
        user_tor_flag="--user-tor"
    fi
    
    # Option for verbose
    read -p "Enable verbose logging? (y/n): " verbose
    verbose_flag=""
    if [[ "$verbose" == "y" || "$verbose" == "Y" ]]; then
        verbose_flag="--verbose"
    fi
    
    # Construct the command
    cmd="$DIR/start_ipchanger.sh"
    
    if [[ ! -z "$interval" ]]; then
        cmd="$cmd --interval $interval"
    fi
    
    if [[ ! -z "$user_tor_flag" ]]; then
        cmd="$cmd $user_tor_flag"
    fi
    
    if [[ ! -z "$verbose_flag" ]]; then
        cmd="$cmd $verbose_flag"
    fi
    
    # Execute the command
    echo -e "${BLUE}[*] Executing: $cmd${NC}"
    $cmd &
    disown
    
    sleep 2
    echo -e "${GREEN}[+] IP Changer started with custom options.${NC}"
    
    echo ""
    read -p "Press Enter to continue..."
    show_menu
}

# Function to stop the IP changer
stop_ip_changer() {
    show_header
    echo -e "${BLUE}[*] Stopping Tor IP Changer...${NC}"
    
    if is_running "torip_changer.py"; then
        pkill -f "torip_changer.py"
        sleep 2
        if ! is_running "torip_changer.py"; then
            echo -e "${GREEN}[+] IP Changer stopped successfully.${NC}"
        else
            echo -e "${RED}[!] Failed to stop IP Changer.${NC}"
        fi
    else
        echo -e "${YELLOW}[!] IP Changer is not running.${NC}"
    fi
    
    echo ""
    read -p "Press Enter to continue..."
    show_menu
}

# Function to check current IP
check_current_ip() {
    show_header
    echo -e "${BLUE}[*] Checking Current Tor IP...${NC}"
    
    python3 "$DIR/torip_checker.py"
    
    echo ""
    read -p "Press Enter to continue..."
    show_menu
}

# Function to start IP monitor
start_ip_monitor() {
    show_header
    echo -e "${BLUE}[*] Starting Tor IP Monitor...${NC}"
    
    if is_running "torip_monitor.sh"; then
        echo -e "${YELLOW}[!] IP Monitor is already running.${NC}"
    else
        # Start in a new terminal if possible
        if command -v gnome-terminal &> /dev/null; then
            gnome-terminal -- "$DIR/torip_monitor.sh"
        elif command -v xterm &> /dev/null; then
            xterm -e "$DIR/torip_monitor.sh" &
        elif command -v konsole &> /dev/null; then
            konsole -e "$DIR/torip_monitor.sh" &
        else
            # Fallback to running in the same terminal
            echo -e "${YELLOW}[!] No terminal emulator found. Running in this terminal.${NC}"
            echo -e "${YELLOW}[!] Control panel will be unavailable until monitor is closed.${NC}"
            echo -e "${YELLOW}[!] Press Ctrl+C to stop the monitor and return to the control panel.${NC}"
            read -p "Press Enter to start the monitor..."
            "$DIR/torip_monitor.sh"
        fi
        
        echo -e "${GREEN}[+] IP Monitor started successfully.${NC}"
    fi
    
    echo ""
    read -p "Press Enter to continue..."
    show_menu
}

# Function to view IP stats
view_ip_stats() {
    show_header
    echo -e "${BLUE}[*] Viewing IP Statistics (Last 7 Days)...${NC}"
    
    python3 "$DIR/torip_stats.py"
    
    # Check if stats folder exists and has images
    stats_dir="$DIR/stats"
    if [[ -d "$stats_dir" && -f "$stats_dir/country_distribution.png" ]]; then
        echo ""
        echo -e "${BLUE}[*] Visualizations have been saved to the 'stats' folder.${NC}"
        
        # Try to open the images if we have a GUI
        if command -v xdg-open &> /dev/null; then
            read -p "Do you want to view the visualizations? (y/n): " view_viz
            if [[ "$view_viz" == "y" || "$view_viz" == "Y" ]]; then
                xdg-open "$stats_dir/country_distribution.png" &>/dev/null &
                xdg-open "$stats_dir/organization_distribution.png" &>/dev/null &
            fi
        fi
    fi
    
    echo ""
    read -p "Press Enter to continue..."
    show_menu
}

# Function to view IP stats with options
view_ip_stats_options() {
    show_header
    echo -e "${BLUE}[*] View IP Statistics with Options${NC}"
    echo ""
    
    # Option for days
    read -p "Enter number of days to analyze (0 for all time): " days
    
    # Construct the command
    cmd="python3 $DIR/torip_stats.py"
    
    if [[ ! -z "$days" ]]; then
        cmd="$cmd --days $days"
    fi
    
    # Execute the command
    echo -e "${BLUE}[*] Executing: $cmd${NC}"
    $cmd
    
    # Check if stats folder exists and has images
    stats_dir="$DIR/stats"
    if [[ -d "$stats_dir" && -f "$stats_dir/country_distribution.png" ]]; then
        echo ""
        echo -e "${BLUE}[*] Visualizations have been saved to the 'stats' folder.${NC}"
        
        # Try to open the images if we have a GUI
        if command -v xdg-open &> /dev/null; then
            read -p "Do you want to view the visualizations? (y/n): " view_viz
            if [[ "$view_viz" == "y" || "$view_viz" == "Y" ]]; then
                xdg-open "$stats_dir/country_distribution.png" &>/dev/null &
                xdg-open "$stats_dir/organization_distribution.png" &>/dev/null &
            fi
        fi
    fi
    
    echo ""
    read -p "Press Enter to continue..."
    show_menu
}

# Function to view documentation
view_documentation() {
    show_header
    echo -e "${BLUE}[*] Viewing Documentation${NC}"
    
    # Check for a markdown viewer
    if command -v glow &> /dev/null; then
        glow "$DIR/README.md"
    elif command -v mdless &> /dev/null; then
        mdless "$DIR/README.md"
    elif command -v mdcat &> /dev/null; then
        mdcat "$DIR/README.md"
    else
        # Fallback to less
        echo -e "${YELLOW}[!] No markdown viewer found. Using less.${NC}"
        less "$DIR/README.md"
    fi
    
    echo ""
    read -p "Press Enter to continue..."
    show_menu
}

# Start the menu
show_menu
