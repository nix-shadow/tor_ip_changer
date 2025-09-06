# Project Components

## Main Components

### Core Files
- `torip_changer.py` - Main Python script for changing IPs through Tor
- `start_ipchanger.sh` - Shell wrapper for starting the Python script

### Enhanced Tools
- `torip_checker.py` - Tool to check and display detailed info about current Tor IP
- `torip_stats.py` - Analytics tool for IP change statistics with visualization
- `torip_monitor.sh` - Real-time monitoring of IP changes
- `torip_control.sh` - Unified control panel for all tools

### Documentation
- `README.md` - Complete documentation and usage instructions
- `COMPONENTS.md` - This file, explaining the project structure

## Directories
- `.tor-data/` - Created when using user-space Tor (needed for functionality)
- `backup/` - Contains backup files and old versions
- `venv/` - Python virtual environment with required packages
- `ip_history/` - Stores IP change history (created automatically)
- `stats/` - Contains statistical visualizations (created automatically)

## Core Tool Parameters
When running the IP changer, you can use these options:
- `--interval X-Y` - Change IP every X-Y seconds (default: 10-15)
- `--user-tor` - Force using a user-space Tor instance
- `--verbose` - Show more detailed logs

## How to Start

### Using the Control Panel (Recommended)
```
./torip_control.sh
```

### Using Individual Tools
```
./start_ipchanger.sh               # Start the IP changer
./torip_checker.py                 # Check current IP details
./torip_monitor.sh                 # Monitor IP changes in real-time
./torip_stats.py [--days DAYS]     # View IP change statistics
```

## Flow Between Components

1. `start_ipchanger.sh` → Launches `torip_changer.py`
2. `torip_changer.py` → Creates `.tor-data/` when needed
3. `torip_checker.py` → Creates `ip_history/` directory with IP records
4. `torip_stats.py` → Reads from `ip_history/` and creates `stats/` visualizations
5. `torip_monitor.sh` → Independently tracks IP changes
6. `torip_control.sh` → Orchestrates all the above components
