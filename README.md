# ShadowIP - Tor IP Changer

*Made by Shadow*

A comprehensive toolset for changing, monitoring, and analyzing your IP address using the Tor network.

## Features

- **Automatic IP Changing**: Changes your IP address every 5-10 seconds (configurable)
- **IP Monitoring**: Real-time tracking of IP changes with statistics
- **IP Analytics**: Visualizations and statistics about your Tor exit nodes
- **User-Friendly Control Panel**: Menu-based interface for all functions
- **Smart Auto-Configuration**: 
  - Auto-detects and installs required dependencies
  - Automatically configures Tor service if needed
  - Falls back to user-space Tor if system Tor isn't accessible
- **Cross-Platform**: Works on Linux, macOS, and Windows (with limitations)
- **Colorized Output**: Clear, color-coded terminal feedback
- **Flexible Options**: Comprehensive command-line argument support

## Requirements

- Python 3.6+
- Tor (system service or standalone binary)
- Python packages: requests, stem, PySocks (auto-installed if missing)
- Optional: matplotlib (for statistics visualization)

## Installation

1. Clone or download this repository
2. Make the scripts executable:
   ```bash
   chmod +x *.py *.sh
   ```

## Usage

### Using the Control Panel (Recommended)

The easiest way to use all features is through the control panel:

```bash
./torip_control.sh
```

This provides a menu-based interface to:
- Start/stop the IP changer
- Check your current Tor IP
- Monitor IP changes in real-time
- View statistics and visualizations
- Access documentation

### Using Individual Tools

#### IP Changer (Core Tool)

```bash
./start_ipchanger.sh
```

### Using the Python script directly

```bash
python3 torip_changer.py
```

### Advanced options

```
usage: torip_changer.py [-h] [--interval INTERVAL] [--socks-port SOCKS_PORT]
                        [--control-port CONTROL_PORT] [--user-tor] [--verbose]

options:
  -h, --help            show this help message and exit
  --interval INTERVAL   Interval between IP changes in seconds (format: MIN-MAX or single value)
  --socks-port SOCKS_PORT
                        Tor SOCKS port to use
  --control-port CONTROL_PORT
                        Tor control port to use
  --user-tor            Force using a user-space Tor instance instead of system Tor
  --verbose             Enable verbose logging

Examples:
  python torip_changer.py                    # Use default settings
  python torip_changer.py --interval 15-30   # Change IP every 15-30 seconds
  python torip_changer.py --user-tor         # Force using a user-space Tor instance
```

#### IP Checker (Get Details About Your Current Tor IP)

```bash
./torip_checker.py
```

This tool shows detailed information about your current Tor IP address including country, region, city, and ISP information. It also saves this information to a history file for later analysis.

#### IP Monitor (Real-time Monitoring)

```bash
./torip_monitor.sh
```

This tool provides real-time monitoring of your IP changes in a separate terminal window. It tracks:
- Current IP address
- Number of changes
- Change rate (changes per minute)
- Total runtime

#### IP Statistics (Analytics)

```bash
./torip_stats.py [--days DAYS]
```

Analyzes your IP change history and provides statistics:
- Total number of IP changes
- Unique IPs used
- IP diversity ratio
- Top countries and organizations
- Visual charts (country distribution, organization distribution)

## How It Works

1. The script checks for required dependencies and installs them if missing
2. It verifies that Tor is installed and properly configured
3. It connects to Tor's control port and requests new circuits at specified intervals
4. Each new circuit provides a new exit node, resulting in a new IP address
5. The monitoring tools track changes and provide analytics

## Troubleshooting

### Common Issues

1. **Missing SOCKS Support**:
   - Error: `Missing dependencies for SOCKS support`
   - Solution: The script will automatically install PySocks, but if it fails, run `pip install PySocks` manually

2. **Connection Refused**:
   - Error: `Error connecting to Tor controller: [Errno 111] Connection refused`
   - Solution: The script will automatically configure Tor if possible. If it fails:
     - Ensure Tor is running: `sudo systemctl start tor`
     - Configure Tor to enable control port: Add these lines to `/etc/tor/torrc`:
       ```
       ControlPort 9051
       CookieAuthentication 1
       ```
     - Restart Tor: `sudo systemctl restart tor`

3. **Authentication Failed**:
   - Error: `Authentication failed - check your Tor configuration`
   - Solution: The script will try to authenticate or fall back to user-space Tor. If it fails:
     - Use the `--user-tor` option to force using a user-space Tor instance

## Security Considerations

- Each Tor circuit change provides anonymity similar to restarting the Tor Browser
- This tool is for legitimate privacy purposes only
- Frequent IP changes may trigger rate limits on some websites

## Disclaimer

This tool is for educational purposes only. Always follow laws and regulations related to network access in your jurisdiction.
