#!/usr/bin/env python3
"""
Tor IP Stats - View statistics about your Tor IP changes
This script analyzes the IP history and provides statistics.
"""

import os
import sys
import json
import argparse
import subprocess
from datetime import datetime, timedelta
from collections import Counter
import glob

# Try importing required packages
try:
    import matplotlib.pyplot as plt
except ImportError:
    print("[!] Missing required packages. Installing...")
    subprocess.check_call([
        sys.executable, "-m", "pip", "install", 
        "--quiet", "--disable-pip-version-check", 
        "matplotlib"
    ])
    print("[+] Required packages installed successfully")
    import matplotlib.pyplot as plt

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

def load_history_files(days=7):
    """Load IP history files for the specified number of days"""
    history_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "ip_history")
    
    if not os.path.exists(history_dir):
        print(colorize("[!] No history directory found. Run the IP changer first.", "RED"))
        return []
    
    # Get files from the past X days
    records = []
    
    # Get all history files
    history_files = glob.glob(os.path.join(history_dir, "*.json"))
    
    if not history_files:
        print(colorize("[!] No history files found. Run the IP changer first.", "YELLOW"))
        return []
    
    # Load each file
    for file_path in history_files:
        try:
            with open(file_path, 'r') as f:
                file_records = json.load(f)
                records.extend(file_records)
        except Exception as e:
            print(colorize(f"[!] Error loading {file_path}: {e}", "YELLOW"))
    
    # Filter by date if needed
    if days > 0:
        cutoff_date = datetime.now() - timedelta(days=days)
        cutoff_str = cutoff_date.strftime("%Y-%m-%d %H:%M:%S")
        records = [r for r in records if r.get('timestamp', '') >= cutoff_str]
    
    return records

def generate_stats(records, days=7):
    """Generate statistics from IP records"""
    if not records:
        return
    
    # Count unique IPs
    ips = [r.get('ip') for r in records if 'ip' in r]
    unique_ips = len(set(ips))
    
    # Count countries
    countries = [r.get('country') for r in records if 'country' in r]
    country_counts = Counter(countries)
    
    # Count organizations
    orgs = [r.get('org', '').split(' ')[0] for r in records if 'org' in r]
    org_counts = Counter(orgs)
    
    # Print statistics
    print(colorize(f"\n===== Tor IP Statistics (Past {days} days) =====", "BLUE"))
    print(colorize(f"Total IP changes: {len(records)}", "GREEN"))
    print(colorize(f"Unique IPs: {unique_ips}", "GREEN"))
    print(colorize(f"IP diversity ratio: {unique_ips/len(records):.2f}", "GREEN"))
    
    print(colorize("\nTop 5 Countries:", "CYAN"))
    for country, count in country_counts.most_common(5):
        if country:
            print(colorize(f"  {country}: {count} ({count/len(records)*100:.1f}%)", "WHITE"))
    
    print(colorize("\nTop 5 Organizations:", "CYAN"))
    for org, count in org_counts.most_common(5):
        if org:
            print(colorize(f"  {org}: {count} ({count/len(records)*100:.1f}%)", "WHITE"))
    
    print(colorize("="*45, "BLUE"))
    
    # Create visualizations
    try:
        create_visualizations(records, country_counts, org_counts, days)
    except Exception as e:
        print(colorize(f"[!] Could not create visualizations: {e}", "YELLOW"))

def create_visualizations(records, country_counts, org_counts, days):
    """Create visualizations of the statistics"""
    output_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "stats")
    
    # Create directory if it doesn't exist
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
    
    # Create country pie chart
    plt.figure(figsize=(10, 6))
    plt.title(f'Exit Node Countries (Past {days} days)')
    
    # Get top countries and combine the rest
    top_countries = dict(country_counts.most_common(5))
    other_count = sum(count for country, count in country_counts.items() if country not in top_countries)
    if other_count > 0:
        top_countries['Other'] = other_count
    
    plt.pie(top_countries.values(), labels=top_countries.keys(), autopct='%1.1f%%', startangle=90)
    plt.axis('equal')
    
    # Save the figure
    country_chart_path = os.path.join(output_dir, 'country_distribution.png')
    plt.savefig(country_chart_path)
    plt.close()
    
    print(colorize(f"[+] Country distribution chart saved to {country_chart_path}", "GREEN"))
    
    # Create organization bar chart
    plt.figure(figsize=(12, 6))
    plt.title(f'Top Exit Node Organizations (Past {days} days)')
    
    # Get top organizations
    top_orgs = dict(org_counts.most_common(10))
    
    plt.bar(top_orgs.keys(), top_orgs.values())
    plt.xticks(rotation=45, ha='right')
    plt.tight_layout()
    
    # Save the figure
    org_chart_path = os.path.join(output_dir, 'organization_distribution.png')
    plt.savefig(org_chart_path)
    plt.close()
    
    print(colorize(f"[+] Organization distribution chart saved to {org_chart_path}", "GREEN"))

def parse_arguments():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        description="Tor IP Stats - View statistics about your Tor IP changes"
    )
    
    parser.add_argument(
        "--days", 
        type=int, 
        default=7,
        help="Number of days to analyze (default: 7, use 0 for all time)"
    )
    
    return parser.parse_args()

def main():
    """Main function"""
    # Print welcome message
    print(colorize("="*60, "BLUE"))
    print(colorize("Tor IP Stats - View statistics about your Tor IP changes", "GREEN"))
    print(colorize("="*60, "BLUE"))
    
    # Parse arguments
    args = parse_arguments()
    
    # Load history
    records = load_history_files(days=args.days)
    
    if records:
        generate_stats(records, days=args.days)
    
    return 0

if __name__ == "__main__":
    sys.exit(main())
