import requests
import os
import time
import threading
import socket
from datetime import datetime
from dotenv import load_dotenv
from requests.auth import HTTPBasicAuth

import config

# .env file with API_KEY, API_SECRET, and OPNSENSE_IP
load_dotenv()

# Store the variable from the .env file in the script
API_KEY = os.getenv("API_KEY")
API_SECRET = os.getenv("API_SECRET")
OPNSENSE_IP = os.getenv("OPNSENSE_IP")

# API Endpoints
LOGS_ENDPOINT = f"{OPNSENSE_IP}/api/diagnostics/firewall/log"

def get_firewall_logs():
    """Fetch firewall logs from OPNsense API."""
    try:
        response = requests.get(LOGS_ENDPOINT, auth=HTTPBasicAuth(API_KEY, API_SECRET), verify="certificate_crt.pem")

        if response.status_code == 200:
            logs = response.json()
            return logs if isinstance(logs, list) else []
        else:
            print(f"❌ Error fetching logs: {response.status_code} - {response.text}")
            return []
    except requests.RequestException as e:
        print(f"⚠️ Network error: {e}")
        return []

def filter_blocked_logs(logs, search_address=None):
    """Filter logs for blocked, rejected, or dropped connections, optionally filtering by IP."""
    filtered_logs = [
        log for log in logs 
        if log.get("action", "").lower() in {"block", "reject", "drop"}
    ]

    # Further filter by IP if provided
    if search_address:
        filtered_logs = [
            log for log in filtered_logs 
            if log.get("src", "") == search_address or log.get("dst", "") == search_address
        ]
    return filtered_logs


def reverse_dns_lookup(ip):
    """Resolve an IP address to a DNS name."""
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        return hostname
    except socket.herror:
        return None  # No DNS record found
    

def get_ip_api(ip):
    url = f"http://ip-api.com/json/{ip}"
    response = requests.get(url)
    if response.status_code == 200:
        data = response.json()
        country = data.get("country", "N/A")
        city = data.get("city", "N/A")
        zip = data.get("zip", "N/A")
        isp = data.get("isp", "N/A")
        org = data.get("org", "N/A")
        response_as = data.get("as", "N/A")
        return org, response_as, isp, zip, city, country

    else:
        return False


def parse_logs(search_address=None):
    """Continuously fetch and parse logs, updating unique IPs."""
    seen_logs = set()

    while True:
        logs = get_firewall_logs()
        blocked_logs = filter_blocked_logs(logs, search_address)

        new_ips = set()
        
        for log in blocked_logs:
            log_entry = f"{log.get('__timestamp__')} - {log.get('action')} - {log.get('interface')} - {log.get('src')}:{log.get('srcport')} -> {log.get('dst')}:{log.get('dstport')}"
            
            if log_entry not in seen_logs:
                seen_logs.add(log_entry)

            destination = log.get('dst')
            if destination and destination not in config.UNIQUE_IPS:
                new_ips.add(destination)

        # Resolve DNS for new IPs
        if new_ips:
            config.UNIQUE_IPS.update(new_ips)
            resolved_ips = {}

            for ip in new_ips:
                dns_name = reverse_dns_lookup(ip)

                # DNS Entry to IP
                resolved_ips[ip] = {"dns_name": dns_name if dns_name else "No DNS found"}

                ip_api_data = get_ip_api(ip)
                
                if ip_api_data is False:
                    resolved_ips[ip]["org"] = "❌ Error fetching ip-api.com - too many requests? Max 45 per 60 seconds"
                else:
                    org, response_as, isp, zip, city, country = ip_api_data
                    resolved_ips[ip].update({
                        "org": org,
                        "response_as": response_as,
                        "isp": isp,
                        "zip": zip,
                        "city": city,
                        "country": country
                    })
            
            timestamp = datetime.now().strftime("%H:%M:%S %d.%m.%Y")
                     
            print(f"\n{timestamp} New Unique IP with Lookups:")
            for ip, data in resolved_ips.items():
                print(f"🌐 {ip}".ljust(20) +
                      f"{data.get('org', 'N/A'):<35} " +
                      f"{data.get('response_as', 'N/A'):<55} " +
                      f"{data.get('isp', 'N/A'):<45} " +
                      f"{data.get('zip', 'N/A'):<5} {data.get('city', 'N/A'):<20}{data.get('country', 'N/A'):<15} " +
                      f"{data.get('dns_name', 'N/A')}")

            # Print all IPs in a single line, comma-separated
            ip_list = ",".join(resolved_ips.keys())
            print(f"\nNew ip addresses:\n{ip_list}")
        
        time.sleep(5)  # Wait for the next batch


def start_log_parser(search_address=None):
    """Start the log parser in a separate background thread."""
    thread = threading.Thread(target=parse_logs, args=(search_address,))
    thread.daemon = True  # Ensures the thread stops when the program exits
    thread.start()

# Start log parsing loop
if __name__ == "__main__":
    search_address = input("Enter IP address to filter logs (optional): ")
    start_log_parser(search_address) if search_address else start_log_parser()

    while True:
        time.sleep(60)
        timestamp = datetime.now().strftime("%H:%M:%S %d.%m.%Y")
        print(f"\n{timestamp} Already seen:")
        print(",".join(config.UNIQUE_IPS))