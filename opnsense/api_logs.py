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
    

def get_ip_api(ip, retry=False):
    url = f"http://ip-api.com/json/{ip}"
    response = requests.get(url)
    if response.status_code == 200:
        data = response.json()

        org = data.get("org", "N/A")
        response_as = data.get("as", "N/A")
        isp = data.get("isp", "N/A")
        zip_code = data.get("zip", "N/A")  # Renamed `zip` to `zip_code` to avoid conflicts
        city = data.get("city", "N/A")
        country = data.get("country", "N/A")

        config.IP_TABLE[ip].update({
            "org": org,
            "response_as": response_as,
            "isp": isp,
            "zip": zip_code,
            "city": city,
            "country": country,
            "console_first_output": False
        })
        return True

    else:
        if not retry:
            print(f"❌ Failed to fetch data for {ip}. Retrying in 45 seconds...")
            time.sleep(45)
            return get_ip_api(ip, retry=True)
        else:
            print(f"❌ Failed again for {ip}. No more retries.")
            return False


def get_ips_company(value):
    if value == "new":
        unique_isps = set()
        for ip, data in config.IP_TABLE.items():
            console_first_output = data.get('console_first_output', False)
            if not console_first_output:
                isp = data.get('isp', 'N/A')
                unique_isps.add(isp)

        unique_isps = {isp for isp in unique_isps if isp is not None}

        for isp in sorted(unique_isps):  
            print_overview_new(isp)  

    elif value == "all":
        unique_isps = set()
        for ip, data in config.IP_TABLE.items():
            isp = data.get('isp', 'N/A')
            unique_isps.add(isp)

        unique_isps = {isp for isp in unique_isps if isp is not None}

        for isp in sorted(unique_isps):  
            print_overview(isp)  


def print_overview_new(company):
    timestamp = datetime.now().strftime("%H:%M:%S %d.%m.%Y")
    unique_ip_list = []
    print(f"\n{timestamp} NEW unique ip addresses by company:")
    for ip, data in config.IP_TABLE.items():
        isp = data.get('isp')
        console_first_output = data.get('console_first_output')
        if isp == company and console_first_output == False:
            print(f"🌐 {ip}".ljust(20) +
                    f"{data.get('response_as', 'N/A'):<55} " +
                    f"{data.get('isp', 'N/A'):<45} " +
                    f"{data.get('zip', 'N/A'):<5} {data.get('city', 'N/A'):<20}{data.get('country', 'N/A'):<15} " +
                    f"{data.get('dns_name', 'N/A')}")
            data.update({"console_first_output": True})
            unique_ip_list.append(ip)
    
    if unique_ip_list:
        print(",".join(unique_ip_list))


def print_overview(company):
    timestamp = datetime.now().strftime("%H:%M:%S %d.%m.%Y")
    unique_ip_list = []
    print(f"\n{timestamp} OVERVIEW unique ip addresses by company:")
    for ip, data in config.IP_TABLE.items():
        isp = data.get('isp')
        if isp == company:
            print(f"🌐 {ip}".ljust(20) +
                    f"{data.get('response_as', 'N/A'):<55} " +
                    f"{data.get('isp', 'N/A'):<45} " +
                    f"{data.get('zip', 'N/A'):<5} {data.get('city', 'N/A'):<20}{data.get('country', 'N/A'):<15} " +
                    f"{data.get('dns_name', 'N/A')}")
            unique_ip_list.append(ip)
    
    if unique_ip_list:
        print(",".join(unique_ip_list))


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
            if destination and destination not in config.IP_TABLE:
                new_ips.add(destination)

        # Resolve DNS for new IPs
        if new_ips:
            config.IP_TABLE.update({ip: {} for ip in new_ips})
            
        for ip in new_ips:
            if ip not in config.IP_TABLE:
                config.IP_TABLE[ip] = {}

            dns_name = reverse_dns_lookup(ip)
            dns_name = dns_name if dns_name else "N/A"

            config.IP_TABLE[ip].update({"dns_name": dns_name})

            ip_api_data = get_ip_api(ip)
                            
            if ip_api_data is False:
                config.IP_TABLE[ip]["org"] = "❌ Error fetching ip-api.com - too many requests? Max 45 per 60 seconds"
        
        time.sleep(5)


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
        for iteration in range(0, 6):
            get_ips_company("new")
            time.sleep(10)
        print("")
        print(100*"#")
        print(40*" " + "OVERVIEW ABOUT ALL IPS")
        print(100*"#")
        get_ips_company("all")
        print("")
        print(100*"#")
        time.sleep(10)

        #time.sleep(60)
        #timestamp = datetime.now().strftime("%H:%M:%S %d.%m.%Y")
        #print(f"\n{timestamp} Already seen:")
        #print(",".join(config.IP_TABLE))

        time.sleep(10)
        #print(50*"#")
        #print("Print the global variable:")
        #for ip, data in config.IP_TABLE.items():
        #    print(f"🌐 {ip}".ljust(20) +
        #        f"{data.get('org', 'N/A'):<40} " +
        #        f"{data.get('response_as', 'N/A'):<55} " +
        #        f"{data.get('isp', 'N/A'):<45} " +
        #        f"{data.get('zip', 'N/A'):<5} {data.get('city', 'N/A'):<20}{data.get('country', 'N/A'):<15} " +
        #        f"{data.get('dns_name', 'N/A')}")