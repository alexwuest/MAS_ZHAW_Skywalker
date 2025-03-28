import requests
import os
import time
import threading
import socket
import datetime
from dotenv import load_dotenv
from requests.auth import HTTPBasicAuth
from pathlib import Path
from django.utils import timezone

from .models import FirewallLog, DestinationMetadata
from django.utils.dateparse import parse_datetime
from . import api_dhcp_parser, config

# Load .env file
load_dotenv()

# Get the absolute path to this script's directory
BASE_DIR = Path(__file__).resolve().parent

CERT_PATH = BASE_DIR / "certificate_crt.pem"

# Store the variable from the .env file in the script
API_KEY = os.getenv("API_KEY")
API_SECRET = os.getenv("API_SECRET")
OPNSENSE_IP = os.getenv("OPNSENSE_IP")

print("Loaded OPNSENSE_IP:", OPNSENSE_IP)

# API Endpoints
LOGS_ENDPOINT = f"{OPNSENSE_IP}/api/diagnostics/firewall/log"

def get_firewall_logs():
    """Fetch firewall logs from OPNsense API."""
    #api_dhcp_parser.parse_opnsense_leases()  # Get the DHCP leases from the firewall
    try:
        response = requests.get(LOGS_ENDPOINT, auth=HTTPBasicAuth(API_KEY, API_SECRET), verify=CERT_PATH)

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
    try:
        response = requests.get(url)
        if response.status_code == 200:
            data = response.json()
            if data.get("status") != "success":
                print(f"⚠️ IP lookup failed: {data}")
                return None

            config.IP_TABLE[ip].update({
                "dns_name": reverse_dns_lookup(ip) or "N/A",
                "status": data.get("status"),
                "continent": data.get("continent"),
                "continent_code": data.get("continentCode"),
                "country": data.get("country"),
                "country_code": data.get("countryCode"),
                "region": data.get("region"),
                "region_name": data.get("regionName"),
                "city": data.get("city"),
                "district": data.get("district"),
                "zip_code": data.get("zip"),
                "lat": data.get("lat"),
                "lon": data.get("lon"),
                "timezone": data.get("timezone"),
                "offset": data.get("offset"),
                "currency": data.get("currency"),
                "isp": data.get("isp"),
                "org": data.get("org"),
                "as_number": data.get("as"),
                "as_name": data.get("asname"),
                "mobile": data.get("mobile"),
                "proxy": data.get("proxy"),
                "hosting": data.get("hosting"),
            })
            return data  # return the whole payload if needed
        else:
            print(f"❌ Failed request: {response.status_code}")
    except requests.RequestException as e:
        print(f"⚠️ Network error: {e}")

    if not retry:
        print(f"🔁 Retrying in 45 seconds...")
        time.sleep(45)
        return get_ip_api(ip, retry=True)
    else:
        print("❌ Permanent failure.")
        return None



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

def run_log_parser_once(search_address=None):
    logs = get_firewall_logs()
    blocked_logs = filter_blocked_logs(logs, search_address)

    new_ips = set()
    output = []

    for log in blocked_logs:
        try:
            timestamp_str = log.get('__timestamp__')
            timestamp = parse_datetime(timestamp_str)
            if timestamp and timezone.is_naive(timestamp):
                timestamp = timezone.make_aware(timestamp)
            elif not timestamp:
                timestamp = timezone.now()

            src = log.get("src")
            dst = log.get("dst")

            log_entry = f"{timestamp_str} - {log.get('action')} - {log.get('interface')} - {src}:{log.get('srcport')} -> {dst}:{log.get('dstport')}"
            output.append(log_entry)

            # Reverse DNS and metadata
            if dst not in config.IP_TABLE:
                config.IP_TABLE[dst] = {}
                config.IP_TABLE[dst]["dns_name"] = reverse_dns_lookup(dst) or "N/A"
                ip_api_data = get_ip_api(dst)

                if not ip_api_data:
                    config.IP_TABLE[dst]["org"] = "❌ Error fetching ip-api.com"
                else:
                    config.IP_TABLE[dst].update(ip_api_data)

            meta_data = config.IP_TABLE.get(dst, {})
            # Get the most recent (non-expired) metadata if it exists
            metadata_obj = DestinationMetadata.objects.filter(ip=dst, end_date__isnull=True).order_by('-start_date').first()

            metadata_changed = False
            # Check if entry has changed with the fields bellow
            if metadata_obj:
                if (
                    metadata_obj.dns_name != meta_data.get("dns_name", "N/A") or
                    metadata_obj.isp != meta_data.get("isp", "N/A") or
                    metadata_obj.city != meta_data.get("city", "N/A") or
                    metadata_obj.country != meta_data.get("country", "N/A")
                ):
                    # Change the entry if the meta data has changed
                    metadata_changed = True
                    metadata_obj.end_date = timezone.now()
                    metadata_obj.save()
                    metadata_obj = None

            # If no entry found make a new entry
            if not metadata_obj:
                metadata_obj = DestinationMetadata.objects.create(
                ip=dst,
                dns_name=meta_data.get("dns_name") or "N/A",
                isp=meta_data.get("isp") or "N/A",
                city=meta_data.get("city") or "N/A",
                country=meta_data.get("country") or "N/A",
                continent=meta_data.get("continent") or "N/A",
                continent_code=meta_data.get("continent_code") or "N/A",
                region=meta_data.get("region") or "N/A",
                region_name=meta_data.get("region_name") or "N/A",
                district=meta_data.get("district") or "N/A",  # 🛠️ critical line
                zip_code=meta_data.get("zip_code") or "N/A",
                lat=meta_data.get("lat") or 0.0,
                lon=meta_data.get("lon") or 0.0,
                timezone=meta_data.get("timezone") or "N/A",
                offset=meta_data.get("offset") or 0,
                currency=meta_data.get("currency") or "N/A",
                org=meta_data.get("org") or "N/A",
                as_number=meta_data.get("as_number") or "N/A",
                as_name=meta_data.get("as_name") or "N/A",
                mobile=meta_data.get("mobile") or False,
                proxy=meta_data.get("proxy") or False,
                hosting=meta_data.get("hosting") or False,
            )


            # If the entry already exists skip
            exists = FirewallLog.objects.filter(
                timestamp=timestamp,
                action=log.get("action", ""),
                interface=log.get("interface", ""),
                source_ip=src,
                source_port=log.get("srcport"),
                destination_ip=dst,
                destination_port=log.get("dstport"),
                protocol=log.get("proto", "")
            ).exists()

            # If there was no entry before... make a new entry now
            if not exists:
                # Save to DB if not already present
                FirewallLog.objects.create(
                    timestamp=timestamp,
                    action=log.get("action", ""),
                    interface=log.get("interface", ""),
                    source_ip=src,
                    source_port=log.get("srcport"),
                    destination_ip=dst,
                    destination_port=log.get("dstport"),
                    protocol=log.get("proto", ""),
                    destination_metadata=metadata_obj
                )

        except Exception as e:
            print(f"⚠️ Error processing log entry: {e}")

    return output
