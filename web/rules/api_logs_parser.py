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
from django.utils.timezone import now as django_now
from datetime import timedelta

from .models import FirewallLog, DestinationMetadata, DeviceLease
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

# Adding private IP check to avoid later IP lookup fails with ip-api.com and keep requests low...
def is_private_ip(ip):
    try:
        first, second, third, *_ = map(int, ip.split('.'))

        return (
            # Private Networks A,B,C
            first == 10 or
            (first == 172 and 16 <= second <= 31) or
            (first == 192 and second == 168) or

            # Loopback and link-local
            (first == 127 and second == 0) or
            (first == 169 and second == 254) or

            # Carrier-grade NAT
            (first == 100 and second == 64) or

            # Reserved / special-use
            (first == 192 and second == 0 and third == 0) or
            (first == 192 and second == 0 and third == 2) or
            (first == 192 and second == 88 and third == 99) or
            (first == 198 and second == 18) or
            (first == 198 and second == 51 and third == 100) or
            (first == 203 and second == 0 and third == 113) or

            # Multicast and broadcast (maybe not necessary, but good for safety)
            (first == 224 and second == 0) or
            (first == 255 and second == 255)
        )
    except Exception:
        return False

# Make sure the enrichment was done just once and avoid unnecessary requests to ip-api.com like private IPs
def enrich_ip(ip):
    RECHECK_AFTER_HOURS = 48
    now = datetime.datetime.now()

    if ip not in config.IP_TABLE:
        config.IP_TABLE[ip] = {}

    memory_entry = config.IP_TABLE[ip]

    # If entry already here and not old for recheck, skip it
    if memory_entry.get("_lookup_done"):
        try:
            last_checked = datetime.datetime.strptime(memory_entry["last_checked"], "%Y-%m-%d %H:%M:%S.%f")
            if (now - last_checked).total_seconds() < RECHECK_AFTER_HOURS * 3600:
                if config.DEBUG_ALL:
                    print(f"✅ Memory-enriched {ip} still fresh.")
                return
        except Exception:
            pass

    # DB check
    
    db_entry = DestinationMetadata.objects.filter(ip=ip, end_date__isnull=True).first()
    if db_entry and django_now() - db_entry.last_checked < datetime.timedelta(hours=RECHECK_AFTER_HOURS):
        config.IP_TABLE[ip]["_lookup_done"] = True
        config.IP_TABLE[ip]["last_checked"] = db_entry.last_checked.strftime("%Y-%m-%d %H:%M:%S.%f")
        config.IP_TABLE[ip]["dns_name"] = db_entry.dns_name or "N/A"
        config.IP_TABLE[ip]["isp"] = db_entry.isp or "N/A"
        return
       
    # Mark entry as not complete
    config.IP_TABLE[ip] = {"_lookup_done": False}
    dns_name = reverse_dns_lookup(ip) or "N/A"

    config.IP_TABLE[ip].update({"dns_name": dns_name})

    if not is_private_ip(ip):
        if config.DEBUG_ALL:
            print(f"🔄 Enriching IP {ip}...")  
        ip_api_data = get_ip_api(ip)
        if ip_api_data:
            config.IP_TABLE[ip].update(ip_api_data)
        else:
            config.IP_TABLE[ip]["org"] = "Error fetching ip-api.com"

    # Update the database with the new metadata
    meta = config.IP_TABLE[ip]
    required = ["isp", "country"]

    if all(meta.get(field) and meta.get(field) != "N/A" for field in required):
        DestinationMetadata.objects.update_or_create(
            ip=ip,
            end_date__isnull=True,
            defaults={
                "last_checked": django_now(),
                "dns_name": meta.get("dns_name") or "N/A",
                "city": meta.get("city") or "N/A",
                "country": meta.get("country") or "N/A",
                "continent": meta.get("continent") or "N/A",
                "continent_code": meta.get("continent_code") or "N/A",
                "region": meta.get("region") or "N/A",
                "region_name": meta.get("region_name") or "N/A",
                "district": meta.get("district") or "N/A",
                "zip_code": meta.get("zip_code") or "N/A",
                "lat": meta.get("lat") or 0.0,
                "lon": meta.get("lon") or 0.0,
                "timezone": meta.get("timezone") or "N/A",
                "offset": meta.get("offset") or 0,
                "currency": meta.get("currency") or "N/A",
                "isp": meta.get("isp") or "N/A",
                "org": meta.get("org") or "N/A",
                "as_number": meta.get("as_number") or "N/A",
                "as_name": meta.get("as_name") or "N/A",
                "mobile": meta.get("mobile") or False,
                "proxy": meta.get("proxy") or False,
                "hosting": meta.get("hosting") or False,
            }
        )

    # Mark it fully complete
    config.IP_TABLE[ip]["_lookup_done"] = True
    config.IP_TABLE[ip]["last_checked"] = now.strftime("%H:%M:%S.%f %d.%m.%Y")

# Normalize values for consistent comparison
def normalize(val):
    if val in [None, "", "N/A"]:
        return "N/A"
    return str(val).strip().lower()

# Start the log parser in a separate thread
def start_log_parser():
    """Run the log parser in a thread that loops forever."""
    thread = threading.Thread(target=parse_logs_loop)
    thread.daemon = True
    thread.start()


def parse_logs_loop():
    while True:
        run_log_parser_once()
        time.sleep(5)


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


def filter_logs(logs, search_address=None):
    # This function filtsers logs
    """Filter logs for blocked, rejected, or dropped connections, optionally filtering by IP."""
    filtered_logs = [
        log for log in logs 
        if log.get("action", "").lower() in {"block", "reject", "drop", "pass"}
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
            if config.DEBUG:
                print(f"📦 Enriched data for {ip}: {data}")
                print(f"✅ IP lookup successful: {ip} - {data.get('isp')}")
            time.sleep(1.4)  # about 43 requests per minute
            return data
        
        elif response.status_code == 429:
            print(f"⚠️ Too many requests to ip-api.com. Retrying in 60 seconds...")
            time.sleep(60)
            return get_ip_api(ip, retry=True)
        elif response.status_code == 403:
            print(f"⚠️ Forbidden access to ip-api.com. Check your API key or endpoint.")
            return None
        elif response.status_code == 500:
            print(f"⚠️ Server error from ip-api.com. Retrying in 60 seconds...")
            time.sleep(60)
            return get_ip_api(ip, retry=True)
        else:
            print(f"❌ Failed request: {response.status_code}")
    except requests.RequestException as e:
        print(f"⚠️ Network error: {e}")

    if not retry:
        print(f"🔁 Retrying in 60 seconds...")
        time.sleep(60)
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
        filtered_logs = filter_logs(logs, search_address)

        new_ips = set()

        for log in filtered_logs:
            log_entry = f"{log.get('__timestamp__')} - {log.get('action')} - {log.get('interface')} - {log.get('src')}:{log.get('srcport')} -> {log.get('dst')}:{log.get('dstport')}"
            if log_entry in seen_logs:
                continue

            seen_logs.add(log_entry)
            dst = log.get("dst")
            src = log.get("src")

            if not dst or not src:
                continue

            timestamp_str = log.get('__timestamp__')
            timestamp = parse_datetime(timestamp_str)
            if timestamp and timezone.is_naive(timestamp):
                timestamp = timezone.make_aware(timestamp)
            elif not timestamp:
                timestamp = timezone.now()
            
            if dst and not is_private_ip(dst):
                if config.DEBUG_ALL:
                    print("🔄 New log entry:", log_entry)
                new_ips.add(dst)

            # Enrich the IP address
            enrich_ip(dst)

            # Lookup existing metadata
            existing_metadata = DestinationMetadata.objects.filter(ip=dst, end_date__isnull=True).order_by('-start_date').first()

            # Avoid duplicate log entries
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

            if not exists:
                FirewallLog.objects.create(
                    timestamp=timestamp,
                    action=log.get("action", ""),
                    interface=log.get("interface", ""),
                    source_ip=src,
                    source_port=log.get("srcport"),
                    destination_ip=dst,
                    destination_port=log.get("dstport"),
                    protocol=log.get("proto", ""),
                    destination_metadata=existing_metadata
                )

        # Wait before starting the next run
        time.sleep(5)


def run_log_parser_once(search_address=None):
    logs = get_firewall_logs()
    filtered_logs = filter_logs(logs, search_address)

    output = []

    for log in filtered_logs:
        try:
            timestamp_str = log.get('__timestamp__')
            timestamp = parse_datetime(timestamp_str)
            if timestamp and timezone.is_naive(timestamp):
                timestamp = timezone.make_aware(timestamp)
            elif not timestamp:
                timestamp = timezone.now()

            # Update last_active time for lease
            src_ip = log.get('src')
            if src_ip:
                try:
                    lease = DeviceLease.objects.filter(ip_address=src_ip).order_by('-lease_start').first()
                    if lease:
                        lease.last_active = timezone.now()
                        lease.save(update_fields=["last_active"])
                except Exception as e:
                    print(f"Error updating last_active for {src_ip}: {e}")

            src = log.get("src")
            dst = log.get("dst")

            src_combined = f"{src}:{log.get('srcport')}".ljust(20)
            dst_combined = f"{dst}:{log.get('dstport')}".ljust(20)

            

            if existing_metadata:
                status = "✅"
                isp_display = existing_metadata.isp or "Unknown"
                log_entry = f"{timestamp_str} - {src_combined} → {dst_combined} [{status}] ({isp_display})"
            else:
                log_entry = f"{timestamp_str} - {src_combined} → {dst_combined} [🆕] (Unknown)"

            output.append(log_entry)

            # Avoid duplicate log entries
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

            if not exists:
                FirewallLog.objects.create(
                    timestamp=timestamp,
                    action=log.get("action", ""),
                    interface=log.get("interface", ""),
                    source_ip=src,
                    source_port=log.get("srcport"),
                    destination_ip=dst,
                    destination_port=log.get("dstport"),
                    protocol=log.get("proto", ""),
                    destination_metadata=existing_metadata
                )

        except Exception as e:
            print(f"⚠️ Error processing log entry: {e}")

    return output


