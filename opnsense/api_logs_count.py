import requests
import os
import time
from collections import Counter
import pandas as pd
from dotenv import load_dotenv
from requests.auth import HTTPBasicAuth

import config  # Assumes config.IP_TABLE = {}

# Load .env file containing credentials and IP
load_dotenv()

API_KEY = os.getenv("API_KEY")
API_SECRET = os.getenv("API_SECRET")
OPNSENSE_IP = os.getenv("OPNSENSE_IP")

# OPNsense API endpoint for logs
LOGS_ENDPOINT = f"{OPNSENSE_IP}/api/diagnostics/firewall/log"


def get_firewall_logs():
    """Fetch firewall logs from OPNsense API."""
    try:
        response = requests.get(LOGS_ENDPOINT, auth=HTTPBasicAuth(API_KEY, API_SECRET), verify="certificate_crt.pem")
        if response.status_code == 200:
            logs = response.json()
            print(f"Fetched {len(logs)} log entries")
            return logs if isinstance(logs, list) else []
        else:
            print(f"❌ Error fetching logs: {response.status_code} - {response.text}")
            return []
    except requests.RequestException as e:
        print(f"⚠️ Network error: {e}")
        return []


def get_ip_api(ip):
    """Query IP-API for info about the IP address."""
    url = f"http://ip-api.com/json/{ip}"
    try:
        response = requests.get(url)
        if response.status_code == 200:
            data = response.json()
            config.IP_TABLE[ip].update({
                "org": data.get("org", "N/A"),
                "response_as": data.get("as", "N/A"),
                "isp": data.get("isp", "N/A"),
                "zip": data.get("zip", "N/A"),
                "city": data.get("city", "N/A"),
                "country": data.get("country", "N/A"),
                "console_first_output": False
            })
            return True
    except Exception as e:
        print(f"Error querying IP {ip}: {e}")
    return False


# Fetch logs
log_data = get_firewall_logs()
if not log_data:
    exit("No logs retrieved. Exiting.")

# Preview first few entries to understand structure
for entry in log_data[:3]:
    print(entry)

TARGET_SRC_IP = input("Enter source IP to filter: ").strip()
filtered_logs = [entry for entry in log_data if entry.get("src") == TARGET_SRC_IP]

# Extract destination IPs for outbound traffic
ips = [entry["dst"] for entry in filtered_logs if "dst" in entry]

# Count requests to each destination IP
ip_counts = Counter(ips)
ip_counts_sorted = sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)

# Create DataFrame
df = pd.DataFrame(ip_counts_sorted, columns=["IP Address", "Request Count"])

# Enrich only top N IPs
TOP_N = 20
top_ips = df.head(TOP_N)["IP Address"]
for ip in top_ips:
    if ip not in config.IP_TABLE:
        config.IP_TABLE[ip] = {}
        get_ip_api(ip)
        time.sleep(1.5)  # to avoid getting into ip-api.com rate limit

# Add enrichment columns
df["Org"] = df["IP Address"].map(lambda ip: config.IP_TABLE.get(ip, {}).get("org", ""))
df["ISP"] = df["IP Address"].map(lambda ip: config.IP_TABLE.get(ip, {}).get("isp", ""))
df["City"] = df["IP Address"].map(lambda ip: config.IP_TABLE.get(ip, {}).get("city", ""))
df["Country"] = df["IP Address"].map(lambda ip: config.IP_TABLE.get(ip, {}).get("country", ""))

# Sort again
df = df.sort_values(by="Request Count", ascending=False)

# Display results
print(df.to_string(index=False))
