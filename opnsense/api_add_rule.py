"""
API DOCUMENTATION OPNsense
https://docs.opnsense.org/development/api.html 

API ENDPOINTS
https://docs.opnsense.org/development/api/core/firewall.html#

API CALL To get a single rule...
curl -k -u "***API_KEY***:***API_SECRET***" \
     "https://OPNsense.localdomain/api/firewall/filter/getRule/***RULE_UUID***"

"""
import requests
import os
import json
import time
from dotenv import load_dotenv
from requests.auth import HTTPBasicAuth

# .env file with API_KEY, API_SECRET, and OPNSENSE_IP
load_dotenv()

# Store the variable from the .env file in the script
API_KEY = os.getenv("API_KEY")
API_SECRET = os.getenv("API_SECRET")
OPNSENSE_IP = os.getenv("OPNSENSE_IP")

# API Endpoints
ADD_RULE_ENDPOINT = f"{OPNSENSE_IP}/api/firewall/filter/addRule"

def kill_states(ip_source):
    """Kills firewall states for a specific source IP."""
    url = f"{OPNSENSE_IP}/api/diagnostics/firewall/killstates"
    payload = {"source": ip_source}
    
    response = requests.post(url, json=payload, auth=HTTPBasicAuth(API_KEY, API_SECRET), verify="certificate_crt.pem")

    if response.status_code == 200:
        print(f"Successfully killed states for {ip_source}")
    else:
        print(f"Error {response.status_code}: {response.text}")


def send_opnsense_command(endpoint):
    """Send an API call to OPNsense."""
    url = f"{OPNSENSE_IP}{endpoint}"
    try:
        response = requests.post(
            url,
            auth=HTTPBasicAuth(API_KEY, API_SECRET),
            headers={"Content-Type": "application/json"},
            verify="certificate_crt.pem"
        )
        if response.status_code == 200:
            print(f"✅ Command executed successfully: {endpoint}")
        else:
            print(f"❌ Error executing {endpoint}: {response.status_code} - {response.text}")
    except requests.RequestException as e:
        print(f"⚠️ Network error: {e}")

def apply_firewall_changes():
    """Automate firewall rules reload, state flush, and service restart."""
    print("🧹 Flushing old sources...")
    send_opnsense_command("/api/diagnostics/firewall/flushSources")

    print("🧹 Flushing old connection states...")
    send_opnsense_command("/api/diagnostics/firewall/flushStates")

    print("🚀 Restarting firewall service...")
    send_opnsense_command("/api/service/restart?service=pf")


def add_firewall_rule(ip_source, ip_destination):
    """Send API request to add a firewall rule allowing traffic from the given IP."""
    
    headers = {"Content-Type": "application/json"}
    payload = {
        "rule": {
            "action": "pass",
            "interface": "lan",
            "ipprotocol": "inet",
            "protocol": "any",
            "source_net": ip_source,
            "destination_net": ip_destination,
            "description": ip_source + " automatically added rule" # If change made here, also change in api_del_rule.py
        }
    }

    try:
        response = requests.post(
            ADD_RULE_ENDPOINT,
            auth=HTTPBasicAuth(API_KEY, API_SECRET),
            headers=headers,
            data=json.dumps(payload),
            verify="certificate_crt.pem"
        )

        if response.status_code == 200:
            print(f"✅ Rule added for {ip_destination}")
        else:
            print(f"❌ Error adding rule for {ip_destination}: {response.status_code} - {response.text}")

    except requests.RequestException as e:
        print(f"⚠️ Network error: {e}")

if __name__ == "__main__":

    ip_source = input("Enter the source IP address: ")

    ip_destination_input = input("Enter the destination IP addresses (separate multiple with commas): ")
    ip_destinations = [ip.strip() for ip in ip_destination_input.split(",")]

    for ip in ip_destinations:
        add_firewall_rule(ip_source, ip)
    
    time.sleep(5)
    print(f"Killing states for the source IP {ip_source}")
    kill_states(ip_source)
    apply_firewall_changes()
