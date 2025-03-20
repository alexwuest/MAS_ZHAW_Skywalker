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
            "description": ip_source + " automatically added rule to " + ip_destination # If change made here, also change in api_del_rule.py
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


def check_rule_exists(ip_source, ip_destination):
    """Check if a firewall rule exists for the given IP."""
    apply_url = f'{OPNSENSE_IP}/api/firewall/filter/searchRule'
    response = requests.post(apply_url, auth=(API_KEY, API_SECRET), verify="certificate_crt.pem")

    if response.status_code == 200:
        rules = response.json().get("rule", [])
    
        for rule in rules:
            uuid = rule.get("uuid")
            description = rule.get("description", "")
            if ip_destination in description:
                if ip_source in description:
                    print(f"IP Address already exists in the firewall rules: {uuid}")       
                    return True
                
        return False # If no IP address found

    else:
        print(f"ERROR fetching rules: {response.status_code} - {response.text}")
        return None


def apply_firewall_changes():
    apply_url = f'{OPNSENSE_IP}/api/firewall/filter/apply'
    response = requests.post(apply_url, auth=(API_KEY, API_SECRET), verify="certificate_crt.pem")

    if response.status_code == 200:
        print('Firewall rules applied.')
    else:
        print(f'Error applying firewall rules: {response.text}')

if __name__ == "__main__":

    ip_source = input("Enter the source IP address: ")
    while True:
        ip_destination_input = input("Enter the destination IP addresses (separate multiple with commas): ")
        ip_destinations = [ip.strip() for ip in ip_destination_input.split(",")]

        for ip in ip_destinations:
            if check_rule_exists(ip_source, ip):
                continue
            else:
                add_firewall_rule(ip_source, ip)
        
        time.sleep(5)
        #kill_states(ip_source)
        #print(f"Killing states for the source IP {ip_source}")
        apply_firewall_changes()
