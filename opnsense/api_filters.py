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
from dotenv import load_dotenv
from requests.auth import HTTPBasicAuth

# .env file with API_KEY, API_SECRET, and OPNSENSE_IP
load_dotenv()

# Store the variable from the .env file in the script
API_KEY = os.getenv("API_KEY")
API_SECRET = os.getenv("API_SECRET")
OPNSENSE_IP = os.getenv("OPNSENSE_IP")

# API Endpoints
SEARCH_RULES_ENDPOINT = f"{OPNSENSE_IP}/api/firewall/filter/searchRule"
GET_RULE_ENDPOINT = f"{OPNSENSE_IP}/api/firewall/filter/getRule"

def extract_selected_option(options):
    """Extract the selected value from a dictionary of options."""
    if isinstance(options, dict):
        for key, value in options.items():
            if isinstance(value, dict) and value.get("selected") == 1:
                return value.get("value", key)  # Default to key if value is missing
    return "N/A"

def format_network_info(network_info):
    """Format source/destination network details."""
    if isinstance(network_info, dict):
        return network_info.get("address", "any")
    return "any"

def get_firewall_rule_uuids():
    """Fetch all firewall rule UUIDs."""
    response = requests.post(SEARCH_RULES_ENDPOINT, auth=HTTPBasicAuth(API_KEY, API_SECRET), verify="certificate_crt.pem")

    if response.status_code == 200:
        return response.json().get("rows", [])
    else:
        print(f"ERROR fetching rule UUIDs: {response.status_code} - {response.text}")
        return []

def get_rule_details(uuid):
    """Fetch details of a single rule."""
    response = requests.get(f"{GET_RULE_ENDPOINT}/{uuid}", auth=HTTPBasicAuth(API_KEY, API_SECRET), verify="certificate_crt.pem")

    if response.status_code == 200:
        return response.json().get("rule", {})
    else:
        print(f"ERROR fetching rule {uuid}: {response.status_code} - {response.text}")
        return None

def fetch_and_display_firewall_rules():
    """Fetch and display all firewall rules with details."""
    rules = get_firewall_rule_uuids()

    if not rules:
        print("ERROR: No firewall rules found.")
        return

    print("\nFirewall Rules")
    for rule in rules:
        uuid = rule.get("uuid")
        enabled = rule.get("enabled", "1")  # Default to enabled if missing
        details = get_rule_details(uuid)

        if details:
            status = "✅" if enabled == "1" else "❌"
            action = extract_selected_option(details.get("action", {}))
            description = rule.get("description", "No description")
            interface = extract_selected_option(details.get("interface", {}))
            protocol = extract_selected_option(details.get("protocol", {}))

            source = details.get("source_net", "N/A")
            source_port = details.get("source_port", "N/A")
            destination = details.get("destination_net", "N/A")
            destination_port = details.get("destination_port", "N/A")

            print(f"Rule UUID: {uuid} ({status})")
            print(f"  - Action: {action}")
            print(f"  - Description: {description}")
            print(f"  - Interface: {interface}")
            print(f"  - Protocol: {protocol}")
            print(f"  - Source: {source}:{source_port}")
            print(f"  - Destination: {destination}:{destination_port}")
            print("-" * 50)

# Run script
if __name__ == "__main__":
    fetch_and_display_firewall_rules()



