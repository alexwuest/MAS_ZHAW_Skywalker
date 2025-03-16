
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
DEL_RULE_ENDPOINT = f"{OPNSENSE_IP}/api/firewall/filter/delRule"

def extract_selected_option(options):
    """Extract the selected value from a dictionary of options."""
    if isinstance(options, dict):
        for key, value in options.items():
            if isinstance(value, dict) and value.get("selected") == 1:
                return value.get("value", key)  # Default to key if value is missing
    return "N/A"

def get_firewall_rule_uuids():
    """Fetch all firewall rule UUIDs."""
    response = requests.get(SEARCH_RULES_ENDPOINT, auth=HTTPBasicAuth(API_KEY, API_SECRET), verify="certificate_crt.pem")

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

def fetch_and_delete_firewall_rules(search_string):
    """Fetch and display all firewall rules with details."""
    rules = get_firewall_rule_uuids()

    if not rules:
        print("ERROR: No firewall rules found.")
        return

    print("\nDeleted Firewall Rules")
    for rule in rules:
        uuid = rule.get("uuid")
        details = get_rule_details(uuid)

        if details:
            description = rule.get("description", "No description")
            if description == search_string + " automatically added rule":
                del_rule = requests.post(f"{DEL_RULE_ENDPOINT}/{uuid}", auth=HTTPBasicAuth(API_KEY, API_SECRET), verify="certificate_crt.pem")
                if del_rule.status_code == 200:
                    print(f"✅ SUCCESS: Deleted rule {uuid}")
                else:
                    print(f"❌ ERROR: {del_rule.status_code}: {del_rule.text}")

# Run script
if __name__ == "__main__":
    search_string = input("Enter the IP address to delete all rules based on it (which were made automatilcy): ")
    fetch_and_delete_firewall_rules(search_string)



