import os
import json
import requests
from dotenv import load_dotenv
from requests.auth import HTTPBasicAuth

# Load API credentials
load_dotenv()
API_KEY = os.getenv("API_KEY")
API_SECRET = os.getenv("API_SECRET")
OPNSENSE_IP = os.getenv("OPNSENSE_IP")

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
CERT_PATH = os.path.join(CURRENT_DIR, "certificate_crt.pem")

# Endpoints
ADD_RULE_ENDPOINT = f"{OPNSENSE_IP}/api/firewall/filter/addRule"
SEARCH_RULE_ENDPOINT = f"{OPNSENSE_IP}/api/firewall/filter/searchRule"
APPLY_ENDPOINT = f"{OPNSENSE_IP}/api/firewall/filter/apply"

def add_firewall_rule(ip_source, ip_destination):
    headers = {"Content-Type": "application/json"}
    payload = {
        "rule": {
            "action": "pass",
            "interface": "lan",
            "ipprotocol": "inet",
            "protocol": "any",
            "source_net": ip_source,
            "destination_net": ip_destination,
            "description": f"{ip_source} automatically added rule to {ip_destination}"
        }
    }

    try:
        response = requests.post(
            ADD_RULE_ENDPOINT,
            auth=HTTPBasicAuth(API_KEY, API_SECRET),
            headers=headers,
            data=json.dumps(payload),
            verify=CERT_PATH
        )

        if response.status_code == 200:
            print(f"✅ Rule added for {ip_destination}")
            return True
        else:
            print(f"❌ Error adding rule for {ip_destination}: {response.status_code} - {response.text}")
            return False

    except requests.RequestException as e:
        print(f"⚠️ Network error: {e}")
        return False


def check_rule_exists(ip_source, ip_destination):
    try:
        response = requests.post(
            SEARCH_RULE_ENDPOINT,
            auth=HTTPBasicAuth(API_KEY, API_SECRET),
            verify=CERT_PATH
        )

        if response.status_code == 200:
            rules = response.json().get("rows", [])
            for rule in rules:
                desc = rule.get("description", "")
                if ip_source in desc and ip_destination in desc:
                    print(f"🛑 Rule already exists: {desc}")
                    return True
            return False
        else:
            print(f"❌ Failed to search rules: {response.status_code} - {response.text}")
            return False
    except requests.RequestException as e:
        print(f"⚠️ Network error while checking rules: {e}")
        return False


def apply_firewall_changes():
    try:
        response = requests.post(
            APPLY_ENDPOINT,
            auth=HTTPBasicAuth(API_KEY, API_SECRET),
            verify=CERT_PATH
        )

        if response.status_code == 200:
            print('✅ Firewall rules applied.')
        else:
            print(f'❌ Error applying firewall rules: {response.text}')
    except requests.RequestException as e:
        print(f"⚠️ Network error while applying rules: {e}")
