import os
import json
import requests
from pathlib import Path
from dotenv import load_dotenv
from requests.auth import HTTPBasicAuth

# Load .env
env_path = Path(__file__).resolve().parent.parent / ".env"
load_dotenv(dotenv_path=env_path)

API_KEY = os.getenv("API_KEY")
API_SECRET = os.getenv("API_SECRET")
OPNSENSE_IP = os.getenv("OPNSENSE_IP")

session = requests.Session()
session.auth = HTTPBasicAuth(API_KEY, API_SECRET)
session.headers.update({"Content-Type": "application/json"})

# Add a rule
ADD_RULE_URL = f"{OPNSENSE_IP}/api/firewall/filter/addRule"
payload = {
    "interface": "lan",
    "action": "pass",
    "direction": "in",
    "protocol": "any",
    "source_address": "",
    "source_port": "",
    "destination_address": "",
    "destination_port": "",
    "description": "Minimal rule for testing add_rule"
}


response = session.post(ADD_RULE_URL, json=payload, verify=False)
print("Add rule response:", response.status_code, response.text)

# Apply rules
APPLY_URL = f"{OPNSENSE_IP}/api/firewall/filter/apply"
apply_response = session.post(APPLY_URL, json={}, verify=False)
print("Apply response:", apply_response.status_code, apply_response.text)

# Search for rules
SEARCH_URL = f"{OPNSENSE_IP}/api/firewall/filter/search_rule"
search_response = session.post(SEARCH_URL, json={}, verify=False)
print("Search result:")
print(json.dumps(search_response.json(), indent=2))
