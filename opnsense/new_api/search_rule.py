import os
import json
import requests
from pathlib import Path
from dotenv import load_dotenv
from requests.auth import HTTPBasicAuth

# === Load .env configuration ===
env_path = Path(__file__).resolve().parent.parent / ".env"
load_dotenv(dotenv_path=env_path)

API_KEY = os.getenv("API_KEY")
API_SECRET = os.getenv("API_SECRET")
OPNSENSE_IP = os.getenv("OPNSENSE_IP")  # e.g., "https://opnsense.localdomain"

# === Session setup ===
session = requests.Session()
session.auth = HTTPBasicAuth(API_KEY, API_SECRET)
session.headers.update({"Content-Type": "application/json"})

# === Endpoint ===
SEARCH_RULES_URL = f"{OPNSENSE_IP}/api/firewall/filter/searchRule"

# === Request ===
def fetch_firewall_rules():
    try:
        response = session.post(SEARCH_RULES_URL, json={}, verify=False)
        response.raise_for_status()

        rules_data = response.json()
        rules = rules_data.get("rows", [])

        if not rules:
            print("No rules found.")
            return

        print("=== 🔥 Firewall Rules ===")
        for rule in rules:
            print(f"- UUID: {rule.get('uuid')}")
            print(f"  Action: {rule.get('action')}")
            print(f"  Interface: {rule.get('interface')}")
            print(f"  Source: {rule.get('source_net')} -> Destination: {rule.get('destination_net')}")
            print(f"  Description: {rule.get('descr')}\n")

    except requests.RequestException as e:
        print(f"❌ Error fetching rules: {e}")


# === Entry point ===
if __name__ == "__main__":
    fetch_firewall_rules()
