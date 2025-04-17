import os
import json
import requests

from .models import FirewallRule
from django.utils import timezone
from django.utils.timezone import now

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
DEL_RULE_ENDPOINT = f"{OPNSENSE_IP}/api/firewall/filter/delRule"
SEARCH_RULE_ENDPOINT = f"{OPNSENSE_IP}/api/firewall/filter/searchRule"
APPLY_ENDPOINT = f"{OPNSENSE_IP}/api/firewall/filter/apply"

def add_firewall_rule(ip_source, ip_destination, manual=False):
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

            # Update the database with the new rule
            try:
                FirewallRule.objects.get_or_create(
                    source_ip=ip_source,
                    destination_ip=ip_destination,
                    protocol="any",
                    port=0,
                    action="PASS",
                    manual=manual,
                    end_date=None,
                )

            except Exception as e:
                print(f"Error updating database: {e}")

            return True
        else:
            print(f"Error adding rule for {ip_destination}: {response.status_code} - {response.text}")
            return False

    except requests.RequestException as e:
        print(f"Network error: {e}")
        return False
    

def delete_rule_by_source_and_destination(ip_source, ip_destination):
    try:
        response = requests.get(
            SEARCH_RULE_ENDPOINT,
            auth=HTTPBasicAuth(API_KEY, API_SECRET),
            verify=CERT_PATH
        )

        if response.status_code != 200:
            print(f"❌ Error searching rules: {response.status_code} - {response.text}")
            return 0

        rules = response.json().get("rows", [])
        deleted_count = 0
        rule_found = False

        for rule in rules:
            desc = rule.get("description", "")
            if ip_source in desc and ip_destination in desc:
                rule_found = True
                uuid = rule.get("uuid")
                del_response = requests.post(
                    f"{DEL_RULE_ENDPOINT}/{uuid}",
                    auth=HTTPBasicAuth(API_KEY, API_SECRET),
                    verify=CERT_PATH
                )

                if del_response.status_code == 200:
                    FirewallRule.objects.filter(
                        source_ip=ip_source,
                        destination_ip=ip_destination,
                        end_date__isnull=True
                    ).update(end_date=timezone.now())

                    deleted_count += 1

                else:
                    print(f"❌ Failed to delete rule {uuid}: {del_response.status_code} - {del_response.text}")

        if not rule_found:
            # Rule not found on firewall but still in db
            db_update = FirewallRule.objects.filter(
                source_ip=ip_source,
                destination_ip=ip_destination,
                end_date__isnull=True
            ).update(end_date=now())

            if db_update:
                print(f"⚠️ Rule not in firewall but still activ in DB, cleaned up: {ip_source} → {ip_destination}")
        return deleted_count

    except requests.RequestException as e:
        print(f"⚠️ Network error: {e}")
        return 0


def get_all_rules():
    try:
        response = requests.post(
            SEARCH_RULE_ENDPOINT,
            auth=HTTPBasicAuth(API_KEY, API_SECRET),
            verify=CERT_PATH
        )
        if response.status_code == 200:
            return response.json().get("rows", [])
        else:
            print(f"Failed to get rules: {response.status_code} - {response.text}")
            return []
    except requests.RequestException as e:
        print(f"Error fetching all rules: {e}")
        return []



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
                    print(f"Rule already exists: {desc}")
                    return True
            return False
        else:
            print(f"Failed to search rules: {response.status_code} - {response.text}")
            return False
    except requests.RequestException as e:
        print(f"error while checking rules: {e}")
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
            print(f'Error applying firewall rules: {response.text}')
    except requests.RequestException as e:
        print(f"Network error while applying rules: {e}")
