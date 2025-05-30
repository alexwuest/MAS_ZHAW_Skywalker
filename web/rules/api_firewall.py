import json
import requests
import time
from django.utils import timezone
from requests.auth import HTTPBasicAuth

from .models import DeviceLease, FirewallRule
from . import config
from .config import API_KEY, API_SECRET, OPNSENSE_IP, CERT_PATH

# Endpoints
ADD_RULE_ENDPOINT = f"{OPNSENSE_IP}/api/firewall/filter/addRule"
DEL_RULE_ENDPOINT = f"{OPNSENSE_IP}/api/firewall/filter/delRule"
ADJUST_RULE_ENDPOINT = f"{OPNSENSE_IP}/api/firewall/filter/setRule"
SEARCH_RULE_ENDPOINT = f"{OPNSENSE_IP}/api/firewall/filter/searchRule"
GET_RULE_ENDPOINT = f"{OPNSENSE_IP}/api/firewall/filter/get_rule"
APPLY_ENDPOINT = f"{OPNSENSE_IP}/api/firewall/filter/apply"

# shared sessions
session = requests.Session()
session.auth = HTTPBasicAuth(API_KEY, API_SECRET)
session.headers.update({"Content-Type": "application/json"})

# sessions without header for get
session_get = requests.Session()
session_get.auth = HTTPBasicAuth(API_KEY, API_SECRET)


def add_firewall_rule(ip_source, ip_destination, description=None):
    """
    Add a firewall rule to allow traffic from ip_source to ip_destination.
    Returns the rule UUID on success, or None on failure.
    """
    rule_description = description or f"{ip_source} automated rule to {ip_destination}"

    payload = {
        "rule": {
            "action": "pass",
            #"interface": "lan",
            "ipprotocol": "inet",
            "protocol": "any",
            "source_net": ip_source,
            "destination_net": ip_destination,
            "log": "1",
            "description": rule_description,
        }
    }

    try:
        response = session.post(
            ADD_RULE_ENDPOINT,
            json=payload,
            verify=CERT_PATH
        )

        if response.status_code == 200:
            data = response.json()
            rule_uuid = data.get("uuid") or data.get("rule", {}).get("uuid")
            if rule_uuid:
                print(f"✅ Rule added. UUID: {rule_uuid} (for {ip_destination})")
                return rule_uuid
            else:
                print("⚠️ Rule added but UUID not returned.")
        else:
            print(f"❌ Failed to add rule: {response.status_code} - {response.text}")

    except requests.RequestException as e:
        print(f"⚠️ Network error while adding rule: {e}")

    return None


def delete_rule_by_uuid(rule_uuid):
    try:
        response = session.post(
            f"{DEL_RULE_ENDPOINT}/{rule_uuid}",
            json={"reason": "Auto-delete"},
            verify=CERT_PATH
        )
        if response.status_code == 200:
            print(f"✅ Deleted rule {rule_uuid}")
            return True
        else:
            print(f"❌ Failed to delete rule {rule_uuid}: {response.status_code} - {response.text}")
            return False
    except requests.RequestException as e:
        print(f"⚠️ Network error deleting rule {rule_uuid}: {e}")
        return False



def delete_rule_by_source_and_destination(ip_source, ip_destination):
    print(f"⚠️ WARNING SHOULD NOT USED ANYMORE")    #TODO REMOVE!!!!
    print(f"⚠️ WARNING SHOULD NOT USED ANYMORE")
    print(f"⚠️ WARNING SHOULD NOT USED ANYMORE")
    print(f"⚠️ WARNING SHOULD NOT USED ANYMORE")
    print(f"⚠️ WARNING SHOULD NOT USED ANYMORE")
    try:
        t0 = time.perf_counter()
        response = session_get.get(
            SEARCH_RULE_ENDPOINT,
            verify=CERT_PATH
        )

        t1 = time.perf_counter()
        api_duration = t1 - t0

        if response.status_code != 200:
            print(f"❌ Error searching rules: {response.status_code} - {response.text}")
            return 0
        
        if config.DEBUG_ALL:
            if response.status_code == 200:
                print(f"✅ Delete completed (Req time: {api_duration:.2f}s)")

        rules = response.json().get("rows", [])
        deleted_count = 0
        rule_found = False

        for rule in rules:
            desc = rule.get("description", "")
            if ip_source in desc and ip_destination in desc:
                rule_found = True
                uuid = rule.get("uuid")
                del_response = session.post(
                    f"{DEL_RULE_ENDPOINT}/{uuid}",
                    json={
                        "reason": "Auto-delete",
                        "source_net": ip_source,
                        "destination_net": ip_destination
                    },
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
            ).update(end_date=timezone.now())

            if db_update:
                print(f"⚠️ Rule not in firewall but still activ in DB, cleaned up: {ip_source} → {ip_destination}")
        return deleted_count

    except requests.RequestException as e:
        print(f"⚠️ Network error: {e}")
        return 0
    

def delete_multiple_rules(rules_to_remove):
    deleted_count = 0

    for ip_source, ip_destination in rules_to_remove:
        # Get rule from DB
        rule = FirewallRule.objects.filter(
            source_ip=ip_source,
            destination_ip=ip_destination,
            end_date__isnull=True
        ).order_by('-start_date').first()

        if rule and rule.uuid:
            if delete_rule_by_uuid(rule.uuid):
                rule.end_date = timezone.now()
                rule.save(update_fields=["end_date"])
                deleted_count += 1
            else:
                print(f"❌ Deletion failed for UUID {rule.uuid}")
        else:
            # Rule exists in DB but has no UUID or not found
            updated = FirewallRule.objects.filter(
                source_ip=ip_source,
                destination_ip=ip_destination,
                end_date__isnull=True
            ).update(end_date=timezone.now())

            if updated:
                print(f"⚠️ Rule not in firewall (or missing UUID), cleaned up DB: {ip_source} → {ip_destination}")

    return deleted_count


def get_all_rules_uuid(uuid):
    try:
        url = f"{GET_RULE_ENDPOINT}/{uuid}"
        response = requests.get(
            url,
            auth=HTTPBasicAuth(API_KEY, API_SECRET),
            verify=CERT_PATH
        )
        if config.DEBUG_ALL:
            print(f"🔄 RULE SYNC - Checking rule in OPNsense: {uuid} → Status code: {response.status_code}")

        if response.status_code == 200:
            data = response.json()
            if not data or "rule" not in data:
                if config.DEBUG:
                    print(f"⚠️ No rule found for UUID: {uuid}")
                return None
            return True  # Rule found
        elif response.status_code == 404:
            return None  # Rule not found
        else:
            print(f"⚠️ Unexpected status code: {response.status_code}")
            return None

    except requests.RequestException as e:
        print(f"❌ Error fetching rule by UUID: {e}")
        return None



def check_rule_exists(ip_source, ip_destination): # TODO REMOVE
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


def source_ip_adjustment(uuid, active_ip):
    """ Adjust source ip for Devices where this has changed """

    payload = {
        "rule": {
            "source_net": active_ip,
        }
    }

    try:
        url = f"{ADJUST_RULE_ENDPOINT}/{uuid}"
        response = session.post(
            url,
            json=payload,
            verify=CERT_PATH
        )

        if response.status_code == 200:
            data = response.json()
            rule_uuid = data.get("uuid") or data.get("rule", {}).get("uuid") or uuid
            print(f"✅ Rule adjusted. UUID: {rule_uuid}")
            return rule_uuid
        else:
            print(f"❌ Failed to adjust rule: {response.status_code} - {response.text}")

    except requests.RequestException as e:
        print(f"⚠️ Network error while adjusting rule: {e}")

    return None