import requests
import datetime
from pprint import pprint
from django.utils.timezone import now, make_aware

from .models import DeviceLease
from .config import API_KEY, API_SECRET, OPNSENSE_IP, CERT_PATH
from . import config

DHCP_ENDPOINT = f"{OPNSENSE_IP}/api/dhcpv4/leases/searchLease"

def parse_opnsense_leases():
    print("Fetching DHCP leases...")

    try:
        # Make the API request to fetch DHCP leases
        print(f"→ Requesting {DHCP_ENDPOINT} with API key and secret")
        response = requests.get(DHCP_ENDPOINT, auth=(API_KEY, API_SECRET), verify=CERT_PATH, timeout=5)
        print(f"→ Status code: {response.status_code}")

        # Check if the request was successful
        response.raise_for_status()

        try:
            data = response.json()
        except ValueError:
            print("❌ Invalid JSON in DHCP response.")
            return
        except Exception as e:
            print(f"❌ Failed to parse JSON: {e}")
            return

        leases = data.get("rows", [])
        print(f"→ {len(leases)} leases found")
    
    except requests.exceptions.RequestException as e:
        print(f"⚠️ DHCP lease fetch failed: {e}")
        return

    for lease in leases:
        try:
            if config.DEBUG_ALL:
                pprint(lease)

            ip = lease["address"]
            mac = lease["mac"].lower()
            starts = make_aware(datetime.datetime.strptime(lease["starts"], "%Y/%m/%d %H:%M:%S"))
            ends = make_aware(datetime.datetime.strptime(lease["ends"], "%Y/%m/%d %H:%M:%S"))
            hostname = lease.get("hostname", "")
            manufacturer = lease.get("man", "")
            interface = lease.get("if_descr", "")

            lease_obj, created = DeviceLease.objects.update_or_create(
                ip_address=ip,
                mac_address=mac,
                defaults={
                    "lease_start": starts,
                    "lease_end": ends,
                    "hostname": hostname,
                    "manufacturer": manufacturer,
                    "interface": interface,
                    "last_active": now()
                }
            )

            # Only clear the device if this is a brand new lease record
            if created:
                lease_obj.device = None
                lease_obj.save()

            action = "Created" if created else "Updated"
            print(f"{action} lease: {mac} @ {ip} ({hostname})")

        except Exception as e:
            print(f"❌ Error processing lease {lease.get('mac', '')}: {e}")
