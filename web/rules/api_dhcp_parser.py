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
    response = requests.get(DHCP_ENDPOINT, auth=(API_KEY, API_SECRET), verify=CERT_PATH)

    print(f"→ Status code: {response.status_code}")

    try:
        data = response.json()
    except Exception as e:
        print(f"Failed to parse JSON: {e}")
        return

    leases = data.get("rows", [])
    print(f"→ {len(leases)} leases found")

    for lease in leases:
        try:
            
            if config.DEBUG_ALL:
                pprint(lease)  # log full raw lease for debugging

            ip = lease["address"]
            mac = lease["mac"].lower()
            starts = make_aware(datetime.datetime.strptime(lease["starts"], "%Y/%m/%d %H:%M:%S"))
            ends = make_aware(datetime.datetime.strptime(lease["ends"], "%Y/%m/%d %H:%M:%S"))
            hostname = lease.get("hostname", "")
            manufacturer = lease.get("man", "")
            interface = lease.get("if_descr", "")

            obj, created = DeviceLease.objects.get_or_create(
                ip_address=ip,
                mac_address=mac,
                lease_start=starts,
                defaults={
                    'lease_end': ends,
                    'hostname': hostname,
                    'manufacturer': manufacturer,
                    'interface': interface,
                    'device': None,
                }
            )

            if created:
                print(f" Created lease: {mac} @ {ip} ({hostname})")
            else:
                obj.lease_end = ends
                obj.last_seen = now()
                obj.save()
                print(f"Updated lease: {mac} @ {ip}")
        except Exception as e:
            print(f"Error processing lease: {e}")