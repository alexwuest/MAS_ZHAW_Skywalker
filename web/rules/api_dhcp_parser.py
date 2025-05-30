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

    if leases:
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

                # Find active lease for this IP and MAC
                existing = DeviceLease.objects.filter(
                    ip_address=ip,
                    mac_address=mac,
                    lease_end__gte=now()
                ).order_by('-lease_start').first()

                if existing:
                    existing.lease_start = starts
                    existing.lease_end = ends
                    existing.hostname = hostname
                    existing.manufacturer = manufacturer
                    existing.interface = interface
                    existing.last_active = now()
                    existing.save()
                    print(f"Updated lease: {mac} @ {ip}")
                
                else:
                    DeviceLease.objects.create(
                        ip_address=ip,
                        mac_address=mac,
                        lease_start=starts,
                        lease_end=ends,
                        hostname=hostname,
                        manufacturer=manufacturer,
                        interface=interface,
                        last_active=now(),
                        device=None
                    )
                    print(f"Created lease: {mac} @ {ip} ({hostname})")

            except Exception as e:
                print(f"Error processing lease: {e}")