#TODO Longer inactive devices should be removed from the firewall list to keep it clean and API calls quicker
#TODO Update when source ip changes /api/firewall/filter/setRule/{uuid}

from django.utils import timezone
from django.utils.timezone import now
from datetime import timedelta
from .models import Device, DeviceLease, DeviceAllowedISP, FirewallLog, FirewallRule, DestinationMetadata
from .api_firewall import add_firewall_rule, get_all_rules_uuid, apply_firewall_changes, delete_multiple_rules, delete_rule_by_uuid
from . import config

def get_active_ip(device_id_str):
    from .models import Device
    now = timezone.now()
    try:
        device = Device.objects.get(device_id=device_id_str)
    except Device.DoesNotExist:
        return None
    lease = DeviceLease.objects.filter(device=device, lease_end__gt=now).order_by('-lease_start').first()
    return lease.ip_address if lease else None


def get_allowed_isps(device_id):
    return list(DeviceAllowedISP.objects.filter(device__device_id=device_id).values_list('isp_name', flat=True))

def get_blocked_ips_by_isp(isp_list):
    return set(
        FirewallLog.objects.filter(
            action='block',
            destination_metadata__isp__in=isp_list
        ).values_list('destination_ip', flat=True)
    )

                                        
def check_rule_exists(ip_source, ip_destination):                                           # NEW Rule check!
    # Try to find rule in the DB
    rule = FirewallRule.objects.filter(
        source_ip=ip_source,
        destination_ip=ip_destination,
        end_date__isnull=True
    ).order_by('-start_date').first()

    if not rule:
        return None

    uuid = rule.uuid
    if not uuid:
        print(f"⚠️ Rule found in DB but has no UUID: {ip_source} → {ip_destination}")
        return None

    try:
        # Confirm via API using UUID
        if get_all_rules_uuid(uuid) is None:
            print(f"⚠️ Rule in DB --- But UUID not found in API: {uuid}")
            return None
        else:
            print(f"✅ Rule found in API: {uuid}")
            return True
    except Exception as e:
        print(f"❌ Exception during rule UUID check: {e}")
        return None

##############################################################################################################################
# Sync OPNsense Firewall Rules
##############################################################################################################################
def db_opnsense_sync():

    # Overview variables
    verified = 0
    ended = 0
    deleted = 0
    failed = 0

    # Load all active rules with verify_opnsense True
    rules_to_verify = FirewallRule.objects.filter(verify_opnsense=True)
    print(f"Found {rules_to_verify.count()} rules to verify against OPNsense.")

    if not rules_to_verify.exists():
        return

    for rule in rules_to_verify:
        if config.DEBUG:
            print(f"🔄 🔄 Rule Sync in progress... 🔄 🔄")
            print(f"Verifying rule: {rule.uuid} ({rule.source_ip} → {rule.destination_ip})")

        try:
            exists = get_all_rules_uuid(rule.uuid)
            if config.DEBUG_ALL:
                print(f"Rule.uuid = {rule.uuid}")
                print(exists)
                print(f"🔄 RULE SYNC - Checking rule in OPNsense: {rule.uuid} ({rule.source_ip} → {rule.destination_ip})")
            
        except Exception as e:
            print(f"⚠️ RULE SYNC - Exception while checking rule in OPNsense: {e}")
            failed += 1
            continue
        
        # If rule has no end_date, still active
        if not rule.end_date:
            
            if exists is None:
                if config.DEBUG:
                    print(f"❌  RULE SYNC - Rule not found in OPNsense (OPNsense inactive / DB active!!!): {rule.uuid} ({rule.source_ip} → {rule.destination_ip}) - mark to end now in DB!")
                rule.end_date = now()
                rule.verify_opnsense = False
                rule.save(update_fields=['end_date', 'verify_opnsense'])
                ended +=1

            else:
                if config.DEBUG_ALL:
                    print(f"✅ RULE SYNC - Rule verified in OPNsense: {rule.uuid} ({rule.source_ip} → {rule.destination_ip})")
                rule.verify_opnsense = False
                rule.save(update_fields=['verify_opnsense'])
                verified += 1

        # Rule has end_date - should not in OPNSense
        else:
            if exists is None:
                rule.verify_opnsense = False
                rule.save(update_fields=['verify_opnsense'])

            else:
                if config.DEBUG:
                    print(f"⚠️ RULE SYNC - Rule still exists in OPNsense (OPNsense active / DB inactive!!!): {rule.uuid} ({rule.source_ip} → {rule.destination_ip})")
                
                try:
                    # Attempt to delete the rule in OPNsense
                    was_deleted = delete_rule_by_uuid(rule.uuid)
                    if was_deleted:
                        if config.DEBUG:
                            print(f"✅ RULE SYNC - Rule deleted in OPNsense (was OPNsense active / DB inactive): {rule.uuid} ({rule.source_ip} → {rule.destination_ip})")
                        rule.verify_opnsense = False
                        rule.save(update_fields=['verify_opnsense'])
                        deleted += 1

                    else:
                        print(f"❌ RULE SYNC - Failed to delete rule in OPNsense (OPNsense active / DB inactive!!!): {rule.uuid} ({rule.source_ip} → {rule.destination_ip})")
                        failed += 1

                except Exception as e:
                    print(f"❌ RULE SYNC - Exception during rule deletion: {e}")
                    failed += 1
                    continue
    # Adding all changes
    if deleted > 0:
        apply_firewall_changes()
    
    print("- RULE SYNC SUMMARY -")
    print(f"  ✅ Verified rules: {verified}")
    print(f"  🧹 Ended rules in DB (missing in OPNsense): {ended}")
    print(f"  ❌ Deleted stale rules from OPNsense: {deleted}")
    print(f"  ⚠️ Failures: {failed}")
                

##############################################################################################################################
# Management ISP Rules
##############################################################################################################################
def allow_blocked_ips_for_device(device_id, return_removed=False):          
    print(f"Allowing blocked IPs for device: {device_id}")
    ip_source = get_active_ip(device_id)
    if not ip_source:
        return 0

    allowed_isps = get_allowed_isps(device_id)
    dest_ips = get_blocked_ips_by_isp(allowed_isps)

    # Preload existing rules from DB (active only, non-manual, non-DNS)
    existing_rules_qs = FirewallRule.objects.filter(
        source_ip=ip_source,
        end_date__isnull=True,
        manual=False,
        dns=False
    )
    existing_rules = {
        (rule.source_ip, rule.destination_ip): rule
        for rule in existing_rules_qs
    }

    # Preload metadata (enrichment cache)
    metadata_lookup = {
        m.ip: m for m in DestinationMetadata.objects.filter(ip__in=dest_ips, end_date__isnull=True)
    }

    added = 0
    valid_dest_ips = set()

    for ip_dest in dest_ips:
        key = (ip_source, ip_dest)
        valid_dest_ips.add(ip_dest)

        rule = existing_rules.get(key)

        if rule:
            rule.verify_opnsense = True
            rule.save(update_fields=["verify_opnsense"])

        else:
            # No rule in DB — create it and send to OPNsense
            metadata = metadata_lookup.get(ip_dest)
            isp_name = metadata.isp if metadata else "Unknown"
            uuid = add_firewall_rule(ip_source, ip_dest)
            if uuid:
                existing = FirewallRule.objects.filter(uuid=uuid).first()
                if existing:
                    print(f"⚠️ Skipped adding duplicate UUID to DB: {uuid}")
                else:
                    device_instance = Device.objects.get(device_id=device_id)
                    FirewallRule.objects.create(
                        source_ip=ip_source,
                        device=device_instance,
                        destination_ip=ip_dest,
                        protocol="any",
                        port=0,
                        action="PASS",
                        end_date=None,
                        manual=False,
                        isp_name=isp_name,
                        destination_info=metadata,
                        uuid=uuid
                    )
                    added += 1

    # Remove stale rules
    rules_to_remove = [
        (rule.source_ip, rule.destination_ip)
        for (key, rule) in existing_rules.items()
        if rule.destination_ip not in valid_dest_ips or rule.isp_name not in allowed_isps
    ]
    removed = delete_multiple_rules(rules_to_remove) if rules_to_remove else 0

    if added > 0 or removed > 0:
        apply_firewall_changes()

    return (added, removed) if return_removed else added


##############################################################################################################################
# Single rule addition from grouped view
##############################################################################################################################

def add_single_rule(source_ip, destination_ip, manual=True, dns=False):
    try:
        rule_uuid = add_firewall_rule(source_ip, destination_ip)

        if not rule_uuid:
            print("❌ Failed to get UUID from OPNsense.")
            return False

    except Exception as e:
        print(f"Error adding firewall rule: {e}")
        return False

    # Lookup Device from source_ip
    lease = DeviceLease.objects.filter(
        ip_address=source_ip,
        lease_end__gt=timezone.now()
    ).order_by('-lease_start').first()
    print(f"Lease: {lease}")
    device = lease.device if lease else None
    print(f"Device: {device}")
    
    # Update the database with the new rule
    try:
        FirewallRule.objects.get_or_create(
            device=device,
            uuid=rule_uuid,
            source_ip=source_ip,
            destination_ip=destination_ip,
            protocol="any",
            port=0,
            action="PASS",
            manual=manual,
            dns=dns,
            end_date=None,
        )
    except Exception as e:
        print(f"Error updating database: {e}")
        return False
    
    apply_firewall_changes()
    return True