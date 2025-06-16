from copy import deepcopy
from django.utils import timezone
import time
from django.utils.timezone import now
from datetime import timedelta
from .models import Device, DeviceLease, DeviceAllowedISP, FirewallLog, FirewallRule, DestinationMetadata, MetadataSeenByDevice
from .api_firewall import add_firewall_rule, get_all_rules_uuid, get_all_rules, apply_firewall_changes, delete_multiple_rules, delete_rule_by_uuid, source_ip_adjustment
from . import config

CHECK_INTERVAL_SECONDS = 60  # 15 minutes 900

def get_active_ip(device=None, device_id=None):
    """
    Returns the latest active IP for the "device" object or "device_id", or None.
    """
    if device:
        return (
            DeviceLease.objects
            .filter(device=device, lease_end__gt=now())
            .order_by('-lease_start')
            .values_list('ip_address', flat=True)
            .first()
        )
    if device_id:
        return (
            DeviceLease.objects
            .filter(device_id=device_id, lease_end__gt=now())
            .order_by('-lease_start')
            .values_list('ip_address', flat=True)
            .first()
        )


def get_allowed_isps(device_id):
    """
    Get Allowed ISPs from database, needed argument "device_id"
    """
    return list(
        DeviceAllowedISP.objects
        .filter(device_id=device_id)
        .values_list('isp_name', flat=True)
    )


def get_blocked_ips_by_isp(isp_list, source_ip):
    return set(
        FirewallLog.objects.filter(
            action='block',
            destination_metadata__isp__in=isp_list,
            source_ip=source_ip,
        ).values_list('destination_ip', flat=True)
    )
                        

def check_rule_exists(ip_source, ip_destination): 
    """
    Check for rule if it exists needed Arguement "ip_source" AND "ip_destination"
    """
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
    """
    This starts the sync for each entry marked before in the DB with "verify_opnsense". It starts to check if Entry is in OPNsense
    API present if not remove from DB as well. If in OPNsense but not in DB remove from OPNsense. Always check if both possible otherwise
    remove from the one or from the other to keep rules alligned.
    """
    # Overview variables
    verified = 0
    ended = 0
    deleted = 0
    failed = 0

    # Make first a cleanup before checking the flagged rules.
    print("🔄 Check for OPNSENSE Rules...")
    check_opnsense_rules()

    # Load all active rules with verify_opnsense True
    rules_to_verify = FirewallRule.objects.filter(verify_opnsense=True)
    print(f"Found {rules_to_verify.count()} rules to verify against OPNsense.")

    if not rules_to_verify.exists():
        return
    
    if rules_to_verify.count() <= 30:
        points = 1
    if rules_to_verify.count() > 30:
        points = 2
    config.API_USAGE += points

    for rule in rules_to_verify:
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
    
    config.API_USAGE -= points

    print("- RULE SYNC SUMMARY -")
    print(f"  ✅ Verified rules: {verified}")
    print(f"  🧹 Ended rules in DB (missing in OPNsense): {ended}")
    print(f"  ❌ Deleted stale rules from OPNsense: {deleted}")
    print(f"  ⚠️ Failures: {failed}")
                

##############################################################################################################################
# Management ISP Rules - ALL
##############################################################################################################################
def allow_blocked_ips_for_device(device_id, return_removed=False):          
    
    print(f"Allowing blocked IPs for device: {device_id}")
    ip_source = get_active_ip(device_id=device_id)
    
    if not ip_source:
        return 0

    allowed_isps = get_allowed_isps(device_id)
    dest_ips = get_blocked_ips_by_isp(allowed_isps, ip_source)
    config.API_USAGE += 1


    # Preload existing rules from DB (active only, non-DNS)
    existing_rules_qs = FirewallRule.objects.filter(
        source_ip=ip_source,
        end_date__isnull=True,
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
                    device_instance = Device.objects.get(id=device_id)
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
        apply_firewall_changes(ip_source)

    config.API_USAGE -= 1

    return (added, removed) if return_removed else added


##############################################################################################################################
# Management ISP Rules - Single ISP
##############################################################################################################################
def allow_ips_for_device_and_isp(device_id, isp_name, mode="sync", return_removed=False):
    """
    Adds firewall allow rules for a device based on its allowed ISPs,
    and removes any removed rules that are no longer valid.

    Workflow:
    - Gets the device's currently active IP.
    - Retrieves destination IPs currently blocked but associated with allowed ISPs.
    - Preloads existing non-DNS rules for the device to avoid duplication.
    - For each allowed destination IP:
        - If a rule already exists, marks it for re-verification.
        - If not, creates a new allow rule both in the firewall (via API) and in the database.
    - Removes any existing rules that no longer match the allowed ISP list or destination IP set.
    - Applies pending firewall changes only if there were additions or deletions.
    """
    print(f"[{mode.upper()}] Updating firewall rules for device {device_id} and ISP: {isp_name}")
    
    ip_source = get_active_ip(device_id=device_id)
    if not ip_source:
        return (0, 0)

    # All destination IPs seen by this device for this ISP
    valid_dest_ips = set(DestinationMetadata.objects.filter(
        isp=isp_name,
        end_date__isnull=True,
        metadataseenbydevice__device_id=device_id
    ).values_list("ip", flat=True))
    print(f"valid_dest_ips: {valid_dest_ips}")

    # Existing firewall rules
    existing_rules_qs = FirewallRule.objects.filter(
        source_ip=ip_source,
        end_date__isnull=True,
        manual=False,
        dns=False,
        isp_name=isp_name
    )
    existing_rules = {
        rule.destination_ip: rule for rule in existing_rules_qs
    }

    added = 0
    removed = 0

    # ADD RULES
    if mode in ("add", "sync"):
        for ip_dest in valid_dest_ips:
            if ip_dest in existing_rules:
                existing_rules[ip_dest].verify_opnsense = True
                existing_rules[ip_dest].save(update_fields=["verify_opnsense"])
            else:
                metadata = DestinationMetadata.objects.filter(ip=ip_dest, end_date__isnull=True).first()
                uuid = add_firewall_rule(ip_source, ip_dest)
                if uuid and not FirewallRule.objects.filter(uuid=uuid).exists():
                    FirewallRule.objects.create(
                        source_ip=ip_source,
                        device_id=device_id,
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

    # REMOVE RULES
    if mode == "remove":
        # Remove all current rules for this ISP/device
        to_remove = list(existing_rules.values())
    elif mode == "sync":
        # Remove only rules that are no longer valid
        to_remove = [
            rule for ip, rule in existing_rules.items()
            if ip not in valid_dest_ips
        ]
    else:
        to_remove = []

    if to_remove:
        removed = delete_multiple_rules([(r.source_ip, r.destination_ip) for r in to_remove])

    apply_firewall_changes(ip_source)

    return (added, removed) if return_removed else added


##############################################################################################################################
# Single rule addition from grouped view
##############################################################################################################################
def add_single_rule(source_ip, destination_ip, manual=True, dns=False):
    """
    Adds a single PASS rule to both the firewall and the local database for a given IP pair.

    Workflow:
    - Sends a request to the firewall (OPNsense) to allow traffic from source_ip to destination_ip.
    - If successful, fetches the related device (if any) using active lease info.
    - Looks up destination metadata (e.g., ISP) for enrichment.
    - Saves the rule to the database (or fetches it if it already exists).
    - Applies pending firewall changes.
    """
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


    metadata = DestinationMetadata.objects.filter(ip=destination_ip, end_date__isnull=True).first()
    isp = metadata.isp if metadata else "Unknown"
    print(isp)

    
    # Update the database with the new rule
    try:
        FirewallRule.objects.get_or_create(
            device=device,
            uuid=rule_uuid,
            source_ip=source_ip,
            destination_ip=destination_ip,
            isp_name=isp,
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
    
    apply_firewall_changes(source_ip)
    return rule_uuid



##############################################################################################################################
# DNS Rule management
##############################################################################################################################
def allow_ips_for_device_and_dns(records):
    """
    Creates firewall PASS rules for DNS-resolved IPs associated with known devices.

    For each DNS record in the input:
    - If a resolved IP is present and belongs to a known device:
        - Checks if a rule already exists in the database.
        - If not, retrieves metadata for the destination IP and adds a rule to the firewall.
        - Saves the new rule to the database and tracks it in the returned list.
    """
    added_rules = []
    for record in records:
        if record.resolved_ip:
            lease = DeviceLease.objects.filter(ip_address=record.source_ip).order_by('-lease_start').first()
            if lease and lease.device:
                db_rule = FirewallRule.objects.filter(
                    source_ip=record.source_ip,
                    destination_ip=record.resolved_ip,
                    end_date=None
                ).first()
                
                if db_rule:
                    print(f"Rule already exists for {record.source_ip} → {record.resolved_ip}")
                else:
                    # Get metadata for the resolved IP
                    metadata = DestinationMetadata.objects.filter(ip=record.resolved_ip, end_date__isnull=True).first()
                    isp = metadata.isp if metadata else "Unknown"

                    uuid = add_firewall_rule(ip_source=record.source_ip, ip_destination=record.resolved_ip)
                    if uuid:
                        print(f"Rule added to OPNsense: {record.source_ip} → {record.resolved_ip}")
                        
                        rule = FirewallRule.objects.create(
                            source_ip=record.source_ip,
                            device=lease.device,
                            destination_ip=record.resolved_ip,
                            protocol="any",
                            isp_name=isp,
                            port=0,
                            action="PASS",
                            end_date=None,
                            manual=False,
                            uuid=uuid
                        )
                        added_rules.append(rule)

                    else:
                        print(f"⚠️ Failed to add rule for {record.source_ip} → {record.resolved_ip}")
    
    apply_firewall_changes(record.source_ip)
    return added_rules


##############################################################################################################################
# Archiving Device cleanup - Housekeeping ;-)
##############################################################################################################################
def archiving_device(device):
    """
    Archives a device by deactivating its firewall rules and clearing associated allowed ISPs.

    Workflow:
    - Marks all active (end_date is null) firewall rules for the given device as ended (sets end_date to now).
    - Flags each rule for OPNsense verification.
    - Deletes all associated DeviceAllowedISP entries for the device.
    """

    ## Get all active rules for the device and set end_date to now
    active_rules = FirewallRule.objects.filter(
        device=device,
        end_date__isnull=True
    )

    print(f"📦 Archiving {active_rules.count()} rules for device {device}")
    print(f"Note this will be done with sync thread...")

    for rule in active_rules:
        rule.end_date = now()
        rule.verify_opnsense = True
        rule.save(update_fields=["end_date", "verify_opnsense"])

    ## Get all active DeviceAllowedISP for the device and delete them
    active_DeviceAllowedISP = DeviceAllowedISP.objects.filter(
        device=device,
    )

    for active_ISP in active_DeviceAllowedISP:
        active_ISP.delete()
    print(f"Deleting {active_DeviceAllowedISP.count()} allowed ISPs for device {device}")

    return True


##############################################################################################################################
# Rule swap if IP changed for DEVICE
##############################################################################################################################
def adjust_invalid_source_ips(device):
    """
    Updates active firewall rules for a device if its source IP has changed.

    This function:
    - Looks up the device's current active IP address from the DHCP lease.
    - Finds all active firewall rules for the device that do not match the current IP.
    - For each such rule:
        - Calls `source_ip_adjustment()` to update the rule in OPNsense.
        - If successful:
            - Marks the existing rule as ended.
            - Creates a new rule with the updated source IP and current timestamp.
    - Increments and decrements `config.API_USAGE` to reflect external API usage.

    """
    print(f"Lookup source IP adjustment for {device}")
    active_ip = get_active_ip(device=device)
    if not active_ip:
        print(f"No active IP found for device {device.device_id}")
        return
    
    print(f"Active IP: {active_ip}")

    # Fetch rules that are still active and source_ip is not equal to the current lease
    rules = FirewallRule.objects.filter(
        device=device,
        end_date__isnull=True
    ).exclude(source_ip=active_ip)
    config.API_USAGE += 1
    for rule in rules:
        uuid = rule.uuid
        
        try:
            result = source_ip_adjustment(uuid, active_ip)

            # If worked out copy rule, mark old entry as ended, new entry with new address with new start date 
            
            try:
                # If worked out copy rule, mark old entry as ended, new entry with new address with new start date
                if result:

                    # End the existing rule
                    rule.end_date = now()
                    rule.save(update_fields=["end_date"])

                    # Duplicate the rule properly
                    new_rule = deepcopy(rule)
                    new_rule.pk = None  # ensures a new DB record
                    new_rule.source_ip = active_ip
                    new_rule.start_date = now()
                    new_rule.end_date = None
                    new_rule.verify_opnsense = False
                    new_rule.save()

                    print(f"✅ Rule {rule.destination_ip} / {rule.destination_info} migrated to {active_ip}. Previous rule closed.")

                else:
                    print("ERROR occured during DB adjustment of firewall rule")

            except Exception as e:
                print(f"ERROR occured during DB adjustment of firewall rule {rule} with {e}") 
                return None

        except FirewallRule.DoesNotExist:
            print("❌ Rule not found.")
            return None
    config.API_USAGE -= 1
    return True


##############################################################################################################################
# Check if MetadataSeenByDevice needs to be updated
##############################################################################################################################
def recheck_metadata_seen():
    """
    Periodically scans recent firewall logs to backfill MetadataSeenByDevice records.

    This function runs in an infinite loop:
    - Every interval (based on CHECK_INTERVAL_SECONDS), it:
        - Retrieves firewall logs from the last 12 hours that contain metadata.
        - Matches each log's source IP and timestamp to a DeviceLease to identify the device.
        - If the metadata has not yet been linked to that device, it creates a MetadataSeenByDevice entry.
    - Tracks and prints the number of new entries added during each cycle.
    """
    print("Recheck for unlinked Metadata service started...")
    while True:
        try:
            now = timezone.now()

            # Get all relevant firewall logs with metadata
            logs = FirewallLog.objects.filter(
                destination_metadata__isnull=False,
                timestamp__gte=now - timedelta(hours=12)
            ).select_related("destination_metadata")

            added_count = 0

            for log in logs:
                dst_ip = log.destination_ip
                src_ip = log.source_ip
                timestamp = log.timestamp
                metadata = log.destination_metadata

                if not metadata or not src_ip:
                    continue

                # Match lease for the source_ip
                leases = DeviceLease.objects.filter(
                    ip_address=src_ip,
                    lease_start__lte=timestamp,
                    lease_end__gt=timestamp
                ).select_related("device")

                for lease in leases:
                    device = lease.device
                    if not device:
                        continue

                    # Check if already seen
                    exists = MetadataSeenByDevice.objects.filter(
                        device=device,
                        metadata=metadata
                    ).exists()

                    if not exists:
                        MetadataSeenByDevice.objects.create(
                            device=device,
                            metadata=metadata,
                            last_seen_at=timestamp
                        )
                        added_count += 1

            print(f"MetadataSeenByDevice recheck completed: {added_count} new entries")

        except Exception as e:
            print(f"❌ MetadataSeenByDevice recheck error: {e}")

        time.sleep(CHECK_INTERVAL_SECONDS)


##############################################################################################################################
# Check for all Rules on OPNsense if any are missing in DB
##############################################################################################################################
def check_opnsense_rules():
    """
    Synchronizes OPNsense firewall rules with the local database.

    Workflow:
    - Retrieves all current rules from the OPNsense firewall.
    - For each rule:
        - If it exists in the local DB as an active rule (`end_date=None`), no action is taken.
        - If it does not exist in the DB, assumes it is orphaned and deletes it from OPNsense.
    - Logs activity for debugging purposes if `config.DEBUG` or `config.DEBUG_ALL` are enabled.
    """
    try:
        response = get_all_rules()
        if not response:
            print("Failed to fetch rules or no rules returned.")
            return False

        for rule in response:
            uuid = rule.get("uuid")
            enabled = rule.get("enabled") == "1"
            description = rule.get("description", "")

            if config.DEBUG:
                print(f"OPNSense UUID: {uuid} | Enabled: {enabled} | Description: {description}")

            try:
                db_rule = FirewallRule.objects.get(uuid=uuid, end_date=None)
                if db_rule:
                    if config.DEBUG_ALL:
                        print("Rule is active in DB and nothing needs to be done.")

            except FirewallRule.DoesNotExist:
                print(f"Found active OPNsense rule not present in DB: UUID={uuid} | Description={description}")
                if delete_rule_by_uuid(uuid):
                    print("Rule removed from OPNsense.")
            except Exception as e:
                print(f"Unexpected error while checking/updating DB for rule {uuid}: {e}")
                continue

        return True
    except Exception as e:
        print(f"Unexpected error in check_opnsense_rules(): {e}")
        return False