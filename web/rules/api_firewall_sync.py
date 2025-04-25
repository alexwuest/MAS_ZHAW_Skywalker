from django.utils import timezone
from .models import DeviceLease, DeviceAllowedISP, FirewallLog, FirewallRule, DestinationMetadata
from .api_firewall import check_rule_exists, add_firewall_rule, apply_firewall_changes, delete_rule_by_source_and_destination, get_all_rules

def get_active_ip(device_id_str):
    from .models import Device  # or wherever your Device model lives
    now = timezone.now()

    try:
        device = Device.objects.get(device_id=device_id_str)
    except Device.DoesNotExist:
        return None

    lease = (
        DeviceLease.objects
        .filter(device_id=device.id, lease_end__gt=now)
        .order_by('-lease_start')
        .first()
    )

    return lease.ip_address if lease else None


def get_allowed_isps(device_id):
    return list(DeviceAllowedISP.objects.filter(device__device_id=device_id).values_list('isp_name', flat=True))

def get_blocked_ips_by_isp(isp_list):
    logs = FirewallLog.objects.filter(action='block', destination_metadata__isp__in=isp_list)
    return set(logs.values_list('destination_ip', flat=True))


def allow_blocked_ips_for_device(device_id, return_removed=False):
    ip_source = get_active_ip(device_id)
    if not ip_source:
        return 0

    allowed_isps = get_allowed_isps(device_id)
    dest_ips = get_blocked_ips_by_isp(allowed_isps)
    added = 0

    # Cache destination metadata
    metadata_lookup = {
        m.ip: m for m in DestinationMetadata.objects.filter(ip__in=dest_ips, end_date__isnull=True)
    }

    # Get all current OPNsense rules once
    all_rules = get_all_rules()
    existing_descriptions = {rule.get("description", "") for rule in all_rules}

    def rule_exists(ip_src, ip_dst):
        return any(ip_src in desc and ip_dst in desc for desc in existing_descriptions)

    # Track all destination IPs that should remain
    valid_dest_ips = set()

    for ip_dest in dest_ips:
        metadata = metadata_lookup.get(ip_dest)
        isp_name = metadata.isp if metadata else "Unknown"
        valid_dest_ips.add(ip_dest)

        rule_qs = FirewallRule.objects.filter(
            source_ip=ip_source,
            destination_ip=ip_dest,
            end_date__isnull=True,
            manual=False
        )

        if rule_qs.exists():
            rule_obj = rule_qs.first()
            created = False
        else:
            rule_obj = FirewallRule.objects.create(
                source_ip=ip_source,
                destination_ip=ip_dest,
                protocol="any",
                port=0,
                action="PASS",
                end_date=None,
                manual=False,
                isp_name=isp_name,
                destination_info=metadata
            )
            created = True


        if created:
            if not check_rule_exists(ip_source, ip_dest):
                if add_firewall_rule(ip_source, ip_dest):
                    added += 1
                else:
                    rule_obj.delete()

    # Remove rules that no longer belong to allowed ISPs
    existing_rules = FirewallRule.objects.filter(source_ip=ip_source, end_date__isnull=True, manual=False, dns=False)
    removed = 0

    for rule in existing_rules:
        if rule.destination_ip not in valid_dest_ips or rule.isp_name not in allowed_isps:
            print(f"Removing rule to {rule.destination_ip} (ISP no longer allowed: {rule.isp_name})")
            deleted_count = delete_rule_by_source_and_destination(rule.source_ip, rule.destination_ip)
            removed += deleted_count

    if added > 0 or removed > 0:
        apply_firewall_changes()

    if return_removed:
        return added, removed
    return added


