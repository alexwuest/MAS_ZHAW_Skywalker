from django.utils import timezone
from .models import DeviceLease, DeviceAllowedISP, FirewallLog, FirewallRule, DestinationMetadata
from .api_firewall import check_rule_exists, add_firewall_rule, apply_firewall_changes

def get_active_ip(device_id):
    now = timezone.now()
    lease = DeviceLease.objects.filter(device__device_id=device_id, lease_end__gt=now).first()
    return lease.ip_address if lease else None

def get_allowed_isps(device_id):
    return list(DeviceAllowedISP.objects.filter(device__device_id=device_id).values_list('isp_name', flat=True))

def get_blocked_ips_by_isp(isp_list):
    logs = FirewallLog.objects.filter(action='block', destination_metadata__isp__in=isp_list)
    return set(logs.values_list('destination_ip', flat=True))

def allow_blocked_ips_for_device(device_id):
    ip_source = get_active_ip(device_id)
    if not ip_source:
        return 0

    isps = get_allowed_isps(device_id)
    if not isps:
        return 0

    dest_ips = get_blocked_ips_by_isp(isps)
    added = 0

    for ip_dest in dest_ips:
        # Get metadata
        metadata = DestinationMetadata.objects.filter(ip=ip_dest, end_date__isnull=True).first()
        isp_name = metadata.isp if metadata else "Unknown"

        rule_obj, created = FirewallRule.objects.get_or_create(
            source_ip=ip_source,
            destination_ip=ip_dest,
            protocol="any",
            port=0,
            action="PASS",
            isp_name=isp_name,
            destination_info=metadata,
            defaults={"pushed_to_opnsense": False}
        )

        if not rule_obj.pushed_to_opnsense:
            if not check_rule_exists(ip_source, ip_dest):
                if add_firewall_rule(ip_source, ip_dest):
                    rule_obj.pushed_to_opnsense = True
                    rule_obj.save()
                    added += 1

    if added > 0:
        apply_firewall_changes()

    return added
