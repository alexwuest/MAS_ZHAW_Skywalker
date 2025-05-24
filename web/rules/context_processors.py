# Regularly API call if OPNSense runs, if yes write in db and just retrieve it from db

from .models import FirewallRule
from .ip_enrichment import ip_enrichment_queue
from . import config

def footer_data(request):
    ip_enrichments_queued = ip_enrichment_queue.qsize()
    if ip_enrichments_queued > 100:
        ip_enrichments_queued_usage = "HIGH"
    elif ip_enrichments_queued >= 20:
        ip_enrichments_queued_usage = "MEDIUM"
    else:
        ip_enrichments_queued_usage = "LOW"

    active_firewall_rules = FirewallRule.objects.filter(end_date__isnull=True).count()
    verify_opnsense = FirewallRule.objects.filter(verify_opnsense=True).count()

    # Calculate system usage
    usage = 0
    if active_firewall_rules >= 700:
        usage += 1
    if verify_opnsense >= 50:
        usage += 1
    system_usage = config.API_USAGE + usage

    return {
        "ip_enrichments_queued": ip_enrichments_queued,
        "ip_enrichments_queued_usage": ip_enrichments_queued_usage,
        "active_firewall_rules": active_firewall_rules,
        "verify_opnsense": verify_opnsense,
        "system_usage": system_usage,
    }
