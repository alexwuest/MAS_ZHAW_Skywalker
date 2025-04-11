from django.db.models.signals import pre_save, post_save
from django.dispatch import receiver
from .models import DeviceLease
from .api_firewall import add_firewall_rule, delete_rule_by_source_and_destination, apply_firewall_changes, check_rule_exists

@receiver(pre_save, sender=DeviceLease)
def cache_old_ip(sender, instance, **kwargs):
    if instance.pk:
        old = DeviceLease.objects.get(pk=instance.pk)
        instance._old_ip_address = old.ip_address
    else:
        instance._old_ip_address = None

@receiver(post_save, sender=DeviceLease)
def handle_device_assignment(sender, instance, created, **kwargs):
    if not instance.device:
        return

    ip = instance.ip_address
    device = instance.device
    dns = (device.dns_server or "").strip().lower()
    dns_map = {
        "cloudflare": "1.1.1.1",
        "google": "8.8.8.8",
        "quad9": "9.9.9.9"
    }
    dns_ip = dns_map.get(dns)
    if not dns_ip:
        print(f"⚠️ Unknown DNS server: {dns}")
        return

    # Remove all other rules for this device on old IPs
    other_leases = DeviceLease.objects.filter(device=device).exclude(id=instance.id)
    for lease in other_leases:
        if lease.ip_address and lease.ip_address != ip:
            print(f"🧹 Removing old rule for {lease.ip_address}")
            delete_rule_by_source_and_destination(lease.ip_address, dns_ip)

    # Check if the rule already exists for the new IP
    if not check_rule_exists(ip, dns_ip):
        if add_firewall_rule(ip, dns_ip):
            print(f"✅ Rule added for {ip} → {dns_ip}")
            apply_firewall_changes()
    else:
        print(f"⚠️ Rule already exists for {ip} → {dns_ip}, skipping.")

