from django.db.models.signals import post_save
from django.dispatch import receiver
from .models import DeviceLease
from .api_firewall import add_firewall_rule, apply_firewall_changes, check_rule_exists

@receiver(post_save, sender=DeviceLease)
def handle_first_device_assignment(sender, instance, created, **kwargs):
    if not instance.device:
        return  # No device assigned
    
    # Re-fetch the device to ensure we have the latest fields (e.g., DNS)
    device = instance.device
    device = device.__class__.objects.get(pk=device.pk)

    # Only continue if this device had no other leases before
    is_first_lease = not DeviceLease.objects.filter(
        device=instance.device
    ).exclude(id=instance.id).exists()

    if not is_first_lease:
        return

    ip = instance.ip_address
    dns = (instance.device.dns_server or "").strip().lower()

    print(f"✅ First lease assigned to device {instance.device.device_id} @ {ip}")
    print(f"DNS preference: {dns}")

    dns_map = {
        "cloudflare": "1.1.1.1",
        "google": "8.8.8.8",
        "quad9": "9.9.9.9"
    }

    dns_ip = dns_map.get(dns)
    if dns_ip:
        if not check_rule_exists(ip, dns_ip):
            if add_firewall_rule(ip, dns_ip):
                print(f"✅ Rule added for {dns_ip}")
                apply_firewall_changes()
        else:
            print(f"⚠️ Rule already exists for {ip} → {dns_ip}, skipping.")
    else:
        print(f"⚠️ Unknown DNS server: {dns}")
