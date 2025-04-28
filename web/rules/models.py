from django.db import models
from .constants import get_dns_choices

class Device(models.Model):
    device_id = models.CharField(max_length=20, unique=True)
    creation_date = models.DateTimeField(auto_now_add=True)

    description = models.TextField(blank=True)
    dns_server = models.CharField(
        max_length=20,
        choices=get_dns_choices(),
        default="cloudflare"
    )
    examiner = models.CharField(max_length=20, blank=False)
    archived = models.BooleanField(default=False)

    def __str__(self):
        return self.device_id


class DeviceAllowedISP(models.Model):
    device = models.ForeignKey(Device, on_delete=models.CASCADE, related_name="allowed_isps")
    isp_name = models.CharField(max_length=100)

    class Meta:
        unique_together = ['device', 'isp_name']
        indexes = [
            models.Index(fields=['isp_name']),
            models.Index(fields=['device', 'isp_name']),
        ]

    def __str__(self):
        return f"{self.device.device_id} → {self.isp_name}"



###################################################################################################


class FirewallLog(models.Model):
    timestamp = models.DateTimeField()
    action = models.CharField(max_length=10)
    interface = models.CharField(max_length=50, blank=True)
    source_ip = models.GenericIPAddressField()
    source_port = models.IntegerField(null=True, blank=True)
    destination_ip = models.GenericIPAddressField()
    destination_port = models.IntegerField(null=True, blank=True)
    protocol = models.CharField(max_length=10, blank=True)

    destination_metadata = models.ForeignKey(
        "DestinationMetadata",
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="logs"
    )
    class Meta:
        unique_together = ['timestamp', 'source_ip', 'destination_ip', 'source_port', 'destination_port']

    def __str__(self):
        return f"{self.timestamp} {self.source_ip}:{self.source_port} → {self.destination_ip}:{self.destination_port}"


class DestinationMetadata(models.Model):
    # ip-api.com
    ip = models.GenericIPAddressField()
    status = models.CharField(max_length=20, null=True, blank=True)
    continent = models.CharField(max_length=50, null=True, blank=True)
    continent_code = models.CharField(max_length=5, null=True, blank=True)
    country = models.CharField(max_length=50, null=True, blank=True)
    country_code = models.CharField(max_length=5, null=True, blank=True)
    region = models.CharField(max_length=50, null=True, blank=True)
    region_name = models.CharField(max_length=100, null=True, blank=True)
    city = models.CharField(max_length=100, null=True, blank=True)
    district = models.CharField(max_length=100, blank=True)
    zip_code = models.CharField(max_length=20, null=True, blank=True)
    lat = models.FloatField(null=True, blank=True)
    lon = models.FloatField(null=True, blank=True)
    timezone = models.CharField(max_length=100, null=True, blank=True)
    offset = models.IntegerField(null=True, blank=True)
    currency = models.CharField(max_length=10, null=True, blank=True)
    isp = models.CharField(max_length=100, null=True, blank=True)
    org = models.CharField(max_length=100, null=True, blank=True)
    as_number = models.CharField(max_length=50, null=True, blank=True)
    as_name = models.CharField(max_length=100, null=True, blank=True)
    mobile = models.BooleanField(null=True, blank=True)
    proxy = models.BooleanField(null=True, blank=True)
    hosting = models.BooleanField(null=True, blank=True)

    # reverse dns
    dns_name = models.CharField(max_length=60, null=True, blank=True)

    # Keep track if a IP address ownership changes...
    start_date = models.DateTimeField(auto_now_add=True)        # when adding
    last_checked = models.DateTimeField(auto_now=True)          # when last checked
    end_date = models.DateTimeField(null=True, blank=True)      # when it was replaced

    class Meta:
        unique_together = ['ip', 'start_date']
        indexes = [
            models.Index(fields=['ip']),
            models.Index(fields=['ip', 'end_date']),
        ]

    def __str__(self):
        return f"{self.ip} ({self.city}, {self.country})"


class MetadataSeenByDevice(models.Model):
    """Keep track of which device has seen which metadata."""
    device = models.ForeignKey(Device, on_delete=models.CASCADE)
    metadata = models.ForeignKey(DestinationMetadata, on_delete=models.CASCADE)
    first_seen_at = models.DateTimeField(auto_now_add=True)  # creation time
    last_seen_at = models.DateTimeField(auto_now=True)       # updated all time


    class Meta:
        unique_together = ('device', 'metadata')
        indexes = [
            models.Index(fields=['device', 'metadata']),
        ]

class FirewallRule(models.Model):
    ACTION_CHOICES = [
        ('PASS', 'Pass'),
        ('BLOCK', 'Block'),
        ('REJECT', 'Reject'),
    ]
    source_ip = models.GenericIPAddressField()
    destination_ip = models.GenericIPAddressField()
    destination_info = models.ForeignKey(
        DestinationMetadata,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='firewall_rules'
    )
    port = models.IntegerField()
    protocol = models.CharField(max_length=10, choices=[('TCP', 'TCP'), ('UDP', 'UDP')])
    action = models.CharField(max_length=6, choices=ACTION_CHOICES)
    manual = models.BooleanField(default=False)                                             # Manual rules by user not by ISP con
    dns = models.BooleanField(default=False)                                                # DNS rules should not be removed automatically  
    start_date = models.DateTimeField(auto_now_add=True)
    end_date = models.DateTimeField(null=True, blank=True)
    isp_name = models.CharField(max_length=100)
    created_at = models.DateTimeField(auto_now_add=True)
   
    class Meta:
        unique_together = ['destination_ip', 'start_date']
        indexes = [
            models.Index(fields=['destination_ip']),
            models.Index(fields=['destination_ip', 'start_date', 'end_date']),
        ]

    def __str__(self):
        return f"{self.action} {self.protocol} {self.source_ip}:{self.port} -> {self.destination_ip}"
    

class DeviceLease(models.Model):
    device = models.ForeignKey(Device, on_delete=models.CASCADE, related_name='leases', null=True, blank=True)
    ip_address = models.GenericIPAddressField()
    mac_address = models.CharField(max_length=17)
    lease_start = models.DateTimeField()
    lease_end = models.DateTimeField()
    hostname = models.CharField(max_length=100, blank=True, null=True)
    manufacturer = models.CharField(max_length=100, blank=True, null=True)
    interface = models.CharField(max_length=50, blank=True, null=True)

    last_active = models.DateTimeField(null=True, blank=True)
    show = models.BooleanField(default=True)                                                # Show in the web interface or to hide older entries     

    class Meta:
        unique_together = ['ip_address', 'mac_address', 'lease_start']
        indexes = [
            models.Index(fields=['mac_address', 'ip_address']),
        ]

    def __str__(self):
        return f"{self.device.device_id if self.device else '?'} - {self.mac_address} @ {self.ip_address}"
