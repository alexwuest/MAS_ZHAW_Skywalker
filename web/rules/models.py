from django.db import models

class DestinationMetadata(models.Model):
    ip = models.GenericIPAddressField(unique=True)
    status = models.CharField(max_length=20)
    continent = models.CharField(max_length=50)
    continent_code = models.CharField(max_length=5)
    country = models.CharField(max_length=50)
    country_code = models.CharField(max_length=5)
    region = models.CharField(max_length=50)
    region_name = models.CharField(max_length=100)
    city = models.CharField(max_length=100)
    district = models.CharField(max_length=100, blank=True)
    zip_code = models.CharField(max_length=20)
    lat = models.FloatField()
    lon = models.FloatField()
    timezone = models.CharField(max_length=100)
    offset = models.IntegerField()
    currency = models.CharField(max_length=10)
    isp = models.CharField(max_length=100)
    org = models.CharField(max_length=100)
    as_number = models.CharField(max_length=50)
    as_name = models.CharField(max_length=100)
    mobile = models.BooleanField()
    proxy = models.BooleanField()
    hosting = models.BooleanField()

    def __str__(self):
        return f"{self.ip} ({self.city}, {self.country})"


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
    timestamp = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.action} {self.protocol} {self.source_ip}:{self.port} -> {self.destination_ip}"
