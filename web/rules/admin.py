from django.contrib import admin

from .models import Device, DeviceMac, FirewallRule, DestinationMetadata

admin.site.register(Device)
admin.site.register(DeviceMac)
admin.site.register(FirewallRule)
admin.site.register(DestinationMetadata)