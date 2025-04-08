from django.contrib import admin

from .models import Device, DeviceMac, DeviceIp, FirewallRule, DestinationMetadata, DeviceLease, DeviceAllowedISP

admin.site.register(Device)
admin.site.register(DeviceMac)
admin.site.register(DeviceIp)
admin.site.register(FirewallRule)
admin.site.register(DestinationMetadata)
admin.site.register(DeviceLease)
admin.site.register(DeviceAllowedISP)