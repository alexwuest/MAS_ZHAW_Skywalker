from django.contrib import admin

from .models import Device, FirewallRule, DestinationMetadata, DeviceLease, DeviceAllowedISP, FirewallLog

admin.site.register(DeviceAllowedISP)

@admin.register(FirewallLog)
class FirewallLogAdmin(admin.ModelAdmin):
    list_display = (
        'timestamp',
        'action',
        'interface',
        'source_ip',
        'source_port',
        'destination_ip',
        'destination_port',
        'protocol',
        'destination_metadata',
    )
    list_filter = (
        'action',
        'interface',
        'protocol',
    )
    search_fields = (
        'source_ip',
        'destination_ip',
    )
    date_hierarchy = 'timestamp'
    ordering = ('-timestamp',)

    # All fields read-only
    readonly_fields = [field.name for field in FirewallLog._meta.fields]

    # Prevent add and edit
    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False

@admin.register(FirewallRule)
class FirewallRuleAdmin(admin.ModelAdmin):
    list_display = (
        'source_ip',
        'destination_ip',
        'protocol',
        'port',
        'action',
        'isp_name',
        'start_date',
        'end_date',
    )
    list_filter = (
        'protocol',
        'action',
        'isp_name',
        'start_date',
        'end_date',
    )
    search_fields = (
        'source_ip',
        'destination_ip',
        'isp_name',
    )
    date_hierarchy = 'start_date'
    ordering = ('-start_date',)


@admin.register(Device)
class Device(admin.ModelAdmin):
    list_display = (
        'device_id',
        'description',
        'dns_server',
        'examiner',
        'creation_date',
        'last_active',
        'archived',
        
    )
    list_filter = (
        'device_id',
        'description',
        'dns_server',
        'examiner',
        'creation_date',
        'last_active',
        'archived',
    )
    search_fields = (
        'device_id',
        'description',
        'dns_server',
        'examiner',
        'creation_date',
        'last_active',
        'archived',
    )


@admin.register(DestinationMetadata)
class DestinationMetadataAdmin(admin.ModelAdmin):
    list_display = (
        'ip',
        'dns_name',
        'city',
        'region',
        'country',
        'isp',
        'as_number',
        'start_date',
        'end_date',
    )
    list_filter = (
        'country',
        'region',
        'isp',
        'end_date',
    )
    search_fields = (
        'ip',
        'dns_name',
        'city',
        'region',
        'country',
        'isp',
        'org',
        'as_number',
        'as_name',
    )
    date_hierarchy = 'start_date'
    ordering = ('-start_date',)

    readonly_fields = ('start_date', 'end_date')


@admin.register(DeviceLease)
class DeviceLeaseAdmin(admin.ModelAdmin):
    list_display = (
        'device_display',
        'ip_address',
        'mac_address',
        'hostname',
        'manufacturer',
        'lease_start',
        'lease_end',
        'last_active',
    )
    list_filter = (
        'manufacturer',
        'hostname',
        'device',
    )
    search_fields = (
        'ip_address',
        'mac_address',
        'hostname',
        'manufacturer',
        'device__device_id',
    )
    date_hierarchy = 'lease_start'
    ordering = ('-lease_start',)

    def device_display(self, obj):
        return obj.device.device_id if obj.device else '–'
    device_display.short_description = 'Device ID'