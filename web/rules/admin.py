from django.contrib import admin

from .models import Device, FirewallRule, DestinationMetadata, DeviceLease, DeviceAllowedISP, FirewallLog, MetadataSeenByDevice, DNSRecord

admin.site.register(DeviceAllowedISP)

@admin.register(FirewallLog)
class FirewallLogAdmin(admin.ModelAdmin):
    list_per_page = 500
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
        'source_ip',
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

    #TODO Uncomment following lines for live system

    # All fields read-only
    #readonly_fields = [field.name for field in FirewallLog._meta.fields] 

    # Prevent add and edit
    #def has_add_permission(self, request):
    #    return False

    #def has_change_permission(self, request, obj=None):
    #    return False

@admin.register(FirewallRule)
class FirewallRuleAdmin(admin.ModelAdmin):
    list_per_page = 500
    list_display = (
        'device',
        'source_ip',
        'destination_ip',
        'isp_name',
        'verify_opnsense',
        'manual',
        'dns',
        'uuid',
        'start_date',
        'end_date',
    )
    list_filter = (
        'device',
        'protocol',
        'action',
        'isp_name',
        'verify_opnsense',
        'start_date',
        'end_date',
    )
    search_fields = [
        'source_ip',
        'destination_ip',
        'isp_name',
        'verify_opnsense',
        'manual',
        'dns',
        'start_date',
        'end_date',    ]

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
        'archived',
        
    )
    list_filter = (
        'device_id',
        'description',
        'dns_server',
        'examiner',
        'creation_date',
        'archived',
    )
    search_fields = (
        'device_id',
        'description',
        'dns_server',
        'examiner',
        'creation_date',
        'archived',
    )


@admin.register(DestinationMetadata)
class DestinationMetadataAdmin(admin.ModelAdmin):
    list_per_page = 500
    list_display = (
        'ip',
        'dns_name',
        'city',
        'region',
        'country',
        'isp',
        'as_number',
        'start_date',
        'last_checked',
        'end_date',
    )
    list_filter = (
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

    readonly_fields = ('start_date', 'last_checked', 'end_date')


@admin.register(MetadataSeenByDevice)
class MetadataSeenByDeviceAdmin(admin.ModelAdmin):
    list_per_page = 500
    list_display = (
        'device',
        'metadata',
        'last_seen_at',
        'first_seen_at',
    )
    list_filter = (
        'device',
    )
    search_fields = (
        'device__device_id',
        'metadata__ip',
    )
    date_hierarchy = 'last_seen_at'
    ordering = ('-last_seen_at',)


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
        'show',
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



@admin.register(DNSRecord)
class DNSRecordAdmin(admin.ModelAdmin):
    list_per_page = 500
    list_display = (
        'timestamp',
        'last_seen_at',
        'source_ip',
        'resolved_ip',
        'query_type',
        'domain',
        'raw_line',
    )
    list_filter = (
        'source_ip',
    )
    search_fields = (
        'source_ip',
        'resolved_ip',
        'domain',
        'raw_line',        
    )
    date_hierarchy = 'timestamp'
    ordering = ('-timestamp',)