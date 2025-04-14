from django.contrib import admin
from django.urls import path
from rules.views import (
    view_firewall_logs,
    manage_devices_view,
    get_linked_isps_view,
    toggle_isp_link_view,
    update_firewall_rules_view,
    domain_lookup_view,
    device_ip_overview_view,
    device_firewall_rules_view,
    remove_firewall_rule_view,
)

urlpatterns = [
    path('admin/', admin.site.urls),
    path('', manage_devices_view, name='manage-devices'),
    path('logs/', view_firewall_logs, name='view-logs'),
    
    path('overview/', device_ip_overview_view, name='device-ip-overview'),

    path('manage-devices/', manage_devices_view, name='manage-devices'),
    path('update-firewall/', update_firewall_rules_view, name='update_firewall_rules'),

    path('api/device/<int:device_id>/linked-isps/', get_linked_isps_view, name='api-linked-isps'),
    path('api/toggle-isp/', toggle_isp_link_view, name='toggle_isp_link'),

    path("device-firewall", device_firewall_rules_view, name="device-firewall-rules"),

    path('domain-lookup/', domain_lookup_view, name='domain-lookup'),


    path('api/remove-firewall-rule/', remove_firewall_rule_view, name='remove-firewall-rule'),

]
