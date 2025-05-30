from django.contrib import admin
from django.contrib.auth import views as auth_views
from django.contrib.auth.views import LogoutView
from django.urls import path
from rules.views import (
    manage_devices_view,
    get_linked_isps_view,
    toggle_isp_link_view,
    update_firewall_rules_view,
    domain_lookup_view,
    device_ip_overview_view,
    device_firewall_rules_view,
    remove_firewall_rule_view,
    flush_metadata_seen_view,
    add_rule_view,
    remove_rule_view,
    device_logs_view,
    system_status_view,
    mark_verify_opnsense_view,
    help_view,
    update_firewall_isp_view,
    combined_firewall_logs_view,
)

urlpatterns = [
    path('admin/', admin.site.urls),
    path("login/", auth_views.LoginView.as_view(), name="login"),
    path("logout/", auth_views.LogoutView.as_view(), name="logout"),

    path('api/device/<int:device_id>/linked-isps/', get_linked_isps_view, name='api-linked-isps'),
    path('api/toggle-isp/', toggle_isp_link_view, name='toggle_isp_link'),
    path("update-firewall-isp/", update_firewall_isp_view, name="update_firewall_isp"),
    
    path("firewall/logs/", combined_firewall_logs_view, name="firewall_logs"),

    path('update-firewall/', update_firewall_rules_view, name='update_firewall_rules'),
    
    path('overview/', device_ip_overview_view, name='device-ip-overview'),
    path('flush-metadata/', flush_metadata_seen_view, name='flush-metadata'),
    path("add-rule/", add_rule_view, name="add-rule-view"),
    path("remove-rule/", remove_rule_view, name="remove-rule-view"),

    path('', manage_devices_view, name='manage-devices'),
    path('manage-devices/', manage_devices_view, name='manage-devices'),
 
    path('domain-lookup/', domain_lookup_view, name='domain-lookup'),

    path("device-firewall", device_firewall_rules_view, name="device-firewall-rules"),
    path("remove-firewall-rule/", remove_firewall_rule_view, name="remove-firewall-rule"),

    path("device_logs", device_logs_view, name="device-logs"),

    path("system/", system_status_view, name="system-status"),
    path("system/verify/", mark_verify_opnsense_view, name="mark-verify-opnsense"),

    path("help/", help_view, name="help"),

]

