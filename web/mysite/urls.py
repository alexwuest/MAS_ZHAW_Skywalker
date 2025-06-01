from django.contrib import admin
from django.contrib.auth import views as auth_views
from django.contrib.auth.views import LogoutView
from django.urls import path
from rules.views import (
    # FIREWALL RULE MANAGEMENT
    add_rule_view,
    remove_rule_view,
    remove_firewall_rule_view,
    # BLOCKED LOGS / PASSED LOGS VIEW
    combined_firewall_logs_view,
    update_firewall_rules_view,
    update_firewall_isp_view,
    # GROUPED IPs VIEW
    device_ip_overview_view,
    get_linked_isps_view,
    toggle_isp_link_view,
    flush_metadata_seen_view,
    # DNS VIEW
    device_dns_records_view,
    submit_dns_records,
    # MANAGE DEVICES VIEW
    manage_devices_view,
    # DOMAIN LOOKUP VIEW
    domain_lookup_view,
    # FIREWALL RULES VIEW
    device_firewall_rules_view,
    # DEVICE LOGS VIEW
    device_logs_view,
    # STATUS VIEW
    system_status_view,
    mark_verify_opnsense_view,
    # ? VIEW
    help_view,
)

urlpatterns = [
    # ADMIN
    path('admin/', admin.site.urls),

    # AUTHENTICATION
    path("auth/login/", auth_views.LoginView.as_view(), name="login"),
    path("auth/logout/", auth_views.LogoutView.as_view(), name="logout"),

    # FIREWALL RULE MANAGEMENT
    path("add_rule/", add_rule_view, name="add-rule-view"),
    path("remove_rule/", remove_rule_view, name="remove-rule-view"),
    path("remove_firewall_rule/", remove_firewall_rule_view, name="remove-firewall-rule"),

    # BLOCKED LOGS / PASSED LOGS VIEW
    path("firewall/logs/", combined_firewall_logs_view, name="firewall_logs"),
    path('firewall/logs/update_firewall/', update_firewall_rules_view, name='update_firewall_rules'),
    path("firewall/logs/update_firewall_isp/", update_firewall_isp_view, name="update_firewall_isp"),

    # GROUPED IPs VIEW
    path('firewall/isp/', device_ip_overview_view, name='device-ip-overview'),
    path('firewall/isp/<int:device_id>/linked-isps/', get_linked_isps_view, name='api-linked-isps'),
    path('firewall/isp/toggle_isp/', toggle_isp_link_view, name='toggle_isp_link'),
    path('firewall/isp/flush_metadata/', flush_metadata_seen_view, name='flush-metadata'),

    # DNS VIEW
    path('firewall/dns/', device_dns_records_view, name='device_dns_records'),
    path('dns/submit/', submit_dns_records, name='submit_dns_records'),

    # MANAGE DEVICES VIEW
    path('', manage_devices_view, name='manage-devices'),
    path('manage_devices/', manage_devices_view, name='manage-devices'),

    # DOMAIN LOOKUP VIEW
    path('domain_lookup/', domain_lookup_view, name='domain-lookup'),

    # FIREWALL RULES VIEW
    path("firewall_rules", device_firewall_rules_view, name="device-firewall-rules"),

    # DEVICE LOGS VIEW
    path("logs", device_logs_view, name="device-logs"),

    # STATUS VIEW
    path("status/", system_status_view, name="system-status"),
    path("status/verify/", mark_verify_opnsense_view, name="mark-verify-opnsense"),

    # ? VIEW
    path("help/", help_view, name="help"),
]

