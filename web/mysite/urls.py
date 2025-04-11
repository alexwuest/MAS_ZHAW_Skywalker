"""
URL configuration for mysite project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/5.1/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path
from rules.views import view_firewall_logs, manage_devices_view, get_linked_isps_view, toggle_isp_link_view, update_firewall_rules_view, domain_lookup_view, device_ip_overview_view


urlpatterns = [
    path('admin/', admin.site.urls),
    path("", manage_devices_view, name='manage-devices'),
    path("logs/", view_firewall_logs, name="view_logs"),

    path("overview/", device_ip_overview_view, name="device-ip-overview"),
    path("overview/<str:device_id>/", device_ip_overview_view, name="device-ip-overview"),

    path('manage-devices/', manage_devices_view, name='manage-devices'),
    path("update-firewall/", update_firewall_rules_view, name="update_firewall_rules"),

    path('api/device/<int:device_id>/linked-isps/', get_linked_isps_view, name='get_linked_isps'),
    path('api/toggle-isp/', toggle_isp_link_view, name='toggle_isp_link'),


    path('domain-lookup/', domain_lookup_view, name='domain-lookup'),

]