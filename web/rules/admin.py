from django.contrib import admin

from .models import FirewallRule, DestinationMetadata

admin.site.register(FirewallRule)
admin.site.register(DestinationMetadata)