from django.shortcuts import render, get_object_or_404, redirect
from django.utils import timezone
from django.utils.timezone import now
from datetime import timedelta
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST
from django.db.models import Q, Max, Exists, OuterRef, Subquery, DateTimeField
from django.http import JsonResponse
from django.core.paginator import Paginator

import socket
import requests

from . import config
from .config import OPNSENSE_IP, API_KEY, API_SECRET, CERT_PATH
from .api_logs_parser import api_dhcp_parser
from .ip_enrichment import ip_enrichment_queue
from .models import Device, DeviceLease, DeviceAllowedISP, FirewallLog, FirewallRule, MetadataSeenByDevice, DestinationMetadata
from .api_firewall_sync import allow_blocked_ips_for_device, add_single_rule, archiving_device
from .api_firewall import delete_rule_by_source_and_destination, delete_rule_by_uuid, apply_firewall_changes, check_rule_exists
from .forms import DeviceApprovalForm, AssignDeviceToLeaseForm, DomainLookupForm, HideLeaseForm


############################################################################
# Emoji legend for code comments
#   🔍	Search or lookup
#   🔑	Authentication, key, or token
#   🔒	Security, encryption, or protectio
#   📜	Log or record
#   📊	Data processing or analysis
#   📈	Statistics or metrics
#   📉	Decrease or reduction
#   📅	Reminder or alert
#   📧	Email or notification
#   📱	Mobile or app
#   📡	Network or connection
#   📶	Signal strength or quality
#   📡	Network or connection
#   📅	Calendar or date
#   📧	Email or notification
#   🧠	Smart logic or algorithm
#   🔄	Loop or recurring process
#   ➕	Addition, appending
#   ➖	Removal, deletion
#   🧩	Modular or reusable component
#   🪝	Hook or signal (Django, etc.)
#   🧵	Thread or concurrency
#   📦	Package or dependency
#   🗂️	Data grouping (like folders/tables)
#   📄	Single file or document
#   📁	Directory
#   🗃️	Database
#   📝	Write operation
#   🔍	Search/query/filter
#   📌	Pinned or important config/key
#   🧪	Unit test or experiment
#   🐞	Bug or issue
#   🔧	Fix or tweak
#   🚧	In progress or under construction
#   🧯	Hotfix/emergency
#   🛑	Critical error
#   ⚠️	Warning/edge case
#   ✅	Success / passed test
#   ❌	Failure / rejected case
#   ❓	Question or unknown
#   ❗	Important note or reminder
#   🆕   New item
#   💡	Idea or tip
#   ⏱️	Timeout or long task
#   💤	Sleep/delay
#   🚀	Speed optimization


###########################################################################
# Show Output with logfile parser run
###########################################################################

from django.db.models import Q

def view_firewall_logs_all(request):
    ip_filter = request.GET.get("ip")

    logs_queryset = FirewallLog.objects.select_related("destination_metadata").order_by("-timestamp")[:1000]

    if ip_filter:
        logs_queryset = logs_queryset.filter(
            Q(source_ip__icontains=ip_filter) | Q(destination_ip__icontains=ip_filter)
        )

    enriched_logs = []
    for log in logs_queryset:
        src = f"{log.source_ip}:{log.source_port}".ljust(20)
        dst = f"{log.destination_ip}:{log.destination_port}".ljust(20)
        timestamp = log.timestamp.strftime("%d.%m.%Y-%d %H:%M:%S")
        status = "✅" if log.destination_metadata else "🆕"
        isp_display = log.destination_metadata.isp if log.destination_metadata else "Unknown"

        enriched_logs.append(f"{timestamp} - {src} → {dst} [{status}] ({isp_display})")

    logs = "\n".join(enriched_logs)

    # Build ISP list from DestinationMetadata
    isp_list = []
    isp_qs = DestinationMetadata.objects.filter(end_date__isnull=True).values("isp").distinct()

    for entry in isp_qs:
        isp = entry["isp"]
        if not isp:
            continue
        if ip_filter and ip_filter not in isp:
            continue
        isp_list.append({"name": isp, "evidence_id": config.IP_TABLE.get(isp, {}).get("evidence_id", False)})

    isp_list.sort(key=lambda x: x["name"])

    return render(request, "firewall_logs.html", {
        "logs": logs,
        "ip_data": config.IP_TABLE,
        "isp_list": isp_list,
        'devices': Device.objects.all().order_by('device_id'),
    })


###########################################################################
# BLOCKED / Logfile Parser / Filtered by Device
###########################################################################

def view_firewall_logs(request):
    ip_filter = request.GET.get("ip")
    device_id = request.GET.get("device_id")

    logs_queryset = FirewallLog.objects.select_related("destination_metadata").filter(action="block")

    # Filter by device using active leases
    if device_id:
        now = timezone.now()
        active_leases = DeviceLease.objects.filter(
            device__id=device_id,
            lease_end__gt=now
        ).values_list('ip_address', flat=True)

        logs_queryset = logs_queryset.filter(
            Q(source_ip__in=active_leases) | Q(destination_ip__in=active_leases)
        )

    recent_logs = logs_queryset.order_by('-timestamp')[:2000]

    # Build log lines from DB
    enriched_logs = []
    for log in recent_logs:
        meta = log.destination_metadata
        status = "✅" if meta else "🆕"
        isp_display = meta.isp if meta and meta.isp else "Unknown, lookup pending"

        src = f"{log.source_ip}:{log.source_port}".ljust(20)
        dst = f"{log.destination_ip}:{log.destination_port}".ljust(20)
        timestamp = log.timestamp.strftime("%H:%M:%S - %d.%m.%Y")

        enriched_logs.append(f"{timestamp} - {src} → {dst} {status} {isp_display}")

    logs = "\n".join(enriched_logs)

    # Build ISP list only from logs related to selected device
    isp_set = set()
    if device_id:
        try:
            now = timezone.now()
            active_leases = DeviceLease.objects.filter(
                device__id=device_id,
                lease_end__gt=now
            ).values_list('ip_address', flat=True)

            logs_queryset = FirewallLog.objects.filter(
                Q(source_ip__in=active_leases) | Q(destination_ip__in=active_leases),
                destination_metadata__isnull=False
            ).select_related('destination_metadata')

            isp_set.update(
                logs_queryset.values_list('destination_metadata__isp', flat=True)
            )

            allowed = DeviceAllowedISP.objects.filter(
                device__id=device_id
            ).values_list("isp_name", flat=True)

            isp_set.update(allowed)

        except Device.DoesNotExist:
            pass


    # ISP list
    isp_list = [{"name": isp, "evidence_id": None} for isp in sorted(filter(None, isp_set))]

    return render(request, "firewall_logs.html", {
        "logs": logs,
        "ip_data": config.IP_TABLE,
        "isp_list": isp_list,
        "devices": Device.objects.all().order_by('device_id'),
        "selected_device_id": int(device_id) if device_id else None,
    })


###########################################################################
# PASSED / Logfile Parser / Filtered by Device
###########################################################################

def firewall_passed_logs_view(request):
    device_id = request.GET.get("device_id")

    logs_queryset = FirewallLog.objects.select_related("destination_metadata").filter(action="pass")

    # Filter by device using active leases
    if device_id:
        now = timezone.now()
        active_leases = DeviceLease.objects.filter(
            device__id=device_id,
            lease_end__gt=now
        ).values_list('ip_address', flat=True)

        logs_queryset = logs_queryset.filter(
            Q(source_ip__in=active_leases) | Q(destination_ip__in=active_leases)
        )

    recent_logs = logs_queryset.order_by('-timestamp')[:2000]

    # Build log lines from DB
    enriched_logs = []
    for log in recent_logs:
        meta = log.destination_metadata
        status = "✅" if meta else "🆕"
        isp_display = meta.isp if meta and meta.isp else "Unknown, lookup pending"

        src = f"{log.source_ip}:{log.source_port}".ljust(20)
        dst = f"{log.destination_ip}:{log.destination_port}".ljust(20)
        timestamp = log.timestamp.strftime("%H:%M:%S - %d.%m.%Y")

        enriched_logs.append(f"{timestamp} - {src} → {dst} {status} {isp_display}")

    logs = "\n".join(enriched_logs)

    # Build ISP list only from logs related to selected device
    isp_set = set()
    if device_id:
        try:
            now = timezone.now()
            active_leases = DeviceLease.objects.filter(
                device__id=device_id,
                lease_end__gt=now
            ).values_list('ip_address', flat=True)

            logs_queryset = FirewallLog.objects.filter(
                Q(source_ip__in=active_leases) | Q(destination_ip__in=active_leases),
                destination_metadata__isnull=False
            ).select_related('destination_metadata')

            isp_set.update(
                logs_queryset.values_list('destination_metadata__isp', flat=True)
            )

            allowed = DeviceAllowedISP.objects.filter(
                device__id=device_id
            ).values_list("isp_name", flat=True)

            isp_set.update(allowed)

        except Device.DoesNotExist:
            pass


    # ISP list
    isp_list = [{"name": isp, "evidence_id": None} for isp in sorted(filter(None, isp_set))]

    return render(request, "firewall_logs_passed.html", {
        "logs": logs,
        "isp_list": isp_list,        
        "ip_data": config.IP_TABLE,
        "devices": Device.objects.all().order_by('device_id'),
        "selected_device_id": int(device_id) if device_id else None,
    })


###########################################################################
# Show grouped output by device
###########################################################################
def device_ip_overview_view(request):
    devices = Device.objects.all().order_by("device_id")
    device_id = request.GET.get("device_id")
    filter_recent = request.GET.get("filter_recent")

    try:
        seconds = int(filter_recent)
    except (TypeError, ValueError):
        seconds = None


    if not device_id:
        return render(request, "device_ip_overview.html", {
            "devices": devices,
            "device": None,
            "new_ips": [],
            "overview": {},
        })

    device = get_object_or_404(Device, id=device_id)
    source_ips = device.leases.values_list("ip_address", flat=True)

    # Check for active firewall rules
    active_rules_dict = {
        f"{src}|{dst}": True
        for src, dst in FirewallRule.objects.filter(
            source_ip__in=source_ips,
            end_date__isnull=True
        ).values_list("source_ip", "destination_ip")
    }

    metadata_seen = MetadataSeenByDevice.objects.filter(device=device).select_related("metadata")

    new_ips = []
    known_ips = {}

    now = timezone.now()

    for seen in metadata_seen:
        meta = seen.metadata
        ip = meta.ip
        isp = meta.isp or "Unknown"

        # Check if the IP is recently seen
        if seen.last_seen_at >= now - timedelta(seconds=seconds or 60):
            new_ips.append((ip, meta, seen))
        else:
            known_ips.setdefault(isp, []).append((ip, meta, seen))

    return render(request, "device_ip_overview.html", {
    "devices": devices,
    "device": device,
    "new_ips": new_ips,
    "overview": known_ips,
    "selected_device_id": device.id if device else None,
    "selected_filter": filter_recent,
    "active_rules_dict": active_rules_dict,
})

###########################################################################

@csrf_exempt
@require_POST
def flush_metadata_seen_view(request):
    device_id = request.POST.get("device_id")
    if device_id:
        MetadataSeenByDevice.objects.filter(device__id=device_id).delete()
    return redirect(f"/overview/?device_id={device_id}")

###########################################################################

@csrf_exempt
@require_POST
def add_rule_view(request):
    source_ip = request.POST.get("source_ip")
    destination_ip = request.POST.get("destination_ip")

    if source_ip and destination_ip:

        # Avoid adding if already exists
        if not check_rule_exists(source_ip, destination_ip):
            add_single_rule(source_ip, destination_ip, manual=True)

    return redirect(request.META.get('HTTP_REFERER', '/overview/'))

###########################################################################

@csrf_exempt
@require_POST
def remove_rule_view(request):
    source_ip = request.POST.get("source_ip")
    destination_ip = request.POST.get("destination_ip")

    if source_ip and destination_ip:
        rule = FirewallRule.objects.filter(
            source_ip=source_ip,
            destination_ip=destination_ip,
            end_date__isnull=True
        ).order_by('-start_date').first()

        if rule:
            if rule.uuid and delete_rule_by_uuid(rule.uuid):
                rule.end_date = timezone.now()
                rule.save(update_fields=["end_date"])
                apply_firewall_changes()
            else:
                # Fallback if UUID is missing or deletion failed
                FirewallRule.objects.filter(
                    source_ip=source_ip,
                    destination_ip=destination_ip,
                    end_date__isnull=True
                ).update(end_date=timezone.now())

    return redirect(request.META.get('HTTP_REFERER', '/overview/'))


###########################################################################
# View firewall rules for a device
###########################################################################


def device_firewall_rules_view(request):
    device_id = request.GET.get("device_id")
    devices = Device.objects.filter(archived=False).order_by("device_id")

    device = None
    rules = []

    if device_id:
        device = get_object_or_404(Device, id=device_id)
        active_ips = DeviceLease.objects.filter(
            device=device,
            lease_end__gt=timezone.now()
        ).values_list('ip_address', flat=True)

        rules = FirewallRule.objects.filter(
            source_ip__in=active_ips,
            end_date__isnull=True
        ).order_by('-start_date')

    return render(request, "device_firewall_rules.html", {
        "device": device,
        "rules": rules,
        "devices": devices,
        "selected_device_id": int(device_id) if device_id else None,
    })


###########################################################################
# Remove a firewall rule
###########################################################################

@csrf_exempt
@require_POST
def remove_firewall_rule_view(request):
    rule_id = request.POST.get("rule_id")
    if not rule_id:
        return JsonResponse({"status": "error", "message": "Missing rule_id"}, status=400)

    try:
        rule = FirewallRule.objects.get(id=rule_id)

        if rule.dns:  # Check the boolean field
            return JsonResponse({"status": "error", "message": "Cannot remove DNS rule"}, status=400)

        rule = FirewallRule.objects.get(id=rule_id)
        uuid = rule.uuid                    
        rule.end_date = timezone.now()
        rule.save(update_fields=["end_date"])

        # Call the API to remove the rule
        print(f"Removing rule: {rule}")
        print(f"Removing rule: {rule.source_ip} → {rule.destination_ip}")
        result = delete_rule_by_uuid(uuid)
        
        if result:
            print(f"Firewall rule removed: {rule}")
        else:
            print(f"⚠️ Firewall rule might not exist anymore: {rule}")

        return JsonResponse({"status": "ok"})

    except FirewallRule.DoesNotExist:
        return JsonResponse({"status": "error", "message": "Rule not found"}, status=404)


###########################################################################
# Combined view for device management
###########################################################################

def manage_devices_view(request):
    client_ip = request.META.get('HTTP_X_FORWARDED_FOR') or request.META.get('REMOTE_ADDR')
    device_form = DeviceApprovalForm(initial={'ip_address': client_ip, 'mac_address': ''})

    if request.method == 'POST':
        action = request.POST.get("action")

        if action == "add_device":
            device_form = DeviceApprovalForm(request.POST)
            if device_form.is_valid():
                device = device_form.save(commit=False)

                existing = Device.objects.filter(device_id=device.device_id).first()
                if existing:
                    existing.description = device.description
                    existing.examiner = device.examiner
                    existing.dns_server = device.dns_server
                    existing.save()
                    print(f"Device {device.device_id} updated.")
                else:
                    device.save()
                    print(f"Device {device.device_id} added.")

                return redirect('manage-devices')
            

        elif action == "archive_devices":
            selected_ids = set(request.POST.getlist("archived"))

            devices_active = Device.objects.filter(archived=False)
            
            for device in devices_active:
                # Update archive status
                device.archived = device.device_id in selected_ids
                print(f"Device {device.device_id} archived status BEFORE: {device.archived}")
                try:
                    archiving_device(device)
                except Exception as e:
                    print(f"Error archiving existing rules {e}")
                
                device.save(update_fields=["archived"])

            print(f"Updated archive status. Archived: {selected_ids}")
            return redirect("manage-devices")
        

        elif action == "unarchive_devices":
            selected_ids = set(request.POST.getlist("unarchived"))

            devices_inactive = Device.objects.filter(archived=True)
            for device in devices_inactive:
                if device.device_id in selected_ids:
                    # Remove the device from the list of archived devices
                    device.archived = False

                    device.save(update_fields=["archived"])

            print(f"Updated archive status. Not archived anymore: {selected_ids}")
            return redirect("manage-devices")
    

        elif action == "assign_lease":
            lease_form = AssignDeviceToLeaseForm(request.POST)
            if lease_form.is_valid():
                device = lease_form.cleaned_data['device']
                lease_id = lease_form.cleaned_data['lease_id']

                lease = get_object_or_404(DeviceLease, id=lease_id)
                lease.device = device
                print(f"Assigning lease {lease_id} to device {device.device_id}")
                lease.save()

                # Determine the newest lease for this device based on lease_start
                newest_lease = (
                    DeviceLease.objects
                    .filter(device=device)
                    .order_by('-lease_start')
                    .first()
                )

                dns = (device.dns_server or "").strip().lower()
                dns_map = {
                    "cloudflare": "1.1.1.1",
                    "google": "8.8.8.8",
                    "quad9": "9.9.9.9"
                }
                dns_ip = dns_map.get(dns)

                if not dns_ip:
                    print(f"ERROR: Unknown DNS server: '{dns}'")
                    return redirect('manage-devices')

                changes_made = False

                # Remove rules from all other leases except the newest
                other_leases = DeviceLease.objects.filter(device=device).exclude(id=newest_lease.id)
                for old_lease in other_leases:
                    if old_lease.ip_address:
                        print(f"INFO: Removing old rule for {old_lease.ip_address}")
                        removed = delete_rule_by_source_and_destination(old_lease.ip_address, dns_ip)  #TODO OLD!!!
                        if removed > 0:
                            changes_made = True

                # Add rule for the newest lease only if needed
                if newest_lease.ip_address and not check_rule_exists(newest_lease.ip_address, dns_ip):
                    if add_single_rule(newest_lease.ip_address, dns_ip, dns=True):
                        print(f"✅ Rule added for {newest_lease.ip_address} → {dns_ip}")
                        changes_made = True
                else:
                    print(f"INFO: Rule already exists for {newest_lease.ip_address} → {dns_ip}")

                if changes_made:
                    apply_firewall_changes()

                return redirect('manage-devices')

        elif action == "hide_lease":
            lease_form = HideLeaseForm(request.POST)
            if lease_form.is_valid():
                lease_id = lease_form.cleaned_data['lease_id']
                try:
                    lease = DeviceLease.objects.get(id=lease_id)
                    lease.show = False
                    lease.save()
                    print(f"Lease {lease.ip_address} hidden.")
                except DeviceLease.DoesNotExist:
                    print("Lease not found.")

    api_dhcp_parser.parse_opnsense_leases()

    # Add logic for colored circles
    now = timezone.now()
    recent_threshold = now - timedelta(minutes=10)  # Less than 30 days but older than 10 minutes will be yellow
    offline_threshold = now - timedelta(days=30)    # Older than 30 days will be red

    devices_with_last_active = (
        Device.objects
        .annotate(last_active_from_leases=Max('leases__last_active'))
        .order_by("device_id")
    )

    # Adding "has_lease" boolean
    leases_subquery = DeviceLease.objects.filter(device=OuterRef('pk'), show=True)
    devices_with_last_active = devices_with_last_active.annotate(has_lease=Exists(leases_subquery))

    devices_active = devices_with_last_active.filter(archived=False)
    devices_inactive = devices_with_last_active.filter(archived=True)

    # Unassigned leases
    unlinked_leases = DeviceLease.objects.filter(device__isnull=True, show=True).order_by('-last_active')
    lease_forms = [AssignDeviceToLeaseForm(initial={'lease_id': lease.id}) for lease in unlinked_leases]
    device_id = request.GET.get("device_id")

    return render(request, 'manage_devices.html', {
        'form': device_form,
        'entries': zip(unlinked_leases, lease_forms),
        'devices': devices_with_last_active,
        'devices_active': devices_active,
        'devices_inactive': devices_inactive,
        'selected_device_id': int(device_id) if device_id else None,
        'now': now,
        'recent_threshold': recent_threshold,
        'offline_threshold': offline_threshold,
    })


###########################################################################
# Update firewall rules
###########################################################################

@csrf_exempt
def update_firewall_rules_view(request):
    if request.method == "POST":
        device_id = request.POST.get("device_id")
        if not device_id:
            return JsonResponse({"status": "error", "message": "Missing device_id"}, status=400)
        try:
            device = Device.objects.get(id=device_id)
        except Device.DoesNotExist:
            return JsonResponse({"status": "error", "message": "Device not found"}, status=404)

        count_added, count_removed = allow_blocked_ips_for_device(device.device_id, return_removed=True)
        return JsonResponse({
            "status": "ok",
            "rules_added": count_added,
            "rules_removed": count_removed,
            "device_id": device.id if device else None,
        })


def get_linked_isps_view(request, device_id):
    device = get_object_or_404(Device, id=device_id)
    linked_isps = DeviceAllowedISP.objects.filter(device=device).values_list("isp_name", flat=True)
    return JsonResponse({"linked_isps": list(linked_isps)})


@csrf_exempt
@require_POST
def toggle_isp_link_view(request):
    device_id = request.POST.get("device_id")
    isp_name = request.POST.get("isp_name")
    link = request.POST.get("link") == "true"

    if not device_id or not isp_name:
        return JsonResponse({"status": "error", "message": "Missing data"}, status=400)

    device = get_object_or_404(Device, id=device_id)

    if link:
        obj, created = DeviceAllowedISP.objects.get_or_create(device=device, isp_name=isp_name)
        return JsonResponse({
            "status": "linked",
            "created": created,
            "device_id": device.id,
            "isp_name": isp_name
        })
    else:
        deleted, _ = DeviceAllowedISP.objects.filter(device=device, isp_name=isp_name).delete()
        return JsonResponse({
            "status": "unlinked",
            "deleted": deleted,
            "device_id": device.id,
            "isp_name": isp_name
        })


###########################################################################
# Lookup page
###########################################################################


def domain_lookup_view(request):
    form = DomainLookupForm()
    results = None

    device_id = request.GET.get("device_id") or request.POST.get("device_id")

    if request.method == 'POST':
        form = DomainLookupForm(request.POST)
        if form.is_valid():
            domain = form.cleaned_data['domain']
            try:
                ip_list = list(set(info[4][0] for info in socket.getaddrinfo(domain, None)))
            except socket.gaierror:
                ip_list = []

            results = []
            for ip in ip_list:
                try:
                    res = requests.get(f"http://ip-api.com/json/{ip}", timeout=3).json()
                    isp = res.get("isp", "Unknown")
                except Exception:
                    isp = "Unknown"
                results.append({'ip': ip, 'isp': isp})

    return render(request, "domain_lookup.html", {
        "form": form,
        "results": results,
        "devices": Device.objects.all().order_by('device_id'),
        "selected_device_id": int(device_id) if device_id else None,
    })


###########################################################################
# View device logs
###########################################################################


def device_logs_view(request):
    device_id = request.GET.get("device_id")
    devices = Device.objects.filter(archived=False).order_by("device_id")

    device = None
    logs = []
    page_obj = None

    if device_id:
        device = get_object_or_404(Device, id=device_id)
        active_ips = DeviceLease.objects.filter(
            device=device,
            lease_end__gt=timezone.now()
        ).values_list('ip_address', flat=True)

        logs_qs = FirewallLog.objects.filter(
            source_ip__in=active_ips,
        ).select_related("destination_metadata").order_by("-timestamp")

        limit = int(request.GET.get("limit", 100))              # Set default limit to 100
        page_number = request.GET.get("page")

        paginator = Paginator(logs_qs, limit)
        page_obj = paginator.get_page(page_number)
        logs = page_obj.object_list


    return render(request, "device_logs.html", {
        "device": device,
        "logs": logs,
        "devices": devices,
        "selected_device_id": int(device_id) if device_id else None,
        "page_obj": page_obj,
        "limit": request.GET.get("limit", 100),
    })


###########################################################################
# System Status View
###########################################################################
#TODO REFACTORING FIREWALL TO API!

def system_status_view(request):
    device_id = request.GET.get("device_id") or request.POST.get("device_id")
    now_time = now()
    sixty_days_ago = now_time - timedelta(days=60)

    active_devices = Device.objects.filter(archived=False).count()
    archived_devices = Device.objects.filter(archived=True).count()
    
    inactive_leases = DeviceLease.objects.filter(
        device=OuterRef('pk')
    ).order_by('-last_active').values('last_active')[:1]
        
    probably_archivable = Device.objects.filter(
        archived=False
    ).annotate(
        last_seen=Subquery(inactive_leases, output_field=DateTimeField())
    ).filter(
        last_seen__lt=sixty_days_ago
    ).count()

    ip_enrichments_queued = ip_enrichment_queue.qsize()
    log_entries = FirewallLog.objects.count()
    metadata_entries = DestinationMetadata.objects.count()
    active_firewall_rules = FirewallRule.objects.filter(end_date__isnull=True).count()
    verify_opnsense = FirewallRule.objects.filter(verify_opnsense=True).count()
    total_firewall_rules = FirewallRule.objects.count()

    try:
        response = requests.get(
            f"{OPNSENSE_IP}/api/diagnostics/firewall/log",
            auth=(API_KEY, API_SECRET),
            verify=CERT_PATH,
            timeout=3
        )
        opnsense_status = "Online" if response.status_code == 200 else "Offline"
    except Exception:
        opnsense_status = "Offline"

    context = {
        "devices": Device.objects.all().order_by('device_id'),
        "selected_device_id": int(device_id) if device_id else None,
        "active_devices": active_devices,
        "archived_devices": archived_devices,
        "probably_archivable": probably_archivable,
        "ip_enrichments_queued": ip_enrichments_queued,
        "log_entries": log_entries,
        "metadata_entries": metadata_entries,
        "active_firewall_rules": active_firewall_rules,
        "total_firewall_rules": total_firewall_rules,
        "opnsense_status": opnsense_status,
        "verify_opnsense": verify_opnsense,
    }

    return render(request, "system_status.html", context)
