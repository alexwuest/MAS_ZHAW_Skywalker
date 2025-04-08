from django.shortcuts import render, get_object_or_404, redirect
from django.utils import timezone
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST
from django.db.models import Q
from django.http import JsonResponse

from . import config
from .api_logs_parser import run_log_parser_once, api_dhcp_parser
from .models import DeviceLease, DeviceAllowedISP, FirewallLog

from .models import Device, DeviceLease, DeviceAllowedISP, FirewallLog
from .api_firewall_sync import allow_blocked_ips_for_device
from .forms import DeviceApprovalForm, AssignDeviceToLeaseForm

###########################################################################
# Show Output with logfile parser run
###########################################################################

def view_firewall_logs_all(request):
    ip_filter = request.GET.get("ip")
    logs = "\n".join(run_log_parser_once(ip_filter))

    # Build list of isps
    isp_list = []
    for ip, v in config.IP_TABLE.items():
        if ip_filter and ip_filter not in ip:
            continue
        isp = v.get("isp")
        mac = v.get("mac") 
        if isp:
            isp_entry = {
                "name": isp,
                "evidence_id": v.get("evidence_id", False)
            }
            if isp_entry not in isp_list:
                isp_list.append(isp_entry)

    # Sort alphabetically by name
    isp_list.sort(key=lambda x: x["name"])

    return render(request, "firewall_logs.html", {
        "logs": logs,
        "ip_data": config.IP_TABLE,
        "isp_list": isp_list,
        'devices': Device.objects.all(),
    })

###########################################################################
# Show Output with logfile parser run and filtered output
###########################################################################

def view_firewall_logs(request):
    ip_filter = request.GET.get("ip")
    device_id = request.GET.get("device")

    run_log_parser_once()

    logs_queryset = FirewallLog.objects.all()

    # Filter by device using active leases
    if device_id:
        try:
            now = timezone.now()
            active_leases = DeviceLease.objects.filter(
                device__id=device_id,
                lease_end__gt=now
            ).values_list('ip_address', flat=True)

            logs_queryset = logs_queryset.filter(
                Q(source_ip__in=active_leases) | Q(destination_ip__in=active_leases)
            )
        except Device.DoesNotExist:
            pass

    logs_queryset = logs_queryset.order_by('-timestamp')[:500] #Limit?
    logs = "\n".join(str(log) for log in logs_queryset)

    isp_set = set()

    # From active logs (config.IP_TABLE)
    for ip, v in config.IP_TABLE.items():
        if ip_filter and ip_filter not in ip:
            continue
        isp = v.get("isp")
        if isp:
            isp_set.add(isp)

    # include allowed ISPs from DB
    if device_id:
        allowed = DeviceAllowedISP.objects.filter(device_id=device_id).values_list("isp_name", flat=True)
        isp_set.update(allowed)


    # Build isp_list
    isp_list = []
    for isp_name in sorted(isp_set):
        isp_list.append({
            "name": isp_name,
            "evidence_id": config.IP_TABLE.get(isp_name, {}).get("evidence_id", False)
        })

    return render(request, "firewall_logs.html", {
        "logs": logs,
        "ip_data": config.IP_TABLE,
        "isp_list": isp_list,
        "devices": Device.objects.all(),
        "selected_device_id": device_id,
    })


###########################################################################
# Combined view for device management
###########################################################################

def manage_devices_view(request):
    # refresh DHCP leases 
    api_dhcp_parser.parse_opnsense_leases()

    client_ip = request.META.get('HTTP_X_FORWARDED_FOR') or request.META.get('REMOTE_ADDR')
    device_form = DeviceApprovalForm(initial={'ip_address': client_ip, 'mac_address': ''})

    if request.method == 'POST':
        action = request.POST.get("action")

        if action == "add_device":
            device_form = DeviceApprovalForm(request.POST)
            if device_form.is_valid():
                device_id = device_form.cleaned_data['device_id']
                description = device_form.cleaned_data['description']
                device, description = Device.objects.get_or_create(device_id=device_id, defaults={'description': description})

                return redirect('manage-devices')

        elif action == "assign_lease":
            lease_form = AssignDeviceToLeaseForm(request.POST)
            if lease_form.is_valid():
                device = lease_form.cleaned_data['device']
                lease_id = lease_form.cleaned_data['lease_id']

                lease = get_object_or_404(DeviceLease, id=lease_id)
                lease.device = device
                lease.save()

                return redirect('manage-devices')

    # Unassigned leases
    unlinked_leases = DeviceLease.objects.filter(device__isnull=True).order_by('-last_seen')
    lease_forms = [AssignDeviceToLeaseForm(initial={'lease_id': lease.id}) for lease in unlinked_leases]

    return render(request, 'manage_devices.html', {
        'form': device_form,
        'entries': zip(unlinked_leases, lease_forms),
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

        count = allow_blocked_ips_for_device(device.device_id)
        return JsonResponse({"status": "ok", "rules_added": count})
    
    return JsonResponse({"status": "error", "message": "Invalid method"}, status=405)



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
        return JsonResponse({"status": "linked", "created": created})
    else:
        deleted, _ = DeviceAllowedISP.objects.filter(device=device, isp_name=isp_name).delete()
        return JsonResponse({"status": "unlinked", "deleted": deleted})





