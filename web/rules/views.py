from django.shortcuts import render, get_object_or_404, redirect
from django.utils import timezone
from .api_logs_parser import run_log_parser_once, api_dhcp_parser
from . import config
from .models import Device, DeviceMac, DeviceIp, DeviceLease
from .forms import DeviceApprovalForm, AssignDeviceToLeaseForm


def view_firewall_logs(request):
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
    })


def add_device_view(request):
    if request.method == 'POST':
        form = DeviceApprovalForm(request.POST)
        if form.is_valid():
            device_id = form.cleaned_data['device_id']
            mac_address = form.cleaned_data['mac_address']
            ip_address = form.cleaned_data['ip_address']

            device, _ = Device.objects.get_or_create(device_id=device_id)
            device_mac = DeviceMac.objects.create(device=device, mac_address=mac_address)
            DeviceIp.objects.create(mac=device_mac, ip_address=ip_address)

            return redirect('view-firewall-logs')  # or show a "thank you" page
    else:
        client_ip = request.META.get('HTTP_X_FORWARDED_FOR') or request.META.get('REMOTE_ADDR')
        initial = {
            'ip_address': client_ip,
            'mac_address': '',  # leave blank, user must enter
        }
        form = DeviceApprovalForm(initial=initial)

    return render(request, 'add_device.html', {'form': form})


def assign_lease_device_view(request):
    api_dhcp_parser.parse_opnsense_leases()
    if request.method == 'POST':
        form = AssignDeviceToLeaseForm(request.POST)
        if form.is_valid():
            device = form.cleaned_data['device']
            lease_id = form.cleaned_data['lease_id']

            lease = get_object_or_404(DeviceLease, id=lease_id)
            lease.device = device
            lease.save()

            return redirect('assign-device-to-lease')  # reload view

    # Show unlinked leases
    unlinked_leases = DeviceLease.objects.filter(device__isnull=True).order_by('-last_seen')
    forms = [AssignDeviceToLeaseForm(initial={'lease_id': lease.id}) for lease in unlinked_leases]

    return render(request, 'add_lease_device.html', {
        'entries': zip(unlinked_leases, forms),
    })




