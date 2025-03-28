from django import forms
from .models import Device, DeviceLease

class DeviceApprovalForm(forms.Form):
    device_id = forms.CharField(label='Device Name / ID', max_length=20)
    mac_address = forms.CharField(label='MAC Address', max_length=17)
    ip_address = forms.GenericIPAddressField(label='IP Address')

class AssignDeviceToLeaseForm(forms.Form):
    device = forms.ModelChoiceField(queryset=Device.objects.all())
    lease_id = forms.IntegerField(widget=forms.HiddenInput)
