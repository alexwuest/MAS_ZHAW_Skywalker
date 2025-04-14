from django import forms
from .models import Device
from .constants import get_dns_choices

class DeviceApprovalForm(forms.ModelForm):
    class Meta:
        model = Device
        fields = ['device_id', 'description', 'dns_server', 'examiner']
        widgets = {
            'dns_server': forms.Select(choices=get_dns_choices())
        }

class DeviceChoiceField(forms.ModelChoiceField):
    def label_from_instance(self, obj):
        return f"{obj.device_id} {obj.description}"

class AssignDeviceToLeaseForm(forms.Form):
    device = DeviceChoiceField(queryset=Device.objects.all())
    lease_id = forms.IntegerField(widget=forms.HiddenInput)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['device'].queryset = Device.objects.all().order_by('device_id')


class DomainLookupForm(forms.Form):
    domain = forms.CharField(label="Enter a domain", max_length=255)

