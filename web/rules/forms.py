from django import forms
from .models import Device
from .constants import get_dns_choices

class DeviceApprovalForm(forms.ModelForm):
    device_id = forms.RegexField(
        regex=r'^A\d{9}$',
        error_messages={'invalid': 'Device ID must start with "A" followed by 9 digits.'},
        widget=forms.TextInput(attrs={'placeholder': 'A123456789'})
    )

    examiner = forms.RegexField(
        regex=r'^stp\w{3}$',
        error_messages={'invalid': 'Examiner must start with stp and followed by 3 characters.'},
        widget=forms.TextInput(attrs={'placeholder': 'stp012'})
    )

    class Meta:
        model = Device
        fields = ['device_id', 'description', 'dns_server', 'examiner']
        widgets = {
            'dns_server': forms.Select(choices=get_dns_choices()),
            'description': forms.TextInput(attrs={'placeholder': 'iPhone 16 Pro'}),
        }

class DeviceChoiceField(forms.ModelChoiceField):
    def label_from_instance(self, obj):
        return f"{obj.device_id} {obj.description}"

class AssignDeviceToLeaseForm(forms.Form):
    device = DeviceChoiceField(queryset=Device.objects.all())
    lease_id = forms.IntegerField(widget=forms.HiddenInput)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['device'].queryset = Device.objects.filter(archived=False).order_by("device_id")

class HideLeaseForm(forms.Form):
    lease_id = forms.IntegerField(widget=forms.HiddenInput)

class DomainLookupForm(forms.Form):
    domain = forms.CharField(label="Enter a domain", max_length=255)
