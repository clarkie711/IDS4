# detection/forms.py
from django import forms
from .models import SQLiPattern, DDoSConfig, PortSpecificDDoSConfig, BlockedIP
from django.conf import settings

# Define standard Tailwind input classes (adjust as needed)
tailwind_input_classes = "appearance-none block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm placeholder-gray-400 focus:outline-none focus:ring-indigo-500 focus:border-indigo-500 sm:text-sm"
tailwind_checkbox_classes = "h-4 w-4 text-indigo-600 border-gray-300 rounded focus:ring-indigo-500"

class SQLiPatternForm(forms.ModelForm):
    class Meta:
        model = SQLiPattern
        fields = ['pattern', 'description', 'is_active']
        widgets = {
            'pattern': forms.TextInput(attrs={
                'class': tailwind_input_classes,
                'placeholder': "Enter the regular expression (e.g., ' OR \\'1\\'=\\'1')"
                }),
            'description': forms.TextInput(attrs={
                'class': tailwind_input_classes,
                'placeholder': "Short description (e.g., Basic SQLi Bypass)"
                }),
            'is_active': forms.CheckboxInput(attrs={
                'class': tailwind_checkbox_classes
            })
        }
        labels = {
            'is_active': 'Enable this pattern?' # Custom label next to checkbox
        }

class DDoSConfigForm(forms.ModelForm):
     class Meta:
        model = DDoSConfig
        fields = [
            'default_time_window_seconds','default_request_threshold',
            'global_rate_window_seconds','global_rate_threshold',
            'syn_flood_window_seconds','syn_flood_threshold',
            'is_active'
        ]
        widgets = { # Add widgets for consistent styling
            'default_time_window_seconds': forms.NumberInput(attrs={'class': tailwind_input_classes}),
            'default_request_threshold': forms.NumberInput(attrs={'class': tailwind_input_classes}),
            'global_rate_window_seconds': forms.NumberInput(attrs={'class': tailwind_input_classes}),
            'global_rate_threshold': forms.NumberInput(attrs={'class': tailwind_input_classes}),
            'syn_flood_window_seconds': forms.NumberInput(attrs={'class': tailwind_input_classes}),
            'syn_flood_threshold': forms.NumberInput(attrs={'class': tailwind_input_classes}),
            'is_active': forms.CheckboxInput(attrs={'class': tailwind_checkbox_classes}),
        }
        labels = { 'is_active': 'Enable All DDoS Detection?' }

class PortSpecificDDoSConfigForm(forms.ModelForm):
    class Meta:
        model = PortSpecificDDoSConfig
        fields = ['port', 'description', 'time_window_seconds', 'request_threshold', 'is_active']
        widgets = {
            'port': forms.NumberInput(attrs={'class': tailwind_input_classes}),
            'description': forms.TextInput(attrs={'class': tailwind_input_classes, 'placeholder': 'e.g., SSH Port Rule'}),
            'time_window_seconds': forms.NumberInput(attrs={'class': tailwind_input_classes}),
            'request_threshold': forms.NumberInput(attrs={'class': tailwind_input_classes}),
            'is_active': forms.CheckboxInput(attrs={'class': tailwind_checkbox_classes}),
        }
        labels = { 'port': 'Port Number', 'is_active': 'Rule Active?' }
        help_texts = { 'port': 'Enter the specific port number (1-65535).' }

class BlockIPForm(forms.Form):
    ip_address = forms.GenericIPAddressField(
        label="IP Address to Block",
        help_text="Enter a valid IPv4 or IPv6 address."
    )
    reason = forms.CharField(
        label="Reason for Blocking (Optional)",
        max_length=200,
        required=False,
        widget=forms.TextInput(attrs={'size': '50'})
    )

    # Add validation to prevent blocking already blocked IPs via this form
    def clean_ip_address(self):
        ip = self.cleaned_data.get('ip_address')
        if BlockedIP.objects.filter(ip_address=ip).exists():
            raise forms.ValidationError("This IP address is already in the blocklist.")
        # Optional: Add check to prevent blocking own server IP or local network?
        if ip == settings.SERVER_IP:
            raise forms.ValidationError("Cannot block the server's own IP address.")
        return ip        