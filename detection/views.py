import csv
import json
import datetime
import os
from pathlib import Path
from django.shortcuts import render, redirect
from django.views.generic import ListView, CreateView, UpdateView, DeleteView
# Ensure ALL needed models and forms are imported
from .models import Alert, SQLiPattern, DDoSConfig, PortSpecificDDoSConfig, GeofenceRule, PacketLog
from .forms import SQLiPatternForm, DDoSConfigForm, PortSpecificDDoSConfigForm
from django.contrib.auth.decorators import login_required
from django.utils import timezone
from datetime import timedelta
from django.db.models import Count, Q, Max
from django.db.models.functions import TruncHour
from django.urls import reverse_lazy
from django.contrib.auth.mixins import LoginRequiredMixin
from django.conf import settings
from .utils import get_geoip_data
from django.http import HttpResponse, HttpResponseNotAllowed, StreamingHttpResponse
from django.contrib import messages
from django.core.cache import cache # Import cache
from .models import BlockedIP # Import BlockedIP model
from .forms import BlockIPForm # Import the new form
from .firewall_utils import unblock_ip_firewall, block_ip_firewall

CACHE_KEY_PACKET_COUNT = 'ids_total_packet_count'

# --- Helper to touch signal file ---
def touch_config_signal_file():
    try:
        if hasattr(settings, 'CONFIG_SIGNAL_FILE') and settings.CONFIG_SIGNAL_FILE:
            signal_file_path = Path(settings.CONFIG_SIGNAL_FILE)
            signal_file_path.touch(exist_ok=True)
            print(f"SIGNAL: Touched signal file: {signal_file_path}")
        else:
            print("SIGNAL: Error - CONFIG_SIGNAL_FILE not defined or empty in settings.")
    except Exception as e:
        print(f"SIGNAL: Error touching signal file: {e}")

# --- Function-Based Views ---

@login_required
def alert_list(request):
    # Add pagination later if needed
    alerts = Alert.objects.all().order_by('-timestamp')[:100]
    context = {'alerts': alerts}
    return render(request, 'detection/alert_list.html', context)

@login_required
def dashboard(request):
    # ... (Aggregation logic as before) ...
    now = timezone.now(); time_delta_24h = now - timedelta(hours=24)
    alerts_last_24h = Alert.objects.filter(timestamp__gte=time_delta_24h)
    total_alerts_24h = alerts_last_24h.count()
    alerts_by_type_24h = alerts_last_24h.values('alert_type').annotate(count=Count('id')).order_by('-count')
    recent_alerts = Alert.objects.all().order_by('-timestamp')[:10]
    active_sqli_rules = SQLiPattern.objects.filter(is_active=True).count()
    ddos_config_obj = None; ddos_config_active = False
    try: ddos_config_obj = DDoSConfig.load(); ddos_config_active = ddos_config_obj.is_active
    except Exception: pass # Handle potential load error gracefully
    alert_trend_data = Alert.objects.filter(timestamp__gte=time_delta_24h).annotate(hour=TruncHour('timestamp')).values('hour').annotate(count=Count('id')).order_by('hour')
    alert_trend_labels = [item['hour'].strftime('%H:00') for item in alert_trend_data]
    alert_trend_counts = [item['count'] for item in alert_trend_data]

    # --- Get Total Packet Count from Cache ---
    total_packet_count = cache.get(CACHE_KEY_PACKET_COUNT, 0)
    # ---------------------------------------

    context = {
        'total_alerts_24h': total_alerts_24h,
        'alerts_by_type_24h': alerts_by_type_24h,
        'recent_alerts': recent_alerts,
        'active_sqli_rules': active_sqli_rules,
        'ddos_config_obj': ddos_config_obj,
        'ddos_config_active': ddos_config_active,
        'alert_trend_labels_json': json.dumps(alert_trend_labels),
        'alert_trend_counts_json': json.dumps(alert_trend_counts),
        'total_packet_count': total_packet_count, # Pass count to template
    }
    return render(request, 'detection/dashboard.html', context)

@login_required
def realtime_packets(request):
    total_packet_count = cache.get(CACHE_KEY_PACKET_COUNT, 0)
    context = {
        'monitored_ip': settings.SERVER_IP,
        'total_packet_count': total_packet_count, # Pass count to template
    }
    return render(request, 'detection/realtime_packets.html', context)

@login_required
def geolocation_map(request):
    try:
        allowed_countries = list(
            GeofenceRule.objects.filter(is_active=True).values_list('country_code', flat=True)
        )
        print(f"Loaded allowed countries for geofence: {allowed_countries}")
    except Exception as e:
         print(f"Error loading geofence rules: {e}")
         allowed_countries = []

    # --- START: Replacement for DISTINCT ON ---
    # 1. Find the timestamp of the latest alert for each source_ip
    latest_timestamps = Alert.objects.values('source_ip').annotate(
        latest_timestamp=Max('timestamp')
    )

    # 2. Build filter conditions for the latest alerts
    latest_alert_filters = Q() # Start with an empty Q object
    for item in latest_timestamps:
         # Create a Q object for each IP/timestamp pair and OR them together
        latest_alert_filters |= Q(source_ip=item['source_ip'], timestamp=item['latest_timestamp'])

    # 3. Fetch the actual Alert objects matching the latest criteria, limited to 50 unique IPs' latest alerts
    # We filter first, then order, then slice. Using PKs can sometimes be slightly more efficient if needed.
    if latest_alert_filters: # Only proceed if there are filters
        alerts = Alert.objects.filter(latest_alert_filters).order_by('-timestamp')[:50]
    else:
        alerts = Alert.objects.none() # Return empty queryset if no alerts found
    # --- END: Replacement for DISTINCT ON ---


    alerts_with_location = []

    for alert in alerts:
        geo_data = get_geoip_data(alert.source_ip) # Calls the utility function
        is_allowed = False
        latitude = None
        longitude = None
        city = "Unknown"
        country = "Unknown"

        # --- Check if geo_data is NOT None before accessing its keys ---
        if geo_data: # <<< ADD THIS CHECK
            latitude = geo_data.get('latitude')   # LINE 101 (or around here)
            longitude = geo_data.get('longitude') # This one too
            city = geo_data.get('city', 'Unknown') # Default value if key missing
            country = geo_data.get('country_name', 'Unknown') # Default value if key missing
            country_code = geo_data.get('country_code') # This one too

            # Check geofence using rules from database
            if country_code in allowed_countries:
                is_allowed = True
            elif not allowed_countries:
                is_allowed = True
        # --- End the if geo_data check ---

        # Only add alerts that have coordinate data to the list for the map?
        if latitude is not None and longitude is not None:
            alerts_with_location.append({
                'id': alert.id,
                'source_ip': alert.source_ip,
                'alert_type': alert.get_alert_type_display(),
                'timestamp': alert.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                'details': alert.details,
                'latitude': latitude,
                'longitude': longitude,
                'city': city,
                'country': country,
                'is_allowed': is_allowed,
            })
     # --- End of loop ----

    context = {
        'alerts_json': json.dumps(alerts_with_location),
    }
    return render(request, 'detection/geolocation_map.html', context)

class Echo:
    """An object that implements just the write method of the file-like
    interface.
    """
    def write(self, value):
        """Write the value by returning it, instead of storing in a buffer."""
        return value

def generate_csv_response(filename, header, data_rows):
    """Creates a streaming HTTP response for a CSV file."""
    pseudo_buffer = Echo()
    writer = csv.writer(pseudo_buffer)

    # Generator function to yield rows
    def stream_csv():
        yield writer.writerow(header) # Write header first
        for row in data_rows:
            yield writer.writerow(row)

    response = StreamingHttpResponse(
        stream_csv(), # Use the generator
        content_type="text/csv",
    )
    response["Content-Disposition"] = f'attachment; filename="{filename}.csv"'
    return response

# --- Main Export View ---
@login_required
def export_data_view(request):
    if not request.user.is_staff:
         messages.error(request, "Permission denied.")
         return redirect('home')

    if request.method == 'POST':
        data_type = request.POST.get('dataType') # Get selected type
        file_format = request.POST.get('fileFormat')
        # Get date directly from the input field (name="dateFilter")
        date_filter_str = request.POST.get('dateFilter', '').strip() # Use strip()

        print(f"Export requested: Type={data_type}, Format={file_format}, Date='{date_filter_str}'")

        timestamp_str = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"ids_export_{data_type}_{timestamp_str}"

        selected_date = None
        if date_filter_str: # Check if a date was actually provided
            try:
                selected_date = datetime.datetime.strptime(date_filter_str, '%Y-%m-%d').date()
            except ValueError:
                messages.error(request, f"Invalid date format '{date_filter_str}'. Please use YYYY-MM-DD or leave blank.")
                return redirect('export_data')

        # --- ALERT EXPORT ---
        if data_type == 'alerts':
            header = ['Timestamp', 'Type', 'Source IP', 'Destination IP', 'Port', 'Details', 'Payload Snippet']
            queryset = Alert.objects.all().order_by('-timestamp')
            if selected_date:
                queryset = queryset.filter(timestamp__date=selected_date)
                filename = f"ids_export_alerts_{date_filter_str}_{timestamp_str}" # Add date to filename

            if file_format == 'csv':
                data_rows = (
                    [
                        alert.timestamp.strftime("%Y-%m-%d %H:%M:%S"), alert.get_alert_type_display(),
                        alert.source_ip, alert.destination_ip, alert.destination_port,
                        alert.details, alert.http_payload
                    ] for alert in queryset.iterator()
                )
                return generate_csv_response(filename, header, data_rows)
            elif file_format == 'json':
                 data_list = []
                 for alert in queryset.iterator():
                     data_list.append({
                         'Timestamp': alert.timestamp.isoformat(), 'Type': alert.alert_type,
                         'SourceIP': alert.source_ip, 'DestinationIP': alert.destination_ip,
                         'Port': alert.destination_port, 'Details': alert.details,
                         'PayloadSnippet': alert.http_payload
                     })
                 response = HttpResponse(json.dumps(data_list, indent=2), content_type="application/json")
                 response["Content-Disposition"] = f'attachment; filename="{filename}.json"'
                 return response
            else:
                 messages.warning(request, f"Unsupported format '{file_format}' for Alerts.")
                 return redirect('export_data')

        # --- *** NEW: PACKET LOG EXPORT *** ---
        elif data_type == 'packets':
            # Check format first
            if file_format not in ['csv', 'json']:
                 messages.warning(request, f"Unsupported format '{file_format}' for Packet Logs.")
                 return redirect('export_data')

            header = ['Timestamp', 'Protocol', 'Source IP', 'Destination IP', 'Dest Port', 'Size Bytes']
            queryset = PacketLog.objects.all().order_by('-timestamp') # Get all logs for now
            # Apply date filter if provided
            if selected_date:
                queryset = queryset.filter(timestamp__date=selected_date)
                filename = f"ids_export_packets_{date_filter_str}_{timestamp_str}"

            # Add limit for safety? Exporting millions of packets can be huge.
            MAX_PACKET_EXPORT = 50000 # Example limit
            queryset = queryset[:MAX_PACKET_EXPORT]
            print(f"Exporting max {MAX_PACKET_EXPORT} packet log entries...")

            if file_format == 'csv':
                 data_rows = (
                     [
                         log.timestamp.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3], # Include milliseconds
                         log.protocol, log.source_ip, log.destination_ip,
                         log.destination_port, log.size_bytes
                     ] for log in queryset.iterator() # Use iterator
                 )
                 return generate_csv_response(filename, header, data_rows)

            elif file_format == 'json':
                  data_list = []
                  for log in queryset.iterator():
                       data_list.append({
                           'Timestamp': log.timestamp.isoformat(), 'Protocol': log.protocol,
                           'SourceIP': log.source_ip, 'DestinationIP': log.destination_ip,
                           'DestPort': log.destination_port, 'SizeBytes': log.size_bytes
                       })
                  response = HttpResponse(json.dumps(data_list, indent=2), content_type="application/json")
                  response["Content-Disposition"] = f'attachment; filename="{filename}.json"'
                  return response
        

    # --- Handle GET request ---
    elif request.method == 'GET':
        # No need to pass available_dates anymore
        context = {}
        return render(request, 'detection/export_data.html', context)
    else:
        return HttpResponseNotAllowed(['GET', 'POST'])
# --- Central Rules Management View ---
@login_required
def manage_rules_view(request):
    if not request.user.is_staff: return redirect('home') # Basic permission check
    context = {
        'sqli_rule_count': SQLiPattern.objects.count(),
        'default_ddos_config_exists': DDoSConfig.objects.filter(pk=1).exists(),
        'port_ddos_rule_count': PortSpecificDDoSConfig.objects.count(),
    }
    return render(request, 'detection/manage_rules.html', context)

@login_required
def block_ip_manually_view(request):
    """Handles the POST request from the manual block form."""
    # Basic permission check
    if not request.user.is_staff:
         messages.error(request, "Permission denied.")
         return redirect('blocked_ip_list') # Redirect back to list

    if request.method == 'POST':
        form = BlockIPForm(request.POST)
        if form.is_valid():
            ip_to_block = form.cleaned_data['ip_address']
            reason = form.cleaned_data['reason'] or "Manual block via UI"

            print(f"UI BLOCK: Attempting manual block for IP {ip_to_block}")
            # Call firewall utility FIRST
            success, err_msg = block_ip_firewall(ip_to_block)

            if success:
                try:
                    # Add to BlockedIP model only if firewall block succeeded
                    BlockedIP.objects.create(ip_address=ip_to_block, reason=reason)
                    messages.success(request, f"IP address {ip_to_block} blocked successfully.")
                    print(f"UI BLOCK: Firewall & DB block successful for {ip_to_block}")
                except Exception as db_e:
                     # If DB save fails after firewall block, we have inconsistency! Log carefully.
                     messages.error(request, f"Firewall rule added for {ip_to_block}, but failed to save to database: {db_e}")
                     print(f"UI BLOCK: Inconsistency! Firewall blocked {ip_to_block} but DB save failed: {db_e}")
            else:
                 messages.error(request, f"Failed to block IP {ip_to_block} in firewall. Error: {err_msg}")
                 print(f"UI BLOCK: Firewall block FAILED for {ip_to_block}. Error: {err_msg}")

            return redirect('blocked_ip_list') # Redirect back anyway
        else:
            # If form is invalid, usually redisplay the list page with errors
            # We need to pass the invalid form back to the ListView's context
            # This is slightly complex; simpler is just showing a generic error
            messages.error(request, "Invalid data submitted. Please check the IP address.")
            return redirect('blocked_ip_list') # Redirect back

    else:
        # If accessed via GET, redirect back to the list view
        return redirect('blocked_ip_list')


@login_required
def unblock_ip_view(request, pk): # Use primary key for clarity
    """Handles unblocking an IP via POST request."""
     # Basic permission check
    if not request.user.is_staff:
         messages.error(request, "Permission denied.")
         return redirect('blocked_ip_list')

    if request.method == 'POST':
        try:
            blocked_entry = BlockedIP.objects.get(pk=pk)
            ip_to_unblock = blocked_entry.ip_address
            print(f"UI UNBLOCK: Attempting unblock for IP {ip_to_unblock}")

            # Call firewall utility FIRST
            success, err_msg = unblock_ip_firewall(ip_to_unblock) # Try firewall first

            if success:
                print(f"UI UNBLOCK: Firewall unblock successful for {ip_to_unblock}.")
                blocked_entry.delete() # Delete from DB
                messages.success(request, f"IP address {ip_to_unblock} unblocked successfully.")
                print(f"UI UNBLOCK: Removed {ip_to_unblock} from BlockedIP model.")
                touch_config_signal_file() # <--- SIGNAL SNIFFER TO RELOAD CACHE
            else:
                 messages.error(request, f"Failed to unblock IP {ip_to_unblock} in firewall. Error: {err_msg}")
                 print(f"UI UNBLOCK: Firewall unblock FAILED for {ip_to_unblock}. DB entry NOT deleted.")

        except BlockedIP.DoesNotExist:
            messages.error(request, "Blocked IP entry not found.")
            print(f"UI UNBLOCK: Error - BlockedIP entry with PK {pk} not found.")
        except Exception as e:
             messages.error(request, f"An unexpected error occurred during unblock: {e}")
             print(f"UI UNBLOCK: Unexpected error for PK {pk}: {e}")

        return redirect('blocked_ip_list') # Redirect back to the list
    else:
        # Only allow POST for unblocking action
        return HttpResponseNotAllowed(['POST'])

# --- END NEW Views ---

# --- Class-Based Views for Rule Management (WITH SIGNALING) ---

class SQLiPatternListView(LoginRequiredMixin, ListView):
    model = SQLiPattern
    template_name = 'detection/sqli_pattern_list.html'
    context_object_name = 'patterns'

class SQLiPatternCreateView(LoginRequiredMixin, CreateView):
    model = SQLiPattern
    form_class = SQLiPatternForm
    template_name = 'detection/sqli_pattern_form.html' # Verify template name
    success_url = reverse_lazy('sqli_pattern_list')

    def form_valid(self, form):
        messages.success(self.request, "SQLi Pattern created successfully.")
        response = super().form_valid(form)
        touch_config_signal_file() # Touch signal file AFTER save
        return response

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['form_title'] = 'Create New SQLi Pattern'
        return context

class SQLiPatternUpdateView(LoginRequiredMixin, UpdateView):
    model = SQLiPattern
    form_class = SQLiPatternForm
    template_name = 'detection/sqli_pattern_form.html' # Verify template name
    success_url = reverse_lazy('sqli_pattern_list')

    def form_valid(self, form):
        messages.success(self.request, "SQLi Pattern updated successfully.")
        response = super().form_valid(form)
        touch_config_signal_file() # Touch signal file AFTER save
        return response

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['form_title'] = 'Update SQLi Pattern'
        return context

class SQLiPatternDeleteView(LoginRequiredMixin, DeleteView):
    model = SQLiPattern
    template_name = 'detection/sqli_pattern_form.html' # Verify template name
    success_url = reverse_lazy('sqli_pattern_list')
    context_object_name = 'object'

    def post(self, request, *args, **kwargs):
        object_display = str(self.get_object())
        response = super().post(request, *args, **kwargs)
        touch_config_signal_file() # Touch signal file AFTER delete
        messages.success(self.request, f"SQLi Pattern '{object_display}' deleted successfully.")
        return response


class DDoSConfigUpdateView(LoginRequiredMixin, UpdateView):
    model = DDoSConfig
    form_class = DDoSConfigForm
    template_name = 'detection/ddos_config_form.html'
    success_url = reverse_lazy('manage_rules') # Redirect to central rules page

    def get_object(self, queryset=None):
        try: return DDoSConfig.load()
        except DDoSConfig.DoesNotExist: messages.error(self.request, "Config not found"); return None # Should redirect via dispatch/get

    def form_valid(self, form):
        messages.success(self.request, "Default DDoS Configuration updated successfully.")
        response = super().form_valid(form)
        touch_config_signal_file() # Touch signal file AFTER save
        return response

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['form_title'] = 'Update Default DDoS Configuration'
        return context

class PortSpecificDDoSConfigListView(LoginRequiredMixin, ListView):
    model = PortSpecificDDoSConfig
    template_name = 'detection/portspecificddosconfig_list.html'
    context_object_name = 'port_rules'
    paginate_by = 20
    def get_queryset(self): return PortSpecificDDoSConfig.objects.all().order_by('port')

class PortSpecificDDoSConfigCreateView(LoginRequiredMixin, CreateView):
    model = PortSpecificDDoSConfig
    form_class = PortSpecificDDoSConfigForm
    template_name = 'detection/portspecificddosconfig_form.html'
    success_url = reverse_lazy('port_specific_ddos_list')

    def form_valid(self, form):
        messages.success(self.request, "Port-specific DDoS rule created.")
        response = super().form_valid(form)
        touch_config_signal_file()
        return response
    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs); context['form_title'] = 'Add Port-Specific DDoS Rule'; return context

class PortSpecificDDoSConfigUpdateView(LoginRequiredMixin, UpdateView):
    model = PortSpecificDDoSConfig
    form_class = PortSpecificDDoSConfigForm
    template_name = 'detection/portspecificddosconfig_form.html'
    success_url = reverse_lazy('port_specific_ddos_list')

    def form_valid(self, form):
        messages.success(self.request, "Port-specific DDoS rule updated.")
        response = super().form_valid(form)
        touch_config_signal_file()
        return response
    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs); context['form_title'] = 'Update Port-Specific DDoS Rule'; return context

class PortSpecificDDoSConfigDeleteView(LoginRequiredMixin, DeleteView):
     model = PortSpecificDDoSConfig
     template_name = 'detection/portspecificddosconfig_confirm_delete.html'
     success_url = reverse_lazy('port_specific_ddos_list')
     context_object_name = 'object'

     def post(self, request, *args, **kwargs):
         object_display = str(self.get_object())
         response = super().post(request, *args, **kwargs)
         touch_config_signal_file()
         messages.success(self.request, f"Port-specific DDoS rule '{object_display}' deleted.")
         return response

class BlockedIPListView(LoginRequiredMixin, ListView):
    model = BlockedIP
    template_name = 'detection/blockedip_list.html' # Create this template
    context_object_name = 'blocked_ips'
    paginate_by = 25 # Add pagination

    # Optional: Add staff check mixin if desired
    # from django.contrib.auth.mixins import UserPassesTestMixin
    # class StaffRequiredMixin(UserPassesTestMixin):
    #     def test_func(self): return self.request.user.is_staff
    # class BlockedIPListView(LoginRequiredMixin, StaffRequiredMixin, ListView): ...

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['form'] = BlockIPForm() # Add blank form for manual blocking on the same page
        return context     