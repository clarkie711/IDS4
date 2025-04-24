from django.contrib import admin
from .models import SQLiPattern, DDoSConfig, Alert, GeofenceRule, PortSpecificDDoSConfig, BlockedIP
from django.contrib import messages
from .models import PacketLog

@admin.register(SQLiPattern)
class SQLiPatternAdmin(admin.ModelAdmin):
    list_display = ('pattern', 'description', 'is_active', 'created_at') # Removed 'score'
    list_filter = ('is_active',)
    search_fields = ('pattern', 'description')

@admin.register(DDoSConfig)
class DDoSConfigAdmin(admin.ModelAdmin):
    # Updated display list
    list_display = (
        'is_active',
        'default_request_threshold', 'default_time_window_seconds',
        'global_rate_threshold', 'global_rate_window_seconds',
        'syn_flood_threshold', 'syn_flood_window_seconds',
        'updated_at'
    )
    # Keep readonly_fields if needed, e.g. 'updated_at'
    # Prevent adding more than one config row
    def has_add_permission(self, request):
        return not DDoSConfig.objects.exists()

@admin.register(PortSpecificDDoSConfig)
class PortSpecificDDoSConfigAdmin(admin.ModelAdmin):
    list_display = ('port', 'description', 'request_threshold', 'time_window_seconds', 'is_active')
    list_filter = ('is_active',)
    search_fields = ('port', 'description')

@admin.register(Alert)
class AlertAdmin(admin.ModelAdmin):
    list_display = ('timestamp', 'alert_type', 'source_ip', 'destination_ip', 'destination_port', 'details')
    list_filter = ('alert_type', 'timestamp', 'source_ip') # Added source_ip filter
    search_fields = ('source_ip', 'destination_ip', 'details', 'http_payload')
    readonly_fields = ('timestamp',)
    list_per_page = 50 # Show more alerts per page

@admin.register(GeofenceRule)
class GeofenceRuleAdmin(admin.ModelAdmin):
    list_display = ('country_code', 'description', 'is_active')
    list_filter = ('is_active',)
    search_fields = ('country_code', 'description')

@admin.register(BlockedIP)
class BlockedIPAdmin(admin.ModelAdmin):
    list_display = ('ip_address', 'reason', 'timestamp')
    search_fields = ('ip_address', 'reason')
    list_filter = ('timestamp',)
    readonly_fields = ('timestamp',) # Usually don't edit the block time
    list_per_page = 50

    def unblock_selected(modeladmin, request, queryset):
         from .firewall_utils import unblock_ip_firewall # Import necessary function
         unblocked_count = 0
         failed_count = 0
         for item in queryset:
             ip = item.ip_address
             success, err = unblock_ip_firewall(ip)
             if success:
                 item.delete() # Delete from DB if firewall unblock succeeds
                 unblocked_count += 1
             else:
                 failed_count += 1
                 messages.error(request, f"Failed to unblock {ip} in firewall: {err}")
         if unblocked_count > 0:
             messages.success(request, f"Successfully unblocked {unblocked_count} IP address(es).")
         if failed_count > 0:
              messages.warning(request, f"Failed to unblock {failed_count} IP address(es) in firewall. Database entries remain.")
    unblock_selected.short_description = "Unblock selected IP addresses in Firewall & DB"
    
    actions = [unblock_selected]
# --- END BlockedIP REGISTRATION --- 

@admin.register(PacketLog)
class PacketLogAdmin(admin.ModelAdmin):
    list_display = ('timestamp', 'protocol', 'source_ip', 'destination_ip', 'destination_port', 'size_bytes')
    list_filter = ('protocol', 'timestamp', 'source_ip') # Add filters
    search_fields = ('source_ip', 'destination_ip')
    readonly_fields = ('timestamp',) # Make timestamp read-only
    list_per_page = 100 # Show more per page
    # Date hierarchy for easier browsing (optional)
    date_hierarchy = 'timestamp'