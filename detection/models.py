from django.db import models
import re
from django.core.validators import MinValueValidator, MaxValueValidator
from django.utils import timezone

class SQLiPattern(models.Model):
    pattern = models.CharField(max_length=255, unique=True, help_text="Regular expression pattern (case-insensitive)")
    description = models.CharField(max_length=255, blank=True)
    is_active = models.BooleanField(default=True)
    # score = models.PositiveIntegerField(default=1, help_text="Risk score (higher is more suspicious)") # Removed score
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.description or self.pattern

    def get_compiled_pattern(self):
        try:
            return re.compile(self.pattern, re.IGNORECASE)
        except re.error:
            return None

    class Meta:
        verbose_name = "SQL Injection Pattern"
        verbose_name_plural = "SQL Injection Patterns"
        ordering = ['description']


class DDoSConfig(models.Model):
    config_id = models.PositiveIntegerField(primary_key=True, default=1)
    # Default rate limits
    default_time_window_seconds = models.PositiveIntegerField(default=60, help_text="Default time window in seconds for rate limiting.")
    default_request_threshold = models.PositiveIntegerField(default=100, help_text="Default max requests per IP in the window (if no port-specific rule matches).")
    # Global enable/disable
    is_active = models.BooleanField(default=True, help_text="Enable/Disable all DDoS detection.")
    # NEW Global/SYN Flood Settings
    global_rate_threshold = models.PositiveIntegerField(default=5000, help_text="Max total incoming packets per second to the server before alerting.")
    syn_flood_threshold = models.PositiveIntegerField(default=50, help_text="Max incoming TCP SYN packets per second from a single source before alerting.")
    global_rate_window_seconds = models.PositiveIntegerField(default=10, help_text="Time window in seconds for global rate limit.")
    syn_flood_window_seconds = models.PositiveIntegerField(default=10, help_text="Time window in seconds for SYN flood rate limit.")
    # Tracking
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        status = "Active" if self.is_active else "Inactive"
        return f"DDoS Config ({status}) - Default: {self.default_request_threshold} req / {self.default_time_window_seconds}s"

    def save(self, *args, **kwargs):
        self.pk = 1
        super().save(*args, **kwargs)

    @classmethod
    def load(cls): # Corrected load method
        obj, created = cls.objects.get_or_create(pk=1)
        return obj

    class Meta:
        verbose_name = "Default DDoS Configuration"
        verbose_name_plural = "Default DDoS Configuration"

class PortSpecificDDoSConfig(models.Model):
    port = models.PositiveIntegerField(unique=True, validators=[MinValueValidator(1), MaxValueValidator(65535)], help_text="The specific network port number (1-65535).")
    time_window_seconds = models.PositiveIntegerField(default=60, help_text="Time window in seconds for this specific port.")
    request_threshold = models.PositiveIntegerField(default=50, help_text="Max requests per IP in the time window for this specific port.")
    description = models.CharField(max_length=100, blank=True, help_text="Optional description (e.g., SSH Port, Web Login).")
    is_active = models.BooleanField(default=True, help_text="Enable/Disable rule for this specific port.")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        status = "Active" if self.is_active else "Inactive"
        return f"Port {self.port} ({status}): {self.request_threshold} req / {self.time_window_seconds}s ({self.description})"

    class Meta:
        verbose_name = "Port-Specific DDoS Rule"
        verbose_name_plural = "Port-Specific DDoS Rules"
        ordering = ['port']


class Alert(models.Model):
    ALERT_TYPES = [
        ('SQLI', 'SQL Injection'),
        ('DDOS', 'DDoS Rate Exceeded'),
        # Add ('ANOMALY', 'Anomaly Detected') later if needed
    ]
    timestamp = models.DateTimeField(auto_now_add=True, db_index=True) # Add index for ordering
    alert_type = models.CharField(max_length=10, choices=ALERT_TYPES, db_index=True) # Add index for filtering
    source_ip = models.GenericIPAddressField(db_index=True) # Add index for filtering/grouping
    destination_ip = models.GenericIPAddressField(null=True, blank=True)
    destination_port = models.PositiveIntegerField(null=True, blank=True)
    details = models.TextField(help_text="Details like matched pattern or request count")
    http_payload = models.TextField(blank=True, null=True, help_text="Snippet of the triggering payload (if applicable)")

    def __str__(self):
        return f"{self.get_alert_type_display()} from {self.source_ip} at {self.timestamp.strftime('%Y-%m-%d %H:%M:%S')}"

    class Meta:
        ordering = ['-timestamp']
        verbose_name = "Security Alert"
        verbose_name_plural = "Security Alerts"


class GeofenceRule(models.Model):
    country_code = models.CharField(max_length=2, unique=True, help_text="ISO 3166-1 alpha-2 country code (e.g., US, GB, CA).")
    description = models.CharField(max_length=100, blank=True, help_text="Optional description (e.g., United States).")
    is_active = models.BooleanField(default=True)

    def __str__(self):
        return f"{self.country_code} ({self.description})"

    class Meta:
        verbose_name = "Geofence Allowed Country"
        verbose_name_plural = "Geofence Allowed Countries"
        ordering = ['country_code']

class BlockedIP(models.Model):
    ip_address = models.GenericIPAddressField(unique=True, db_index=True)
    reason = models.CharField(max_length=255, blank=True, help_text="Why this IP was blocked (e.g., DDoS, SQLi Attempt, Manual)")
    timestamp = models.DateTimeField(auto_now_add=True, help_text="When the IP was blocked")
    # Optional: Add an expiry time for temporary blocks
    # expires_at = models.DateTimeField(null=True, blank=True, help_text="Block automatically expires at this time (optional)")

    def __str__(self):
        return f"{self.ip_address} (Blocked: {self.timestamp.strftime('%Y-%m-%d %H:%M')})"

    class Meta:
        verbose_name = "Blocked IP Address"
        verbose_name_plural = "Blocked IP Addresses"
        ordering = ['-timestamp']        

class PacketLog(models.Model):
    """Stores summarized information about processed packets."""
    # Use DateTimeField with auto_now_add=False because sniffer provides timestamp
    timestamp = models.DateTimeField(default=timezone.now, db_index=True) # Store exact time
    protocol = models.CharField(max_length=10, db_index=True) # TCP, UDP, ICMP, etc.
    source_ip = models.GenericIPAddressField(db_index=True)
    destination_ip = models.GenericIPAddressField(null=True, blank=True) # Can be null
    destination_port = models.PositiveIntegerField(null=True, blank=True)
    size_bytes = models.PositiveIntegerField()
    # Optional: Add source port? TCP flags?
    source_port = models.PositiveIntegerField(null=True, blank=True)
    tcp_flags = models.CharField(max_length=10, blank=True, null=True)

    # Optional: Add ForeignKey to Alert if this packet triggered one? (More complex)
    related_alert = models.ForeignKey(Alert, null=True, blank=True, on_delete=models.SET_NULL)

    def __str__(self):
        return f"{self.timestamp.strftime('%Y-%m-%d %H:%M:%S')} | {self.protocol} | {self.source_ip} -> {self.destination_ip}:{self.destination_port or '*'}"

    class Meta:
        ordering = ['-timestamp'] # Show newest first by default
        verbose_name = "Packet Log Entry"
        verbose_name_plural = "Packet Log Entries"
        # Add index for common filtering/ordering
        indexes = [
            models.Index(fields=['timestamp', 'source_ip']),
            models.Index(fields=['timestamp', 'protocol']),
        ]        