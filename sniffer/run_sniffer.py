#!/usr/bin/env python3
import os
import sys
import time
import logging
import re
import urllib.parse
import datetime
from collections import defaultdict, deque
import threading
from pathlib import Path

# --- Explicitly add project root to sys.path ---
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(SCRIPT_DIR)
if PROJECT_ROOT not in sys.path:
    print(f"DEBUG: Adding Project Root to sys.path: {PROJECT_ROOT}")
    sys.path.insert(0, PROJECT_ROOT)
else:
    print(f"DEBUG: Project Root already in sys.path: {PROJECT_ROOT}")
# ----------------------------------------------

# --- Configure Django FIRST ---
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "ids_project.settings") # Set env variable
import django # Now import django itself
try:
    django.setup() # Configure settings based on env variable
    print("[Info] Django setup completed.")
except Exception as e:
    print(f"[-] Error initializing Django: {e}")
    sys.exit(1)
# --- END Django Setup ---

# --- NOW Import Django components and your app modules ---
from django.conf import settings
from django.core.cache import cache
from channels.layers import get_channel_layer
from asgiref.sync import async_to_sync
from detection.models import PacketLog
from datetime import timezone
# Import your app's modules AFTER django.setup()
try:
    from detection.models import SQLiPattern, DDoSConfig, Alert, PortSpecificDDoSConfig, BlockedIP # Import all needed models
    from detection.firewall_utils import block_ip_firewall, is_ip_blocked_firewall # Import utils
except ImportError as e:
    print(f"[-] Error importing detection modules after Django setup: {e}")
    sys.exit(1)
# -------------------------------------------------------

# --- Scapy Import (can usually come after Django setup) ---
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
try:
    from scapy.all import sniff, IP, TCP, UDP, Raw, ICMP
except ImportError: print("[-] Scapy is not installed..."); sys.exit(1)
except OSError as e: print(f"[-] OSError during Scapy import: {e}"); sys.exit(1)


# --- Sniffer Configuration & Globals ---
# (Define these AFTER settings are available via django.setup)
NETWORK_INTERFACE = getattr(settings, 'NETWORK_INTERFACE', "enp7s0") # Read from settings
SERVER_IP = getattr(settings, 'SERVER_IP', "192.168.254.101") # Read from settings
MAX_PAYLOAD_SNIPPET = 500
PACKET_GROUP_NAME = 'live_packets'
ALERT_INTERVAL_SECONDS = getattr(settings, 'DDOS_ALERT_INTERVAL_SECONDS', 30)
STATS_UPDATE_INTERVAL = getattr(settings, 'STATS_UPDATE_INTERVAL_SECONDS', 15)
CACHE_KEY_PACKET_COUNT = 'ids_total_packet_count'
SQLI_SCORE_THRESHOLD = getattr(settings, 'SQLI_ALERT_THRESHOLD', 1)

# ... (Rest of globals: ip_requests, active_sqli_patterns, etc.) ...
ip_requests = defaultdict(lambda: {'timestamps': deque(), 'last_alert_time': 0.0})
global_packet_timestamps = deque()
_global_rate_last_alert_time = 0.0
active_sqli_patterns = []
ddos_default_config = None
ddos_port_configs = {}
ddos_global_config = {}
ddos_syn_config = {}
blocked_ips_cache = set()
config_lock = threading.Lock()
_sniffer_stop_event = threading.Event()
_last_config_mtime = 0.0
packet_counter = 0
packet_counter_lock = threading.Lock()
stats_update_timer = None

# --- Initialize Channel Layer ---
channel_layer = get_channel_layer()
if channel_layer is None: print("[-] Error: Could not get channel layer.")

# --- Helper Functions (send_packet_update, load_config_from_db, monitor_config_changes, create_alert, update_persistent_stats) ---

def send_packet_update(packet_data):
    # ... (Keep as is) ...
    if not channel_layer: return
    message = { 'type': 'packet.update', 'data': packet_data }
    try: async_to_sync(channel_layer.group_send)(PACKET_GROUP_NAME, message)
    except Exception as e: print(f"SNIFFER: [Error] Failed to send WS packet update: {e}")

def load_config_from_db():
    # ... (Keep corrected version loading all DDoS fields & SQLi patterns without score) ...
    global active_sqli_patterns, ddos_default_config, ddos_port_configs
    global ddos_global_config, ddos_syn_config, blocked_ips_cache # 

    print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] [Config] Loading configuration...")
    new_compiled_patterns = []
    new_default_config = None
    new_port_configs = {}
    new_global_config = None
    new_syn_config = None
    new_blocked_ips = set()
    try:
        # SQLi
        patterns_from_db = SQLiPattern.objects.filter(is_active=True)
        for p in patterns_from_db:
             compiled = p.get_compiled_pattern()
             if compiled: new_compiled_patterns.append({'compiled': compiled, 'description': p.description or p.pattern}) # No score
             else: print(f"[Warning] Invalid regex: {p.pattern}")
        sqli_count = len(new_compiled_patterns)

        # DDoS
        try: default_config_obj = DDoSConfig.objects.get(pk=1); is_ddos_overall_active = default_config_obj.is_active
        except DDoSConfig.DoesNotExist: default_config_obj = None; is_ddos_overall_active = False; print(f"[Warning] Default DDoSConfig not found...")
        if is_ddos_overall_active and default_config_obj:
            new_default_config = default_config_obj
            new_global_config = {'window': default_config_obj.global_rate_window_seconds, 'threshold': default_config_obj.global_rate_threshold }
            new_syn_config = {'window': default_config_obj.syn_flood_window_seconds, 'threshold': default_config_obj.syn_flood_threshold }
            port_rules = PortSpecificDDoSConfig.objects.filter(is_active=True)
            for rule in port_rules: new_port_configs[rule.port] = {'window': rule.time_window_seconds, 'threshold': rule.request_threshold}
            port_rule_count = len(new_port_configs)
        else: port_rule_count = 0; print(f"[Config] Overall DDoS disabled...")

        # --- Load Blocked IPs ---
        try:
            # Get a flat list of IP address strings from the DB
            new_blocked_ips = set(BlockedIP.objects.values_list('ip_address', flat=True))
            print(f"[Config] Loaded {len(new_blocked_ips)} blocked IPs from database.")
        except Exception as e:
            print(f"[Error] Failed to load blocked IPs from database: {e}")
            # Decide behavior: keep old cache or clear it? Let's clear it to be safe.
            new_blocked_ips = set()
        # ------------------------

        # Update Globals
        with config_lock:
            active_sqli_patterns = new_compiled_patterns; ddos_default_config = new_default_config; ddos_port_configs = new_port_configs; ddos_global_config = new_global_config if new_default_config else {}; ddos_syn_config = new_syn_config if new_default_config else {}
            print(f"[Config] Loaded {sqli_count} SQLi patterns.")
            if ddos_default_config: print(f"[Config] Default DDoS: Win={ddos_default_config.default_time_window_seconds}s, Thr={ddos_default_config.default_request_threshold}"); print(f"[Config] Port DDoS Rules: {port_rule_count}");
            if ddos_global_config: print(f"[Config] Global Rate: Win={ddos_global_config['window']}s, Thr={ddos_global_config['threshold']}/s")
            if ddos_syn_config: print(f"[Config] SYN Flood: Win={ddos_syn_config['window']}s, Thr={ddos_syn_config['threshold']}/s per IP")
            if not ddos_default_config: print(f"[Config] DDoS detection disabled.")
            blocked_ips_cache = new_blocked_ips
            print(f"[Config] In-memory blocklist cache updated with {len(blocked_ips_cache)} IPs.")
    except Exception as e:
        print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] [Error] Failed to load configuration/blocklist: {e}")

def monitor_config_changes():
    # ... (Keep corrected version checking settings.CONFIG_SIGNAL_FILE mtime) ...
    global _last_config_mtime
    if not hasattr(settings, 'CONFIG_SIGNAL_FILE') or not settings.CONFIG_SIGNAL_FILE: print("[Config Monitor] Error: CONFIG_SIGNAL_FILE not set."); return
    signal_file = Path(settings.CONFIG_SIGNAL_FILE); print(f"[Config Monitor] Watching: {signal_file}")
    try: _last_config_mtime = signal_file.stat().st_mtime
    except FileNotFoundError: _last_config_mtime = 0.0; print("[Config Monitor] Signal file not found initially.")
    except Exception as e: _last_config_mtime = 0.0; print(f"[Config Monitor] Error init mtime: {e}")
    while not _sniffer_stop_event.is_set():
        try:
            current_mtime = signal_file.stat().st_mtime
            if current_mtime > _last_config_mtime: print(f"[Config Monitor] Signal detected. Reloading..."); load_config_from_db(); _last_config_mtime = current_mtime
        except FileNotFoundError:
             if _last_config_mtime != -1: print(f"[Config Monitor] Warning: Signal file not found."); _last_config_mtime = -1
        except Exception as e: print(f"[Config Monitor] Error checking file: {e}"); _sniffer_stop_event.wait(5.0)
        _sniffer_stop_event.wait(1.0) # Check interval
    print("[Config Monitor] Monitor thread stopping.")

def update_persistent_stats():
    # ... (Keep corrected version using cache.set) ...
    global stats_update_timer, packet_counter
    current_count = 0
    with packet_counter_lock: current_count = packet_counter
    try:
        print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] [Stats] Updating packet count: {current_count}")
        cache.set(CACHE_KEY_PACKET_COUNT, current_count, timeout=None)
    except Exception as e: print(f"[Error] Failed update stats: {e}")
    if not _sniffer_stop_event.is_set():
        stats_update_timer = threading.Timer(STATS_UPDATE_INTERVAL, update_persistent_stats); stats_update_timer.daemon = True; stats_update_timer.start()

def detect_sql_injection(payload_str, src_ip, dst_ip, dst_port):
    """
    Checks payload against loaded SQLi patterns, applies decoding.
    Blocks offender on any match.
    Returns True if suspicious, False otherwise.
    """
    if not payload_str: return False
    with config_lock: current_patterns = active_sqli_patterns[:]
    if not current_patterns: return False

    matched_rules = []
    try:
        decoded_payload_once = urllib.parse.unquote_plus(payload_str)
        decoded_payload_twice = urllib.parse.unquote_plus(decoded_payload_once)
    except Exception as e:
        print(f"[Warning] Payload decoding error for SQLi check: {e}")
        decoded_payload_once = payload_str; decoded_payload_twice = payload_str
    payloads_to_check = {payload_str, decoded_payload_once, decoded_payload_twice}
    match_found = False

    # print(f"DEBUG SQLi: Checking {len(payloads_to_check)} versions for {src_ip}")
    for pattern_info in current_patterns:
        compiled_pattern = pattern_info['compiled']
        description = pattern_info['description']
        # score = pattern_info.get('score', 1) # Score field removed for now

        for payload_version in payloads_to_check:
            if compiled_pattern.search(payload_version):
                # print(f"DEBUG SQLi: Match! IP={src_ip}, Pattern='{description}'")
                # suspicious_score += score # Score field removed
                matched_rules.append(description)
                match_found = True # Set flag indicating at least one match
                break # Stop checking versions for this pattern

    # Alert if ANY pattern matched (effectively SQLI_SCORE_THRESHOLD = 1)
    if match_found:
        details = f"Potential SQLi detected. Matched Rules: {', '.join(list(set(matched_rules)))}"
        payload_snippet = payload_str[:MAX_PAYLOAD_SNIPPET] + ('...' if len(payload_str) > MAX_PAYLOAD_SNIPPET else '')
        # --- Block on SQLi attempt ---
        print(f"DEBUG SQLi: Triggering block for {src_ip}")
        create_alert(
            alert_type='SQLI',
            src_ip=src_ip,
            dst_ip=dst_ip,
            dst_port=dst_port,
            details=details,
            payload=payload_snippet,
            block_offender=True # Set blocking flag to True
        )
        # ---------------------------
        return True # Indicate suspicious activity found

    return False # Not deemed suspicious

def detect_ddos_rate_limit(ip_address, dest_port=None):
    """
    Checks Per-IP/Port request rate using time-based re-alerting.
    Blocks offender if rate significantly exceeds threshold.
    """
    with config_lock:
        current_default_config = ddos_default_config
        current_port_configs = ddos_port_configs

    print(f"DEBUG RATE_LIMIT - ENTER: Checking IP {ip_address} for Port {dest_port}.")

    if not current_default_config:
        print("DEBUG RATE_LIMIT - EXIT: Global DDoS disabled.")
        return

    window = current_default_config.default_time_window_seconds
    threshold = current_default_config.default_request_threshold
    rule_type = "Default"
    if dest_port and dest_port in current_port_configs:
        port_config = current_port_configs[dest_port]
        window = port_config['window']
        threshold = port_config['threshold']
        rule_type = f"Port {dest_port}"
    print(f"DEBUG RATE_LIMIT - CONFIG: Using Rule={rule_type}, Threshold={threshold}, Window={window}")

    current_time = time.time()
    request_key = (ip_address, dest_port if rule_type != "Default" else "default")
    tracking_data = ip_requests.setdefault(request_key, {'timestamps': deque(), 'last_alert_time': 0.0})
    request_times = tracking_data['timestamps']
    last_alert_time = tracking_data['last_alert_time']

    q_len_before = len(request_times)
    while request_times and current_time - request_times[0] > window: request_times.popleft()
    q_len_after = len(request_times)
    print(f"DEBUG RATE_LIMIT - DEQUE: Key {request_key}: BeforePop={q_len_before}, AfterPop={q_len_after}.")

    request_times.append(current_time)
    current_count = len(request_times)
    print(f"DEBUG RATE_LIMIT - COUNT: Key {request_key}: NewCount={current_count} (Threshold={threshold})")

    if current_count > threshold:
        print(f"DEBUG RATE_LIMIT - THRESHOLD EXCEEDED: Key {request_key}: Count={current_count}, Threshold={threshold}")
        allow_alert = (last_alert_time == 0.0) or (current_time - last_alert_time > ALERT_INTERVAL_SECONDS)
        time_since_last = current_time - last_alert_time if last_alert_time != 0.0 else float('inf')
        print(f"DEBUG RATE_LIMIT - TIME CHECK: Key {request_key}, Allow={allow_alert}, LastAlert={last_alert_time:.2f}, Now={current_time:.2f}, Interval={ALERT_INTERVAL_SECONDS}s")

        if allow_alert:
             # --- Decide whether to block ---
             should_block = False
             # Example: Block if count > 2 times the threshold
             if current_count > (threshold * 2):
                 should_block = True
                 print(f"DEBUG RATE_LIMIT: Block condition met for {request_key} (Count={current_count}, Threshold*2={threshold*2})")
             # -----------------------------

             details = (f"Request rate exceeded ({rule_type} Rule): {current_count} req in {window}s (Threshold: {threshold})")
             print(f"DEBUG RATE_LIMIT - CREATING ALERT: Key {request_key}: Block={should_block}, Details={details}")
             create_alert(
                 alert_type='DDOS',
                 src_ip=ip_address,
                 dest_port=dest_port,
                 details=details,
                 block_offender=should_block # Pass the flag
             )
             tracking_data['last_alert_time'] = current_time # Update time only when alerting
        # else: print(f"DEBUG RATE_LIMIT - ALERT SKIPPED: Key {request_key}: Interval not met.")

_global_rate_last_alert_time = 0.0
def detect_global_rate():
    """Checks overall incoming packet rate using time-based re-alerting."""
    global _global_rate_last_alert_time
    with config_lock: current_global_config = ddos_global_config.copy()
    if not current_global_config or 'window' not in current_global_config or 'threshold' not in current_global_config: return

    window = current_global_config['window']; threshold = current_global_config['threshold']; current_time = time.time()
    request_times = global_packet_timestamps
    while request_times and current_time - request_times[0] > window: request_times.popleft()
    current_count = len(request_times)
    print(f"DEBUG GLOBAL RATE: Count={current_count} (Threshold={threshold})")

    if current_count > threshold:
        print(f"DEBUG GLOBAL RATE: THRESHOLD EXCEEDED! Count={current_count}, Threshold={threshold}")
        allow_alert = (current_time - _global_rate_last_alert_time > ALERT_INTERVAL_SECONDS)
        print(f"DEBUG GLOBAL RATE: ALERT CHECK: Allow={allow_alert} (Interval={ALERT_INTERVAL_SECONDS}s)")
        if allow_alert:
             details = (f"Global incoming packet rate exceeded: {current_count} packets "
                        f"in {window}s (Threshold: {threshold})")
             print(f"DEBUG GLOBAL RATE: CREATING ALERT: {details}")
             # --- Do NOT block based on global rate ---
             create_alert('DDOS', 'N/A (Global)', details=details, block_offender=False)
             # ----------------------------------------
             _global_rate_last_alert_time = current_time

# --- UPDATED detect_syn_flood function signature and create_alert call ---
def detect_syn_flood(ip_address, dest_ip=None, dest_port=None):
    """
    Checks incoming SYN packet rate per source IP using time-based re-alerting.
    Blocks offender if threshold exceeded.
    """
    with config_lock: current_syn_config = ddos_syn_config.copy()
    if not current_syn_config or 'window' not in current_syn_config or 'threshold' not in current_syn_config: return

    window = current_syn_config['window']; threshold = current_syn_config['threshold']; current_time = time.time()
    request_key = (ip_address, 'syn')
    tracking_data = ip_requests.setdefault(request_key, {'timestamps': deque(), 'last_alert_time': 0.0})
    request_times = tracking_data['timestamps']; last_alert_time = tracking_data['last_alert_time']

    # Timestamp for current SYN is added in process_packet *after* this check
    # Remove old ones first
    while request_times and current_time - request_times[0] > window: request_times.popleft()

    # Calculate count including the packet being processed now
    current_count = len(request_times) + 1
    print(f"DEBUG SYN FLOOD: IP={ip_address}, Potential Count={current_count} (Threshold={threshold})")

    if current_count > threshold:
        print(f"DEBUG SYN FLOOD: THRESHOLD EXCEEDED: IP={ip_address}")
        allow_alert = (last_alert_time == 0.0) or (current_time - last_alert_time > ALERT_INTERVAL_SECONDS)
        print(f"DEBUG SYN FLOOD: ALERT CHECK: IP={ip_address}, Allow={allow_alert}")
        if allow_alert:
            details = (f"Potential SYN Flood detected: {current_count} SYN packets "
                       f"from {ip_address} in {window}s (Threshold: {threshold})")
            print(f"DEBUG SYN FLOOD: CREATING ALERT: IP={ip_address}, Details={details}")
            # --- Block on SYN Flood ---
            create_alert(
                alert_type='DDOS',
                src_ip=ip_address,
                dst_ip=dest_ip,     # Pass destination IP
                dst_port=dest_port,   # Pass destination Port
                details=details,
                block_offender=True # Block SYN flood offender
            )
            # ------------------------
            tracking_data['last_alert_time'] = current_time
    # Timestamp is added after return in process_packet

def create_alert(alert_type, src_ip, dst_ip=None, dst_port=None, details="", payload=None, block_offender=False):
    """Creates an Alert record and optionally blocks the source IP, checking in-memory cache first."""

    # --- Check In-Memory Cache FIRST ---
    # Avoid checking for the placeholder 'N/A (Global)' source IP
    if src_ip and src_ip != 'N/A (Global)':
         with config_lock: # Access cache safely
             # Make local copy for check to minimize lock time? Optional.
             # current_blocked_cache = blocked_ips_cache.copy()
             # is_already_blocked = src_ip in current_blocked_cache
             is_already_blocked = src_ip in blocked_ips_cache # Direct check is usually fine
         if is_already_blocked:
             # IP is already known to be blocked according to our memory cache.
             # Suppress creating a new alert and attempting to re-block.
             print(f"[Info] Alert condition met for already blocked IP {src_ip} (in memory cache). Alert/Block suppressed.")
             # logger.info(f"Alert condition met for already blocked IP {src_ip} (in memory cache). Alert/Block suppressed.")
             return # Don't proceed further
    # --- End Cache Check ---

    # Proceed with creating alert since IP is not in memory cache (or is N/A)
    print(f"[ALERT] Create: Type={alert_type}, Src={src_ip}, Block={block_offender}")
    # logger.info(f"Create Alert: Type={alert_type}, Src={src_ip}, Block={block_offender}")
    alert_saved = False
    alert_obj = None # To hold the saved alert instance
    try:
        # Save alert to DB
        alert_obj = Alert.objects.create(
            alert_type=alert_type,
            source_ip=src_ip,
            destination_ip=dst_ip,
            destination_port=dst_port,
            details=details,
            http_payload=payload[:MAX_PAYLOAD_SNIPPET] if payload else None
        )
        print(f"[ALERT] Success: Alert {alert_obj.id} for {src_ip} saved.")
        # logger.info(f"Success: Alert {alert_obj.id} for {src_ip} saved.")
        alert_saved = True
    except Exception as e:
        print(f"[Error] Failed to save alert to database for {src_ip}: {e}")
        # logger.error(f"Failed to save alert to database for {src_ip}: {e}", exc_info=True)
        # Do not proceed to block if alert couldn't be saved
        return

    # --- Trigger Blocking Logic ---
    # Only block if requested, alert was saved successfully, and IP is valid
    if alert_saved and block_offender and src_ip and src_ip != 'N/A (Global)':
        # Note: We already checked the memory cache at the start. No need to re-check DB/cache here.
        print(f"BLOCKING: Attempting firewall block for IP {src_ip} (Alert ID: {alert_obj.id})...")
        # logger.info(f"Attempting firewall block for IP {src_ip} (Alert ID: {alert_obj.id})...")
        success, err_msg = block_ip_firewall(src_ip) # Call firewall util

        if success:
            print(f"BLOCKING: Firewall block successful for {src_ip}.")
            # logger.info(f"Firewall block successful for {src_ip}.")
            try:
                # Add to BlockedIP model
                BlockedIP.objects.create(ip_address=src_ip, reason=f"{alert_type}: {details[:100]}") # Link to Alert ID if needed?
                print(f"BLOCKING: Added {src_ip} to BlockedIP model.")
                # logger.info(f"Added {src_ip} to BlockedIP model.")
                # --- Add to in-memory cache immediately AFTER successful DB add ---
                with config_lock:
                    blocked_ips_cache.add(src_ip)
                    print(f"BLOCKING: Added {src_ip} to in-memory block cache.")
                    # logger.info(f"Added {src_ip} to in-memory block cache.")
                # -------------------------------------------------------------------
            except Exception as db_e:
                 # Firewall rule WAS added, but DB failed. Cache not updated.
                 # Next config reload will fix the cache based on DB state.
                 print(f"BLOCKING: Error adding {src_ip} to BlockedIP model (will sync on next reload): {db_e}")
                 # logger.error(f"Error adding {src_ip} to BlockedIP model (will sync on next reload): {db_e}", exc_info=True)
        else:
            # Firewall command failed, don't add to DB or cache
            print(f"BLOCKING: Firewall block FAILED for {src_ip}. Error: {err_msg}")
            # logger.error(f"Firewall block FAILED for {src_ip}. Error: {err_msg}")
    # --- End Blocking Logic ---


# --- process_packet function ---
def process_packet(packet):
    global packet_counter
    try:
        with packet_counter_lock: packet_counter += 1
        if IP in packet:
            protocol_name = "Other"; src_ip = packet[IP].src; dst_ip = packet[IP].dst; dst_port = None; packet_size = len(packet); is_syn_only = False
            packet_time = datetime.datetime.now(timezone.utc) # Get timestamp early

            if TCP in packet: protocol_name = "TCP"; dst_port = packet[TCP].dport; 
            if packet[TCP].flags == 0x02: is_syn_only = True
            elif UDP in packet: protocol_name = "UDP"; dst_port = packet[UDP].dport
            elif ICMP in packet: protocol_name = "ICMP"

            if dst_ip != SERVER_IP and src_ip != SERVER_IP: return

        packet_details_ws = {
                'timestamp': packet_time.strftime("%Y-%m-%d %H:%M:%S"), # Format for WS
                'source_ip': src_ip, 'dest_ip': dst_ip, 'dest_port': dst_port,
                'protocol': protocol_name, 'size': packet_size
            }
        send_packet_update(packet_details_ws) # Send to WebSocket


            # --- Run Detection Logic only for INCOMING packets ---
        if dst_ip == SERVER_IP:
                # --- Add timestamp to global rate deque FIRST ---
                current_proc_time = time.time() # Use consistent time for this packet
                global_packet_timestamps.append(current_proc_time)
                # --- Check global rate ---
                detect_global_rate() # This uses the global deque

        try:
                PacketLog.objects.create(
                    timestamp=packet_time, # Use the actual datetime object
                    protocol=protocol_name[:10], # Ensure protocol fits max_length
                    source_ip=src_ip,
                    destination_ip=dst_ip,
                    destination_port=dst_port,
                    size_bytes=packet_size
                    # Add other fields like source_port, tcp_flags if you parse them
                )
                # print(f"DEBUG PACKET LOG: Saved packet summary for {src_ip}") # Very verbose! Keep commented.
        except Exception as db_e:
                 print(f"[Error] Failed to save packet log to database: {db_e}")
            # --- *** END NEW *** ---
                # --- If TCP SYN packet, check SYN flood THEN add timestamp ---
        if is_syn_only:
                    print(f"DEBUG SYN: Detected SYN packet from {src_ip} to {dst_ip}:{dst_port}") # Debug
                    detect_syn_flood(src_ip, dst_ip, dst_port) # Check *before* adding timestamp
                    # Add SYN timestamp *after* check
                    syn_key = (src_ip, 'syn')
                    ip_requests.setdefault(syn_key, {'timestamps': deque(), 'last_alert_time': 0.0})['timestamps'].append(current_proc_time)

                # --- Check general Per-IP/Port rate limit ---
        if protocol_name in ["TCP", "UDP"]:
                     # Pass the timestamp for consistency? Optional, detect_ddos_rate_limit uses time.time() currently
                     detect_ddos_rate_limit(src_ip, dst_port) # Renamed function call

                # --- Check SQLi / Payload rules ---
        if protocol_name == "TCP" and dst_port in [80, 5000, 8000, 8001, 8002]:
                    if Raw in packet:
                         payload = packet[Raw].load
                         payload_str = payload.decode('utf-8', errors='ignore')
                         if "HTTP/" in payload_str.split('\n', 1)[0]:
                             if detect_sql_injection(payload_str, src_ip, dst_ip, dst_port): return # Stop if SQLi found
                         # Add signature matching check here if implemented
    except Exception as e:
        # print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] [Error] Packet processing error: {e}") # Keep commented unless debugging hard crashes
        pass

# --- Main Execution ---
if __name__ == "__main__":
    # Check for root privileges
    if os.geteuid() != 0:
        print("[-] Error: This script requires root/administrator privileges for packet sniffing.")
        sys.exit(1)

    print(f"--- Initializing Django IDS Sniffer ---")

    # --- Initial Config Load ---
    print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Performing initial configuration load...")
    load_config_from_db() # Load config once at start

    # --- Start Config Monitor Thread ---
    print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Starting configuration monitor thread...")
    # Ensure settings.CONFIG_SIGNAL_FILE is defined before starting thread
    if hasattr(settings, 'CONFIG_SIGNAL_FILE') and settings.CONFIG_SIGNAL_FILE:
        monitor_thread = threading.Thread(target=monitor_config_changes, daemon=True)
        monitor_thread.start()
    else:
        print("[Warning] CONFIG_SIGNAL_FILE not set in Django settings. Config monitor thread not started.")
        monitor_thread = None # Ensure variable exists

# --- Start Persistent Stats Update Thread ---
    print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Starting persistent stats update thread (Interval: {STATS_UPDATE_INTERVAL}s)...")
    update_persistent_stats() # Start the first update & scheduling
    # ----------------------------------------

    # Set up BPF filter
    bpf_filter = f"host {SERVER_IP} and (tcp or udp or icmp)"
    print(f"--- Starting Real-Time Sniffing on interface {NETWORK_INTERFACE} ---")
    print(f"--- Monitoring traffic involving Host IP: {SERVER_IP} ---")
    print(f"--- Using BPF filter: \"{bpf_filter}\" ---")
    print("--- Press Ctrl+C to stop ---")

    try:
        # Keep sniffing indefinitely, monitor thread runs in background
        sniff(iface=NETWORK_INTERFACE, prn=process_packet, filter=bpf_filter, store=0)
    except KeyboardInterrupt: # Handle Ctrl+C more explicitly
         print("\nCtrl+C received.")
    except OSError as e:
         if "No such device" in str(e): print(f"[-] Error: Network interface '{NETWORK_INTERFACE}' not found.")
         else: print(f"[-] An OS error occurred during sniffing: {e}")
    except Exception as e:
        print(f"\n[-] An unexpected error occurred: {e}")
    finally:
        print("\n--- Stopping Sniffer ---")
        # --- Signal monitor thread to stop ---
        print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Signaling monitor thread to stop...")
        _sniffer_stop_event.set() # Set the event to break the monitor loop
        if monitor_thread and monitor_thread.is_alive():
            monitor_thread.join(timeout=2.0) # Wait briefly for thread to exit
            # Cancel stats timer
        if stats_update_timer and stats_update_timer.is_alive():
            stats_update_timer.cancel()
            print("[Stats] Stats update timer cancelled.")
        # ---------------------------------------------------
        print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Sniffer stopped.")
# --- End Main Execution ---