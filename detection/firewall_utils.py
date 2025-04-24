# detection/firewall_utils.py
import subprocess
import logging
import shlex # For safe command splitting

logger = logging.getLogger(__name__)

# --- Choose your firewall type ---
FIREWALL_TYPE = 'iptables' # Options: 'iptables', 'ufw', 'firewalld' (adapt commands!)
# ---------------------------------

# --- Define Commands (Adapt these carefully!) ---
# These assume you want to block *incoming* traffic from the source IP

# IPTABLES Examples (adjust chain names like INPUT/FORWARD if needed)
IPTABLES_BLOCK_CMD = "sudo /sbin/iptables -I INPUT 1 -s {ip_address} -j DROP"
IPTABLES_UNBLOCK_CMD = "sudo /sbin/iptables -D INPUT -s {ip_address} -j DROP"
IPTABLES_CHECK_CMD = "sudo /sbin/iptables -C INPUT -s {ip_address} -j DROP" # -C checks rule existence

# UFW Examples
UFW_BLOCK_CMD = "sudo /usr/sbin/ufw insert 1 deny from {ip_address} to any" # Insert at top
UFW_UNBLOCK_CMD = "sudo /usr/sbin/ufw delete deny from {ip_address} to any"
UFW_CHECK_CMD = None # ufw status numbered doesn't easily check a specific rule like iptables -C

# FIREWALLD Examples (might need specific zone)
# FIREWALLD_BLOCK_CMD = "sudo firewall-cmd --permanent --add-rich-rule='rule family=ipv4 source address={ip_address} reject'" # or drop
# FIREWALLD_UNBLOCK_CMD = "sudo firewall-cmd --permanent --remove-rich-rule='rule family=ipv4 source address={ip_address} reject'"
# FIREWALLD_RELOAD_CMD = "sudo firewall-cmd --reload" # Needed after permanent changes
# FIREWALLD_CHECK_CMD = "sudo firewall-cmd --list-rich-rules" # Need to parse output

# --- Helper Function to Run Commands ---
def _run_firewall_command(command_template, ip_address):
    """Executes a firewall command safely."""
    try:
        # Format command with the specific IP address
        command = command_template.format(ip_address=shlex.quote(ip_address))
        logger.info(f"Executing firewall command: {command}")

        # Split command for subprocess, handle sudo correctly
        # Note: Running sudo without password requires specific sudoers config
        cmd_parts = shlex.split(command)

        # Run the command
        # Consider using check=True to raise error on failure, but check return code instead for block/unblock
        result = subprocess.run(cmd_parts, capture_output=True, text=True, timeout=5)

        logger.info(f"Firewall command result: RC={result.returncode}, stdout={result.stdout.strip()}, stderr={result.stderr.strip()}")

        # Check return code (0 usually means success for add/delete, might differ for check)
        return result.returncode == 0, result.stderr.strip()

    except FileNotFoundError:
        logger.error(f"Error executing firewall command: sudo or firewall binary not found.")
        return False, "Firewall command not found."
    except subprocess.TimeoutExpired:
        logger.error(f"Error executing firewall command: Timeout expired.")
        return False, "Command timed out."
    except Exception as e:
        logger.error(f"Error executing firewall command for IP {ip_address}: {e}")
        return False, str(e)

# --- Public Functions ---

def block_ip_firewall(ip_address):
    """Adds the IP address to the firewall block rules."""
    logger.info(f"Requesting firewall block for IP: {ip_address}")
    cmd = None
    if FIREWALL_TYPE == 'iptables': cmd = IPTABLES_BLOCK_CMD
    elif FIREWALL_TYPE == 'ufw': cmd = UFW_BLOCK_CMD
    # Add firewalld logic here if needed (incl. reload)
    else: return False, f"Unsupported firewall type: {FIREWALL_TYPE}"

    if cmd: return _run_firewall_command(cmd, ip_address)
    return False, "No command defined for firewall type."


def unblock_ip_firewall(ip_address):
    """Removes the IP address from the firewall block rules."""
    logger.info(f"Requesting firewall unblock for IP: {ip_address}")
    cmd = None
    if FIREWALL_TYPE == 'iptables': cmd = IPTABLES_UNBLOCK_CMD
    elif FIREWALL_TYPE == 'ufw': cmd = UFW_UNBLOCK_CMD
    # Add firewalld logic here if needed (incl. reload)
    else: return False, f"Unsupported firewall type: {FIREWALL_TYPE}"

    if cmd: return _run_firewall_command(cmd, ip_address)
    return False, "No command defined for firewall type."

def is_ip_blocked_firewall(ip_address):
     """Checks if an IP block rule exists (currently only for iptables)."""
     logger.info(f"Checking firewall block status for IP: {ip_address}")
     cmd = None
     if FIREWALL_TYPE == 'iptables': cmd = IPTABLES_CHECK_CMD
     # UFW/Firewalld check needs different logic (parsing status output) - return False for now
     elif FIREWALL_TYPE in ['ufw', 'firewalld']:
         logger.warning(f"Firewall rule check not implemented for {FIREWALL_TYPE}. Assuming not blocked.")
         return False # Cannot reliably check with simple command
     else: return False # Unsupported

     if cmd:
         success, _ = _run_firewall_command(cmd, ip_address)
         # For iptables -C, success (RC=0) means the rule *exists* (is blocked)
         return success
     return False
