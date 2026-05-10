#!/usr/bin/env python3
# =============================================================================
# isolate_beachhead.py
# Wazuh Active Response - Isolate compromised host via iptables
#
# Triggered by: Wazuh rule 100512 (LSASS credential dump detected)
#
# What it does:
#   1. Preserves Wazuh log shipping (port 1514 ACCEPT rules inserted first)
#   2. Drops all other inbound/outbound traffic for the compromised host
#
# Deploy to: /var/ossec/active-response/bin/isolate_beachhead.py
# Permissions: chmod 750, chown root:wazuh
#
# NOTE: Update MANAGER_IP and WAZUH_PORT to match your environment before deploying.
# =============================================================================

import sys
import json
import datetime
import subprocess

LOG_FILE      = "/var/ossec/logs/active-responses.log"
EVIDENCE_FILE = "/var/ossec/logs/isolated_hosts.txt"

# Update these values to match your Wazuh manager IP and agent communication port
MANAGER_IP = "10.0.10.150"   # <-- Change to your Wazuh manager IP
WAZUH_PORT = "1514"

def log(msg):
    ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(LOG_FILE, "a") as f:
        f.write(f"[{ts}] [isolate_beachhead] {msg}\n")

def run(cmd):
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=5)
        return result.returncode, result.stdout.strip(), result.stderr.strip()
    except subprocess.TimeoutExpired:
        return 1, "", "Timeout expired"

def main():
    input_str = sys.stdin.readline()
    if not input_str:
        sys.exit(0)

    try:
        data = json.loads(input_str)
        # Unwrap Wazuh 4.x JSON envelope
        alert = data.get("parameters", {}).get("alert", data)
    except Exception:
        sys.exit(1)

    rule_id    = alert.get("rule", {}).get("id", "unknown")
    agent_name = alert.get("agent", {}).get("name", "unknown")
    host_ip    = alert.get("agent", {}).get("ip")

    if not host_ip or host_ip == MANAGER_IP:
        log(f"[ABORT] Invalid host IP or matches Manager: {host_ip}")
        sys.exit(1)

    log(f"ISOLATING HOST: {host_ip} (Rule: {rule_id})")

    # Rule ordering is critical:
    # ACCEPT rules for Wazuh port 1514 must be inserted at positions 1 and 2
    # BEFORE the DROP rules are appended. iptables evaluates top-to-bottom
    # and stops at first match - this ensures log shipping survives isolation.
    commands = [
        f"iptables -I FORWARD 1 -s {host_ip} -d {MANAGER_IP} -p tcp --dport {WAZUH_PORT} -j ACCEPT",
        f"iptables -I FORWARD 2 -d {host_ip} -s {MANAGER_IP} -p tcp --sport {WAZUH_PORT} -j ACCEPT",
        f"iptables -A FORWARD -s {host_ip} -j DROP",
        f"iptables -A FORWARD -d {host_ip} -j DROP"
    ]

    for cmd in commands:
        rc, out, err = run(cmd)
        if rc != 0:
            log(f"ERROR executing: {cmd} - {err}")

    ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(EVIDENCE_FILE, "a") as f:
        f.write(f"{ts} | ISOLATED | {host_ip} | Rule: {rule_id} | Agent: {agent_name}\n")

    log(f"COMPLETE: {host_ip} isolated from network.")

if __name__ == "__main__":
    main()