#!/usr/bin/env python3
# =============================================================================
# block_attacker.py
# Wazuh Active Response - Block attacker IP via iptables
#
# Triggered by: Wazuh rule 100504 (C2 beacon confirmed after IternalJob loader)
#
# What it does:
#   Extracts the attacker's destination IP from the Sysmon Event 3 alert JSON
#   and applies DROP rules on both INPUT and FORWARD chains at the gateway.
#
# Deploy to: /var/ossec/active-response/bin/block_attacker.py
# Permissions: chmod 750, chown root:wazuh
# =============================================================================

import sys
import json
import subprocess
from datetime import datetime

LOG = "/var/ossec/logs/active-responses.log"

def log(msg):
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(LOG, "a") as f:
        f.write(f"[{ts}] [block_attacker] {msg}\n")

def main():
    input_str = sys.stdin.readline()

    try:
        data = json.loads(input_str)
        alert = data.get("parameters", {}).get("alert", {})

        # Extract destination IP from Sysmon Event 3 (network connection)
        # Field path: data -> win -> eventdata -> destinationIp
        attacker_ip = (
            alert.get("data", {})
                 .get("win", {})
                 .get("eventdata", {})
                 .get("destinationIp")
        )

        if not attacker_ip:
            log("[ERROR] Could not extract destinationIp from Sysmon alert")
            sys.exit(1)

        # Block on INPUT chain (attacker -> router)
        subprocess.run(["iptables", "-I", "INPUT",   "-s", attacker_ip, "-j", "DROP"])
        # Block on FORWARD chain (attacker -> any internal host)
        subprocess.run(["iptables", "-I", "FORWARD", "-s", attacker_ip, "-j", "DROP"])

        rule_id = alert.get("rule", {}).get("id", "unknown")
        log(f"[SUCCESS] {attacker_ip} blocked (Rule: {rule_id})")

    except Exception as e:
        log(f"[ERROR] {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()