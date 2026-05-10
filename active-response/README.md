# Active Response Scripts

Two Python scripts that deploy automated containment at the network layer via iptables. Both are triggered automatically by Wazuh when specific detection rules fire - no human intervention required.

## Architecture

```
Wazuh Rule Fires
      |
      v
Wazuh Manager dispatches active response command
      |
      v
IPSWAF (Ubuntu router/gateway) receives command
      |
      v
Python script reads alert JSON from stdin
      |
      v
iptables rules applied at network layer
      |
      v
Evidence logged to /var/ossec/logs/
```

The active response host (IPSWAF) sits between the compromised endpoint and the rest of the network, making it the ideal enforcement point for network-layer containment.

## Scripts

### `block_attacker.py` - Triggered by Rule 100504 (C2 beacon confirmed)

Dynamically extracts the attacker IP from the alert JSON (`data.win.eventdata.destinationIp` from Sysmon Event 3) and applies DROP rules at the gateway:

```
iptables -I FORWARD 1 -s <attacker_ip> -j DROP
iptables -I INPUT  1 -s <attacker_ip> -j DROP
```

- FORWARD chain: prevents attacker from reaching any internal host through the router
- INPUT chain: prevents attacker from reaching the router itself
- No IPs are hardcoded - extraction is fully dynamic from alert JSON
- Safety check prevents accidental blocking of the Wazuh manager IP

### `isolate_beachhead.py` - Triggered by Rule 100512 (LSASS credential dump confirmed)

Isolates the compromised host while preserving forensic log shipping. The critical design decision is rule ordering:

```
# ACCEPT rules inserted first (positions 1 and 2)
iptables -I FORWARD 1 -s <host_ip> -d <wazuh_mgr> -p tcp --dport 1514 -j ACCEPT
iptables -I FORWARD 2 -s <wazuh_mgr> -d <host_ip> -p tcp --sport 1514 -j ACCEPT

# DROP rules appended after
iptables -A FORWARD -s <host_ip> -j DROP
iptables -A FORWARD -d <host_ip> -j DROP
```

iptables evaluates rules top-to-bottom and stops at the first match. Inserting ACCEPT rules for Wazuh port 1514 before the DROP rules guarantees that log shipping continues during isolation - the attacker is cut off while full forensic visibility is maintained.

**Before deploying:** Update `MANAGER_IP` in `isolate_beachhead.py` to match your Wazuh manager's IP address.

## Deployment

```bash
# Copy scripts to Wazuh active response directory
sudo cp block_attacker.py isolate_beachhead.py /var/ossec/active-response/bin/

# Set correct permissions (required by Wazuh)
sudo chmod 750 /var/ossec/active-response/bin/block_attacker.py
sudo chmod 750 /var/ossec/active-response/bin/isolate_beachhead.py
sudo chown root:wazuh /var/ossec/active-response/bin/block_attacker.py
sudo chown root:wazuh /var/ossec/active-response/bin/isolate_beachhead.py
```

Then configure the triggers in `/var/ossec/etc/ossec.conf` on the Wazuh manager:

```xml
<active-response>
  <disabled>no</disabled>
  <command>block_attacker</command>
  <location>defined-agent</location>
  <agent_id>008</agent_id>
  <rules_id>100504</rules_id>
  <timeout>no</timeout>
</active-response>

<active-response>
  <disabled>no</disabled>
  <command>isolate_beachhead</command>
  <location>defined-agent</location>
  <agent_id>008</agent_id>
  <rules_id>100512</rules_id>
  <timeout>no</timeout>
</active-response>
```

> **Note:** The `<disabled>no</disabled>` tag is required in Wazuh 4.x to explicitly enable active response dispatch. Without it, Wazuh silently ignores the configuration.

## Evidence

Both scripts write to:
- `/var/ossec/logs/active-responses.log` - timestamped action log
- `/var/ossec/logs/blocked_attackers.txt` or `isolated_hosts.txt` - evidence files for IR documentation