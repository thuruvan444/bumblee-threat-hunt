# Detection Rules

15 custom Wazuh rules across 4 kill chain clusters, each targeting **vulnerability-level invariants** - structural properties of each TTP that the attacker cannot change without breaking their own attack chain.

## Deployment

Copy all four XML files to `/var/ossec/etc/rules/` on your Wazuh manager, then restart the Wazuh manager service:

```bash
sudo cp cluster*.xml /var/ossec/etc/rules/
sudo systemctl restart wazuh-manager
sudo /var/ossec/bin/wazuh-control restart
```

Verify rules loaded without errors:

```bash
sudo /var/ossec/bin/ossec-logtest
```

## Rule Clusters

### `cluster1_initial_access.xml` - Rules 100500-100504

Covers BumbleBee DLL loader execution, C2 beacon staging, and outbound C2 communication.

Key invariant: The `IternalJob` export name is hardcoded in every BumbleBee DLL. The attacker cannot rename it without breaking the LNK shortcut that calls `rundll32.exe namr.dll,IternalJob`. Rule 100500 has zero false positives in any legitimate environment.

Rule 100504 uses `if_matched_sid:100500` - it only fires when a prior IternalJob event has been seen on the same agent AND a new outbound connection from ProgramData is detected. This chaining eliminates isolated false positives from either condition alone.

### `cluster2_credential_access.xml` - Rules 100510-100514

Covers Kerberoasting (Invoke-Kerberoast) and LSASS credential dumping (comsvcs.dll MiniDump).

Key invariant: PowerShell Event 4104 logs **decoded** script block content before execution. Even heavily obfuscated scripts are decoded internally by Windows before running. The attacker cannot evade Event 4104 without disabling script block logging entirely - which itself generates a detectable audit event.

Rules 100510 and 100512 are tagged `auto_response` - they trigger `isolate_beachhead.py` automatically.

### `cluster3_lateral_movement.xml` - Rules 100520-100523

Covers PsExec lateral movement (ANONYMOUS LOGON + random service name), AnyDesk persistence, and cracked credential use.

Key invariant: PsExec has a structural two-event fingerprint. It must authenticate to SVCCTL using a NULL session (Event 4624 - ANONYMOUS LOGON) before creating its execution service (Event 7045 - random 4-8 character name). Both events are structurally required. The attacker cannot skip either step without breaking PsExec.

Rule 100523 detects cracked credential use by identifying service accounts authenticating via NTLMv2 instead of Kerberos - in a properly configured domain, service accounts authenticate via Kerberos. This mismatch is the detection invariant.

### `cluster4_discovery.xml` - Rule 100530

Covers Active Directory enumeration via AdFind or native AD cmdlets.

Key invariant: Legitimate administrators never run AD queries from `C:\ProgramData\`. The combination of AD enumeration cmdlets (`Get-ADUser`, `Get-ADComputer`, `objectcategory=` LDAP syntax) executed from the attacker's staging directory produces zero false positives.

## Prerequisites

- Wazuh v4.x (rules use Wazuh 4.x JSON field syntax)
- Sysmon deployed on Windows endpoints with SwiftOnSecurity config (for Event 1, 3, 8)
- PowerShell Script Block Logging enabled (for Event 4104)
- Windows Security Auditing enabled (for Event 4624, 7045)