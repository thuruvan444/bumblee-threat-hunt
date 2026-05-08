# BumbleBee Loader — Intrusion Detection, Threat Hunting & Automated Response

> **Defensive security research project.**  
> All attack simulation was conducted exclusively in an isolated home lab environment with no connection to external networks or real systems. No actual malware was used. This repo is intended for educational and defensive research purposes only.

---

## Overview

This project simulates the complete 11-day **BumbleBee loader intrusion** documented in the [DFIR Report (August 2022)](https://thedfirreport.com/2022/08/08/bumblebee-roasts-its-way-to-domain-admin/) inside a purpose-built Active Directory home lab, then builds a full detection and automated response pipeline around it.

The goal is to answer a real SOC question: **can you detect every stage of a modern Initial Access Broker campaign — and automatically contain it — before the attacker reaches Domain Admin?**

**Answer: yes.** Every kill chain phase was detected. Two automated containment responses fired without human intervention.

---

## What's In This Repo

| Folder | Contents |
|--------|----------|
| [`detection-rules/`](./detection-rules/) | 15 custom Wazuh rules across 4 kill chain clusters |
| [`active-response/`](./active-response/) | Python scripts for automated attacker blocking and host isolation |
| [`attack-simulation/`](./attack-simulation/) | Python orchestrator + Ansible playbooks replicating the full kill chain |
| [`docs/`](./docs/) | Lab architecture, kill chain timeline, threat hunting methodology, detection gaps |
| [`screenshots/`](./screenshots/) | Evidence: Wazuh alerts, Wireshark captures, active response logs |

---

## Lab Architecture — CapsuleCorp Active Directory

A six-VM home lab replicating a realistic corporate environment on the `10.0.10.128/25` subnet.

| Host | IP | OS | Role |
|------|----|----|------|
| Goku (DC) | 10.0.10.200 | Windows Server 2019 | Domain Controller — `capsulecorp.local` |
| BEACHHEAD-PC | 10.0.10.210 | Windows 10 | Initial compromise target |
| YAMCHA-PC | 10.0.10.211 | Windows 10 | Lateral movement target |
| IPSWAF | 10.0.10.129 / 10.0.10.1 | Ubuntu 24 LTS | Router / Wazuh Agent / Active Response host |
| gmt (Wazuh) | 10.0.10.150 | Ubuntu 24 LTS | Wazuh Manager v4.14.2 / OpenSearch SIEM |
| Kali | 10.0.10.60 | Kali Linux | Attacker — Sliver C2 / Ansible orchestrator |

---

## Detection Stack

| Tool | Purpose |
|------|---------|
| **Wazuh v4.14.2** | SIEM / HIDS — alert collection, custom rule engine, active response orchestration |
| **Sysmon (SwiftOnSecurity config)** | Host telemetry — process creation (E1), network connections (E3), process injection (E8), script blocks (E4104) |
| **Suricata** | Network IDS on IPSWAF — community rules + custom C2 beacon detection |
| **Zeek** | Network analysis — conn.log, dns.log, ssl.log, krb5.log |
| **OpenSearch** | Dashboard and visualization layer for Wazuh alerts |

---

## Incident Background

BumbleBee is a sophisticated malware loader used by Initial Access Brokers as a pre-ransomware foothold tool. The DFIR Report case covers an 11-day intrusion where BumbleBee was delivered via phishing (ISO/LNK), established C2, performed credential theft via Kerberoasting and LSASS dumping, and achieved Domain Admin via PsExec with cracked credentials.

**Key TTPs:** `T1218.011` `T1071.001` `T1003.001` `T1558.003` `T1021.002` `T1543.003` `T1219` `T1055` `T1087.002`

### Kill Chain Timeline

| Day | Phase | Actions |
|-----|-------|---------|
| Day 1 | Initial Access | ISO/LNK → rundll32 IternalJob → Sliver C2 → explorer.exe injection → AnyDesk install → AdFind recon |
| Day 2 | Reconnaissance | VulnRecon.ps1 — installed software, patch level, network config |
| Day 4 | Credential Access | Procdump64 over SMB → LSASS memory dump → tool deletion |
| Day 7 | Persistence Check | AnyDesk re-access → VulnRecon + Seatbelt → persistence verification |
| Day 11 | Final Objectives | Invoke-Kerberoast → hash cracked → comsvcs MiniDump on DC → PsExec → Domain Admin |

---

## Attack Simulation

Real malware was replaced with legitimate red team tools that produce **identical Windows event artifacts**.

| Real Component | Simulation Substitute | Artifacts Produced |
|---------------|----------------------|-------------------|
| BumbleBee DLL loader | `namr.dll` with IternalJob export | Sysmon E1 — rundll32 + IternalJob |
| Cobalt Strike C2 | Sliver C2 (mTLS on port 443) | Sysmon E3 — outbound beacon |
| Real comsvcs dump | comsvcs.dll MiniDump (native) | PowerShell E4104 — script block |
| Invoke-Kerberoast | keroast.ps1 (native PS) | PowerShell E4104 — decoded Kerberoast |
| Real AdFind | adfind_sub.ps1 (native AD cmdlets) | PowerShell E4104 — Get-ADUser/Computer |
| Real PsExec | impacket-psexec | Event 7045 (random service) + Event 4624 |

The simulation is **fully automated** — zero manual steps required:

```bash
# Run the complete 11-day kill chain
python3 run_attack.py --fast

# Target a specific day for detection rule testing
python3 run_attack.py --day 1 --fast
python3 run_attack.py --day 11 --fast
```

See [`attack-simulation/`](./attack-simulation/) for the orchestrator and playbooks.

---

## Detection Philosophy — Pyramid of Pain

All 15 custom Wazuh rules target **vulnerability-level invariants** — structural properties of each TTP that the attacker cannot change without breaking their own attack chain.

This means detections remain effective even when attackers rotate IPs, change filenames, or obfuscate scripts. Surface indicators (hashes, IPs) sit at the bottom of the Pyramid of Pain. Behavioral TTPs sit at the top. Every rule in this project targets the top.

---

## Custom Wazuh Detection Rules

### Cluster 1 — Initial Access & C2 (`cluster1_initial_access.xml`)

| Rule ID | Level | Description | Event Source |
|---------|-------|-------------|--------------|
| 100500 | 14 | BumbleBee DLL loader via rundll32 — IternalJob export (T1218.011) | Sysmon E1 |
| 100502 | 12 | EXE from ProgramData by suspicious parent — C2 beacon (T1059) | Sysmon E1 |
| 100503 | 13 | IEX DownloadString C2 staging — wab.exe download (T1105) | PS E4104 |
| 100504 | 14 | Outbound connection from ProgramData EXE after IternalJob — **triggers block_attacker.py** | Sysmon E3 |

**Invariant for 100500:** The `IternalJob` export name is hardcoded in every BumbleBee DLL loader. The attacker cannot rename it without breaking the LNK shortcut that calls it. Zero false positives in any legitimate environment.

### Cluster 2 — Credential Access (`cluster2_credential_access.xml`)

| Rule ID | Level | Description | Event Source |
|---------|-------|-------------|--------------|
| 100510 | 15 | Kerberoasting in PowerShell script block — TGS ticket harvesting (T1558.003) | PS E4104 |
| 100512 | 15 | LSASS dump via comsvcs.dll MiniDump — **triggers isolate_beachhead.py** (T1003.001) | PS E4104 |
| 100514 | 15 | Kerberoasting + LSASS dump correlation — full credential access phase confirmed | Correlation |

**Invariant for 100510/100512:** PowerShell Event 4104 logs *decoded* script block content before execution. Even obfuscated scripts are decoded internally by Windows and logged. The attacker cannot evade E4104 without disabling script block logging entirely — which itself generates a detectable audit event.

### Cluster 3 — Lateral Movement & Persistence (`cluster3_lateral_movement.xml`)

| Rule ID | Level | Description | Event Source |
|---------|-------|-------------|--------------|
| 100520 | 13 | ANONYMOUS LOGON via NTLM to DC from internal host — PsExec precursor (T1021.002) | Security E4624 |
| 100521 | 13 | Short random service name installed as LocalSystem — PsExec artifact (T1543.003) | System E7045 |
| 100522 | 14 | AnyDesk persistence service — auto-start LocalSystem (T1219) | System E7045 |
| 100523 | 15 | Service account NTLMv2 to DC — cracked credential in use (T1078.002) | Security E4624 |

**Invariant for 100520/100521:** PsExec has a structural two-event fingerprint — ANONYMOUS LOGON (E4624) followed by random-named service creation (E7045). Both events are structurally required. The attacker cannot skip either without breaking PsExec.

### Cluster 4 — Discovery (`cluster4_discovery.xml`)

| Rule ID | Level | Description | Event Source |
|---------|-------|-------------|--------------|
| 100530 | 13 | AD enumeration from ProgramData — Get-ADUser/Computer or LDAP objectcategory (T1087.002) | PS E4104 |

**Invariant for 100530:** Legitimate administrators never run AD queries from `C:\ProgramData\`. Location + AD cmdlet combination = zero false positives.

---

## Active Response Architecture

Two Python scripts deploy automated containment at the network layer via iptables, triggered automatically by Wazuh when specific rules fire.

### Response 1 — `block_attacker.py` (Trigger: Rule 100504)

Fires when C2 beacon is confirmed. Dynamically extracts the attacker IP from the alert JSON and applies DROP rules at IPSWAF:

```
iptables -I FORWARD 1 -s <attacker_ip> -j DROP
iptables -I INPUT  1 -s <attacker_ip> -j DROP
```

No IPs are hardcoded. A safety check prevents accidental blocking of the Wazuh manager.

### Response 2 — `isolate_beachhead.py` (Trigger: Rule 100512)

Fires when LSASS credential dump is confirmed. Isolates the compromised host while preserving forensic log shipping:

```
# Rule ordering is critical — ACCEPT before DROP
iptables -I FORWARD 1 -s <host> -d <wazuh_mgr> -p tcp --dport 1514 -j ACCEPT
iptables -I FORWARD 2 -s <wazuh_mgr> -d <host> -p tcp --sport 1514 -j ACCEPT
iptables -A FORWARD -s <host> -j DROP
iptables -A FORWARD -d <host> -j DROP
```

The ACCEPT rules for Wazuh port 1514 are inserted at the top of the chain before DROP rules. This guarantees log shipping continues during isolation — the attacker is cut off while full forensic visibility is maintained.

See [`active-response/`](./active-response/) for the full scripts.

---

## Results

### Detection Coverage

| Rule ID | Level | Phase | Agent | Status |
|---------|-------|-------|-------|--------|
| 100500 | 14 | Initial Access | Beachhead | ✅ FIRING |
| 100502 | 12 | Initial Access | YAMCHA | ✅ FIRING |
| 100503 | 13 | C2 Staging | Beachhead | ✅ FIRING |
| 100504 | 14 | C2 Beacon | Beachhead | ✅ FIRING |
| 100510 | 15 | Credential Access | Beachhead | ✅ FIRING |
| 100512 | 15 | Credential Access | Beachhead | ✅ FIRING |
| 100520 | 13 | Lateral Movement | Goku (DC) | ✅ FIRING |
| 100521 | 13 | Lateral Movement | Goku (DC) | ✅ FIRING |
| 100522 | 14 | Persistence | YAMCHA | ✅ FIRING |
| 100523 | 15 | Lateral Movement | Goku (DC) | ✅ FIRING |
| 100530 | 13 | Discovery | Beachhead | ✅ FIRING |

### Active Response

| Script | Trigger | Result |
|--------|---------|--------|
| `block_attacker.py` | Rule 100504 | Attacker IP blocked at FORWARD + INPUT chains within seconds of C2 detection |
| `isolate_beachhead.py` | Rule 100512 | Compromised host isolated — all traffic dropped, Wazuh port 1514 preserved |

---

## Known Detection Gaps

Honest documentation of what didn't work and why.

**Suricata dsize mismatch — C2 beacon size detection failed.**  
Custom Suricata rules targeting 88-byte Sliver beacons used `dsize:88`. Wireshark reports 88-byte frame lengths, but Suricata's `dsize` measures reassembled TCP payload, not the Ethernet frame. Actual TCP payloads were 1235–1480 bytes due to Sliver batching multiple TLS records. Host-based detection via Wazuh rule 100504 (Sysmon E3) provided the compensating control.

**Sysmon Event 23 (FileDelete) not captured.**  
Defense evasion (tool deletion after LSASS dump) was simulated but not detected. Event 23 is disabled by default in the SwiftOnSecurity config to reduce noise. Acceptable trade-off — the LSASS dump itself was detected by rule 100512.

See [`docs/detection-gaps.md`](./docs/detection-gaps.md) for full analysis.

---

## Key Takeaways

- **PowerShell Event 4104** (script block logging) is the most reliable source for credential access detection — it defeats obfuscation by design, since Windows decodes scripts before execution
- **iptables rule ordering** is critical for preserve-then-block isolation — ACCEPT rules must be inserted before DROP rules
- **TLSv1.3 encrypted C2** cannot be reliably detected by packet size heuristics at the network layer — compensating with host-based Sysmon telemetry is the practical answer
- **Honest gap documentation** is more valuable than overclaiming coverage — knowing where your detection fails is essential for real SOC work

---

## References

- [The DFIR Report — BumbleBee Roasts Its Way to Domain Admin (Aug 2022)](https://thedfirreport.com/2022/08/08/bumblebee-roasts-its-way-to-domain-admin/)
- [MITRE ATT&CK Enterprise Matrix](https://attack.mitre.org/)
- [Wazuh v4.x Documentation](https://documentation.wazuh.com/)
- [SwiftOnSecurity Sysmon Config](https://github.com/SwiftOnSecurity/sysmon-config)
- [Sliver C2 Framework — BishopFox](https://github.com/BishopFox/sliver)
- [Suricata Documentation](https://docs.suricata.io/)
- [Pyramid of Pain — David Bianco](https://detect-respond.blogspot.com/2013/03/the-pyramid-of-pain.html)

---

> **Disclaimer:** This project was conducted entirely within an isolated home lab environment. All tools were used for defensive research and educational purposes. No external systems were targeted. Offensive simulation artifacts are published solely to demonstrate detection capability.
