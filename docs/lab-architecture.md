# Lab Architecture

## CapsuleCorp Active Directory Lab

A six-VM home lab replicating a realistic corporate environment, themed after Dragon Ball Z.
All VMs run on the `10.0.10.128/25` subnet with no external network access during simulation.

```
                          10.0.10.128/25
                    ┌─────────────────────────┐
                    │                         │
     Kali (attacker)│   IPSWAF (router/SIEM)  │  Goku/DC01
     10.0.10.60     │   10.0.10.1             │  10.0.10.200
                    │   10.0.10.129           │
                    │         |               │
                    │   gmt (Wazuh manager)   │
                    │   10.0.10.150           │
                    │                         │
                    │   BEACHHEAD-PC          │  YAMCHA-PC
                    │   10.0.10.210           │  10.0.10.211
                    └─────────────────────────┘
```

## Host Configuration

| Host | IP | OS | Role |
|------|----|----|------|
| Goku (DC) | 10.0.10.200 | Windows Server 2019 | Domain Controller - `capsulecorp.local` |
| BEACHHEAD-PC | 10.0.10.210 | Windows 10 | Initial compromise target |
| YAMCHA-PC | 10.0.10.211 | Windows 10 | Lateral movement target |
| IPSWAF | 10.0.10.1 / 10.0.10.129 | Ubuntu 24 LTS | Router / Wazuh Agent 008 / Active Response host |
| gmt (Wazuh) | 10.0.10.150 | Ubuntu 24 LTS | Wazuh Manager v4.14.2 / OpenSearch SIEM |
| Kali | 10.0.10.60 | Kali Linux | Attacker - Sliver C2 / Ansible orchestrator |

## Detection Stack

| Tool | Version | Purpose |
|------|---------|---------|
| Wazuh | 4.14.2 | SIEM / HIDS - alert collection, custom rule engine, active response |
| Sysmon | v15 (SwiftOnSecurity config) | Host telemetry - E1, E3, E8, E10, E11, E23, E4104 |
| Suricata | Community rules | Network IDS on IPSWAF |
| Zeek | Latest | Network protocol analysis - conn.log, dns.log, ssl.log, krb5.log |
| OpenSearch | Latest | Dashboard and visualization for Wazuh alerts |
| Sliver C2 | Latest | Open-source C2 (Cobalt Strike substitute) - mTLS on port 443 |
| Ansible | Latest | Attack automation - playbook-based payload delivery |

## AD Configuration

Configured by `lab_prep.yml`:

- Domain: `capsulecorp.local`
- Domain Admin account: `Administrator`
- Kerberoastable service account: `svc_backup` (Domain Admin group, SPN registered)
- Victim workstation user: `yamcha` (local admin on BEACHHEAD-PC and YAMCHA-PC)
- Audit policies enabled: Kerberos (4769), Logon (4624), Service install (7045), Process creation (4688)
- PowerShell Script Block Logging enabled on all hosts (Event 4104)
- Sysmon deployed with SwiftOnSecurity config on all Windows hosts

## Network Layout

IPSWAF acts as both the network gateway and the active response enforcement point.
All traffic between the attacker (Kali) and the Windows hosts passes through IPSWAF,
making it the ideal location to apply iptables-based containment rules when active response fires.

Wazuh agent 008 runs on IPSWAF. When `block_attacker.py` or `isolate_beachhead.py` execute,
they apply iptables rules locally on the machine that sits between the attacker and all victims.