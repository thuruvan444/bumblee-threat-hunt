# Screenshots

Key evidence from the full simulation run.

## Suggested screenshots to add from your lab

| Filename | What to capture |
|----------|----------------|
| `01_wazuh_full_killchain.png` | Wazuh OpenSearch dashboard - all rules firing across beachhead, Goku, YAMCHA |
| `02_sysmon_e1_ternaljob.png` | Sysmon Event 1 - rundll32 IternalJob commandline |
| `03_sysmon_e3_c2_beacon.png` | Sysmon Event 3 - wab.exe outbound to Kali:443 |
| `04_ps_e4104_kerberoast.png` | PowerShell Event 4104 - Invoke-Kerberoast script block |
| `05_ps_e4104_lsass_dump.png` | PowerShell Event 4104 - comsvcs MiniDump command |
| `06_event7045_psexec_dc.png` | System Event 7045 - random service on Goku (DC) |
| `07_active_response_block.png` | active-responses.log - block_attacker SUCCESS |
| `08_active_response_isolate.png` | iptables FORWARD chain - isolation rules + Wazuh ACCEPT |
| `09_wireshark_c2_beacon.png` | Wireshark - consistent 88-byte TLSv1.3 packets from BEACHHEAD-PC |
| `10_threat_hunt_dashboard.png` | BumbleBee Threat Hunting Dashboard - all four panels |