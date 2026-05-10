# Detection Gaps and Lessons Learned

Honest documentation of what didn't work, why, and what the compensating controls were.

---

## Gap 1 - Suricata dsize Mismatch (C2 Beacon Size Detection)

**What was attempted:**
Custom Suricata rule targeting the 88-byte Sliver C2 beacon using `dsize:88`.
Wireshark showed consistent 88-byte Application Data packets from BEACHHEAD-PC to Kali on port 443.

**Why it failed:**
Suricata's `dsize` keyword measures the reassembled TCP payload, not the total Ethernet frame length.
Wireshark's "Length" column reports the full on-wire frame size including all headers (14 Ethernet + 20 IP + 20 TCP + 5 TLS + payload).

Sliver uses TCP stream optimization: multiple application-layer TLS records are batched into single
TCP segments before transmission. The actual TCP payload sizes in the PCAP were 1235, 1329, 1239,
and 1480 bytes - not 88.

**Verification:**
```bash
tshark -r bumblebee_full_attack.pcap \
  -Y "ip.src==10.0.10.210 && ip.dst==10.0.10.60" \
  -T fields -e tcp.len | sort | uniq -c | sort -rn | head -10
```

Output: 400x 1235, 104x 1329, 104x 1239, 72x 1480

**Compensating control:**
Host-based detection via Wazuh rule 100504 (Sysmon Event 3) provided reliable C2 confirmation.
Sysmon logs the initiating process (`C:\ProgramData\wab.exe`) and destination (`10.0.10.60:443`),
which is more reliable than packet size heuristics against encrypted traffic.

**Production alternatives:**
- JA3/JA3S TLS fingerprinting to identify Sliver's TLS client hello signature
- ML-based beacon interval analysis (consistent timing = C2 heartbeat)
- TLS inspection via forward proxy if permitted in the environment

---

## Gap 2 - Wazuh Active Response Silent Failure

**What happened:**
Active response scripts were deployed and manually tested successfully, but did not fire
automatically when rules triggered during initial simulation runs.

**Root cause:**
Wazuh 4.x requires an explicit `<disabled>no</disabled>` tag inside each `<active-response>`
block in `ossec.conf`. Without this tag, Wazuh silently ignores the active response configuration.
This is not clearly documented in the main Wazuh active response docs.

**Fix:**
```xml
<active-response>
  <disabled>no</disabled>   <!-- Required in Wazuh 4.x - missing = silently ignored -->
  <command>block_attacker</command>
  ...
</active-response>
```

---

## Gap 3 - Wazuh 4.x Alert JSON Wrapping

**What happened:**
Active response scripts failed to extract alert fields when triggered by Wazuh,
despite working correctly when tested with direct JSON input.

**Root cause:**
Wazuh 4.x wraps the alert JSON in an additional envelope:
```json
{"version": 1, "parameters": {"alert": { ... actual alert ... }}}
```
Scripts written to parse the flat alert format did not handle this wrapping.

**Fix:**
```python
data  = json.loads(input_str)
alert = data.get("parameters", {}).get("alert", data)  # Unwrap 4.x envelope
```

---

## Gap 4 - Wazuh Correlation Rule Syntax (Rule 100505)

**What happened:**
Rule 100505, designed to correlate IternalJob (100500) with C2 beacon (100504) using
two `if_matched_sid` tags, did not fire during simulation.

**Root cause:**
Wazuh does not support multiple `if_matched_sid` tags in a single rule. The rule was silently
ignored with a warning in `ossec.log`.

**Fix:**
The correlation logic was folded directly into rule 100504 by adding `if_matched_sid:100500`.
Rule 100504 now only fires when both IternalJob has been detected on the same agent AND
a new outbound connection from ProgramData is seen - achieving the same two-event correlation
without a separate rule.

---

## Gap 5 - Sysmon Event 23 (FileDelete) Not Captured

**What happened:**
Defense evasion (file deletion after LSASS dump) was simulated but not detected by Wazuh.

**Root cause:**
Sysmon Event 23 (FileDelete) is disabled by default in the SwiftOnSecurity config
to reduce noise on high-volume environments.

**Assessment:**
Acceptable trade-off. The LSASS dump itself was detected via Event 4104 (rule 100512),
which provides equivalent coverage for the credential access phase.
Enabling Event 23 globally generates significant noise and would require tuning.

---

## Summary

| Gap | Impact | Compensating Control | Status |
|-----|--------|---------------------|--------|
| Suricata dsize C2 detection | Network-layer C2 not detected | Wazuh 100504 (Sysmon E3) | Mitigated |
| Active response silent failure | No automated containment | Fixed via `<disabled>no</disabled>` | Resolved |
| Wazuh 4.x JSON wrapping | Script extraction failure | Fixed via envelope unwrap | Resolved |
| Correlation rule 100505 | Correlation rule non-functional | Fixed via if_matched_sid in 100504 | Resolved |
| Sysmon Event 23 file deletion | Defense evasion not logged | Event 4104 coverage sufficient | Accepted |