import subprocess
import sys
import time

import requests


if len(sys.argv) != 2:
    print(f"Usage: python3 {sys.argv[0]} <target_ip>")
    sys.exit(1)


TARGET_IP = sys.argv[1]

HTTP_PORT = 80
UDP_PORT = 53
SSH_PORT = 22
NORMAL_REQUEST_COUNT = 200


def generate_normal_http_traffic(count):
    print(f"\n[+] Starting normal HTTP traffic: {count} requests")

    success = 0
    failed = 0

    for i in range(1, count + 1):
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

        if i % 20 == 0 or i == count:
            print(
                f"[*] HTTP progress: {i}/{count} "
                f"success={success} failed={failed}"
            )

        time.sleep(0.05)

    print("[+] Normal HTTP traffic completed")


def run_command(name, command):
    print(f"\n[+] Starting {name}")

    result = subprocess.run(command, check=False)

    if result.returncode == 0:
        print(f"[+] {name} completed")
    else:
        print(f"[-] {name} failed with exit code {result.returncode}")


generate_normal_http_traffic(NORMAL_REQUEST_COUNT)

run_command(
    "SYN flood",
    ["python3", "syn_flood.py", TARGET_IP, str(HTTP_PORT)],
)

generate_normal_http_traffic(NORMAL_REQUEST_COUNT)

run_command(
    "UDP flood",
    ["python3", "udp_flood.py", TARGET_IP, str(UDP_PORT)],
)

generate_normal_http_traffic(NORMAL_REQUEST_COUNT)

run_command(
    "Nmap port scan",
    ["nmap", "-p", "1-1000", TARGET_IP],
)

generate_normal_http_traffic(NORMAL_REQUEST_COUNT)

run_command(
    "SSH brute-force test",
    [
        "hydra",
        "-l", "test",
        "-P", "passwords.txt",
        "-s", str(SSH_PORT),
        f"ssh://{TARGET_IP}",
    ],
)

generate_normal_http_traffic(NORMAL_REQUEST_COUNT)

print("\n[+] All traffic generation tasks completed")
