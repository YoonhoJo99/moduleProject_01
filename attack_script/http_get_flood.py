#!/usr/bin/env python3

from concurrent.futures import ThreadPoolExecutor, as_completed
import sys
import time

import requests


if len(sys.argv) < 3:
    print(f"Usage: python3 {sys.argv[0]} <TARGET_IP> <TARGET_PORT>")
    sys.exit(1)


TARGET_IP = sys.argv[1]
TARGET_PORT = int(sys.argv[2])

if not 1 <= TARGET_PORT <= 65535:
    print("Invalid port")
    sys.exit(1)


REQUEST_COUNT = 500
WORKERS = 20
TIMEOUT = 3

TARGET_URL = f"http://{TARGET_IP}:{TARGET_PORT}/"


def send_request():
    try:
        response = requests.get(
            TARGET_URL,
            headers={
                "Connection": "close",
                "User-Agent": "Traffic-Test-Client",
            },
            timeout=TIMEOUT,
        )

        return response.status_code

    except requests.RequestException:
        return None


print(
    f"[+] Starting HTTP GET flood: "
    f"target={TARGET_URL} requests={REQUEST_COUNT} workers={WORKERS}"
)

success = 0
failed = 0
start_time = time.time()

with ThreadPoolExecutor(max_workers=WORKERS) as executor:
    futures = [
        executor.submit(send_request)
        for _ in range(REQUEST_COUNT)
    ]

    for index, future in enumerate(as_completed(futures), start=1):
        status_code = future.result()

        if status_code is not None:
            success += 1
        else:
            failed += 1

        if index % 100 == 0 or index == REQUEST_COUNT:
            print(
                f"[*] Progress: {index}/{REQUEST_COUNT} "
                f"success={success} failed={failed}"
            )

elapsed_time = time.time() - start_time

print(
    f"[+] HTTP GET flood completed: "
    f"success={success} failed={failed} "
    f"elapsed={elapsed_time:.2f}s"
)
