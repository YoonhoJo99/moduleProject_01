#!/usr/bin/env python3
# normal_traffic.py <TARGET_IP>
# Generates realistic BENIGN traffic (no attacks) for IDS training/baseline.
# Run capture separately:  tcpdump -i docker0 -Z root -w normal.pcap
import sys
import time
import random
import subprocess
import urllib.request

if len(sys.argv) != 2:
    print(f"Usage: python3 {sys.argv[0]} <TARGET_IP>")
    sys.exit(1)

TARGET = sys.argv[1]
HTTP_PORT = 80
DURATION = 60            # total run time (seconds)

# common paths a normal user/browser would request
PATHS = ["/", "/index.html", "/about", "/contact", "/images/logo.png",
         "/css/style.css", "/js/main.js", "/favicon.ico", "/products", "/help"]

# realistic browser user-agents
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
]

def normal_http():
    """Complete, well-formed HTTP GET (connection opens, transfers, closes)."""
    path = random.choice(PATHS)
    url = f"http://{TARGET}:{HTTP_PORT}{path}"
    req = urllib.request.Request(url, headers={
        "User-Agent": random.choice(USER_AGENTS),
        "Accept": "text/html,application/xhtml+xml,image/png,*/*",
        "Accept-Language": "en-US,en;q=0.9",
        "Connection": "keep-alive",
    })
    try:
        urllib.request.urlopen(req, timeout=3).read()
    except Exception:
        pass

def normal_ping():
    """A few ICMP echoes, like normal connectivity checks."""
    subprocess.run(["ping", "-c", "3", TARGET],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def main():
    print(f"[Normal Traffic] target={TARGET} duration={DURATION}s")
    start = time.time()
    reqs = 0
    while time.time() - start < DURATION:
        # mostly web browsing, occasionally a ping
        action = random.choices(["http", "ping"], weights=[9, 1])[0]
        if action == "http":
            normal_http()
        else:
            normal_ping()
        reqs += 1
        # human-like pacing: wait a bit between actions (NOT a flood)
        time.sleep(random.uniform(0.2, 0.8))
    print(f"[Normal Traffic] done, ~{reqs} normal actions")

if __name__ == "__main__":
    main()
