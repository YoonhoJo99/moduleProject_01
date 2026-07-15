#!/usr/bin/env python3
# A_upload.py  (A: Ubuntu/Kali)
# Continuous tcpdump with -G 10s rotation (lossless) + -Z root (fixes permission drop).
# Clears old files + old tcpdump on startup, then:
# Watches for finished pcaps -> CICFlowMeter convert -> upload csv to B -> delete.

import os
import sys
import time
import glob
import signal
import logging
import subprocess

# ============================================================
# CONFIG - edit these for your environment
# ============================================================
INTERFACE = "ens33"                              # capture interface (ip link to check)
ROTATE_SEC = 10                                  # new pcap every N seconds
PCAP_DIR = "pcaps"
CSV_DIR = "csvs"
UPLOAD_URL = "http://IP:5000/upload"   # <-- B server
DELETE_AFTER_UPLOAD = True
POLL_SEC = 2
# ============================================================

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler(), logging.FileHandler("A_upload.log")],
)
log = logging.getLogger()

# create folders and clear any leftover files from previous runs
for d in (PCAP_DIR, CSV_DIR):
    os.makedirs(d, exist_ok=True)
    for old in glob.glob(os.path.join(d, "*")):
        try:
            os.remove(old)
        except OSError:
            pass

processed = set()
tcpdump_proc = None


def start_tcpdump():
    # kill any leftover tcpdump from previous runs so we don't get duplicate captures
    subprocess.run(["pkill", "-9", "tcpdump"], stderr=subprocess.DEVNULL)
    time.sleep(1)
    # -G rotates every ROTATE_SEC; -Z root keeps root so it can write the files.
    pattern = os.path.join(PCAP_DIR, "cap_%Y%m%d_%H%M%S.pcap")
    cmd = ["tcpdump", "-i", INTERFACE, "-G", str(ROTATE_SEC), "-Z", "root", "-w", pattern]
    log.info("Starting tcpdump: %s", " ".join(cmd))
    return subprocess.Popen(cmd, stderr=subprocess.DEVNULL)


def finished_pcaps():
    # all but the newest (newest is still being written), and skip empty files
    files = sorted(glob.glob(os.path.join(PCAP_DIR, "cap_*.pcap")))
    if len(files) <= 1:
        return []
    ready = []
    for f in files[:-1]:
        if os.path.getsize(f) > 0:      # skip 0-byte (no traffic) files
            ready.append(f)
        else:
            # empty file: mark processed and remove so it doesn't linger
            processed.add(os.path.basename(f))
            try: os.remove(f)
            except OSError: pass
    return ready


def convert(pcap_path, csv_path):
    result = subprocess.run(
        ["cicflowmeter", "-f", pcap_path, "-c", csv_path],
        capture_output=True, text=True, timeout=120,
    )
    if result.returncode != 0:
        log.error("Convert failed (%s): %s", os.path.basename(pcap_path), result.stderr.strip())
        return False
    return True


def upload(csv_path):
    fname = os.path.basename(csv_path)
    try:
        result = subprocess.run(
            ["curl", "-s", "-S", "-F", f"file=@{csv_path}", UPLOAD_URL],
            capture_output=True, text=True, timeout=30,
        )
        if result.returncode == 0:
            log.info("Uploaded: %s", fname)
            return True
        log.error("Upload failed (%s): %s", fname, result.stderr.strip())
        return False
    except Exception as e:
        log.error("Upload error (%s): %s", fname, e)
        return False


def cleanup(signum, frame):
    log.info("Stopping...")
    if tcpdump_proc:
        tcpdump_proc.terminate()
    sys.exit(0)


def main():
    global tcpdump_proc
    signal.signal(signal.SIGINT, cleanup)
    signal.signal(signal.SIGTERM, cleanup)

    tcpdump_proc = start_tcpdump()
    log.info("Watching %s/ -> convert -> upload to %s", PCAP_DIR, UPLOAD_URL)

    while True:
        for pcap_path in finished_pcaps():
            fname = os.path.basename(pcap_path)
            if fname in processed:
                continue

            base = os.path.splitext(fname)[0]
            csv_path = os.path.join(CSV_DIR, base + ".csv")

            if not convert(pcap_path, csv_path):
                processed.add(fname)
                continue

            if upload(csv_path):
                processed.add(fname)
                if DELETE_AFTER_UPLOAD:
                    for p in (pcap_path, csv_path):
                        try: os.remove(p)
                        except OSError as e:
                            log.error("Delete failed (%s): %s", os.path.basename(p), e)
        time.sleep(POLL_SEC)


if __name__ == "__main__":
    main()
