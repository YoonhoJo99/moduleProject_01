#!/usr/bin/env python3
# capture_upload.py
# Run once: starts tcpdump (10s rotation) + auto-uploads each finished pcap to the analysis server.
# Only manual step in the whole pipeline is launching the attack separately.

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
INTERFACE = "eth0"                       # capture interface (docker0 for docker traffic)
ROTATE_SEC = 10                             # new pcap file every N seconds
PCAP_DIR = "pcaps"                          # local folder to store pcaps (created under cwd)
UPLOAD_URL = "http://IP:5000/upload"   # <-- B server Tailscale IP + endpoint
DELETE_AFTER_UPLOAD = True                  # remove pcap after successful upload
POLL_SEC = 2                                # how often to check for finished files
# ============================================================

# logging to both console and file
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler(), logging.FileHandler("capture_upload.log")],
)
log = logging.getLogger()

os.makedirs(PCAP_DIR, exist_ok=True)
uploaded = set()          # filenames already uploaded (avoid duplicates)
tcpdump_proc = None       # handle to the tcpdump process


def start_tcpdump():
    # tcpdump with -G rotates the output file every ROTATE_SEC seconds.
    # %Y%m%d_%H%M%S in the name makes each file unique and sortable.
    pattern = os.path.join(PCAP_DIR, "cap_%Y%m%d_%H%M%S.pcap")
    cmd = ["tcpdump", "-i", INTERFACE, "-G", str(ROTATE_SEC), "-w", pattern]
    log.info("Starting tcpdump: %s", " ".join(cmd))
    # start in background; suppress tcpdump's own stderr chatter
    return subprocess.Popen(cmd, stderr=subprocess.DEVNULL)


def finished_pcaps():
    # Return finished pcap files, EXCLUDING the newest one
    # (the newest is still being written by tcpdump right now).
    files = sorted(glob.glob(os.path.join(PCAP_DIR, "cap_*.pcap")))
    if len(files) <= 1:
        return []            # only the currently-writing file exists
    return files[:-1]        # all but the last (last = still writing)


def upload(path):
    # Upload one pcap via curl multipart POST (same method proven to work).
    fname = os.path.basename(path)
    try:
        result = subprocess.run(
            ["curl", "-s", "-S", "-F", f"file=@{path}", UPLOAD_URL],
            capture_output=True, text=True, timeout=30,
        )
        if result.returncode == 0:
            log.info("Uploaded: %s", fname)
            return True
        else:
            log.error("Upload failed (%s): %s", fname, result.stderr.strip())
            return False
    except subprocess.TimeoutExpired:
        log.error("Upload timeout: %s", fname)
        return False
    except Exception as e:
        log.error("Upload error (%s): %s", fname, e)
        return False


def cleanup(signum, frame):
    # Graceful shutdown: stop tcpdump on Ctrl+C.
    log.info("Stopping...")
    if tcpdump_proc:
        tcpdump_proc.terminate()
    sys.exit(0)


def main():
    global tcpdump_proc
    signal.signal(signal.SIGINT, cleanup)
    signal.signal(signal.SIGTERM, cleanup)

    tcpdump_proc = start_tcpdump()
    log.info("Watching %s/ , uploading to %s", PCAP_DIR, UPLOAD_URL)

    while True:
        for path in finished_pcaps():
            fname = os.path.basename(path)
            if fname in uploaded:
                continue
            if upload(path):
                uploaded.add(fname)
                if DELETE_AFTER_UPLOAD:
                    try:
                        os.remove(path)
                        log.info("Deleted: %s", fname)
                    except OSError as e:
                        log.error("Delete failed (%s): %s", fname, e)
            # if upload failed, leave file and retry next loop
        time.sleep(POLL_SEC)


if __name__ == "__main__":
    main()
