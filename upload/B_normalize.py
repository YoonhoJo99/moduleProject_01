#!/usr/bin/env python3
# analysis_server.py  (B: analysis server)
# Receives pcap from A -> CICFlowMeter convert -> normalize (teammate's script) -> send to C.
# The whole chain runs automatically on each received file.

import os
import logging
import threading
import subprocess
from flask import Flask, request

# ============================================================
# CONFIG - edit these for your environment
# ============================================================
LISTEN_PORT = 5000                                  # port A uploads to
PREDICT_URL = "http://C:6000/upload"    # <-- C server Tailscale IP + endpoint
NORMALIZE_SCRIPT = "normalize.py"                   # <-- teammate's normalize script filename
DELETE_INTERMEDIATE = True                          # remove raw/converted files after sending
# ============================================================

RECV_DIR = "received"       # incoming pcaps from A
CONV_DIR = "converted"      # raw CICFlowMeter csv
NORM_DIR = "normalized"     # normalized csv (final, sent to C)
for d in (RECV_DIR, CONV_DIR, NORM_DIR):
    os.makedirs(d, exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler(), logging.FileHandler("analysis_server.log")],
)
log = logging.getLogger()

app = Flask(__name__)


# Step 1: pcap -> raw csv  (CICFlowMeter)
def convert(pcap_path, csv_path):
    log.info("Converting: %s", os.path.basename(pcap_path))
    result = subprocess.run(
        ["cicflowmeter", "-f", pcap_path, "-c", csv_path],
        capture_output=True, text=True, timeout=120,
    )
    if result.returncode != 0:
        log.error("Convert failed (%s): %s", os.path.basename(pcap_path), result.stderr.strip())
        return False
    return True


# Step 2: raw csv -> normalized csv  (teammate's script; only the filename above is edited)
def normalize(raw_csv, norm_csv):
    log.info("Normalizing: %s", os.path.basename(raw_csv))
    result = subprocess.run(
        ["python", NORMALIZE_SCRIPT, raw_csv, norm_csv],
        capture_output=True, text=True, timeout=120,
    )
    if result.returncode != 0:
        log.error("Normalize failed (%s): %s", os.path.basename(raw_csv), result.stderr.strip())
        return False
    return True


# Step 3: normalized csv -> C (predict server)
def send_to_predict(norm_csv):
    fname = os.path.basename(norm_csv)
    try:
        result = subprocess.run(
            ["curl", "-s", "-S", "-F", f"file=@{norm_csv}", PREDICT_URL],
            capture_output=True, text=True, timeout=30,
        )
        if result.returncode == 0:
            log.info("Sent to predict server: %s", fname)
            return True
        log.error("Send failed (%s): %s", fname, result.stderr.strip())
        return False
    except Exception as e:
        log.error("Send error (%s): %s", fname, e)
        return False


# Full chain for one file, run in a background thread so the HTTP response returns fast.
def process(pcap_path):
    base = os.path.splitext(os.path.basename(pcap_path))[0]
    raw_csv = os.path.join(CONV_DIR, base + ".csv")
    norm_csv = os.path.join(NORM_DIR, base + ".csv")

    try:
        if not convert(pcap_path, raw_csv):
            return
        if not normalize(raw_csv, norm_csv):
            return
        if not send_to_predict(norm_csv):
            return

        # cleanup intermediates on success (keep disk from filling)
        if DELETE_INTERMEDIATE:
            for p in (pcap_path, raw_csv, norm_csv):
                try:
                    os.remove(p)
                except OSError:
                    pass
        log.info("Done: %s", base)
    except subprocess.TimeoutExpired:
        log.error("Timeout while processing %s", base)
    except Exception as e:
        log.error("Process error (%s): %s", base, e)


@app.route("/upload", methods=["POST"])
def upload():
    f = request.files.get("file")
    if not f:
        return "no file", 400
    save_path = os.path.join(RECV_DIR, f.filename)
    f.save(save_path)
    log.info("Received: %s", f.filename)
    # process in background so A gets an immediate response and keeps uploading
    threading.Thread(target=process, args=(save_path,), daemon=True).start()
    return "ok", 200


if __name__ == "__main__":
    log.info("Analysis server listening on :%d , forwarding to %s", LISTEN_PORT, PREDICT_URL)
    app.run(host="0.0.0.0", port=LISTEN_PORT)
