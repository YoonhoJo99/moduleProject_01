#!/usr/bin/env python3
# recv_test.py  (B: receive-only test)
# Just receives files from A and saves them. No convert / normalize / forward.
# Use this to verify the A -> B connection first, before running the full pipeline.

import os
import logging
from flask import Flask, request

# ============================================================
# CONFIG
# ============================================================
LISTEN_PORT = 5000          # port A uploads to
RECV_DIR = "received"       # where incoming files are saved
# ============================================================

os.makedirs(RECV_DIR, exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler(), logging.FileHandler("recv_test.log")],
)
log = logging.getLogger()

app = Flask(__name__)


@app.route("/upload", methods=["POST"])
def upload():
    f = request.files.get("file")
    if not f:
        log.error("Upload with no file")
        return "no file", 400
    save_path = os.path.join(RECV_DIR, f.filename)
    f.save(save_path)
    size = os.path.getsize(save_path)
    log.info("Received: %s (%d bytes)", f.filename, size)
    return "ok", 200


if __name__ == "__main__":
    log.info("Receive-only test server listening on :%d", LISTEN_PORT)
    app.run(host="0.0.0.0", port=LISTEN_PORT)
