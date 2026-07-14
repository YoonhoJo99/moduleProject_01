#!/usr/bin/env python3
# predict_server.py  (C: predict server)
# Receives normalized CSV from B and saves it. Prediction is handled separately later.

import os
import logging
from flask import Flask, request

# ============================================================
# CONFIG
# ============================================================
LISTEN_PORT = 6000          # port B sends to
RECV_DIR = "received"       # incoming normalized csv from B
# ============================================================

os.makedirs(RECV_DIR, exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler(), logging.FileHandler("predict_server.log")],
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
    log.info("Received: %s", f.filename)
    # --- prediction hook goes here later (call model on save_path) ---
    return "ok", 200


if __name__ == "__main__":
    log.info("Predict server listening on :%d", LISTEN_PORT)
    app.run(host="0.0.0.0", port=LISTEN_PORT)
