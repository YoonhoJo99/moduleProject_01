#!/usr/bin/env python3
"""
sensor_pipeline.py

Run on the Ubuntu machine that hosts DVWA and captures its traffic.

Pipeline:
  tcpdump rotation
  + 1-second DVWA service metrics
  + attack label events received from attacker
  -> NTLFlowLyzer
  -> nearest-time metrics merge
  -> label assignment
  -> raw_merged_*.csv upload to normalization server

Run:
  sudo python3 sensor_pipeline.py <DVWA_IP>

Edit CONFIG first:
  INTERFACE
  UPLOAD_URL
  NTL_REPO_DIR
  NTL_CONFIG_TEMPLATE
"""

from __future__ import annotations

import csv
import json
import logging
import os
import shutil
import signal
import subprocess
import sys
import threading
import time
from datetime import datetime
from pathlib import Path
from typing import Any

# ============================== CONFIG ==============================
INTERFACE = "docker0"
DVWA_PORT = 80

ROTATE_SEC = 10
POLL_SEC = 1
METRICS_INTERVAL_SEC = 1.0

UPLOAD_URL = "http://127.0.0.1:5000/upload"

LABEL_LISTEN_HOST = "0.0.0.0"
LABEL_LISTEN_PORT = 5100

NTL_REPO_DIR = Path("./NTLFlowLyzer")
NTL_CONFIG_TEMPLATE = NTL_REPO_DIR / "config.json"

WORK_DIR = Path("./realtime_work")
PCAP_DIR = WORK_DIR / "pcaps"
NTL_DIR = WORK_DIR / "ntl"
RAW_DIR = WORK_DIR / "raw"
CONFIG_DIR = WORK_DIR / "configs"
STATE_DIR = WORK_DIR / "state"

METRICS_FILE = STATE_DIR / "metrics.csv"
ATTACK_WINDOWS_FILE = STATE_DIR / "attack_windows.csv"

DELETE_AFTER_UPLOAD = False
UPLOAD_TIMEOUT_SEC = 30
NTL_TIMEOUT_SEC = 180

DVWA_PROCESS_NAMES = {
    "apache2",
    "httpd",
    "nginx",
    "php",
    "php-fpm",
    "mysqld",
    "mariadbd",
}
# ===================================================================

if len(sys.argv) < 2:
    print(f"Usage: sudo python3 {sys.argv[0]} <DVWA_IP>")
    sys.exit(1)

DVWA_IP = sys.argv[1]

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler("sensor_pipeline.log"),
    ],
)
log = logging.getLogger("sensor_pipeline")

tcpdump_proc: subprocess.Popen | None = None
stop_event = threading.Event()
processed: set[str] = set()
state_lock = threading.Lock()

METRIC_COLUMNS = [
    "Timestamp",
    "container_cpu_cfs_periods_total",
    "container_cpu_cfs_throttled_periods_total",
    "container_cpu_cfs_throttled_seconds_total",
    "container_cpu_system_seconds_total",
    "container_cpu_usage_seconds_total",
    "container_cpu_user_seconds_total",
    "container_memory_failures_total",
    "container_memory_rss",
    "container_memory_usage_bytes",
    "container_memory_working_set_bytes",
    "container_memory_cache",
    "container_network_receive_bytes_total",
    "container_network_receive_packets_total",
    "container_network_transmit_bytes_total",
    "container_network_transmit_packets_total",
    "container_processes",
    "container_sockets",
    "container_threads",
    "container_file_descriptors",
    "container_last_seen",
]


def ensure_dependencies() -> None:
    apt_packages = {
        "tcpdump": "tcpdump",
        "git": "git",
        "curl": "curl",
    }

    apt_updated = False

    for command, package in apt_packages.items():
        if shutil.which(command):
            continue

        if not apt_updated:
            subprocess.run(["apt-get", "update"], check=False)
            apt_updated = True

        log.info("Installing apt package: %s", package)
        subprocess.run(
            ["apt-get", "install", "-y", package],
            check=True,
        )

    required_modules = {
        "pandas": "pandas",
        "psutil": "psutil",
        "requests": "requests",
        "flask": "flask",
    }

    for module, package in required_modules.items():
        try:
            __import__(module)
        except ImportError:
            log.info("Installing Python package: %s", package)
            subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "pip",
                    "install",
                    package,
                    "--break-system-packages",
                ],
                check=True,
            )


ensure_dependencies()

import pandas as pd  # noqa: E402
import psutil  # noqa: E402
import requests  # noqa: E402
from flask import Flask, jsonify, request  # noqa: E402


def prepare_directories() -> None:
    for directory in (
        PCAP_DIR,
        NTL_DIR,
        RAW_DIR,
        CONFIG_DIR,
        STATE_DIR,
    ):
        directory.mkdir(parents=True, exist_ok=True)

    for directory in (PCAP_DIR, NTL_DIR, RAW_DIR, CONFIG_DIR):
        for path in directory.glob("*"):
            if path.is_file():
                path.unlink(missing_ok=True)

    with METRICS_FILE.open("w", newline="") as file:
        csv.DictWriter(file, fieldnames=METRIC_COLUMNS).writeheader()

    with ATTACK_WINDOWS_FILE.open("w", newline="") as file:
        csv.writer(file).writerow(["label", "start", "end"])


def service_processes() -> list[psutil.Process]:
    matches: list[psutil.Process] = []

    for proc in psutil.process_iter(["pid", "name", "cmdline"]):
        try:
            name = (proc.info.get("name") or "").lower()
            cmdline = " ".join(proc.info.get("cmdline") or []).lower()

            if (
                name in DVWA_PROCESS_NAMES
                or any(token in name for token in DVWA_PROCESS_NAMES)
                or any(token in cmdline for token in DVWA_PROCESS_NAMES)
            ):
                matches.append(proc)

        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    return matches


def process_faults(pid: int) -> int:
    try:
        fields = Path(f"/proc/{pid}/stat").read_text().split()
        return int(fields[9]) + int(fields[11])
    except (OSError, ValueError, IndexError):
        return 0


def process_fd_count(proc: psutil.Process) -> int:
    try:
        return proc.num_fds()
    except (AttributeError, psutil.NoSuchProcess, psutil.AccessDenied):
        return 0


def process_connection_count(proc: psutil.Process) -> int:
    try:
        return len(proc.net_connections(kind="inet"))
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return 0


def interface_counters() -> tuple[int, int, int, int]:
    counters = psutil.net_io_counters(pernic=True)

    if INTERFACE not in counters:
        raise RuntimeError(
            f"Interface '{INTERFACE}' does not exist. "
            f"Available: {', '.join(sorted(counters))}"
        )

    stat = counters[INTERFACE]
    return (
        int(stat.bytes_recv),
        int(stat.packets_recv),
        int(stat.bytes_sent),
        int(stat.packets_sent),
    )


def collect_metric_row() -> dict[str, float | str]:
    processes = service_processes()

    cpu_user = 0.0
    cpu_system = 0.0
    rss = 0
    shared = 0
    failures = 0
    threads = 0
    file_descriptors = 0
    sockets = 0

    for proc in processes:
        try:
            cpu = proc.cpu_times()
            mem = proc.memory_info()

            cpu_user += float(cpu.user)
            cpu_system += float(cpu.system)
            rss += int(mem.rss)
            shared += int(getattr(mem, "shared", 0))
            failures += process_faults(proc.pid)
            threads += int(proc.num_threads())
            file_descriptors += process_fd_count(proc)
            sockets += process_connection_count(proc)

        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    recv_bytes, recv_packets, sent_bytes, sent_packets = interface_counters()

    return {
        "Timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f"),
        "container_cpu_cfs_periods_total": 0.0,
        "container_cpu_cfs_throttled_periods_total": 0.0,
        "container_cpu_cfs_throttled_seconds_total": 0.0,
        "container_cpu_system_seconds_total": cpu_system,
        "container_cpu_usage_seconds_total": cpu_user + cpu_system,
        "container_cpu_user_seconds_total": cpu_user,
        "container_memory_failures_total": float(failures),
        "container_memory_rss": float(rss),
        "container_memory_usage_bytes": float(rss + shared),
        "container_memory_working_set_bytes": float(rss),
        "container_memory_cache": float(shared),
        "container_network_receive_bytes_total": float(recv_bytes),
        "container_network_receive_packets_total": float(recv_packets),
        "container_network_transmit_bytes_total": float(sent_bytes),
        "container_network_transmit_packets_total": float(sent_packets),
        "container_processes": float(len(processes)),
        "container_sockets": float(sockets),
        "container_threads": float(threads),
        "container_file_descriptors": float(file_descriptors),
        "container_last_seen": time.time(),
    }


def metrics_worker() -> None:
    log.info(
        "Metrics collection started: interval=%.1fs, interface=%s",
        METRICS_INTERVAL_SEC,
        INTERFACE,
    )

    while not stop_event.is_set():
        started = time.monotonic()

        try:
            row = collect_metric_row()

            with state_lock:
                with METRICS_FILE.open("a", newline="") as file:
                    writer = csv.DictWriter(
                        file,
                        fieldnames=METRIC_COLUMNS,
                    )
                    writer.writerow(row)

        except Exception:
            log.exception("Metric collection failed")

        elapsed = time.monotonic() - started
        stop_event.wait(
            max(0.0, METRICS_INTERVAL_SEC - elapsed)
        )


label_app = Flask(__name__)


@label_app.get("/health")
def health():
    return jsonify({"ok": True}), 200


@label_app.post("/label-event")
def receive_label_event():
    payload = request.get_json(silent=True) or {}

    event = str(payload.get("event", "")).strip().lower()
    label = str(payload.get("label", "")).strip()
    timestamp = str(payload.get("timestamp", "")).strip()

    if event not in {"start", "end"} or not label or not timestamp:
        return jsonify(
            {
                "ok": False,
                "error": "event(start/end), label and timestamp are required",
            }
        ), 400

    try:
        datetime.strptime(
            timestamp,
            "%Y-%m-%d %H:%M:%S.%f",
        )
    except ValueError:
        return jsonify(
            {
                "ok": False,
                "error": (
                    "timestamp must be "
                    "YYYY-MM-DD HH:MM:SS.ffffff"
                ),
            }
        ), 400

    with state_lock:
        rows: list[dict[str, str]] = []

        if ATTACK_WINDOWS_FILE.exists():
            with ATTACK_WINDOWS_FILE.open(newline="") as file:
                rows = list(csv.DictReader(file))

        if event == "start":
            rows.append(
                {
                    "label": label,
                    "start": timestamp,
                    "end": "",
                }
            )
        else:
            for row in reversed(rows):
                if row["label"] == label and not row["end"]:
                    row["end"] = timestamp
                    break
            else:
                rows.append(
                    {
                        "label": label,
                        "start": timestamp,
                        "end": timestamp,
                    }
                )

        with ATTACK_WINDOWS_FILE.open("w", newline="") as file:
            writer = csv.DictWriter(
                file,
                fieldnames=["label", "start", "end"],
            )
            writer.writeheader()
            writer.writerows(rows)

    log.info(
        "Label event received: %s %s %s",
        label,
        event,
        timestamp,
    )
    return jsonify({"ok": True}), 200


def label_server_worker() -> None:
    log.info(
        "Label event server listening on %s:%d",
        LABEL_LISTEN_HOST,
        LABEL_LISTEN_PORT,
    )

    label_app.run(
        host=LABEL_LISTEN_HOST,
        port=LABEL_LISTEN_PORT,
        debug=False,
        use_reloader=False,
        threaded=True,
    )


def start_tcpdump() -> subprocess.Popen:
    subprocess.run(
        ["pkill", "-9", "tcpdump"],
        stderr=subprocess.DEVNULL,
        check=False,
    )
    time.sleep(1)

    pattern = str(
        PCAP_DIR / "cap_%Y%m%d_%H%M%S.pcap"
    )
    capture_filter = (
        f"host {DVWA_IP} and tcp port {DVWA_PORT}"
    )

    command = [
        "tcpdump",
        "-i",
        INTERFACE,
        "-s",
        "0",
        "-G",
        str(ROTATE_SEC),
        "-Z",
        "root",
        "-w",
        pattern,
        capture_filter,
    ]

    log.info("Starting tcpdump: %s", " ".join(command))

    return subprocess.Popen(
        command,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        text=True,
    )


def finished_pcaps() -> list[Path]:
    files = sorted(PCAP_DIR.glob("cap_*.pcap"))

    if len(files) <= 1:
        return []

    ready: list[Path] = []

    for path in files[:-1]:
        if path.name in processed:
            continue

        try:
            if path.stat().st_size > 24:
                ready.append(path)
            else:
                processed.add(path.name)
                path.unlink(missing_ok=True)

        except OSError:
            continue

    return ready


def patch_ntl_config(
    node: Any,
    pcap_path: str,
    output_path: str,
) -> tuple[Any, bool, bool]:
    input_patched = False
    output_patched = False

    if isinstance(node, dict):
        result = {}

        for key, value in node.items():
            lower_key = key.lower()

            if isinstance(value, str):
                if (
                    "pcap" in lower_key
                    or lower_key in {
                        "input",
                        "input_file",
                        "input_path",
                        "capture_file",
                    }
                ):
                    result[key] = pcap_path
                    input_patched = True
                    continue

                if (
                    "output" in lower_key
                    or "csv" in lower_key
                    or lower_key in {
                        "result",
                        "result_file",
                        "result_path",
                    }
                ):
                    result[key] = output_path
                    output_patched = True
                    continue

            patched, child_input, child_output = (
                patch_ntl_config(
                    value,
                    pcap_path,
                    output_path,
                )
            )

            result[key] = patched
            input_patched = input_patched or child_input
            output_patched = output_patched or child_output

        return result, input_patched, output_patched

    if isinstance(node, list):
        result_list = []

        for value in node:
            patched, child_input, child_output = (
                patch_ntl_config(
                    value,
                    pcap_path,
                    output_path,
                )
            )

            result_list.append(patched)
            input_patched = input_patched or child_input
            output_patched = output_patched or child_output

        return result_list, input_patched, output_patched

    return node, False, False


def build_batch_ntl_config(
    pcap_path: Path,
    output_path: Path,
    config_path: Path,
) -> bool:
    if not NTL_CONFIG_TEMPLATE.exists():
        log.error(
            "NTL config template not found: %s",
            NTL_CONFIG_TEMPLATE,
        )
        return False

    try:
        template = json.loads(
            NTL_CONFIG_TEMPLATE.read_text(
                encoding="utf-8"
            )
        )
    except (OSError, json.JSONDecodeError) as error:
        log.error(
            "Cannot read NTL config template: %s",
            error,
        )
        return False

    patched, input_ok, output_ok = patch_ntl_config(
        template,
        str(pcap_path.resolve()),
        str(output_path.resolve()),
    )

    if not input_ok or not output_ok:
        log.error(
            "Could not identify input/output keys in %s",
            NTL_CONFIG_TEMPLATE,
        )
        return False

    config_path.write_text(
        json.dumps(patched, indent=2),
        encoding="utf-8",
    )
    return True


def run_ntlflowlyzer(
    pcap_path: Path,
    ntl_output_path: Path,
) -> bool:
    config_path = CONFIG_DIR / (
        f"{pcap_path.stem}.json"
    )

    if not build_batch_ntl_config(
        pcap_path,
        ntl_output_path,
        config_path,
    ):
        return False

    command = [
        sys.executable,
        "-m",
        "NTLFlowLyzer",
        "-c",
        str(config_path.resolve()),
    ]

    log.info("NTLFlowLyzer: %s", pcap_path.name)

    try:
        result = subprocess.run(
            command,
            cwd=str(NTL_REPO_DIR.parent.resolve()),
            capture_output=True,
            text=True,
            timeout=NTL_TIMEOUT_SEC,
        )
    except subprocess.TimeoutExpired:
        log.error(
            "NTLFlowLyzer timeout: %s",
            pcap_path.name,
        )
        return False

    if result.returncode != 0:
        log.error(
            "NTLFlowLyzer failed (%s): %s",
            pcap_path.name,
            result.stderr.strip()
            or result.stdout.strip(),
        )
        return False

    if not ntl_output_path.exists():
        log.error(
            "NTLFlowLyzer output missing: %s",
            ntl_output_path,
        )
        return False

    return True


def read_attack_windows() -> pd.DataFrame:
    with state_lock:
        if not ATTACK_WINDOWS_FILE.exists():
            return pd.DataFrame(
                columns=["label", "start", "end"]
            )

        windows = pd.read_csv(
            ATTACK_WINDOWS_FILE
        )

    if windows.empty:
        return windows

    windows["start"] = pd.to_datetime(
        windows["start"],
        errors="coerce",
    )
    windows["end"] = pd.to_datetime(
        windows["end"],
        errors="coerce",
    )
    return windows


def assign_labels(flows: pd.DataFrame) -> pd.Series:
    label_map = {
        "dos-s": 1,
        "dos-t": 2,
        "bf": 3,
        "sqli": 4,
    }

    labels = pd.Series(
        0,
        index=flows.index,
        dtype="int64",
    )
    windows = read_attack_windows()

    if windows.empty:
        return labels

    now = pd.Timestamp.now()

    for _, window in windows.iterrows():
        label_name = str(
            window.get("label", "")
        )
        start = window.get("start")
        end = window.get("end")

        if (
            pd.isna(start)
            or label_name not in label_map
        ):
            continue

        if pd.isna(end):
            end = now

        mask = (
            (flows["timestamp"] >= start)
            & (flows["timestamp"] <= end)
        )
        labels.loc[mask] = label_map[label_name]

    return labels


def build_raw_merged(
    ntl_output_path: Path,
    raw_output_path: Path,
) -> bool:
    try:
        flows = pd.read_csv(ntl_output_path)
    except Exception as error:
        log.error(
            "Cannot read NTL output: %s",
            error,
        )
        return False

    if flows.empty:
        log.warning(
            "No flows in %s",
            ntl_output_path.name,
        )
        return False

    if "timestamp" not in flows.columns:
        log.error(
            "NTL output has no 'timestamp' column"
        )
        return False

    flows["timestamp"] = pd.to_datetime(
        flows["timestamp"],
        errors="coerce",
    )
    flows = (
        flows.dropna(subset=["timestamp"])
        .sort_values("timestamp")
    )

    with state_lock:
        try:
            metrics = pd.read_csv(METRICS_FILE)
        except Exception as error:
            log.error(
                "Cannot read metrics: %s",
                error,
            )
            return False

    if metrics.empty:
        log.error("metrics.csv is empty")
        return False

    metrics["Timestamp"] = pd.to_datetime(
        metrics["Timestamp"],
        errors="coerce",
    )
    metrics = (
        metrics.dropna(subset=["Timestamp"])
        .sort_values("Timestamp")
        .rename(
            columns={
                "Timestamp": "metrics_timestamp"
            }
        )
    )

    flows["label"] = assign_labels(flows)

    merged = pd.merge_asof(
        flows,
        metrics,
        left_on="timestamp",
        right_on="metrics_timestamp",
        direction="nearest",
        tolerance=pd.Timedelta(seconds=2),
    )

    metric_value_columns = [
        column
        for column in METRIC_COLUMNS
        if column != "Timestamp"
    ]

    missing_metrics = (
        merged[metric_value_columns]
        .isna()
        .all(axis=1)
        .sum()
    )

    if missing_metrics:
        log.warning(
            "%d rows have no metric match",
            missing_metrics,
        )

    merged.to_csv(
        raw_output_path,
        index=False,
    )

    log.info(
        "Built %s: rows=%d, columns=%d, labels=%s",
        raw_output_path.name,
        len(merged),
        len(merged.columns),
        merged["label"]
        .value_counts()
        .sort_index()
        .to_dict(),
    )
    return True


def upload_raw(raw_path: Path) -> bool:
    try:
        with raw_path.open("rb") as file:
            response = requests.post(
                UPLOAD_URL,
                files={
                    "file": (
                        raw_path.name,
                        file,
                        "text/csv",
                    )
                },
                timeout=UPLOAD_TIMEOUT_SEC,
            )

        if response.ok:
            log.info(
                "Uploaded: %s -> %s",
                raw_path.name,
                UPLOAD_URL,
            )
            return True

        log.error(
            "Upload failed (%s): HTTP %d %s",
            raw_path.name,
            response.status_code,
            response.text[:300],
        )
        return False

    except requests.RequestException as error:
        log.error(
            "Upload error (%s): %s",
            raw_path.name,
            error,
        )
        return False


def process_pcap(pcap_path: Path) -> None:
    ntl_output = (
        NTL_DIR
        / f"{pcap_path.stem}_ntl.csv"
    )
    raw_output = (
        RAW_DIR
        / f"{pcap_path.stem}_raw_merged.csv"
    )

    if not run_ntlflowlyzer(
        pcap_path,
        ntl_output,
    ):
        return

    if not build_raw_merged(
        ntl_output,
        raw_output,
    ):
        return

    if not upload_raw(raw_output):
        return

    processed.add(pcap_path.name)

    if DELETE_AFTER_UPLOAD:
        for path in (
            pcap_path,
            ntl_output,
            raw_output,
        ):
            try:
                path.unlink(missing_ok=True)
            except OSError as error:
                log.error(
                    "Delete failed (%s): %s",
                    path.name,
                    error,
                )


def cleanup(signum=None, frame=None) -> None:
    log.info("Stopping pipeline")
    stop_event.set()

    if (
        tcpdump_proc
        and tcpdump_proc.poll() is None
    ):
        tcpdump_proc.terminate()

        try:
            tcpdump_proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            tcpdump_proc.kill()

    sys.exit(0)


def validate_configuration() -> None:
    if os.geteuid() != 0:
        raise RuntimeError(
            "Run with sudo."
        )

    if (
        UPLOAD_URL
        == "http://NORMALIZE_SERVER_IP:5000/upload"
    ):
        raise RuntimeError(
            "Edit UPLOAD_URL before running."
        )

    if not NTL_REPO_DIR.exists():
        raise RuntimeError(
            f"NTLFlowLyzer directory not found: "
            f"{NTL_REPO_DIR}"
        )

    if not NTL_CONFIG_TEMPLATE.exists():
        raise RuntimeError(
            f"NTL config not found: "
            f"{NTL_CONFIG_TEMPLATE}"
        )

    interface_counters()


def main() -> None:
    global tcpdump_proc

    prepare_directories()
    validate_configuration()

    signal.signal(signal.SIGINT, cleanup)
    signal.signal(signal.SIGTERM, cleanup)

    threading.Thread(
        target=metrics_worker,
        daemon=True,
        name="metrics-worker",
    ).start()

    threading.Thread(
        target=label_server_worker,
        daemon=True,
        name="label-server",
    ).start()

    tcpdump_proc = start_tcpdump()

    log.info(
        "Pipeline ready: capture=%s, DVWA=%s:%d, upload=%s",
        INTERFACE,
        DVWA_IP,
        DVWA_PORT,
        UPLOAD_URL,
    )
    log.info(
        "Label endpoint: "
        "http://<THIS_SENSOR_MACHINE_IP>:%d/label-event",
        LABEL_LISTEN_PORT,
    )
    log.info(
        "Health endpoint: "
        "http://<THIS_SENSOR_MACHINE_IP>:%d/health",
        LABEL_LISTEN_PORT,
    )

    while not stop_event.is_set():
        if tcpdump_proc.poll() is not None:
            stderr = ""

            if tcpdump_proc.stderr:
                stderr = (
                    tcpdump_proc.stderr
                    .read()
                    .strip()
                )

            raise RuntimeError(
                f"tcpdump stopped unexpectedly: "
                f"{stderr}"
            )

        for pcap_path in finished_pcaps():
            try:
                process_pcap(pcap_path)
            except Exception:
                log.exception(
                    "Batch processing failed: %s",
                    pcap_path.name,
                )

        stop_event.wait(POLL_SEC)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        cleanup()
    except Exception as error:
        log.exception(
            "Fatal error: %s",
            error,
        )
        cleanup()
