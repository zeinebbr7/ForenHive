#!/usr/bin/env python3
"""
Simulated SQL injection attack on Cowrie honeypot
Attacker IP: 80.82.77.33
"""

import paramiko
import time

COWRIE_HOST = "localhost"
COWRIE_PORT = 2222
ATTACKER_IP = "80.82.77.33"  # IP simulée dans le commentaire / log

# Credentials foireux pour déclencher une session Cowrie
USERNAME = "root"
PASSWORD = "root"

SQL_COMMANDS = [
    "' OR '1'='1",
    "SELECT * FROM users WHERE id=1 UNION SELECT username,password FROM users--",
    "'; DROP TABLE users;--",
    "1; SELECT sleep(5)--",
    "admin'--",
]

def run():
    print(f"[*] Simulated attacker: {ATTACKER_IP}")
    print(f"[*] Target: {COWRIE_HOST}:{COWRIE_PORT}")
    print(f"[*] Connecting as {USERNAME}:{PASSWORD}\n")

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        client.connect(
            COWRIE_HOST,
            port=COWRIE_PORT,
            username=USERNAME,
            password=PASSWORD,
            timeout=10,
            look_for_keys=False,
            allow_agent=False,
        )
        print("[+] Connected to Cowrie\n")

        shell = client.invoke_shell()
        time.sleep(1)

        for cmd in SQL_COMMANDS:
            print(f"[>] Sending: {cmd}")
            shell.send(cmd + "\n")
            time.sleep(1)

        time.sleep(2)
        output = shell.recv(4096).decode(errors="ignore")
        print(f"\n[Cowrie response]\n{output}")

    except Exception as e:
        print(f"[-] Error: {e}")
    finally:
        client.close()
        print("\n[*] Done. Check Cowrie logs and the platform.")

if __name__ == "__main__":
    run()
