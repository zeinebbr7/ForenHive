#!/usr/bin/env python3
"""
Inject DoS attack logs into Elasticsearch
Attacker IP : 106.75.8.160 — 500 connexions en 8 secondes
"""

from datetime import datetime, timezone, timedelta
import requests

IP      = "106.75.8.160"
SESSION = "demo-dos-10675-01"
BASE    = "http://localhost:9200"

# Date et heure dynamiques — toujours aujourd'hui à l'heure actuelle
TODAY      = datetime.now(timezone.utc).strftime("%Y.%m.%d")
INDEX      = f"honeypot-logs-{TODAY}"
BASE_TIME  = datetime.now(timezone.utc) - timedelta(minutes=10)  # il y a 10 min


def ts(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%S.000Z")


def post(doc):
    r = requests.post(f"{BASE}/{INDEX}/_doc",
                      json=doc,
                      headers={"Content-Type": "application/json"})
    return r.status_code == 201


docs = []

# Session connect principale
docs.append({
    "@timestamp":        ts(BASE_TIME),
    "session.id":        SESSION,
    "source.ip":         IP,
    "destination.port":  2222,
    "honeypot.type":     "cowrie",
    "event.id":          "cowrie.session.connect",
    "event.action":      "session.connect",
    "event.category":    "network",
    "network.transport": "ssh",
    "message":           f"New connection: {IP}:63000 ({SESSION})",
    "tags":              ["cowrie", "honeypot_cowrie"],
})

# 500 tentatives de connexion rapides (DoS flood)
for i in range(500):
    offset = timedelta(seconds=i * 0.016)   # ~62 conn/sec sur 8 secondes
    docs.append({
        "@timestamp":        ts(BASE_TIME + offset),
        "session.id":        SESSION,
        "source.ip":         IP,
        "destination.port":  2222,
        "honeypot.type":     "cowrie",
        "event.id":          "cowrie.login.failed",
        "event.action":      "login.failed",
        "event.category":    "authentication",
        "network.transport": "ssh",
        "username":          "root",
        "password":          f"pass{i:04d}",
        "message":           f"login attempt [{IP}] [root/pass{i:04d}] failed",
        "tags":              ["cowrie", "honeypot_cowrie"],
    })

# Session fermée
docs.append({
    "@timestamp":        ts(BASE_TIME + timedelta(seconds=9)),
    "session.id":        SESSION,
    "source.ip":         IP,
    "destination.port":  2222,
    "honeypot.type":     "cowrie",
    "event.id":          "cowrie.session.closed",
    "event.action":      "session.closed",
    "event.category":    "network",
    "network.transport": "ssh",
    "message":           "Connection lost after 9 seconds",
    "tags":              ["cowrie", "honeypot_cowrie"],
})

print(f"[*] Date    : {TODAY}")
print(f"[*] Index   : {INDEX}")
print(f"[*] Base ts : {ts(BASE_TIME)}")
print(f"[*] Injecting {len(docs)} documents for IP {IP} ...")
ok = sum(1 for d in docs if post(d))
print(f"[+] {ok}/{len(docs)} documents injectés")
print(f"[+] IP: {IP} | Session: {SESSION}")
print(f"[+] 500 tentatives en 8 secondes → ~62 conn/sec")
print(f"\n[*] Lance l'engine :")
print(f"    docker exec forenhive-forensic-engine python3 engine.py --hours 1")
