"""
Simulate a Kali pentest from the internal LAN — private-IP attacker.
Used to validate the full forensic pipeline end-to-end when a real
Kali VM is not available.
"""

import json
import urllib.request
from datetime import datetime, timedelta, timezone

ES = "http://172.16.1.100:9200"
KALI_IP = "10.212.134.201"


def _post(doc):
    day = doc["@timestamp"][:10].replace("-", ".")
    req = urllib.request.Request(
        f"{ES}/honeypot-logs-{day}/_doc",
        data=json.dumps(doc).encode(),
        headers={"Content-Type": "application/json"}, method="POST")
    urllib.request.urlopen(req, timeout=5).read()


def _ts(base, ms):
    return (base + timedelta(milliseconds=ms)).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def main():
    base = datetime.now(timezone.utc).replace(microsecond=0)
    sid = "kali0001demo"

    # Cowrie: 2 fail → success → recon commands → close
    _post({"@timestamp": _ts(base, 0), "honeypot.type": "cowrie",
           "event.id": "cowrie.session.connect", "event.action": "session.connect",
           "session.id": sid, "source.ip": KALI_IP, "src_port": 51001,
           "destination.ip": "172.18.0.3", "destination.port": 2222,
           "network.transport": "ssh"})
    _post({"@timestamp": _ts(base, 600), "honeypot.type": "cowrie",
           "event.id": "cowrie.login.failed", "session.id": sid,
           "source.ip": KALI_IP, "user.name": "root"})
    _post({"@timestamp": _ts(base, 1200), "honeypot.type": "cowrie",
           "event.id": "cowrie.login.failed", "session.id": sid,
           "source.ip": KALI_IP, "user.name": "admin"})
    _post({"@timestamp": _ts(base, 2000), "honeypot.type": "cowrie",
           "event.id": "cowrie.login.success", "session.id": sid,
           "source.ip": KALI_IP, "user.name": "root"})
    for i, cmd in enumerate([
        "uname -a", "id", "cat /etc/passwd", "ls /root", "w",
    ]):
        _post({"@timestamp": _ts(base, 2500 + i*500), "honeypot.type": "cowrie",
               "event.id": "cowrie.command.input", "session.id": sid,
               "source.ip": KALI_IP, "cowrie.input": cmd})
    _post({"@timestamp": _ts(base, 6000), "honeypot.type": "cowrie",
           "event.id": "cowrie.session.closed", "session.id": sid,
           "source.ip": KALI_IP})

    # Dionaea: SMB scan (nmap-like)
    for i in range(4):
        _post({"@timestamp": _ts(base, 10000 + i*300), "honeypot.type": "dionaea",
               "event.action": "accept", "source.ip": KALI_IP,
               "destination.port": "445", "network.transport": "tcp"})

    # Galah: quick web recon
    for i, (m, p) in enumerate([
        ("GET", "/"), ("GET", "/admin"), ("GET", "/robots.txt"),
    ]):
        _post({"@timestamp": _ts(base, 15000 + i*700), "honeypot.type": "galah",
               "event.action": "http_request", "source.ip": KALI_IP,
               "http.request.method": m, "http.request.uri": p,
               "http.request.user_agent": "Mozilla/5.0 (X11; Linux x86_64)",
               "destination.port": "8080",
               "galah.response.source": "llm"})

    # Refresh
    day = base.strftime("%Y.%m.%d")
    urllib.request.urlopen(f"{ES}/honeypot-logs-{day}/_refresh", timeout=5).read()
    print(f"Kali scenario injected at {base.isoformat()} — ip={KALI_IP}")


if __name__ == "__main__":
    main()
