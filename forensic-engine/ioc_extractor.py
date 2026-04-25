"""
ForenHive Forensic Engine — IOC Extractor

Reads forensic_timeline_events, extracts structured indicators of
compromise (URLs, domains, external IPs, hashes, CVEs, user-agents,
commands, file paths, email addresses) and upserts them into
`forensic_iocs` with seen counts and provenance.

IoC types produced:
  url            — full http(s) URL found in a command / HTTP request
  domain         — FQDN (derived from URLs or direct mention)
  ipv4_external  — public IPv4 referenced by an attacker (e.g. C2/drop host)
  sha256, md5    — file hashes from Dionaea offers or Cowrie downloads
  cve            — CVE-YYYY-NNNN identifier in any field
  user_agent     — Galah HTTP User-Agent strings
  cmdline        — raw shell command executed in Cowrie
  file_path      — absolute paths dropped/touched (/tmp/x, /etc/passwd…)
  email          — email addresses (often embedded in malware/phishing)

Sources scanned: event_action, summary, raw JSONB (full ES doc).
"""

import ipaddress
import json
import logging
import re
from collections import defaultdict
from datetime import datetime
from urllib.parse import urlparse

import psycopg2
import psycopg2.extras

log = logging.getLogger("ioc")


# ── Regexes (compiled once) ──────────────────────────────────────────────────

RE_URL       = re.compile(r"https?://[^\s'\"<>`]+", re.IGNORECASE)
RE_IPV4      = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
RE_SHA256    = re.compile(r"\b[a-fA-F0-9]{64}\b")
RE_MD5       = re.compile(r"(?<![a-fA-F0-9])[a-fA-F0-9]{32}(?![a-fA-F0-9])")
RE_CVE       = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
RE_EMAIL     = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
RE_FILE_PATH = re.compile(r"(?:^|\s)(/(?:bin|sbin|tmp|var|etc|usr|root|home|opt|dev)/[^\s;|&'\"`<>]+)")


def _is_public_ipv4(s: str) -> bool:
    try:
        ip = ipaddress.IPv4Address(s)
    except ValueError:
        return False
    return not (ip.is_private or ip.is_loopback or ip.is_multicast
                or ip.is_reserved or ip.is_link_local or ip.is_unspecified)


def _flatten_strings(obj, acc: list):
    """Walk any JSON-like structure and collect string leaves."""
    if isinstance(obj, str):
        acc.append(obj)
    elif isinstance(obj, dict):
        for v in obj.values():
            _flatten_strings(v, acc)
    elif isinstance(obj, list):
        for v in obj:
            _flatten_strings(v, acc)


# ── Per-event extractor ──────────────────────────────────────────────────────

def extract_from_event(row: dict) -> list[tuple[str, str, dict]]:
    """
    row keys: source_ip, honeypot_type, event_action, summary, raw (dict).
    Returns list of (ioc_type, ioc_value, context_dict).
    """
    found: list[tuple[str, str, dict]] = []
    raw = row.get("raw") or {}
    hp = row.get("honeypot_type") or ""
    action = row.get("event_action") or ""

    # Concatenate all string fields for regex scanning
    strings: list[str] = []
    _flatten_strings(raw, strings)
    if row.get("summary"):
        strings.append(row["summary"])
    haystack = "\n".join(strings)

    # URLs + derived domains
    for url in set(RE_URL.findall(haystack)):
        url = url.rstrip(".,;)\"'")
        found.append(("url", url, {"via": "regex"}))
        try:
            host = urlparse(url).hostname
            if host:
                if _is_public_ipv4(host):
                    found.append(("ipv4_external", host, {"via": "url", "url": url}))
                elif "." in host:
                    found.append(("domain", host.lower(), {"via": "url", "url": url}))
        except Exception:
            pass

    # External IPv4 (direct mentions — e.g. `nc 45.9.148.108 4444`)
    for ip in set(RE_IPV4.findall(haystack)):
        if _is_public_ipv4(ip) and ip != row.get("source_ip"):
            found.append(("ipv4_external", ip, {"via": "regex"}))

    # Hashes
    for sha in set(RE_SHA256.findall(haystack)):
        found.append(("sha256", sha.lower(), {}))
    for md5 in set(RE_MD5.findall(haystack)):
        # Skip MD5s that are actually substrings of a SHA256 we already captured
        if not any(md5.lower() in s.lower() for s in {h for h in RE_SHA256.findall(haystack)}):
            found.append(("md5", md5.lower(), {}))

    # CVEs
    for cve in set(RE_CVE.findall(haystack)):
        found.append(("cve", cve.upper(), {}))

    # Emails (filter SSH algorithm identifiers like aes256-gcm@openssh.com)
    for em in set(RE_EMAIL.findall(haystack)):
        em_low = em.lower()
        domain = em_low.rsplit("@", 1)[-1]
        if domain in ("openssh.com", "ssh.com", "libssh.org", "putty.projects.tartarus.org"):
            continue
        found.append(("email", em_low, {}))

    # File paths (shell commands, download destinations…)
    for fp in set(RE_FILE_PATH.findall(haystack)):
        fp = fp.strip()
        if fp:
            found.append(("file_path", fp, {}))

    # Structured fields by honeypot
    if hp == "cowrie":
        cmd = (raw.get("cowrie.input")
               or (raw.get("cowrie") or {}).get("input")
               or raw.get("input"))
        if cmd and isinstance(cmd, str) and cmd.strip():
            found.append(("cmdline", cmd.strip()[:500], {"event": action}))

    if hp == "galah":
        ua = (raw.get("http.request.user_agent")
              or ((raw.get("http") or {}).get("request") or {}).get("user_agent"))
        if ua and isinstance(ua, str):
            found.append(("user_agent", ua[:300], {"via": "galah"}))
        uri = (raw.get("http.request.uri")
               or ((raw.get("http") or {}).get("request") or {}).get("uri"))
        if uri and isinstance(uri, str) and len(uri) > 1:
            found.append(("http_path", uri[:300], {"method": raw.get("http.request.method")}))

    return found


# ── Main builder ─────────────────────────────────────────────────────────────

class IOCExtractor:

    def __init__(self, pg_conn_factory):
        self._pg = pg_conn_factory

    def build(self, hours_back: int = 24) -> dict:
        log.info(f"IOC extraction — scanning timeline events from last {hours_back}h")
        conn = self._pg()
        try:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute("""
                    SELECT ts, source_ip, honeypot_type, event_action, summary, raw
                    FROM forensic_timeline_events
                    WHERE ts >= NOW() - (%s * INTERVAL '1 hour')
                """, (hours_back,))
                rows = cur.fetchall()

            log.info(f"  scanning {len(rows)} timeline events")

            # Aggregate by (type, value, source_ip)
            agg = defaultdict(lambda: {
                "first": None, "last": None, "count": 0,
                "honeypots": set(), "context": {},
            })
            for row in rows:
                ip = row["source_ip"]
                ts = row["ts"]
                hp = row["honeypot_type"]
                for ioc_type, ioc_value, ctx in extract_from_event(row):
                    key = (ioc_type, ioc_value, ip)
                    rec = agg[key]
                    if rec["first"] is None or ts < rec["first"]:
                        rec["first"] = ts
                    if rec["last"] is None or ts > rec["last"]:
                        rec["last"] = ts
                    rec["count"] += 1
                    if hp:
                        rec["honeypots"].add(hp)
                    if ctx and not rec["context"]:
                        rec["context"] = ctx

            log.info(f"  extracted {len(agg)} distinct IoCs")

            if not agg:
                return {"extracted": 0, "rows_scanned": len(rows)}

            payload = [
                (
                    ioc_type, ioc_value, ip,
                    list(rec["honeypots"]),
                    rec["first"], rec["last"], rec["count"],
                    psycopg2.extras.Json(rec["context"]),
                )
                for (ioc_type, ioc_value, ip), rec in agg.items()
            ]

            with conn.cursor() as cur:
                psycopg2.extras.execute_values(
                    cur,
                    """
                    INSERT INTO forensic_iocs
                        (ioc_type, ioc_value, source_ip, honeypot_types,
                         first_seen, last_seen, occurrences, context)
                    VALUES %s
                    ON CONFLICT (ioc_type, ioc_value, source_ip) DO UPDATE SET
                        honeypot_types = (
                            SELECT ARRAY(SELECT DISTINCT unnest(
                                forensic_iocs.honeypot_types || EXCLUDED.honeypot_types))
                        ),
                        first_seen  = LEAST(forensic_iocs.first_seen, EXCLUDED.first_seen),
                        last_seen   = GREATEST(forensic_iocs.last_seen, EXCLUDED.last_seen),
                        occurrences = forensic_iocs.occurrences + EXCLUDED.occurrences,
                        context     = COALESCE(EXCLUDED.context, forensic_iocs.context)
                    """,
                    payload,
                    template="(%s, %s, %s, %s, %s, %s, %s, %s)",
                    page_size=200,
                )
            conn.commit()
            log.info(f"  upserted {len(payload)} IoC rows")
            return {"extracted": len(payload), "rows_scanned": len(rows)}
        finally:
            conn.close()
