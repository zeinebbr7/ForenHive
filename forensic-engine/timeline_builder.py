"""
ForenHive Forensic Engine — Timeline Builder

Builds a per-IP unified event timeline by fusing Cowrie, Dionaea, Galah and
Zeek events from Elasticsearch into a single stream persisted in PostgreSQL
(`forensic_timeline_events`).

Each attacker event — TCP connect, login attempt, shell command, HTTP
request, SMB exploit, file drop, Zeek conn/weird — becomes one row with
millisecond-precise timestamp, enabling cross-honeypot reconstruction of
the kill chain for a given source IP.

Idempotent: uses the ES `_id` as a unique key so re-running the builder on
overlapping time windows does not create duplicates.
"""

import logging
from datetime import UTC, datetime, timedelta

import config
import psycopg2
import psycopg2.extras
from elasticsearch import Elasticsearch

log = logging.getLogger("timeline")

ES_PAGE_SIZE = 1000


# ══════════════════════════════════════════════════════════════════════════════
# Per-honeypot normalizers — map raw ES doc → unified timeline row
# ══════════════════════════════════════════════════════════════════════════════


def _get(src: dict, *path, default=None):
    """Fetch a field that may be stored either nested ({"a":{"b":1}}) or
    flat-dotted ({"a.b":1}) — both shapes exist in our ES docs depending on
    the Logstash filter branch."""
    if not path:
        return default
    flat = ".".join(path)
    if flat in src and src[flat] is not None:
        return src[flat]
    cur = src
    for k in path:
        if not isinstance(cur, dict) or k not in cur:
            return default
        cur = cur[k]
    return cur if cur is not None else default


def _norm_cowrie(src: dict) -> dict | None:
    eid = _get(src, "event", "id") or ""
    action = eid or "cowrie.event"

    if eid.startswith("cowrie.session.connect"):
        category = "connect"
        dport = _get(src, "destination", "port") or "?"
        summary = f"SSH/Telnet TCP connect on port {dport}"
    elif eid.startswith("cowrie.login.success"):
        category = "auth"
        u = _get(src, "user", "name", default="?")
        summary = f"Login SUCCESS user={u}"
    elif eid.startswith("cowrie.login.failed"):
        category = "auth"
        u = _get(src, "user", "name", default="?")
        summary = f"Login FAILED user={u}"
    elif eid.startswith("cowrie.command"):
        category = "command"
        cmd = _get(src, "cowrie", "input") or _get(src, "process", "command_line") or ""
        summary = f"Shell: {cmd[:180]}"
    elif eid.startswith("cowrie.session.file_download"):
        category = "file"
        url = _get(src, "url", "original") or _get(src, "cowrie", "url") or ""
        summary = f"File download {url[:180]}"
    elif eid.startswith("cowrie.session.closed"):
        category = "connect"
        summary = "Session closed"
    else:
        category = "other"
        summary = eid

    return {
        "category": category,
        "action": action,
        "session_id": _get(src, "session", "id"),
        "protocol": _get(src, "network", "transport") or "tcp",
        "summary": summary,
    }


def _norm_dionaea(src: dict) -> dict | None:
    eid = _get(src, "event", "id") or _get(src, "event", "action") or "dionaea.event"
    mod = _get(src, "event", "module") or ""
    dport = _get(src, "destination", "port")

    if "smb" in (mod or "").lower() or dport in (445, 139):
        category = "exploit" if "exploit" in eid.lower() else "connect"
        summary = f"SMB {eid} dport={dport}"
    elif "download" in eid.lower() or "offer" in eid.lower():
        category = "file"
        sha = _get(src, "file", "hash", "sha256") or _get(src, "dionaea", "sha256") or ""
        summary = f"Malware {eid} sha256={sha[:16]}"
    elif "login" in eid.lower():
        category = "auth"
        summary = f"Service auth attempt dport={dport}"
    else:
        category = "connect"
        summary = f"{eid} dport={dport}"

    return {
        "category": category,
        "action": eid,
        "session_id": _get(src, "dionaea", "connection", "id") or _get(src, "session", "id"),
        "protocol": _get(src, "network", "transport") or "tcp",
        "summary": summary,
    }


def _norm_galah(src: dict) -> dict | None:
    method = _get(src, "http", "request", "method") or _get(src, "method") or ""
    path = (
        _get(src, "http", "request", "uri")
        or _get(src, "url", "path")
        or _get(src, "request", "path")
        or ""
    )[:200]
    status = (
        _get(src, "http", "response", "status_code")
        or _get(src, "http", "response", "status")
        or "?"
    )
    ua = (_get(src, "http", "request", "user_agent") or _get(src, "user_agent", "original") or "")[
        :80
    ]
    llm_src = _get(src, "galah", "response", "source") or ""
    suffix = f" [llm={llm_src}]" if llm_src else ""
    return {
        "category": "http",
        "action": f"galah.http.{(method or 'req').lower()}",
        "session_id": _get(src, "session", "id"),
        "protocol": "http",
        "summary": f"{method} {path} → {status} ua={ua}{suffix}",
    }


def _norm_zeek(src: dict) -> dict | None:
    mod = (_get(src, "event", "module") or _get(src, "zeek", "log_path") or "").lower()
    dport = _get(src, "destination", "port")
    proto = _get(src, "network", "transport") or _get(src, "zeek", "conn", "proto") or ""

    if "conn" in mod:
        state = _get(src, "zeek", "conn", "state") or ""
        duration = _get(src, "zeek", "conn", "duration")
        summary = f"Zeek conn dport={dport} proto={proto} state={state} dur={duration}"
        category = "connect"
        action = "zeek.conn"
    elif "weird" in mod:
        name = _get(src, "zeek", "weird", "name") or ""
        summary = f"Zeek weird: {name}"
        category = "recon"
        action = "zeek.weird"
    elif "dns" in mod:
        q = _get(src, "dns", "question", "name") or ""
        summary = f"Zeek DNS query {q}"
        category = "recon"
        action = "zeek.dns"
    elif "http" in mod:
        host = _get(src, "url", "domain") or ""
        uri = _get(src, "url", "path") or ""
        summary = f"Zeek HTTP {host}{uri}"
        category = "http"
        action = "zeek.http"
    elif "ssl" in mod or "x509" in mod:
        summary = f"Zeek TLS dport={dport}"
        category = "connect"
        action = "zeek.ssl"
    elif "files" in mod:
        sha = _get(src, "file", "hash", "sha256") or ""
        summary = f"Zeek file extracted sha256={sha[:16]}"
        category = "file"
        action = "zeek.files"
    else:
        summary = f"Zeek {mod} dport={dport}"
        category = "other"
        action = f"zeek.{mod or 'event'}"

    return {
        "category": category,
        "action": action,
        "session_id": _get(src, "zeek", "session", "uid") or _get(src, "zeek", "uid"),
        "protocol": proto or "tcp",
        "summary": summary,
    }


NORMALIZERS = {
    "cowrie": _norm_cowrie,
    "dionaea": _norm_dionaea,
    "galah": _norm_galah,
    "zeek": _norm_zeek,
}


# ══════════════════════════════════════════════════════════════════════════════
# Elasticsearch scroll
# ══════════════════════════════════════════════════════════════════════════════


def _scroll_honeypot(es: Elasticsearch, honeypot_type: str, since_iso: str):
    """Yield all ES docs for one honeypot type in the time window."""
    query = {
        "query": {
            "bool": {
                "filter": [
                    {"range": {"@timestamp": {"gte": since_iso}}},
                    {"term": {"honeypot.type.keyword": honeypot_type}},
                    {"exists": {"field": "source.ip"}},
                ]
            }
        },
        "sort": [{"@timestamp": "asc"}],
        "_source": True,
    }

    resp = es.search(index=config.ES_INDEX, body=query, size=ES_PAGE_SIZE, scroll="2m")
    sid = resp.get("_scroll_id")
    hits = resp["hits"]["hits"]
    try:
        while hits:
            yield from hits
            resp = es.scroll(scroll_id=sid, scroll="2m")
            sid = resp.get("_scroll_id")
            hits = resp["hits"]["hits"]
    finally:
        if sid:
            try:
                es.clear_scroll(scroll_id=sid)
            except Exception:
                pass


# ══════════════════════════════════════════════════════════════════════════════
# Main builder
# ══════════════════════════════════════════════════════════════════════════════


class TimelineBuilder:
    def __init__(self, es: Elasticsearch, pg_conn_factory):
        self.es = es
        self._pg = pg_conn_factory

    def build(self, hours_back: int = 24) -> dict:
        since = (datetime.now(UTC) - timedelta(hours=hours_back)).isoformat()
        totals = {hp: 0 for hp in NORMALIZERS}
        inserted = 0

        log.info(f"Timeline build — looking back {hours_back}h (since {since})")

        conn = self._pg()
        try:
            with conn.cursor() as cur:
                cur.execute("SELECT COUNT(*) FROM forensic_timeline_events")
                before_count = cur.fetchone()[0]
                for hp, normalizer in NORMALIZERS.items():
                    batch = []
                    for hit in _scroll_honeypot(self.es, hp, since):
                        src = hit.get("_source", {})
                        ts = src.get("@timestamp")
                        ip = _get(src, "source", "ip")
                        if not ts or not ip:
                            continue

                        norm = normalizer(src)
                        if not norm:
                            continue

                        dport_raw = _get(src, "destination", "port")
                        try:
                            dport = int(dport_raw) if dport_raw not in (None, "") else None
                        except (TypeError, ValueError):
                            dport = None

                        batch.append(
                            (
                                ip,
                                ts,
                                hp,
                                norm["category"],
                                norm["action"][:64],
                                norm.get("session_id"),
                                dport,
                                (norm.get("protocol") or "")[:16],
                                (norm.get("summary") or "")[:1000],
                                psycopg2.extras.Json(src),
                                hit["_id"],
                            )
                        )
                        totals[hp] += 1

                        if len(batch) >= 500:
                            inserted += self._flush(cur, batch)
                            conn.commit()
                            batch.clear()

                    if batch:
                        inserted += self._flush(cur, batch)
                        conn.commit()

                cur.execute("SELECT COUNT(*) FROM forensic_timeline_events")
                after_count = cur.fetchone()[0]
                inserted = after_count - before_count

            log.info(f"Timeline build complete — inserted {inserted} new events (seen: {totals})")
        finally:
            conn.close()

        return {"inserted": inserted, "seen": totals}

    @staticmethod
    def _flush(cur, rows) -> int:
        psycopg2.extras.execute_values(
            cur,
            """
            INSERT INTO forensic_timeline_events
                (source_ip, ts, honeypot_type, event_category, event_action,
                 session_id, destination_port, protocol, summary, raw, es_doc_id)
            VALUES %s
            ON CONFLICT (es_doc_id) DO NOTHING
            """,
            rows,
            template="(%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)",
            page_size=200,
        )
        return cur.rowcount if cur.rowcount and cur.rowcount > 0 else 0
