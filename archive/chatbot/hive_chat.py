#!/usr/bin/env python3
"""HIVE — ForenHive forensic CLI chatbot."""

import os
import sys
import json
import textwrap
from datetime import datetime, timezone

import requests
from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich.live import Live
from rich.markup import escape

# ── optional deps ──────────────────────────────────────────────────────────────
try:
    from groq import Groq
    _groq_available = True
except ImportError:
    _groq_available = False

try:
    from elasticsearch import Elasticsearch
    _es_available = True
except ImportError:
    _es_available = False

try:
    import psycopg2
    import psycopg2.extras
    _pg_available = True
except ImportError:
    _pg_available = False

# ── config ─────────────────────────────────────────────────────────────────────
GROQ_API_KEY  = os.getenv("GROQ_API_KEY", "")
GROQ_MODEL    = os.getenv("GROQ_MODEL", "mixtral-8x7b-32768")
ES_URL        = os.getenv("ES_URL", "http://localhost:9200")
ES_INDEX      = os.getenv("ES_INDEX", "honeypot-logs-*")
PG_DSN        = os.getenv("PG_DSN", "postgresql://forenhive:forenhive@localhost:5432/forenhive")

SYSTEM_PROMPT = (
    "You are HIVE, the forensic assistant built into the ForenHive platform. "
    "SCOPE — you ONLY help with: (1) the ForenHive platform itself — its honeypots "
    "(Cowrie, Dionaea, Galah), forensic engine, sessions, risk scores, suspect profiles, "
    "IOCs, MITRE ATT&CK mappings, dashboards, and the data shown in this app; and "
    "(2) cybersecurity fundamentals directly related to that work — attacker TTPs, "
    "honeypots, threat intelligence, incident triage, digital forensics, IOCs, MITRE ATT&CK. "
    "If a question is outside this scope (general coding help, unrelated trivia, personal "
    "advice, other products, math, etc.), politely decline in one sentence and steer the user "
    "back to ForenHive or its security data. Do not answer off-topic questions even if you know the answer. "
    "Apply FBI-style criminal profiling to cyber attackers. "
    "Map behavior to MITRE ATT&CK. Risk scores are 0-100 (18 signals). "
    "Reply in user's language (FR/EN). "
    "Be concise, analytical. Cite session_id/honeypot/timestamp when referencing data. "
    "Never invent data you were not given in the context."
)

MAX_HISTORY = 8  # conversation turns kept

console = Console()


# ── backend detection ──────────────────────────────────────────────────────────

def _groq_reachable() -> bool:
    if not _groq_available or not GROQ_API_KEY:
        return False
    try:
        client = Groq(api_key=GROQ_API_KEY)
        client.models.list()
        return True
    except Exception:
        return False


def detect_backend() -> tuple[str, object]:
    """Groq-only. Return ("groq", client) or ("none", None) if unavailable."""
    if _groq_reachable():
        return "groq", Groq(api_key=GROQ_API_KEY)
    return "none", None


# ── DB helpers ─────────────────────────────────────────────────────────────────

def _es_client():
    if not _es_available:
        return None
    try:
        es = Elasticsearch(ES_URL, request_timeout=5)
        es.info()
        return es
    except Exception:
        return None


def _pg_conn():
    if not _pg_available:
        return None
    try:
        return psycopg2.connect(PG_DSN, connect_timeout=5)
    except Exception:
        return None


def _es_recent_sessions(es, n: int = 10) -> list[dict]:
    if es is None:
        return []
    try:
        resp = es.search(
            index=ES_INDEX,
            body={
                "size": n,
                "sort": [{"@timestamp": {"order": "desc"}}],
                # Zeek is a network sensor, not a honeypot — exclude it.
                "query": {"terms": {"honeypot.type": ["cowrie", "dionaea", "galah"]}},
                "_source": [
                    "@timestamp", "honeypot.type", "source.ip",
                    "event.action", "geoip.country_name",
                ],
            },
        )
        return [h["_source"] for h in resp["hits"]["hits"]]
    except Exception:
        return []


def _es_stats(es) -> dict:
    if es is None:
        return {}
    try:
        resp = es.search(
            index=ES_INDEX,
            body={
                "size": 0,
                "query": {"terms": {"honeypot.type": ["cowrie", "dionaea", "galah"]}},
                "aggs": {
                    "total": {"value_count": {"field": "@timestamp"}},
                    "by_honeypot": {"terms": {"field": "honeypot.type", "size": 10}},
                    "by_country": {"terms": {"field": "geoip.country_name", "size": 5}},
                },
            },
        )
        aggs = resp.get("aggregations", {})
        return {
            "total_events": resp["hits"]["total"]["value"],
            "by_honeypot": {
                b["key"]: b["doc_count"]
                for b in aggs.get("by_honeypot", {}).get("buckets", [])
            },
            "top_countries": {
                b["key"]: b["doc_count"]
                for b in aggs.get("by_country", {}).get("buckets", [])
            },
        }
    except Exception:
        return {}


# Mirror of forensic-engine/risk_thresholds.PROFILE_RISK_MIN.
# Chatbot runs in its own container so we can't share the module; override via env.
_HIGH_RISK_MIN = int(os.environ.get("PROFILE_RISK_THRESHOLD", "60"))


def _pg_high_risk_sessions(conn, limit: int = 10) -> list[dict]:
    if conn is None:
        return []
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(
                """
                SELECT session_id, source_ip, risk_score, risk_level, country
                FROM sessions
                WHERE risk_score >= %s
                ORDER BY risk_score DESC
                LIMIT %s
                """,
                (_HIGH_RISK_MIN, limit),
            )
            return [dict(r) for r in cur.fetchall()]
    except Exception:
        return []


def _pg_suspect_profiles(conn, limit: int = 5) -> list[dict]:
    if conn is None:
        return []
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(
                """
                SELECT sophistication, objective, organized_score, detective_narrative
                FROM suspect_profiles
                ORDER BY id DESC
                LIMIT %s
                """,
                (limit,),
            )
            return [dict(r) for r in cur.fetchall()]
    except Exception:
        return []


def _pg_iocs(conn, limit: int = 20) -> list[dict]:
    if conn is None:
        return []
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(
                """
                SELECT ioc_type, value, confidence
                FROM iocs
                ORDER BY id DESC
                LIMIT %s
                """,
                (limit,),
            )
            return [dict(r) for r in cur.fetchall()]
    except Exception:
        return []


def _pg_mitre(conn, limit: int = 15) -> list[dict]:
    if conn is None:
        return []
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(
                """
                SELECT technique_id, technique_name, tactic, confidence
                FROM mitre_mappings
                ORDER BY id DESC
                LIMIT %s
                """,
                (limit,),
            )
            return [dict(r) for r in cur.fetchall()]
    except Exception:
        return []


# ── keyword router ─────────────────────────────────────────────────────────────

def build_context(message: str, es, pg_conn) -> str:
    """Query data sources based on keywords and return XML context block."""
    msg = message.lower()
    parts: list[str] = []

    def _xml(tag: str, rows: list[dict]) -> str:
        if not rows:
            return ""
        inner = "\n".join(
            "  <item>" + "".join(f"<{k}>{escape(str(v))}</{k}>" for k, v in r.items()) + "</item>"
            for r in rows
        )
        return f"<{tag}>\n{inner}\n</{tag}>"

    # ES recent sessions
    if any(kw in msg for kw in ("session", "attack", "honeypot", "recent", "last", "event")):
        rows = _es_recent_sessions(es)
        if rows:
            parts.append(_xml("recent_sessions", rows))

    # ES stats
    if any(kw in msg for kw in ("stat", "total", "count", "overview", "summary")):
        stats = _es_stats(es)
        if stats:
            parts.append(f"<stats>{json.dumps(stats)}</stats>")

    # PG sessions (risk)
    if any(kw in msg for kw in ("risk", "score", "high", "critical", "dangerous")):
        rows = _pg_high_risk_sessions(pg_conn)
        if rows:
            parts.append(_xml("high_risk_sessions", rows))

    # PG suspect profiles
    if any(kw in msg for kw in ("profil", "suspect", "actor", "threat", "who", "who is")):
        rows = _pg_suspect_profiles(pg_conn)
        if rows:
            parts.append(_xml("suspect_profiles", rows))

    # PG IOCs
    if any(kw in msg for kw in ("ioc", "hash", "yara", "indicator", "malware", "sha")):
        rows = _pg_iocs(pg_conn)
        if rows:
            parts.append(_xml("iocs", rows))

    # PG MITRE
    if any(kw in msg for kw in ("mitre", "ttp", "technique", "tactic", "att&ck", "attack")):
        rows = _pg_mitre(pg_conn)
        if rows:
            parts.append(_xml("mitre_mappings", rows))

    if not parts:
        return ""

    return "<context>\n" + "\n".join(parts) + "\n</context>"


# ── streaming LLM calls ────────────────────────────────────────────────────────

def _stream_groq(client, messages: list[dict]) -> str:
    stream = client.chat.completions.create(
        model=GROQ_MODEL,
        messages=messages,
        stream=True,
    )
    full = ""
    with Live(Text(""), console=console, refresh_per_second=20) as live:
        for chunk in stream:
            token = chunk.choices[0].delta.content or ""
            full += token
            live.update(Text(full))
    console.print()
    return full


def chat(
    backend: str,
    client,
    history: list[dict],
    user_message: str,
    es,
    pg_conn,
) -> str:
    context = build_context(user_message, es, pg_conn)

    user_content = user_message
    if context:
        user_content = f"{context}\n\n{user_message}"

    messages = [{"role": "system", "content": SYSTEM_PROMPT}]
    messages += history[-MAX_HISTORY:]
    messages.append({"role": "user", "content": user_content})

    console.print("\n[dim]HIVE ›[/dim] ", end="")

    if backend == "groq":
        return _stream_groq(client, messages)
    console.print("[red]Groq unavailable: set GROQ_API_KEY and check connectivity.[/red]")
    return ""


# ── commands ───────────────────────────────────────────────────────────────────

def cmd_sessions(es, pg_conn, args: list[str]) -> None:
    n = int(args[0]) if args and args[0].isdigit() else 10
    rows = _es_recent_sessions(es, n)
    if not rows:
        console.print("[yellow]No sessions found (ES unavailable or no data).[/yellow]")
        return
    from rich.table import Table
    tbl = Table(title=f"Last {n} Sessions", show_lines=True)
    for col in ("timestamp", "honeypot", "source_ip", "action", "country"):
        tbl.add_column(col, style="cyan" if col == "source_ip" else "")
    for r in rows:
        tbl.add_row(
            str(r.get("@timestamp", ""))[:19],
            str(r.get("honeypot", {}).get("type", r.get("honeypot.type", ""))),
            str(r.get("source", {}).get("ip", r.get("source.ip", ""))),
            str(r.get("event", {}).get("action", r.get("event.action", ""))),
            str(r.get("geoip", {}).get("country_name", r.get("geoip.country_name", ""))),
        )
    console.print(tbl)


def cmd_iocs(pg_conn) -> None:
    rows = _pg_iocs(pg_conn)
    if not rows:
        console.print("[yellow]No IOCs found (PG unavailable or no data).[/yellow]")
        return
    from rich.table import Table
    tbl = Table(title="Latest IOCs", show_lines=True)
    for col in ("type", "value", "confidence"):
        tbl.add_column(col)
    for r in rows:
        tbl.add_row(str(r["ioc_type"]), str(r["value"]), str(r["confidence"]))
    console.print(tbl)


def cmd_help() -> None:
    console.print(
        Panel(
            textwrap.dedent("""\
                [bold]/help[/bold]           Show this help
                [bold]/clear[/bold]          Clear conversation history
                [bold]/sessions [n][/bold]   Show last n ES sessions (default 10)
                [bold]/iocs[/bold]           Show latest IOCs from PostgreSQL
                [bold]/quit[/bold]           Exit HIVE

                Ask anything: sessions, risk scores, suspect profiles, MITRE TTPs, IOCs…
                HIVE auto-fetches relevant data and answers in FR or EN.
            """),
            title="HIVE Commands",
            border_style="dim",
        )
    )


# ── startup banner ─────────────────────────────────────────────────────────────

def print_banner(backend: str, es_ok: bool, pg_ok: bool) -> None:
    backend_color = "green" if backend == "groq" else "red"
    backend_label = f"[{backend_color}]{'Groq · ' + GROQ_MODEL if backend == 'groq' else 'Groq unavailable (set GROQ_API_KEY)'}[/{backend_color}]"

    es_label  = "[green]✓ Elasticsearch[/green]" if es_ok  else "[red]✗ Elasticsearch[/red]"
    pg_label  = "[green]✓ PostgreSQL[/green]"    if pg_ok  else "[red]✗ PostgreSQL[/red]"

    body = (
        f"[bold white]HIVE[/bold white] — ForenHive Forensic Assistant\n\n"
        f"LLM   {backend_label}\n"
        f"Data  {es_label}  {pg_label}\n\n"
        "[dim]Type /help for commands, /quit to exit.[/dim]"
    )
    console.print(Panel(body, border_style="bold blue"))


# ── REPL ───────────────────────────────────────────────────────────────────────

def repl() -> None:
    backend, client = detect_backend()

    es      = _es_client()
    pg_conn = _pg_conn()

    print_banner(backend, es is not None, pg_conn is not None)

    history: list[dict] = []

    while True:
        try:
            raw = console.input("\n[bold blue]You ›[/bold blue] ").strip()
        except (EOFError, KeyboardInterrupt):
            console.print("\n[dim]Goodbye.[/dim]")
            break

        if not raw:
            continue

        if raw.startswith("/"):
            parts = raw[1:].split()
            cmd   = parts[0].lower() if parts else ""

            if cmd in ("quit", "exit", "q"):
                console.print("[dim]Goodbye.[/dim]")
                break
            elif cmd == "help":
                cmd_help()
            elif cmd == "clear":
                history.clear()
                console.print("[dim]History cleared.[/dim]")
            elif cmd == "sessions":
                cmd_sessions(es, pg_conn, parts[1:])
            elif cmd == "iocs":
                cmd_iocs(pg_conn)
            else:
                console.print(f"[red]Unknown command /{cmd}. Type /help.[/red]")
            continue

        reply = chat(backend, client, history, raw, es, pg_conn)
        if reply:
            history.append({"role": "user",      "content": raw})
            history.append({"role": "assistant",  "content": reply})
            # keep only last MAX_HISTORY turns
            if len(history) > MAX_HISTORY * 2:
                history = history[-(MAX_HISTORY * 2):]


if __name__ == "__main__":
    repl()
