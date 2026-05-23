"""
chat.py — Endpoint chat conversationnel (HIVE)
Rôle : proxy SSE vers Ollama Mistral pour le terminal forensique de la SPA.
URL    : /api/chat
Deps   : Ollama (LLM local), Elasticsearch (contexte logs).
Auth   : Bearer token (forenhive.token) requis (sauf chat public).
Codes  : 200 OK | 401 non auth | 403 interdit | 404 absent | 422 valid | 500 engine.
"""

from __future__ import annotations

import json
import logging
from collections.abc import AsyncIterator

import httpx
from config import get_settings
from db import get_session
from fastapi import APIRouter, Depends
from pydantic import BaseModel
from services.elasticsearch import get_es
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession
from sse_starlette.sse import EventSourceResponse

log = logging.getLogger(__name__)
router = APIRouter(prefix="/api/chat", tags=["chat"])

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
    "Reply in the user's language (FR/EN). "
    "Be concise and analytical. Cite session_id/honeypot/timestamp when referencing data. "
    "Never invent data you were not given in the context."
)

GROQ_BASE = "https://api.groq.com/openai/v1"


class Msg(BaseModel):
    role: str
    content: str


class ChatRequest(BaseModel):
    message: str
    history: list[Msg] = []
    lang: str = "en"  # "en" or "fr" — sent by frontend based on document.documentElement.lang


# ── backend detection ──────────────────────────────────────────────────────────


async def _groq_reachable(settings) -> bool:
    """Check Groq reachability. Uses 12s timeout — server latency to api.groq.com is ~4s."""
    if not settings.groq_api_key:
        return False
    try:
        async with httpx.AsyncClient(timeout=12) as c:
            r = await c.get(
                f"{GROQ_BASE}/models",
                headers={"Authorization": f"Bearer {settings.groq_api_key}"},
            )
            return r.status_code == 200
    except Exception:
        return False


# ── data context ───────────────────────────────────────────────────────────────


async def _safe_pg(session: AsyncSession, query: str, params: dict | None = None) -> list[dict]:
    try:
        result = await session.execute(text(query), params or {})
        cols = list(result.keys())
        return [dict(zip(cols, row)) for row in result.fetchall()]
    except Exception:
        return []


def _xml(tag: str, rows: list[dict]) -> str:
    if not rows:
        return ""
    lines = []
    for r in rows:
        inner = "".join(f"<{k}>{v}</{k}>" for k, v in r.items() if v is not None)
        lines.append(f"  <item>{inner}</item>")
    return f"<{tag}>\n" + "\n".join(lines) + f"\n</{tag}>"


async def build_context(message: str, session: AsyncSession) -> str:
    msg = message.lower()
    parts: list[str] = []
    es = get_es()
    settings = get_settings()

    if any(kw in msg for kw in ("session", "attack", "honeypot", "recent", "last", "event")):
        try:
            resp = await es.client.search(
                index=settings.es_index_honeypot,
                body={
                    "size": 10,
                    "sort": [{"@timestamp": {"order": "desc"}}],
                    "query": {"terms": {"honeypot.type": ["cowrie", "dionaea", "galah"]}},
                    "_source": [
                        "@timestamp",
                        "honeypot.type",
                        "source.ip",
                        "event.action",
                        "geoip.country_name",
                    ],
                },
            )
            rows = [h["_source"] for h in resp["hits"]["hits"]]
            x = _xml("recent_sessions", rows)
            if x:
                parts.append(x)
        except Exception:
            pass

    if any(kw in msg for kw in ("stat", "total", "count", "overview", "summary")):
        try:
            resp = await es.client.search(
                index=settings.es_index_honeypot,
                body={
                    "size": 0,
                    "query": {"terms": {"honeypot.type": ["cowrie", "dionaea", "galah"]}},
                    "aggs": {
                        "by_honeypot": {"terms": {"field": "honeypot.type", "size": 10}},
                        "by_country": {"terms": {"field": "geoip.country_name", "size": 5}},
                    },
                },
            )
            aggs = resp.get("aggregations", {})
            stats = {
                "total_events": resp["hits"]["total"]["value"],
                "by_honeypot": {
                    b["key"]: b["doc_count"] for b in aggs.get("by_honeypot", {}).get("buckets", [])
                },
                "top_countries": {
                    b["key"]: b["doc_count"] for b in aggs.get("by_country", {}).get("buckets", [])
                },
            }
            parts.append(f"<stats>{json.dumps(stats)}</stats>")
        except Exception:
            pass

    if any(kw in msg for kw in ("risk", "score", "high", "critical", "dangerous")):
        rows = await _safe_pg(
            session,
            "SELECT session_id, source_ip, risk_score, risk_level, country "
            "FROM sessions WHERE risk_score >= :minrisk ORDER BY risk_score DESC LIMIT 10",
            {"minrisk": get_settings().risk_high_threshold},
        )
        x = _xml("high_risk_sessions", rows)
        if x:
            parts.append(x)

    if any(kw in msg for kw in ("profil", "suspect", "actor", "threat", "who")):
        rows = await _safe_pg(
            session,
            "SELECT sophistication, objective, organized_score, detective_narrative "
            "FROM suspect_profiles ORDER BY id DESC LIMIT 5",
        )
        x = _xml("suspect_profiles", rows)
        if x:
            parts.append(x)

    if any(kw in msg for kw in ("ioc", "hash", "yara", "indicator", "malware", "sha")):
        rows = await _safe_pg(
            session,
            "SELECT ioc_type, value, confidence FROM iocs ORDER BY id DESC LIMIT 20",
        )
        x = _xml("iocs", rows)
        if x:
            parts.append(x)

    if any(kw in msg for kw in ("mitre", "ttp", "technique", "tactic", "att&ck")):
        rows = await _safe_pg(
            session,
            "SELECT technique_id, technique_name, tactic, confidence "
            "FROM mitre_mappings ORDER BY id DESC LIMIT 15",
        )
        x = _xml("mitre_mappings", rows)
        if x:
            parts.append(x)

    return ("<context>\n" + "\n".join(parts) + "\n</context>") if parts else ""


# ── streaming generators ───────────────────────────────────────────────────────


async def _stream_groq(messages: list[dict], settings) -> AsyncIterator[dict]:
    try:
        async with httpx.AsyncClient(timeout=90) as c:
            async with c.stream(
                "POST",
                f"{GROQ_BASE}/chat/completions",
                json={"model": settings.groq_model, "messages": messages, "stream": True},
                headers={
                    "Authorization": f"Bearer {settings.groq_api_key}",
                    "Content-Type": "application/json",
                },
            ) as resp:
                resp.raise_for_status()
                async for line in resp.aiter_lines():
                    if not line.startswith("data: "):
                        continue
                    payload = line[6:]
                    if payload == "[DONE]":
                        break
                    try:
                        chunk = json.loads(payload)
                        token = chunk["choices"][0]["delta"].get("content", "")
                        if token:
                            yield {"data": json.dumps({"token": token})}
                    except Exception:
                        pass
    except Exception as exc:
        yield {"data": json.dumps({"error": str(exc)})}
    yield {"data": "[DONE]"}


# ── routes ─────────────────────────────────────────────────────────────────────


@router.get("/status")
async def chat_status():
    settings = get_settings()
    reachable = await _groq_reachable(settings)
    return {"backend": "groq", "model": settings.groq_model, "reachable": reachable}


@router.get("/sessions")
async def sessions_endpoint(n: int = 20):
    """Return last n honeypot sessions from ES for direct terminal display."""
    es = get_es()
    settings = get_settings()
    try:
        resp = await es.client.search(
            index=settings.es_index_honeypot,
            body={
                "size": min(n, 100),
                "sort": [{"@timestamp": {"order": "desc"}}],
                # Only real honeypots — Zeek is a network sensor, not a honeypot.
                "query": {"terms": {"honeypot.type": ["cowrie", "dionaea", "galah"]}},
                "_source": [
                    "@timestamp",
                    "honeypot.type",
                    "source.ip",
                    "event.action",
                    "geoip.country_name",
                    "geoip.country_iso_code",
                ],
            },
        )
        rows = []
        for h in resp["hits"]["hits"]:
            s = h["_source"]
            ts = str(s.get("@timestamp", ""))[:19].replace("T", " ")
            hp = (s.get("honeypot") or {}).get("type") or s.get("honeypot.type", "—")
            ip = (s.get("source") or {}).get("ip") or s.get("source.ip", "—")
            act = (s.get("event") or {}).get("action") or s.get("event.action", "—")
            cc = (s.get("geoip") or {}).get("country_iso_code") or s.get(
                "geoip.country_iso_code", "—"
            )
            rows.append({"ts": ts, "honeypot": hp, "ip": ip, "action": act, "cc": cc})
        return {"total": resp["hits"]["total"]["value"], "rows": rows}
    except Exception as exc:
        return {"error": str(exc), "rows": []}


@router.post("")
async def chat_endpoint(
    req: ChatRequest,
    session: AsyncSession = Depends(get_session),
):
    settings = get_settings()
    context = await build_context(req.message, session)
    user_content = f"{context}\n\n{req.message}" if context else req.message

    lang_instruction = (
        "You MUST reply exclusively in English. Never use French, even if the data contains French text."
        if req.lang != "fr"
        else "Tu DOIS répondre exclusivement en français. N'utilise jamais l'anglais."
    )
    system = f"{SYSTEM_PROMPT}\n{lang_instruction}"

    messages = [{"role": "system", "content": system}]
    messages += [m.model_dump() for m in req.history[-30:]]
    messages.append({"role": "user", "content": user_content})

    # Groq-only: HIVE uses the Groq free API exclusively, no local fallback.
    if not settings.groq_api_key:

        async def _no_key() -> AsyncIterator[dict]:
            yield {"data": json.dumps({"error": "GROQ_API_KEY is not set"})}
            yield {"data": "[DONE]"}

        return EventSourceResponse(_no_key())

    return EventSourceResponse(_stream_groq(messages, settings))
