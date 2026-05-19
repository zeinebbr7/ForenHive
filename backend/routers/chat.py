from __future__ import annotations

import json
import logging
from typing import AsyncIterator

import httpx
from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sse_starlette.sse import EventSourceResponse
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from config import get_settings
from db import get_session
from services.elasticsearch import get_es

log = logging.getLogger(__name__)
router = APIRouter(prefix="/api/chat", tags=["chat"])

SYSTEM_PROMPT = (
    "You are HIVE, ForenHive forensic assistant. "
    "Apply FBI criminal profiling to cyber attackers. "
    "Map behavior to MITRE ATT&CK. Risk scores 0-100 (18 signals). "
    "Reply in user's language (FR/EN). "
    "Be concise, analytical. Cite session_id/honeypot/timestamp when referencing data."
)

GROQ_BASE = "https://api.groq.com/openai/v1"


class Msg(BaseModel):
    role: str
    content: str


class ChatRequest(BaseModel):
    message: str
    history: list[Msg] = []
    lang: str = "en"   # "en" or "fr" — sent by frontend based on document.documentElement.lang


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
                    "_source": ["@timestamp", "honeypot.type", "source.ip",
                                "event.action", "geoip.country_name"],
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
                    b["key"]: b["doc_count"]
                    for b in aggs.get("by_honeypot", {}).get("buckets", [])
                },
                "top_countries": {
                    b["key"]: b["doc_count"]
                    for b in aggs.get("by_country", {}).get("buckets", [])
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


async def _stream_groq_with_fallback(messages: list[dict], settings) -> AsyncIterator[dict]:
    """Try Groq; if connection fails, transparently fall back to Ollama."""
    groq_failed = False
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
                if resp.status_code >= 400:
                    groq_failed = True
                else:
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
    except (httpx.ConnectTimeout, httpx.ConnectError, httpx.ReadTimeout,
            httpx.HTTPStatusError):
        groq_failed = True
    except Exception:
        groq_failed = True

    if groq_failed:
        log.warning("Groq unavailable, falling back to Ollama")
        async for event in _stream_ollama(messages, settings):
            yield event
        return

    yield {"data": "[DONE]"}


async def _stream_ollama(messages: list[dict], settings) -> AsyncIterator[dict]:
    try:
        async with httpx.AsyncClient(timeout=120) as c:
            async with c.stream(
                "POST",
                f"{settings.ollama_host}/api/chat",
                json={"model": settings.ollama_model, "messages": messages, "stream": True},
            ) as resp:
                resp.raise_for_status()
                async for line in resp.aiter_lines():
                    if not line:
                        continue
                    try:
                        data = json.loads(line)
                        token = data.get("message", {}).get("content", "")
                        if token:
                            yield {"data": json.dumps({"token": token})}
                        if data.get("done"):
                            break
                    except Exception:
                        pass
    except Exception as exc:
        yield {"data": json.dumps({"error": str(exc)})}
    yield {"data": "[DONE]"}


# ── routes ─────────────────────────────────────────────────────────────────────

@router.get("/status")
async def chat_status():
    settings = get_settings()
    if await _groq_reachable(settings):
        return {"backend": "groq", "model": settings.groq_model}
    return {"backend": "ollama", "model": settings.ollama_model}


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
                "_source": [
                    "@timestamp", "honeypot.type", "source.ip",
                    "event.action", "geoip.country_name", "geoip.country_iso_code",
                ],
            },
        )
        rows = []
        for h in resp["hits"]["hits"]:
            s = h["_source"]
            ts  = str(s.get("@timestamp", ""))[:19].replace("T", " ")
            hp  = (s.get("honeypot") or {}).get("type") or s.get("honeypot.type", "—")
            ip  = (s.get("source")   or {}).get("ip")   or s.get("source.ip",    "—")
            act = (s.get("event")    or {}).get("action")or s.get("event.action", "—")
            cc  = (s.get("geoip")    or {}).get("country_iso_code") or \
                  s.get("geoip.country_iso_code", "—")
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
        if req.lang != "fr" else
        "Tu DOIS répondre exclusivement en français. N'utilise jamais l'anglais."
    )
    system = f"{SYSTEM_PROMPT}\n{lang_instruction}"

    messages = [{"role": "system", "content": system}]
    messages += [m.model_dump() for m in req.history[-30:]]
    messages.append({"role": "user", "content": user_content})

    # Prefer Groq; _stream_groq falls back to Ollama on any exception via the caller.
    if settings.groq_api_key:
        gen = _stream_groq_with_fallback(messages, settings)
    else:
        gen = _stream_ollama(messages, settings)

    return EventSourceResponse(gen)
