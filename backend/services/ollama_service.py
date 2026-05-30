from __future__ import annotations

import hashlib
import json
import logging
import re
from datetime import UTC, datetime
from typing import Any

import httpx
from config import get_settings

from services.elasticsearch import get_es

log = logging.getLogger(__name__)

_FALLBACK_MSG = (
    "Mistral 7B analysis unavailable; showing structured metadata only. "
    "The source IP exhibits activity consistent with reconnaissance or "
    "brute-force behaviour; manual triage recommended."
)

PROMPT_TEMPLATE = """You are a senior threat intelligence analyst.
Given the attacker metadata below, produce a concise 2-3 sentence
assessment of the likely threat actor, their sophistication level,
and the probable intent. Do not invent facts.

STRICT GROUNDING — only state what the metadata shows:
  - If "Top usernames tried" is "none", do NOT mention usernames, credentials,
    passwords, or login attempts at all.
  - If "Top commands observed" is "none", do NOT mention commands or shell access.
  - If MITRE techniques and YARA matches are both "none", do NOT claim malware,
    exploitation, post-exploitation, or compromise — describe it as scanning or
    reconnaissance only.
  - Never assert a specific country/origin other than the Country field below.

IP: {ip}
Country: {country} ({country_iso})
ASN: {asn} — {as_org}
Tor/VPN: tor={is_tor}, vpn={is_vpn}
AbuseIPDB score: {abuseipdb_score}
Total events: {event_count} across {session_count} sessions
Honeypots hit: {honeypots}
Top usernames tried: {usernames}
Top commands observed: {commands}
MITRE ATT&CK techniques: {mitre}
YARA matches: {yara}

Assessment:"""

_RECOMMENDATIONS_PROMPT = """\
You are a senior SOC analyst. Based on the attack data below, output exactly 3 to 5 actionable \
defensive recommendations as a JSON array. Each item must have exactly these three fields:
  "priority": one of IMMEDIATE, HIGH, MEDIUM, or LOW
  "action": a concise imperative sentence (max 20 words)
  "rationale": one sentence explaining why (max 20 words)

GROUNDING RULES (mandatory — stay faithful to the evidence):
  - Calibrate priority to the risk level: CRITICAL→up to IMMEDIATE, HIGH→up to HIGH,
    MEDIUM→up to MEDIUM, LOW/INFO→MEDIUM or LOW only (never HIGH/IMMEDIATE).
  - Do NOT claim or imply compromise, post-exploitation, lateral movement, data
    exfiltration, or malware UNLESS auth success is true OR commands were observed
    OR YARA matched. With none of those, treat it as reconnaissance/scanning only.
  - Every rationale must be supported by a field below; do not invent activity.

Output ONLY the JSON array — no markdown, no explanation, no extra text.

Attack data:
  Source IP     : {ip}
  Country       : {country}
  Risk score    : {risk_score}/100 ({risk_level})
  Honeypots hit : {honeypots}
  MITRE          : {mitre}
  Auth attempts  : {auth_attempts} (success: {auth_success})
  YARA matches   : {yara}
  Tor/VPN        : tor={is_tor}, vpn={is_vpn}
  Commands seen  : {commands}

JSON array:"""


class OllamaService:
    def __init__(self) -> None:
        self.settings = get_settings()

    def _cache_key(self, ip: str) -> str:
        return hashlib.sha256(f"profile:{ip}".encode()).hexdigest()[:32]

    async def _get_cached(self, ip: str) -> str | None:
        es = get_es()
        doc = await es.get_doc(self.settings.es_index_profiles, self._cache_key(ip))
        if not doc:
            return None
        updated = doc.get("updated_at")
        if not updated:
            return None
        try:
            ts = datetime.fromisoformat(str(updated).replace("Z", "+00:00"))
        except Exception:
            return None
        age = (datetime.now(UTC) - ts).total_seconds()
        if age > self.settings.ollama_cache_ttl:
            return None
        return doc.get("mistral_analysis")

    async def _store_cache(self, ip: str, analysis: str, risk_score: int) -> None:
        es = get_es()
        await es.index_doc(
            self.settings.es_index_profiles,
            self._cache_key(ip),
            {
                "ip": ip,
                "mistral_analysis": analysis,
                "risk_score": risk_score,
                "updated_at": datetime.now(UTC).isoformat(),
            },
        )

    def _recs_cache_key(self, ip: str) -> str:
        return hashlib.sha256(f"recs:{ip}".encode()).hexdigest()[:32]

    async def _get_cached_recs(self, ip: str) -> list[dict] | None:
        es = get_es()
        doc = await es.get_doc(self.settings.es_index_profiles, self._recs_cache_key(ip))
        if not doc:
            return None
        updated = doc.get("updated_at")
        if not updated:
            return None
        try:
            ts = datetime.fromisoformat(str(updated).replace("Z", "+00:00"))
        except Exception:
            return None
        if (datetime.now(UTC) - ts).total_seconds() > self.settings.ollama_cache_ttl:
            return None
        return doc.get("ollama_recommendations")

    async def _store_cached_recs(self, ip: str, recs: list[dict]) -> None:
        es = get_es()
        await es.index_doc(
            self.settings.es_index_profiles,
            self._recs_cache_key(ip),
            {
                "ip": ip,
                "ollama_recommendations": recs,
                "updated_at": datetime.now(UTC).isoformat(),
            },
        )

    def _parse_recs(self, raw: str) -> list[dict] | None:
        """Extract a JSON array from the LLM response (strips markdown fences)."""
        raw = re.sub(r"^```[a-z]*\s*", "", raw.strip(), flags=re.MULTILINE)
        raw = re.sub(r"\s*```$", "", raw.strip(), flags=re.MULTILINE)
        start, end = raw.find("["), raw.rfind("]")
        if start == -1 or end == -1:
            return None
        try:
            items = json.loads(raw[start : end + 1])
        except json.JSONDecodeError:
            return None
        result = []
        for item in items:
            if not isinstance(item, dict):
                continue
            result.append(
                {
                    "priority": str(item.get("priority", "MEDIUM")).upper(),
                    "action": str(item.get("action", "")),
                    "rationale": str(item.get("rationale", "")),
                }
            )
        return result if result else None

    async def generate_recommendations(
        self,
        ip: str,
        *,
        country: str = "unknown",
        risk_score: int = 0,
        risk_level: str = "INFO",
        honeypots: list[str] | None = None,
        mitre: list[str] | None = None,
        auth_attempts: int = 0,
        auth_success: bool = False,
        yara: list[str] | None = None,
        is_tor: bool = False,
        is_vpn: bool = False,
        commands: list[str] | None = None,
        use_cache: bool = True,
    ) -> list[dict]:
        """Return 3-5 Ollama-generated SOC recommendations for a given attacker."""
        if use_cache:
            cached = await self._get_cached_recs(ip)
            if cached:
                # Re-ground even cached recs against the current evidence so an
                # old over-stated rec (e.g. HIGH "post-exploitation" on a 0/INFO
                # session) can never slip through.
                return self._ground_recs(
                    cached, risk_level=risk_level, auth_success=auth_success,
                    commands=commands, yara=yara, ip=ip,
                )

        prompt = _RECOMMENDATIONS_PROMPT.format(
            ip=ip,
            country=country,
            risk_score=risk_score,
            risk_level=risk_level,
            honeypots=", ".join(honeypots or []) or "unknown",
            mitre=", ".join(mitre or []) or "none",
            auth_attempts=auth_attempts,
            auth_success=auth_success,
            yara=", ".join(yara or []) or "none",
            is_tor=is_tor,
            is_vpn=is_vpn,
            commands=", ".join((commands or [])[:5]) or "none",
        )

        recs: list[dict] | None = None
        try:
            async with httpx.AsyncClient(timeout=self.settings.ollama_timeout) as client:
                resp = await client.post(
                    f"{self.settings.ollama_host}/api/generate",
                    json={
                        "model": self.settings.ollama_model,
                        "prompt": prompt,
                        "stream": False,
                        "options": {"temperature": 0.15, "num_predict": 400},
                    },
                )
                resp.raise_for_status()
                raw = (resp.json().get("response") or "").strip()
                recs = self._parse_recs(raw)
        except Exception as exc:
            log.warning("Ollama recommendations call failed for %s: %s", ip, exc)

        if not recs:
            recs = [
                {
                    "priority": "MEDIUM",
                    "action": f"Monitor and log activity from {ip}.",
                    "rationale": "Ollama unavailable — conservative fallback recommendation.",
                }
            ]

        recs = self._ground_recs(
            recs, risk_level=risk_level, auth_success=auth_success,
            commands=commands, yara=yara, ip=ip,
        )
        await self._store_cached_recs(ip, recs)
        return recs

    # Priority ranking + per-risk-level caps (mirror risk_thresholds bands).
    _PRIO_RANK = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "IMMEDIATE": 3}
    _LEVEL_CAP = {
        "INFO": "LOW", "LOW": "MEDIUM", "MEDIUM": "HIGH",
        "HIGH": "IMMEDIATE", "CRITICAL": "IMMEDIATE",
    }
    _COMPROMISE_TERMS = (
        "post-exploit", "post exploit", "compromis", "lateral", "exfiltrat",
        "data theft", "breach", "backdoor", "c2", "command-and-control",
    )

    def _ground_recs(
        self, recs: list[dict], *, risk_level: str, auth_success: bool,
        commands: list[str] | None, yara: list[str] | None, ip: str,
    ) -> list[dict]:
        """Deterministically constrain LLM recs to the evidence: cap priority to the
        risk level and drop recommendations that assert compromise when none occurred."""
        cap = self._LEVEL_CAP.get((risk_level or "INFO").upper(), "IMMEDIATE")
        cap_rank = self._PRIO_RANK[cap]
        has_activity = bool(auth_success) or bool(commands) or bool(yara)
        out: list[dict] = []
        for r in recs:
            prio = str(r.get("priority", "MEDIUM")).upper()
            if self._PRIO_RANK.get(prio, 1) > cap_rank:
                prio = cap
            action = str(r.get("action", ""))
            rationale = str(r.get("rationale", ""))
            if not has_activity and any(
                t in (action + " " + rationale).lower() for t in self._COMPROMISE_TERMS
            ):
                continue  # no successful auth / commands / YARA → drop compromise claim
            out.append({"priority": prio, "action": action, "rationale": rationale})
        if not out:
            out = [{
                "priority": cap,
                "action": f"Monitor and log activity from {ip}; no compromise observed.",
                "rationale": "Reconnaissance/scanning only — no auth success, commands, or malware.",
            }]
        return out

    async def analyze_profile(self, profile: dict[str, Any], *, use_cache: bool = True) -> str:
        ip = profile.get("ip", "")
        if use_cache:
            cached = await self._get_cached(ip)
            if cached:
                return cached

        prompt = PROMPT_TEMPLATE.format(
            ip=ip,
            country=profile.get("country") or "unknown",
            country_iso=profile.get("country_iso") or "??",
            asn=profile.get("asn") or "?",
            as_org=profile.get("as_org") or "unknown",
            is_tor=profile.get("is_tor", False),
            is_vpn=profile.get("is_vpn", False),
            abuseipdb_score=profile.get("abuseipdb_score"),
            event_count=profile.get("event_count", 0),
            session_count=profile.get("session_count", 0),
            honeypots=", ".join(profile.get("honeypots") or []) or "none",
            usernames=", ".join(profile.get("top_usernames") or []) or "none",
            commands=", ".join((profile.get("top_commands") or [])[:5]) or "none",
            mitre=", ".join(profile.get("mitre_techniques") or []) or "none",
            yara=", ".join(profile.get("yara_matches") or []) or "none",
        )

        try:
            async with httpx.AsyncClient(timeout=self.settings.ollama_timeout) as client:
                resp = await client.post(
                    f"{self.settings.ollama_host}/api/generate",
                    json={
                        "model": self.settings.ollama_model,
                        "prompt": prompt,
                        "stream": False,
                        "options": {"temperature": 0.2, "num_predict": 220},
                    },
                )
                resp.raise_for_status()
                data = resp.json()
                text = (data.get("response") or "").strip()
                if not text:
                    text = _FALLBACK_MSG
        except Exception as exc:
            log.warning("Ollama call failed for %s: %s", ip, exc)
            text = _FALLBACK_MSG

        await self._store_cache(ip, text, profile.get("risk_score", 0))
        return text


_svc: OllamaService | None = None


def get_ollama() -> OllamaService:
    global _svc
    if _svc is None:
        _svc = OllamaService()
    return _svc
