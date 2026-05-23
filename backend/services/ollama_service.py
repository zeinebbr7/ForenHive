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
  "priority": one of IMMEDIATE, HIGH, or MEDIUM
  "action": a concise imperative sentence (max 20 words)
  "rationale": one sentence explaining why (max 20 words)

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
                return cached

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
                    "priority": "HIGH",
                    "action": f"Block {ip} at perimeter firewall.",
                    "rationale": "Ollama unavailable — fallback recommendation.",
                }
            ]

        await self._store_cached_recs(ip, recs)
        return recs

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
