from __future__ import annotations

import hashlib
import logging
from datetime import datetime, timezone
from typing import Any, Dict, Optional

import httpx

from config import get_settings
from services.elasticsearch import get_es

log = logging.getLogger(__name__)


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


class OllamaService:
    def __init__(self) -> None:
        self.settings = get_settings()

    def _cache_key(self, ip: str) -> str:
        return hashlib.sha256(f"profile:{ip}".encode()).hexdigest()[:32]

    async def _get_cached(self, ip: str) -> Optional[str]:
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
        age = (datetime.now(timezone.utc) - ts).total_seconds()
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
                "updated_at": datetime.now(timezone.utc).isoformat(),
            },
        )

    async def analyze_profile(
        self, profile: Dict[str, Any], *, use_cache: bool = True
    ) -> str:
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
                    return None
        except Exception as exc:
            log.warning("Ollama call failed for %s: %s", ip, exc)
            return None

        await self._store_cache(ip, text, profile.get("risk_score", 0))
        return text


_svc: Optional[OllamaService] = None


def get_ollama() -> OllamaService:
    global _svc
    if _svc is None:
        _svc = OllamaService()
    return _svc
