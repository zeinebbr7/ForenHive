from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

import httpx

from config import get_settings

log = logging.getLogger(__name__)


class ForensicEngineClient:
    """Thin HTTP client for the sidecar forensic-engine service.

    The backend doesn't run YARA itself (heavy C deps, different image).
    It delegates to forenhive-forensic-engine on backend-net. If the engine
    doesn't expose HTTP endpoints yet, these calls degrade gracefully.
    """

    def __init__(self) -> None:
        self.settings = get_settings()

    async def _get(self, path: str, **kwargs) -> Any:
        url = f"{self.settings.forensic_engine_url.rstrip('/')}{path}"
        async with httpx.AsyncClient(timeout=self.settings.forensic_engine_timeout) as client:
            r = await client.get(url, **kwargs)
            r.raise_for_status()
            return r.json()

    async def _post(self, path: str, json: Dict[str, Any]) -> Any:
        url = f"{self.settings.forensic_engine_url.rstrip('/')}{path}"
        async with httpx.AsyncClient(timeout=self.settings.forensic_engine_timeout) as client:
            r = await client.post(url, json=json)
            r.raise_for_status()
            return r.json()

    async def scan_sha256(self, sha256: str) -> Dict[str, Any]:
        try:
            return await self._get(f"/yara/scan/{sha256}")
        except Exception as exc:
            log.warning("yara scan via engine failed for %s: %s", sha256, exc)
            return {"sha256": sha256, "matches": [], "engine_available": False}

    async def scan_all_dionaea(self, limit: int = 50) -> List[Dict[str, Any]]:
        try:
            data = await self._get("/yara/scan-dionaea", params={"limit": limit})
            return data if isinstance(data, list) else data.get("results", [])
        except Exception as exc:
            log.warning("bulk yara scan failed: %s", exc)
            return []

    async def enrich_ip(self, ip: str) -> Dict[str, Any]:
        try:
            return await self._post("/enrich/ip", {"ip": ip})
        except Exception as exc:
            log.warning("engine ip enrichment failed for %s: %s", ip, exc)
            return {"ip": ip, "engine_available": False}

    async def mitre_map(self, text: str) -> List[str]:
        try:
            data = await self._post("/mitre/map", {"text": text})
            return data.get("techniques", [])
        except Exception as exc:
            log.warning("MITRE mapping failed: %s", exc)
            return []

<<<<<<< HEAD
    async def run_now(self) -> Dict[str, Any]:
        try:
            return await self._post("/run-now", {})
        except Exception as exc:
            log.warning("manual engine trigger failed: %s", exc)
            return {"triggered": False, "message": str(exc)}

=======
>>>>>>> ismail

_svc: Optional[ForensicEngineClient] = None


def get_forensic_engine() -> ForensicEngineClient:
    global _svc
    if _svc is None:
        _svc = ForensicEngineClient()
    return _svc
