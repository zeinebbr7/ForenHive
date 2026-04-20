from __future__ import annotations

import base64
import hashlib
import json
import logging
from dataclasses import dataclass
from typing import Any, Dict, Optional

import httpx

from config import get_settings

log = logging.getLogger(__name__)

try:
    from rfc3161_client import TimestampRequestBuilder, decode_timestamp_response
    _RFC3161_AVAILABLE = True
except Exception:  # pragma: no cover
    _RFC3161_AVAILABLE = False


@dataclass
class CustodyRecord:
    sha256: str
    tsa_token_b64: Optional[str]
    tsa_url: str
    tsa_ok: bool

    def to_dict(self) -> Dict[str, Any]:
        return {
            "sha256": self.sha256,
            "tsa_token": self.tsa_token_b64,
            "tsa_url": self.tsa_url,
            "tsa_ok": self.tsa_ok,
        }


class ChainOfCustody:
    def __init__(self) -> None:
        self.settings = get_settings()

    @staticmethod
    def sha256_payload(payload: Any) -> str:
        if isinstance(payload, (dict, list)):
            raw = json.dumps(payload, sort_keys=True, default=str).encode()
        elif isinstance(payload, bytes):
            raw = payload
        else:
            raw = str(payload).encode()
        return hashlib.sha256(raw).hexdigest()

    async def timestamp(self, sha256_hex: str) -> CustodyRecord:
        if not _RFC3161_AVAILABLE:
            return CustodyRecord(sha256_hex, None, self.settings.tsa_url, False)

        try:
            digest = bytes.fromhex(sha256_hex)
            req = (
                TimestampRequestBuilder()
                .data(digest, hash_algorithm="sha256", is_digest=True)
                .cert_req(True)
                .build()
            )
            async with httpx.AsyncClient(timeout=20) as client:
                r = await client.post(
                    self.settings.tsa_url,
                    content=req.as_bytes(),
                    headers={"Content-Type": "application/timestamp-query"},
                )
                r.raise_for_status()
                token_bytes = r.content
                decode_timestamp_response(token_bytes)  # validates structure
                token_b64 = base64.b64encode(token_bytes).decode()
                return CustodyRecord(sha256_hex, token_b64, self.settings.tsa_url, True)
        except Exception as exc:
            log.warning("TSA timestamping failed: %s", exc)
            return CustodyRecord(sha256_hex, None, self.settings.tsa_url, False)

    async def seal(self, payload: Any) -> CustodyRecord:
        digest = self.sha256_payload(payload)
        return await self.timestamp(digest)

    async def verify(self, payload: Any, record: Dict[str, Any]) -> bool:
        if not record:
            return False
        computed = self.sha256_payload(payload)
        if computed != record.get("sha256"):
            return False
        token_b64 = record.get("tsa_token")
        if not token_b64 or not _RFC3161_AVAILABLE:
            return bool(record.get("tsa_ok"))
        try:
            token_bytes = base64.b64decode(token_b64)
            decode_timestamp_response(token_bytes)
            return True
        except Exception as exc:
            log.warning("TSA token verification failed: %s", exc)
            return False


_svc: Optional[ChainOfCustody] = None


def get_custody() -> ChainOfCustody:
    global _svc
    if _svc is None:
        _svc = ChainOfCustody()
    return _svc
