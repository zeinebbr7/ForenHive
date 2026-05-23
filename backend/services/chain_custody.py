from __future__ import annotations

import base64
import hashlib
import json
import logging
from dataclasses import dataclass
from typing import Any

import httpx
from config import get_settings

log = logging.getLogger(__name__)

try:
    from rfc3161_client import (
        HashAlgorithm,
        TimestampRequestBuilder,
        decode_timestamp_response,
    )

    _RFC3161_AVAILABLE = True
except Exception:  # pragma: no cover
    _RFC3161_AVAILABLE = False


@dataclass
class CustodyRecord:
    sha256: str
    tsa_token_b64: str | None
    tsa_url: str
    tsa_ok: bool

    def to_dict(self) -> dict[str, Any]:
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
    def _serialize(payload: Any) -> bytes:
        if isinstance(payload, bytes):
            return payload
        if isinstance(payload, (dict, list)):
            return json.dumps(payload, sort_keys=True, default=str).encode()
        return str(payload).encode()

    @classmethod
    def sha256_payload(cls, payload: Any) -> str:
        return hashlib.sha256(cls._serialize(payload)).hexdigest()

    async def _request_token(self, raw: bytes) -> bytes | None:
        if not _RFC3161_AVAILABLE:
            return None
        req = (
            TimestampRequestBuilder()
            .data(raw)
            .hash_algorithm(HashAlgorithm.SHA256)
            .nonce(nonce=True)
            .cert_request(cert_request=True)
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
            return token_bytes

    async def seal(self, payload: Any) -> CustodyRecord:
        raw = self._serialize(payload)
        digest = hashlib.sha256(raw).hexdigest()
        try:
            token = await self._request_token(raw)
        except Exception as exc:
            log.warning("TSA timestamping failed: %s", exc)
            return CustodyRecord(digest, None, self.settings.tsa_url, False)
        if token is None:
            return CustodyRecord(digest, None, self.settings.tsa_url, False)
        return CustodyRecord(
            digest,
            base64.b64encode(token).decode(),
            self.settings.tsa_url,
            True,
        )

    # Kept for backward compatibility (e.g. callers that already have a digest).
    async def timestamp(self, sha256_hex: str) -> CustodyRecord:
        return CustodyRecord(sha256_hex, None, self.settings.tsa_url, False)

    async def verify(self, payload: Any, record: dict[str, Any]) -> bool:
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


_svc: ChainOfCustody | None = None


def get_custody() -> ChainOfCustody:
    global _svc
    if _svc is None:
        _svc = ChainOfCustody()
    return _svc
