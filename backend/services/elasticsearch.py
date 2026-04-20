from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from elasticsearch import AsyncElasticsearch, NotFoundError
from elasticsearch.helpers import async_bulk

from config import get_settings
from models.attack import (
    AttackEvent,
    AttackFilter,
    GeoInfo,
    HoneypotType,
    Severity,
)

log = logging.getLogger(__name__)


class ESClient:
    _instance: Optional["ESClient"] = None

    def __init__(self) -> None:
        settings = get_settings()
        self.settings = settings
        self.client = AsyncElasticsearch(
            settings.es_host,
            request_timeout=settings.es_request_timeout,
            retry_on_timeout=True,
            max_retries=3,
        )

    @classmethod
    def instance(cls) -> "ESClient":
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    async def close(self) -> None:
        await self.client.close()

    async def ping(self) -> bool:
        try:
            return await self.client.ping()
        except Exception as exc:
            log.warning("ES ping failed: %s", exc)
            return False

    # ---------- index bootstrap ----------
    async def ensure_internal_indices(self) -> None:
        """Create the indices owned by the backend if they don't yet exist."""
        mappings = {
            self.settings.es_index_alerts: {
                "properties": {
                    "timestamp": {"type": "date"},
                    "severity": {"type": "keyword"},
                    "threat_type": {"type": "keyword"},
                    "source_ip": {"type": "ip"},
                    "country": {"type": "keyword"},
                    "honeypot": {"type": "keyword"},
                    "risk_score": {"type": "integer"},
                    "attempts": {"type": "integer"},
                    "mitre_tags": {"type": "keyword"},
                    "yara_match": {"type": "keyword"},
                    "abuseipdb_score": {"type": "integer"},
                    "ioc_hash": {"type": "keyword"},
                    "tsa_timestamp": {"type": "keyword"},
                    "mistral_analysis": {"type": "text"},
                    "recipients": {"type": "keyword"},
                    "dispatched": {"type": "boolean"},
                    "dispatch_error": {"type": "text"},
                }
            },
            self.settings.es_index_profiles: {
                "properties": {
                    "ip": {"type": "ip"},
                    "updated_at": {"type": "date"},
                    "mistral_analysis": {"type": "text"},
                    "risk_score": {"type": "integer"},
                }
            },
            self.settings.es_index_reports: {
                "properties": {
                    "id": {"type": "keyword"},
                    "title": {"type": "text"},
                    "scope": {"type": "keyword"},
                    "created_at": {"type": "date"},
                    "created_by": {"type": "keyword"},
                    "path": {"type": "keyword"},
                    "stix_path": {"type": "keyword"},
                    "sha256": {"type": "keyword"},
                    "tsa_timestamp": {"type": "keyword"},
                    "size_bytes": {"type": "long"},
                    "event_count": {"type": "integer"},
                }
            },
            "forenhive-config": {
                "properties": {
                    "key": {"type": "keyword"},
                    "value": {"type": "object", "enabled": True},
                }
            },
        }
        for index, mapping in mappings.items():
            if not await self.client.indices.exists(index=index):
                await self.client.indices.create(
                    index=index,
                    mappings=mapping,
                )
                log.info("created ES index %s", index)

    # ---------- query builders ----------
    @staticmethod
    def _severity_from_doc(src: Dict[str, Any]) -> Severity:
        level = (
            src.get("severity")
            or src.get("event", {}).get("severity")
            or src.get("log", {}).get("level")
        )
        if isinstance(level, int):
            if level >= 4:
                return Severity.CRITICAL
            if level == 3:
                return Severity.HIGH
            if level == 2:
                return Severity.MEDIUM
            return Severity.LOW
        if isinstance(level, str):
            level = level.lower()
            if level in ("critical", "emerg", "alert"):
                return Severity.CRITICAL
            if level in ("high", "error", "err"):
                return Severity.HIGH
            if level in ("medium", "warn", "warning"):
                return Severity.MEDIUM
        return Severity.LOW

    @staticmethod
    def _honeypot_from_doc(src: Dict[str, Any], index: str) -> HoneypotType:
        hp = (
            src.get("honeypot")
            or src.get("fileset", {}).get("module")
            or src.get("service", {}).get("type")
        )
        if hp:
            hp = str(hp).lower()
            for k in HoneypotType:
                if k.value in hp:
                    return k
        for k in HoneypotType:
            if k.value in index:
                return k
        return HoneypotType.UNKNOWN

    def _doc_to_event(self, doc: Dict[str, Any]) -> AttackEvent:
        src = doc.get("_source", {})
        geo_src = src.get("source", {}).get("geo") or src.get("geoip") or {}
        asn_src = src.get("source", {}).get("as") or {}
        geo = None
        if geo_src or asn_src:
            loc = geo_src.get("location")
            if isinstance(loc, dict) and "lat" in loc and "lon" in loc:
                location = {"lat": float(loc["lat"]), "lon": float(loc["lon"])}
            else:
                location = None
            geo = GeoInfo(
                country_name=geo_src.get("country_name"),
                country_iso=geo_src.get("country_iso_code") or geo_src.get("country_code2"),
                city=geo_src.get("city_name"),
                location=location,
                asn=asn_src.get("number"),
                as_org=asn_src.get("organization", {}).get("name")
                if isinstance(asn_src.get("organization"), dict)
                else asn_src.get("organization"),
            )

        ts_raw = src.get("@timestamp") or src.get("timestamp")
        try:
            ts = datetime.fromisoformat(str(ts_raw).replace("Z", "+00:00"))
        except Exception:
            ts = datetime.now(timezone.utc)

        return AttackEvent(
            id=doc.get("_id", ""),
            timestamp=ts,
            honeypot=self._honeypot_from_doc(src, doc.get("_index", "")),
            source_ip=(src.get("source") or {}).get("ip") or src.get("src_ip"),
            source_port=(src.get("source") or {}).get("port") or src.get("src_port"),
            dest_port=(src.get("destination") or {}).get("port") or src.get("dst_port"),
            protocol=(src.get("network") or {}).get("protocol") or src.get("protocol"),
            severity=self._severity_from_doc(src),
            risk_score=src.get("risk_score"),
            event_type=src.get("eventid") or (src.get("event") or {}).get("type"),
            session_id=src.get("session") or src.get("session_id"),
            username=(src.get("user") or {}).get("name") or src.get("username"),
            password=src.get("password"),
            command=src.get("input") or src.get("command"),
            http_method=(src.get("http") or {}).get("request", {}).get("method"),
            http_path=(src.get("url") or {}).get("path") or (src.get("http") or {}).get("path"),
            user_agent=(src.get("user_agent") or {}).get("original"),
            geo=geo,
            raw=src,
        )

    def _build_filter_query(self, f: AttackFilter) -> Dict[str, Any]:
        must: List[Dict[str, Any]] = []
        filt: List[Dict[str, Any]] = []
        if f.ip:
            filt.append({"term": {"source.ip": f.ip}})
        if f.country:
            filt.append({"term": {"source.geo.country_iso_code": f.country.upper()}})
        if f.severity:
            filt.append({"term": {"severity": f.severity.value}})
        if f.honeypot:
            filt.append(
                {
                    "bool": {
                        "should": [
                            {"term": {"honeypot": f.honeypot.value}},
                            {"wildcard": {"_index": f"*{f.honeypot.value}*"}},
                        ]
                    }
                }
            )
        if f.date_from or f.date_to:
            rng: Dict[str, str] = {}
            if f.date_from:
                rng["gte"] = f.date_from.isoformat()
            if f.date_to:
                rng["lte"] = f.date_to.isoformat()
            filt.append({"range": {"@timestamp": rng}})
        if not must and not filt:
            return {"match_all": {}}
        return {"bool": {"must": must or [{"match_all": {}}], "filter": filt}}

    # ---------- queries ----------
    async def search_attacks(self, f: AttackFilter) -> Tuple[int, List[AttackEvent]]:
        body = {
            "query": self._build_filter_query(f),
            "sort": [{"@timestamp": {"order": "desc"}}],
            "from": (f.page - 1) * f.page_size,
            "size": f.page_size,
            "track_total_hits": True,
        }
        resp = await self.client.search(
            index=self.settings.honeypot_indices,
            body=body,
            ignore_unavailable=True,
            allow_no_indices=True,
        )
        hits = resp["hits"]
        total = hits["total"]["value"] if isinstance(hits["total"], dict) else hits["total"]
        events = [self._doc_to_event(h) for h in hits["hits"]]
        return total, events

    async def get_attack(self, doc_id: str) -> Optional[AttackEvent]:
        body = {"query": {"ids": {"values": [doc_id]}}, "size": 1}
        resp = await self.client.search(
            index=self.settings.honeypot_indices,
            body=body,
            ignore_unavailable=True,
            allow_no_indices=True,
        )
        hits = resp["hits"]["hits"]
        return self._doc_to_event(hits[0]) if hits else None

    async def count_last_seconds(self, seconds: int) -> int:
        body = {
            "query": {"range": {"@timestamp": {"gte": f"now-{seconds}s"}}},
        }
        resp = await self.client.count(
            index=self.settings.honeypot_indices,
            body=body,
            ignore_unavailable=True,
            allow_no_indices=True,
        )
        return int(resp.get("count", 0))

    async def hourly_breakdown(self, hours: int = 24) -> List[Dict[str, Any]]:
        body = {
            "size": 0,
            "query": {"range": {"@timestamp": {"gte": f"now-{hours}h"}}},
            "aggs": {
                "per_hour": {
                    "date_histogram": {
                        "field": "@timestamp",
                        "fixed_interval": "1h",
                        "min_doc_count": 0,
                    },
                    "aggs": {
                        "per_honeypot": {"terms": {"field": "honeypot", "size": 10}},
                    },
                }
            },
        }
        resp = await self.client.search(
            index=self.settings.honeypot_indices,
            body=body,
            ignore_unavailable=True,
            allow_no_indices=True,
        )
        buckets = []
        for b in resp["aggregations"]["per_hour"]["buckets"]:
            per_hp = {sub["key"]: sub["doc_count"] for sub in b["per_honeypot"]["buckets"]}
            buckets.append(
                {
                    "hour": datetime.fromtimestamp(b["key"] / 1000, tz=timezone.utc),
                    "count": b["doc_count"],
                    "by_honeypot": per_hp,
                }
            )
        return buckets

    async def country_breakdown(self, top: int = 25) -> List[Dict[str, Any]]:
        body = {
            "size": 0,
            "aggs": {
                "countries": {
                    "terms": {"field": "source.geo.country_iso_code", "size": top},
                    "aggs": {
                        "name": {"terms": {"field": "source.geo.country_name", "size": 1}},
                        "unique_ips": {"cardinality": {"field": "source.ip"}},
                        "avg_risk": {"avg": {"field": "risk_score"}},
                    },
                }
            },
        }
        resp = await self.client.search(
            index=self.settings.honeypot_indices,
            body=body,
            ignore_unavailable=True,
            allow_no_indices=True,
        )
        out = []
        for b in resp["aggregations"]["countries"]["buckets"]:
            name_bucket = b["name"]["buckets"]
            name = name_bucket[0]["key"] if name_bucket else b["key"]
            avg_risk = b["avg_risk"]["value"] or 0
            risk_level = (
                "critical" if avg_risk >= 80
                else "high" if avg_risk >= 60
                else "medium" if avg_risk >= 40
                else "low"
            )
            out.append(
                {
                    "country_iso": b["key"],
                    "country_name": name,
                    "hits": b["doc_count"],
                    "unique_ips": b["unique_ips"]["value"],
                    "avg_risk_score": round(avg_risk, 1),
                    "risk_level": risk_level,
                }
            )
        return out

    async def honeypot_split(self) -> List[Dict[str, Any]]:
        body = {
            "size": 0,
            "aggs": {
                "per_honeypot": {"terms": {"field": "honeypot", "size": 10, "missing": "unknown"}}
            },
        }
        resp = await self.client.search(
            index=self.settings.honeypot_indices,
            body=body,
            ignore_unavailable=True,
            allow_no_indices=True,
        )
        buckets = resp["aggregations"]["per_honeypot"]["buckets"]
        total = sum(b["doc_count"] for b in buckets) or 1
        return [
            {
                "honeypot": b["key"],
                "count": b["doc_count"],
                "percent": round(b["doc_count"] / total * 100, 2),
            }
            for b in buckets
        ]

    async def sessions(
        self, limit: int = 100, active_only: bool = False
    ) -> List[Dict[str, Any]]:
        must: List[Dict[str, Any]] = []
        if active_only:
            must.append({"range": {"@timestamp": {"gte": "now-10m"}}})
        body: Dict[str, Any] = {
            "size": 0,
            "query": {"bool": {"must": must or [{"match_all": {}}]}},
            "aggs": {
                "sessions": {
                    "terms": {"field": "session", "size": limit, "order": {"latest": "desc"}},
                    "aggs": {
                        "latest": {"max": {"field": "@timestamp"}},
                        "earliest": {"min": {"field": "@timestamp"}},
                        "honeypot": {"terms": {"field": "honeypot", "size": 1}},
                        "src_ip": {"terms": {"field": "source.ip", "size": 1}},
                        "src_port": {"terms": {"field": "source.port", "size": 1}},
                        "username": {"terms": {"field": "user.name", "size": 1}},
                        "cmd_count": {
                            "filter": {"term": {"eventid": "cowrie.command.input"}}
                        },
                        "auth_count": {
                            "filter": {
                                "bool": {
                                    "should": [
                                        {"term": {"eventid": "cowrie.login.success"}},
                                        {"term": {"eventid": "cowrie.login.failed"}},
                                    ]
                                }
                            }
                        },
                    },
                }
            },
        }
        resp = await self.client.search(
            index=self.settings.honeypot_indices,
            body=body,
            ignore_unavailable=True,
            allow_no_indices=True,
        )
        out = []
        for b in resp["aggregations"]["sessions"]["buckets"]:
            latest = datetime.fromtimestamp(b["latest"]["value"] / 1000, tz=timezone.utc)
            earliest = datetime.fromtimestamp(b["earliest"]["value"] / 1000, tz=timezone.utc)
            hp_b = b["honeypot"]["buckets"]
            ip_b = b["src_ip"]["buckets"]
            user_b = b["username"]["buckets"]
            port_b = b["src_port"]["buckets"]
            active = (datetime.now(tz=timezone.utc) - latest).total_seconds() < 600
            out.append(
                {
                    "session_id": b["key"],
                    "honeypot": hp_b[0]["key"] if hp_b else "unknown",
                    "source_ip": ip_b[0]["key"] if ip_b else None,
                    "source_port": port_b[0]["key"] if port_b else None,
                    "username": user_b[0]["key"] if user_b else None,
                    "started_at": earliest,
                    "ended_at": None if active else latest,
                    "duration_seconds": (latest - earliest).total_seconds(),
                    "command_count": b["cmd_count"]["doc_count"],
                    "auth_attempts": b["auth_count"]["doc_count"],
                    "event_count": b["doc_count"],
                    "status": "active" if active else "closed",
                }
            )
        return out

    async def session_detail(self, session_id: str) -> Optional[Dict[str, Any]]:
        body = {
            "size": 500,
            "query": {"term": {"session": session_id}},
            "sort": [{"@timestamp": {"order": "asc"}}],
        }
        resp = await self.client.search(
            index=self.settings.honeypot_indices,
            body=body,
            ignore_unavailable=True,
            allow_no_indices=True,
        )
        hits = resp["hits"]["hits"]
        if not hits:
            return None
        events = [h["_source"] for h in hits]
        first = events[0]
        last = events[-1]
        commands, downloads, logins = [], [], []
        for e in events:
            evid = e.get("eventid", "")
            ts = e.get("@timestamp")
            if evid == "cowrie.command.input":
                commands.append({"timestamp": ts, "input": e.get("input"), "success": True})
            elif evid in ("cowrie.session.file_download", "cowrie.session.file_upload"):
                url = e.get("url") or e.get("outfile")
                if url:
                    downloads.append(str(url))
            elif evid.startswith("cowrie.login"):
                logins.append(
                    {
                        "success": evid == "cowrie.login.success",
                        "username": e.get("username") or (e.get("user") or {}).get("name"),
                        "password": e.get("password"),
                        "timestamp": ts,
                    }
                )
        try:
            started = datetime.fromisoformat(str(first["@timestamp"]).replace("Z", "+00:00"))
            ended = datetime.fromisoformat(str(last["@timestamp"]).replace("Z", "+00:00"))
        except Exception:
            started = ended = datetime.now(tz=timezone.utc)
        return {
            "session_id": session_id,
            "honeypot": first.get("honeypot", "unknown"),
            "source_ip": (first.get("source") or {}).get("ip") or first.get("src_ip"),
            "source_port": (first.get("source") or {}).get("port"),
            "username": (first.get("user") or {}).get("name") or first.get("username"),
            "started_at": started,
            "ended_at": ended,
            "duration_seconds": (ended - started).total_seconds(),
            "command_count": len(commands),
            "auth_attempts": len(logins),
            "status": "closed",
            "commands": commands,
            "downloads": downloads,
            "login_attempts": logins,
        }

    async def mark_session_closed(self, session_id: str) -> bool:
        body = {
            "script": {"source": "ctx._source.session_closed_by_admin = true"},
            "query": {"term": {"session": session_id}},
        }
        try:
            resp = await self.client.update_by_query(
                index=self.settings.honeypot_indices,
                body=body,
                conflicts="proceed",
                ignore_unavailable=True,
                allow_no_indices=True,
            )
            return int(resp.get("updated", 0)) > 0
        except Exception as exc:
            log.warning("force close failed: %s", exc)
            return False

    async def events_for_ip(self, ip: str, size: int = 200) -> List[Dict[str, Any]]:
        body = {
            "size": size,
            "query": {"term": {"source.ip": ip}},
            "sort": [{"@timestamp": {"order": "desc"}}],
        }
        resp = await self.client.search(
            index=self.settings.honeypot_indices,
            body=body,
            ignore_unavailable=True,
            allow_no_indices=True,
        )
        return [h["_source"] | {"_id": h["_id"]} for h in resp["hits"]["hits"]]

    async def profile_aggregates(self, ip: str) -> Dict[str, Any]:
        body = {
            "size": 0,
            "query": {"term": {"source.ip": ip}},
            "aggs": {
                "first_seen": {"min": {"field": "@timestamp"}},
                "last_seen": {"max": {"field": "@timestamp"}},
                "honeypots": {"terms": {"field": "honeypot", "size": 10}},
                "sessions": {"cardinality": {"field": "session"}},
                "usernames": {"terms": {"field": "user.name", "size": 10}},
                "passwords": {"terms": {"field": "password", "size": 10}},
                "commands": {"terms": {"field": "input.keyword", "size": 10}},
                "country": {"terms": {"field": "source.geo.country_name", "size": 1}},
                "country_iso": {"terms": {"field": "source.geo.country_iso_code", "size": 1}},
                "city": {"terms": {"field": "source.geo.city_name", "size": 1}},
                "asn": {"terms": {"field": "source.as.number", "size": 1}},
                "as_org": {"terms": {"field": "source.as.organization.name", "size": 1}},
                "total": {"value_count": {"field": "@timestamp"}},
            },
        }
        resp = await self.client.search(
            index=self.settings.honeypot_indices,
            body=body,
            ignore_unavailable=True,
            allow_no_indices=True,
        )
        return resp["aggregations"]

    # ---------- generic index ops ----------
    async def index_doc(self, index: str, doc_id: str, body: Dict[str, Any]) -> None:
        await self.client.index(index=index, id=doc_id, document=body, refresh="wait_for")

    async def get_doc(self, index: str, doc_id: str) -> Optional[Dict[str, Any]]:
        try:
            resp = await self.client.get(index=index, id=doc_id)
            return resp["_source"]
        except NotFoundError:
            return None

    async def delete_doc(self, index: str, doc_id: str) -> bool:
        try:
            await self.client.delete(index=index, id=doc_id, refresh="wait_for")
            return True
        except NotFoundError:
            return False

    async def search_docs(self, index: str, body: Dict[str, Any]) -> Dict[str, Any]:
        return await self.client.search(index=index, body=body, ignore_unavailable=True)

    async def bulk_index(self, actions: List[Dict[str, Any]]) -> None:
        await async_bulk(self.client, actions)


def get_es() -> ESClient:
    return ESClient.instance()
