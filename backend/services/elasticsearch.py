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
                return Severity.critical
            if level == 3:
                return Severity.high
            if level == 2:
                return Severity.medium
            return Severity.low
        if isinstance(level, str):
            level = level.lower()
            if level in ("critical", "emerg", "alert"):
                return Severity.critical
            if level in ("high", "error", "err"):
                return Severity.high
            if level in ("medium", "warn", "warning"):
                return Severity.medium
        return Severity.low

    @staticmethod
    def _f(src: Dict[str, Any], *keys: str):
        """Get a value from src, trying nested object access first then dot-notation fallback.
        Handles both Logstash dot-notation keys ("source.ip") and nested dicts ({"source": {"ip": ...}}).
        """
        result = src
        for k in keys:
            if isinstance(result, dict):
                result = result.get(k)
            else:
                result = None
                break
        if result is not None:
            return result
        return src.get(".".join(keys))

    @staticmethod
    def _honeypot_from_doc(src: Dict[str, Any], index: str) -> HoneypotType:
        fileset = src.get("fileset") if isinstance(src.get("fileset"), dict) else {}
        service = src.get("service") if isinstance(src.get("service"), dict) else {}
        # handle both {"honeypot": {"type": "cowrie"}} and {"honeypot.type": "cowrie"}
        hp_raw = src.get("honeypot")
        hp = (
            (hp_raw.get("type") if isinstance(hp_raw, dict) else hp_raw)
            or src.get("honeypot.type")
            or fileset.get("module")
            or service.get("type")
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
        f = self._f

        # Geo: handle {"source": {"geo": {...}}} and {"source.geo": {...}}
        # Zeek events store geo as {"source.geo": {"ip": ..., "geo": {...}}} with an extra nesting level
        geo_src = f(src, "source", "geo") or src.get("source.geo") or src.get("geoip") or {}
        asn_src = f(src, "source", "as") or src.get("source.as") or {}
        if not isinstance(geo_src, dict):
            geo_src = {}
        if not isinstance(asn_src, dict):
            asn_src = {}
        # Unwrap Zeek's extra geo nesting: {"ip":..., "geo": {"country_name":..., "location":...}}
        if isinstance(geo_src.get("geo"), dict):
            geo_src = geo_src["geo"]

        geo = None
        if geo_src or asn_src:
            loc = geo_src.get("location")
            if isinstance(loc, dict) and "lat" in loc and "lon" in loc:
                location = {"lat": float(loc["lat"]), "lon": float(loc["lon"])}
            else:
                location = None
            org_raw = asn_src.get("organization")
            as_org = (org_raw.get("name") if isinstance(org_raw, dict) else org_raw)
            geo = GeoInfo(
                country_name=geo_src.get("country_name"),
                country_iso=geo_src.get("country_iso_code") or geo_src.get("country_code2"),
                city=geo_src.get("city_name"),
                location=location,
                asn=asn_src.get("number"),
                as_org=as_org,
            )

        ts_raw = src.get("@timestamp") or src.get("timestamp")
        try:
            ts = datetime.fromisoformat(str(ts_raw).replace("Z", "+00:00"))
        except Exception:
            ts = datetime.now(timezone.utc)

        # session_id: handle {"session": {"id": "..."}} and {"session": "..."} and {"session.id": "..."}
        sess_raw = src.get("session")
        session_id = (
            (sess_raw.get("id") if isinstance(sess_raw, dict) else sess_raw)
            or src.get("session.id")
            or src.get("session_id")
        )

        # event_type: handle {"event": {"id": "cowrie.login.failed"}} and {"eventid": "..."} and {"event.id": "..."}
        ev_raw = src.get("event")
        event_type = (
            src.get("eventid")
            or src.get("event.id")
            or (ev_raw.get("id") if isinstance(ev_raw, dict) else None)
            or (ev_raw.get("type") if isinstance(ev_raw, dict) else None)
            or src.get("event.type")
        )

        # username/password: handle nested and dot-notation
        user_raw = src.get("user")
        username = (
            (user_raw.get("name") if isinstance(user_raw, dict) else None)
            or src.get("user.name")
            or src.get("username")
        )
        password = (
            (user_raw.get("password") if isinstance(user_raw, dict) else None)
            or src.get("user.password")
            or src.get("password")
        )

        return AttackEvent(
            id=doc.get("_id", ""),
            timestamp=ts,
            honeypot=self._honeypot_from_doc(src, doc.get("_index", "")),
            source_ip=f(src, "source", "ip") or src.get("source.ip") or src.get("src_ip"),
            source_port=f(src, "source", "port") or src.get("source.port") or src.get("src_port"),
            dest_port=f(src, "destination", "port") or src.get("destination.port") or src.get("dst_port"),
            protocol=f(src, "network", "protocol") or src.get("network.protocol") or src.get("protocol"),
            severity=self._severity_from_doc(src),
            risk_score=src.get("risk_score"),
            event_type=event_type,
            session_id=session_id,
            username=username,
            password=password,
            command=src.get("input") or src.get("cowrie.input") or src.get("command"),
            http_method=f(src, "http", "request", "method") or src.get("http.request.method"),
            http_path=(f(src, "url", "path") or src.get("url.path")
                       or f(src, "http", "request", "uri") or src.get("http.request.uri")),
            user_agent=(f(src, "user_agent", "original") or src.get("user_agent.original")
                        or f(src, "http", "request", "user_agent") or src.get("http.request.user_agent")),
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
                {"term": {"honeypot.type.keyword": f.honeypot.value}}
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
                        "per_honeypot": {"terms": {"field": "honeypot.type.keyword", "size": 10}},
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
                        "unique_ips": {"cardinality": {"field": "source.ip.keyword"}},
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

    async def top_attackers(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Aggregate the top attacker IPs with summary stats.

        One row per source.ip with event_count, distinct honeypots, country,
        and average risk_score. Used by /api/profiling listing.
        """
        body = {
            "size": 0,
            "query": {"bool": {"must": [{"exists": {"field": "source.ip"}}], "filter": [
                {"terms": {"honeypot.type.keyword": ["cowrie", "dionaea", "galah"]}}
            ]}},
            "aggs": {
                "ips": {
                    "terms": {"field": "source.ip.keyword", "size": limit},
                    "aggs": {
                        "honeypots": {"terms": {"field": "honeypot.type.keyword", "size": 5}},
                        "country": {"terms": {"field": "source.geo.country_iso_code", "size": 1}},
                        "avg_risk": {"avg": {"field": "risk_score"}},
                        "max_risk": {"max": {"field": "risk_score"}},
                        "first_seen": {"min": {"field": "@timestamp"}},
                        "last_seen": {"max": {"field": "@timestamp"}},
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
        out: List[Dict[str, Any]] = []
        for b in resp["aggregations"]["ips"]["buckets"]:
            avg = float(b["avg_risk"]["value"] or 0)
            mx = float(b["max_risk"]["value"] or 0)
            score = round(max(avg, mx), 1)
            severity = (
                "CRITICAL" if score >= 80
                else "HIGH" if score >= 60
                else "MEDIUM" if score >= 40
                else "LOW"
            )
            country_buckets = b["country"]["buckets"]
            out.append({
                "source_ip": b["key"],
                "event_count": b["doc_count"],
                "honeypots": [hp["key"] for hp in b["honeypots"]["buckets"]],
                "country": country_buckets[0]["key"] if country_buckets else None,
                "risk_score": score,
                "severity": severity,
                "first_seen": b["first_seen"].get("value_as_string"),
                "last_seen": b["last_seen"].get("value_as_string"),
            })
        return out

    async def honeypot_split(self) -> List[Dict[str, Any]]:
        body = {
            "size": 0,
            "aggs": {
                "per_honeypot": {"terms": {"field": "honeypot.type.keyword", "size": 10, "missing": "unknown"}}
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
                    "terms": {"field": "session.id.keyword", "size": limit, "order": {"latest": "desc"}},
                    "aggs": {
                        "latest": {"max": {"field": "@timestamp"}},
                        "earliest": {"min": {"field": "@timestamp"}},
                        "honeypot": {"terms": {"field": "honeypot.type.keyword", "size": 1}},
                        "src_ip": {"terms": {"field": "source.ip.keyword", "size": 1}},
                        "src_port": {"terms": {"field": "source.port", "size": 1}},
                        "username": {"terms": {"field": "user.name.keyword", "size": 1}},
                        "cmd_count": {
                            "filter": {"bool": {"should": [
                                {"term": {"eventid": "cowrie.command.input"}},
                                {"term": {"event.id": "cowrie.command.input"}},
                            ]}}
                        },
                        "auth_count": {
                            "filter": {
                                "bool": {
                                    "should": [
                                        {"term": {"eventid": "cowrie.login.success"}},
                                        {"term": {"eventid": "cowrie.login.failed"}},
                                        {"term": {"event.id": "cowrie.login.success"}},
                                        {"term": {"event.id": "cowrie.login.failed"}},
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
            "query": {"bool": {"should": [
                {"term": {"session.id.keyword": session_id}},
                {"term": {"session": session_id}},
                {"term": {"session_id": session_id}},
            ], "minimum_should_match": 1}},
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
            evid = (e.get("eventid") or e.get("event.id")
                    or (e.get("event") or {}).get("id", ""))
            ts = e.get("@timestamp")
            if evid == "cowrie.command.input":
                cmd = e.get("input") or e.get("cowrie.input") or (e.get("process") or {}).get("command_line")
                commands.append({"timestamp": ts, "input": cmd, "success": True})
            elif evid in ("cowrie.session.file_download", "cowrie.session.file_upload"):
                url = e.get("url") or e.get("outfile")
                if url:
                    downloads.append(str(url))
            elif evid.startswith("cowrie.login"):
                user_raw = e.get("user")
                logins.append(
                    {
                        "success": evid == "cowrie.login.success",
                        "username": (user_raw.get("name") if isinstance(user_raw, dict) else None)
                                    or e.get("user.name") or e.get("username"),
                        "password": (user_raw.get("password") if isinstance(user_raw, dict) else None)
                                    or e.get("user.password") or e.get("password"),
                        "timestamp": ts,
                    }
                )
        try:
            started = datetime.fromisoformat(str(first["@timestamp"]).replace("Z", "+00:00"))
            ended = datetime.fromisoformat(str(last["@timestamp"]).replace("Z", "+00:00"))
        except Exception:
            started = ended = datetime.now(tz=timezone.utc)
        hp_raw = first.get("honeypot")
        hp_str = (hp_raw.get("type") if isinstance(hp_raw, dict) else hp_raw) or first.get("honeypot.type", "unknown")
        src_raw = first.get("source")
        src_ip = (src_raw.get("ip") if isinstance(src_raw, dict) else None) or first.get("source.ip") or first.get("src_ip")
        src_port = (src_raw.get("port") if isinstance(src_raw, dict) else None) or first.get("source.port")
        user_raw = first.get("user")
        uname = (user_raw.get("name") if isinstance(user_raw, dict) else None) or first.get("user.name") or first.get("username")
        return {
            "session_id": session_id,
            "honeypot": hp_str,
            "source_ip": src_ip,
            "source_port": src_port,
            "username": uname,
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
            "query": {"bool": {"should": [
                {"term": {"session.id.keyword": session_id}},
                {"term": {"session": session_id}},
            ], "minimum_should_match": 1}},
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
            "query": {"bool": {"must": [{"term": {"source.ip": ip}}], "filter": [
                {"terms": {"honeypot.type.keyword": ["cowrie", "dionaea", "galah"]}}
            ]}},
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
            "query": {"bool": {"must": [{"term": {"source.ip": ip}}], "filter": [
                {"terms": {"honeypot.type.keyword": ["cowrie", "dionaea", "galah"]}}
            ]}},
            "aggs": {
                "first_seen": {"min": {"field": "@timestamp"}},
                "last_seen": {"max": {"field": "@timestamp"}},
                "honeypots": {"terms": {"field": "honeypot.type.keyword", "size": 10}},
                "sessions": {"cardinality": {"field": "session.id.keyword"}},
                "usernames": {"terms": {"field": "user.name.keyword", "size": 10}},
                "passwords": {"terms": {"field": "user.password.keyword", "size": 10}},
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
