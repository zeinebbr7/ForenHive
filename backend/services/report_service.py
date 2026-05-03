from __future__ import annotations

import json
import logging
import os
import uuid
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from jinja2 import Environment, FileSystemLoader, select_autoescape

from config import get_settings
from models.report import AttackerProfile, ReportMeta, ReportRequest, ReportScope
from services.chain_custody import get_custody
from services.elasticsearch import get_es

log = logging.getLogger(__name__)

TEMPLATE_DIR = Path(__file__).resolve().parent.parent / "templates"


class ReportService:
    def __init__(self) -> None:
        self.settings = get_settings()
        self.env = Environment(
            loader=FileSystemLoader(TEMPLATE_DIR),
            autoescape=select_autoescape(["html", "xml"]),
        )
        Path(self.settings.reports_dir).mkdir(parents=True, exist_ok=True)

    async def _collect_events(self, req: ReportRequest) -> List[Dict[str, Any]]:
        es = get_es()
        if req.scope == ReportScope.IP:
            return await es.events_for_ip(req.ip or "", size=500)
        if req.scope == ReportScope.SESSION:
            detail = await es.session_detail(req.session_id or "")
            if not detail:
                return []
            return detail.get("commands", []) + detail.get("login_attempts", [])
        # time range
        body = {
            "size": 500,
            "query": {
                "range": {
                    "@timestamp": {
                        "gte": (req.date_from or datetime.now(tz=timezone.utc)).isoformat(),
                        "lte": (req.date_to or datetime.now(tz=timezone.utc)).isoformat(),
                    }
                }
            },
            "sort": [{"@timestamp": {"order": "desc"}}],
        }
        resp = await es.search_docs(self.settings.honeypot_indices, body)
        return [h["_source"] | {"_id": h["_id"]} for h in resp["hits"]["hits"]]

    async def _collect_forensic_data(self, req: ReportRequest) -> Dict[str, Any]:
        """Fetch enrichment + forensic data from PostgreSQL for the report."""
        import asyncpg
        import json as _json
        data: Dict[str, Any] = {
            "sessions": [], "enrichment": None, "iocs": [], "profiles": []
        }

        def _parse_json(v: Any) -> Any:
            """asyncpg returns jsonb as str; normalize to dict/list."""
            if isinstance(v, str):
                try:
                    return _json.loads(v)
                except Exception:
                    return v
            return v

        try:
            conn = await asyncpg.connect(
                host=self.settings.pg_host,
                port=self.settings.pg_port,
                database=self.settings.pg_db,
                user=self.settings.pg_user,
                password=self.settings.pg_password or "",
            )
            # Sessions forensiques
            if req.scope == ReportScope.IP and req.ip:
                rows = await conn.fetch(
                    """SELECT session_id, honeypot_type, source_ip, risk_score,
                              kill_chain_phase, kill_chain_stage, primary_technique,
                              mitre_techniques, forensic_narrative, started_at, ended_at
                       FROM forensic_sessions WHERE source_ip = $1
                       ORDER BY risk_score DESC NULLS LAST""", req.ip)
                sessions = []
                for r in rows:
                    d = dict(r)
                    d["mitre_techniques"] = _parse_json(d.get("mitre_techniques"))
                    sessions.append(d)
                data["sessions"] = sessions
                # Enrichissement IP
                row = await conn.fetchrow(
                    "SELECT data FROM ip_enrichment_cache WHERE ip = $1", req.ip)
                if row:
                    data["enrichment"] = _parse_json(row["data"])
                # IOCs
                ioc_rows = await conn.fetch(
                    """SELECT ioc_type, ioc_value, occurrences, first_seen, last_seen
                       FROM forensic_iocs WHERE source_ip = $1
                       ORDER BY occurrences DESC LIMIT 30""", req.ip)
                data["iocs"] = [dict(r) for r in ioc_rows]
            elif req.scope == ReportScope.SESSION and req.session_id:
                row = await conn.fetchrow(
                    """SELECT session_id, honeypot_type, source_ip, risk_score,
                              kill_chain_phase, kill_chain_stage, primary_technique,
                              mitre_techniques, forensic_narrative, started_at, ended_at
                       FROM forensic_sessions WHERE session_id = $1""", req.session_id)
                if row:
                    d = dict(row)
                    d["mitre_techniques"] = _parse_json(d.get("mitre_techniques"))
                    data["sessions"] = [d]
                    ip = row["source_ip"]
                    enrich = await conn.fetchrow(
                        "SELECT data FROM ip_enrichment_cache WHERE ip = $1", ip)
                    if enrich:
                        data["enrichment"] = _parse_json(enrich["data"])
                    ioc_rows = await conn.fetch(
                        """SELECT ioc_type, ioc_value, occurrences
                           FROM forensic_iocs WHERE source_ip = $1
                           ORDER BY occurrences DESC LIMIT 20""", ip)
                    data["iocs"] = [dict(r) for r in ioc_rows]
            await conn.close()
        except Exception as exc:
            log.warning("Could not fetch forensic data from PostgreSQL: %s", exc)
        return data

    async def generate(self, req: ReportRequest) -> ReportMeta:
        # WeasyPrint is imported lazily so the app can still boot if libs are missing.
        from weasyprint import HTML

        report_id = str(uuid.uuid4())
        events = await self._collect_events(req)
        forensic = await self._collect_forensic_data(req)
        title = req.title or self._default_title(req)
        summary = self._summarize(events)

        html_body = self.env.get_template("report.html").render(
            report_id=report_id,
            title=title,
            scope=req.scope.value,
            created_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
            analyst=req.analyst or "ForenHive",
            request=req.model_dump(mode="json"),
            events=events[:200],
            event_count=len(events),
            summary=summary,
            sessions=forensic["sessions"],
            enrichment=forensic["enrichment"],
            iocs=forensic["iocs"],
        )
        out_dir = Path(self.settings.reports_dir)
        out_dir.mkdir(parents=True, exist_ok=True)
        pdf_path = out_dir / f"{report_id}.pdf"
        HTML(string=html_body).write_pdf(str(pdf_path))
        size = pdf_path.stat().st_size

        with open(pdf_path, "rb") as fp:
            pdf_bytes = fp.read()
        custody = await get_custody().seal(pdf_bytes)

        stix_path: Optional[str] = None
        if req.include_stix:
            stix_bundle = self.build_stix_bundle(events, title)
            stix_file = out_dir / f"{report_id}.stix.json"
            stix_file.write_text(json.dumps(stix_bundle, indent=2))
            stix_path = str(stix_file)

        meta = ReportMeta(
            id=report_id,
            title=title,
            scope=req.scope,
            created_at=datetime.now(timezone.utc),
            created_by=req.analyst,
            path=str(pdf_path),
            sha256=custody.sha256,
            tsa_timestamp=custody.tsa_token_b64,
            size_bytes=size,
            event_count=len(events),
            stix_path=stix_path,
        )
        await get_es().index_doc(
            self.settings.es_index_reports, report_id, meta.model_dump(mode="json")
        )
        return meta

    async def list_reports(self, limit: int = 100) -> Tuple[int, List[ReportMeta]]:
        es = get_es()
        body = {
            "size": limit,
            "sort": [{"created_at": {"order": "desc"}}],
            "track_total_hits": True,
        }
        try:
            resp = await es.search_docs(self.settings.es_index_reports, body)
        except Exception:
            return 0, []
        hits = resp["hits"]
        total = hits["total"]["value"] if isinstance(hits["total"], dict) else hits["total"]
        items = [ReportMeta.model_validate(h["_source"]) for h in hits["hits"]]
        return total, items

    async def get_meta(self, report_id: str) -> Optional[ReportMeta]:
        doc = await get_es().get_doc(self.settings.es_index_reports, report_id)
        return ReportMeta.model_validate(doc) if doc else None

    async def stix_for(self, report_id: str) -> Optional[Dict[str, Any]]:
        meta = await self.get_meta(report_id)
        if not meta:
            return None
        events: List[Dict[str, Any]] = []
        es = get_es()
        if meta.scope == ReportScope.IP:
            ip = self._extract_ip_from_title(meta.title)
            if ip:
                events = await es.events_for_ip(ip=ip, size=500)
        elif meta.scope == ReportScope.SESSION:
            sid = self._extract_session_from_title(meta.title)
            if sid:
                detail = await es.session_detail(sid)
                if detail:
                    # Reconstitute raw events for STIX observables
                    body = {
                        "size": 500,
                        "query": {"term": {"session": sid}},
                        "sort": [{"@timestamp": {"order": "asc"}}],
                    }
                    resp = await es.search_docs(self.settings.honeypot_indices, body)
                    events = [h["_source"] | {"_id": h["_id"]} for h in resp["hits"]["hits"]]
        # time_range scope: we cannot reconstruct dates from title alone — return empty bundle.

        bundle = self.build_stix_bundle(events, meta.title)
        stix_file = Path(self.settings.reports_dir) / f"{report_id}.stix.json"
        stix_file.write_text(json.dumps(bundle, indent=2))
        if not meta.stix_path:
            meta.stix_path = str(stix_file)
            await es.index_doc(
                self.settings.es_index_reports, report_id, meta.model_dump(mode="json")
            )
        return bundle

    # ---------- helpers ----------
    @staticmethod
    def _extract_ip_from_title(title: str) -> Optional[str]:
        import re
        m = re.search(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b", title)
        return m.group(1) if m else None

    @staticmethod
    def _extract_session_from_title(title: str) -> Optional[str]:
        import re
        m = re.search(r"Session\s+([A-Za-z0-9_-]+)", title)
        return m.group(1) if m else None

    @staticmethod
    def _default_title(req: ReportRequest) -> str:
        if req.scope == ReportScope.IP:
            return f"Forensic Report — IP {req.ip}"
        if req.scope == ReportScope.SESSION:
            return f"Forensic Report — Session {req.session_id}"
        return "Forensic Report — Time Range"

    @staticmethod
    def _summarize(events: List[Dict[str, Any]]) -> Dict[str, Any]:
        # ES stores fields as flat dot-notation strings ("source.ip", "honeypot.type")
        ips: Counter = Counter()
        honeypots: Counter = Counter()
        event_types: Counter = Counter()
        for e in events:
            ip = e.get("source.ip") or e.get("src_ip")
            if ip:
                ips[ip] += 1
            hp = e.get("honeypot.type") or e.get("honeypot")
            if hp:
                honeypots[hp] += 1
            ev = e.get("event.id") or e.get("eventid") or e.get("event.action")
            if ev:
                event_types[ev] += 1
        return {
            "top_ips": ips.most_common(10),
            "honeypots": honeypots.most_common(),
            "event_types": event_types.most_common(10),
        }

    @staticmethod
    def build_stix_bundle(events: List[Dict[str, Any]], title: str) -> Dict[str, Any]:
        now = datetime.now(tz=timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
        identity_id = f"identity--{uuid.uuid5(uuid.NAMESPACE_DNS, 'forenhive')}"
        objects: List[Dict[str, Any]] = [
            {
                "type": "identity",
                "spec_version": "2.1",
                "id": identity_id,
                "created": now,
                "modified": now,
                "name": "ForenHive",
                "identity_class": "system",
            }
        ]

        ip_seen: Dict[str, str] = {}
        hash_seen: Dict[str, str] = {}

        for e in events:
            src = (e.get("source") or {})
            ip = src.get("ip") or e.get("src_ip")
            if ip and ip not in ip_seen:
                obs_id = f"ipv4-addr--{uuid.uuid5(uuid.NAMESPACE_DNS, f'ip:{ip}')}"
                ip_seen[ip] = obs_id
                objects.append(
                    {
                        "type": "ipv4-addr",
                        "spec_version": "2.1",
                        "id": obs_id,
                        "value": ip,
                    }
                )
                ind_id = f"indicator--{uuid.uuid5(uuid.NAMESPACE_DNS, f'ind-ip:{ip}')}"
                objects.append(
                    {
                        "type": "indicator",
                        "spec_version": "2.1",
                        "id": ind_id,
                        "created_by_ref": identity_id,
                        "created": now,
                        "modified": now,
                        "name": f"Malicious IP {ip}",
                        "pattern": f"[ipv4-addr:value = '{ip}']",
                        "pattern_type": "stix",
                        "valid_from": now,
                        "indicator_types": ["malicious-activity"],
                    }
                )

            file_hash = e.get("file", {}).get("hash", {}).get("sha256") if isinstance(e.get("file"), dict) else None
            if file_hash and file_hash not in hash_seen:
                file_id = f"file--{uuid.uuid5(uuid.NAMESPACE_DNS, f'hash:{file_hash}')}"
                hash_seen[file_hash] = file_id
                objects.append(
                    {
                        "type": "file",
                        "spec_version": "2.1",
                        "id": file_id,
                        "hashes": {"SHA-256": file_hash},
                    }
                )

        report_id = f"report--{uuid.uuid4()}"
        objects.append(
            {
                "type": "report",
                "spec_version": "2.1",
                "id": report_id,
                "created_by_ref": identity_id,
                "created": now,
                "modified": now,
                "name": title,
                "published": now,
                "object_refs": [o["id"] for o in objects if o["id"] != identity_id],
                "report_types": ["threat-report"],
            }
        )

        return {
            "type": "bundle",
            "id": f"bundle--{uuid.uuid4()}",
            "objects": objects,
        }

    def resolve_pdf_path(self, meta: ReportMeta) -> Path:
        path = Path(meta.path)
        if not path.exists():
            raise FileNotFoundError(str(path))
        # prevent traversal: must live under reports_dir
        reports_root = Path(self.settings.reports_dir).resolve()
        if reports_root not in path.resolve().parents:
            raise PermissionError("report outside reports directory")
        return path


_svc: Optional[ReportService] = None


def get_reports() -> ReportService:
    global _svc
    if _svc is None:
        _svc = ReportService()
    return _svc
