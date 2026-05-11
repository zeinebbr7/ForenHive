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

from sqlalchemy import text

from config import get_settings
from db import session_scope
from models.report import AttackerProfile, ReportMeta, ReportRequest, ReportScope
from services.chain_custody import get_custody
from services.elasticsearch import get_es
from services.report_adapter import adapt_risk_data_for_report

log = logging.getLogger(__name__)

TEMPLATE_DIR = Path(__file__).resolve().parent.parent / "templates"


async def _query_unified_risk_score(source_ip: str) -> dict:
    """Query the unified risk score from ip_risk_scores table for an IP."""
    try:
        async with session_scope() as db:
            result = await db.execute(
                text(
                    """
                    SELECT source_ip, risk_score, risk_level, confidence, active_signals,
                           signal_breakdown, honeypots_hit, honeypot_count, honeypot_summary,
                           sessions_count, key_findings, recommendations, enrichment_snapshot
                    FROM ip_risk_scores
                    WHERE source_ip = CAST(:ip AS INET)
                    LIMIT 1
                    """
                ),
                {"ip": source_ip},
            )
            row = result.mappings().first()
            if not row:
                return {}
            d = dict(row)
            d["source_ip"] = str(d["source_ip"])
            return d
    except Exception:
        return {}


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

    async def generate(self, req: ReportRequest) -> ReportMeta:
        # WeasyPrint is imported lazily so the app can still boot if libs are missing.
        from weasyprint import HTML

        report_id = str(uuid.uuid4())
        events = await self._collect_events(req)
        title = req.title or self._default_title(req)
        summary = self._summarize(events)

        # Inject unified risk score for IP-scoped reports
        risk_ctx: dict = {}
        if req.scope == ReportScope.IP and req.ip:
            raw_risk = await _query_unified_risk_score(req.ip)
            if raw_risk:
                risk_ctx = adapt_risk_data_for_report(raw_risk)

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
            **risk_ctx,
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
        ips = Counter()
        countries = Counter()
        honeypots = Counter()
        severities = Counter()
        for e in events:
            src = (e.get("source") or {})
            ip = src.get("ip") or e.get("src_ip")
            if ip:
                ips[ip] += 1
            country = (src.get("geo") or {}).get("country_name")
            if country:
                countries[country] += 1
            hp = e.get("honeypot")
            if hp:
                honeypots[hp] += 1
            sev = e.get("severity")
            if sev:
                severities[str(sev)] += 1
        return {
            "top_ips": ips.most_common(10),
            "top_countries": countries.most_common(10),
            "honeypots": honeypots.most_common(),
            "severities": severities.most_common(),
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
