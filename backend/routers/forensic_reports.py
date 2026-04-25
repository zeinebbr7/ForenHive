"""Forensic session PDF reports (WeasyPrint + Jinja2).

Runs alongside the existing report_service-based router. Endpoints:

    GET  /api/reports/forensic/sessions           list candidate sessions
    GET  /api/reports/forensic/{sid}/preview      HTML preview (debug)
    POST /api/reports/forensic/{sid}/generate     returns PDF binary
    GET  /api/reports/forensic/{sid}/pdf          same as POST, GET-friendly

Path differs from the legacy router's `{report_id}/download` to avoid
route collision.
"""
from __future__ import annotations

import hashlib
import logging
import os
from pathlib import Path

from fastapi import APIRouter, HTTPException
from fastapi.responses import HTMLResponse, Response
from jinja2 import Environment, FileSystemLoader, select_autoescape
from sqlalchemy import text
from weasyprint import HTML

from db import session_scope
from services.forensic_report_builder import build_report_data

log = logging.getLogger(__name__)

router = APIRouter(prefix="/api/reports/forensic", tags=["forensic-reports"])

TEMPLATES_DIR = Path(__file__).resolve().parent.parent / "templates"

_env = Environment(
    loader=FileSystemLoader(str(TEMPLATES_DIR)),
    autoescape=select_autoescape(["html"]),
)


async def _render_html(session_id: str) -> tuple[str, dict]:
    data = await build_report_data(session_id)
    tmpl = _env.get_template("forensic_report.html")
    return tmpl.render(**data), data


@router.get("/sessions")
async def list_candidate_sessions(limit: int = 50):
    """Sessions available for PDF generation, highest risk first."""
    async with session_scope() as db:
        rows = (await db.execute(text("""
            SELECT session_id, source_ip, honeypot_type, risk_score,
                   kill_chain_phase, primary_technique, started_at, created_at
              FROM forensic_sessions
              ORDER BY risk_score DESC NULLS LAST, created_at DESC
              LIMIT :lim
        """), {"lim": int(limit)})).mappings().all()
    return [
        {
            "session_id": r["session_id"],
            "source_ip": r["source_ip"],
            "honeypot_type": r["honeypot_type"],
            "risk_score": r["risk_score"],
            "kill_chain_phase": r["kill_chain_phase"],
            "primary_technique": r["primary_technique"],
            "started_at": str(r["started_at"]) if r["started_at"] else None,
            "created_at": str(r["created_at"]) if r["created_at"] else None,
        }
        for r in rows
    ]


@router.get("/{session_id}/preview", response_class=HTMLResponse)
async def preview(session_id: str) -> HTMLResponse:
    try:
        html, _ = await _render_html(session_id)
        return HTMLResponse(content=html)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except Exception as exc:
        log.exception("preview failed for %s", session_id)
        raise HTTPException(status_code=500, detail=f"preview error: {exc}")


async def _build_pdf(session_id: str) -> tuple[bytes, dict, str]:
    html, data = await _render_html(session_id)
    pdf_bytes = HTML(string=html, base_url=str(TEMPLATES_DIR)).write_pdf()
    pdf_sha256 = hashlib.sha256(pdf_bytes).hexdigest()
    return pdf_bytes, data, pdf_sha256


def _pdf_response(pdf_bytes: bytes, data: dict, pdf_sha256: str) -> Response:
    filename = f"ForenHive-{data['ref']}.pdf"
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "X-PDF-SHA256": pdf_sha256,
            "X-Session-ID": data["session_id"],
        },
    )


@router.post("/{session_id}/generate")
async def generate(session_id: str) -> Response:
    try:
        pdf_bytes, data, sha = await _build_pdf(session_id)
        return _pdf_response(pdf_bytes, data, sha)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except Exception as exc:
        log.exception("PDF generation failed for %s", session_id)
        raise HTTPException(status_code=500, detail=f"generation error: {exc}")


@router.get("/{session_id}/pdf")
async def download(session_id: str) -> Response:
    """GET equivalent — useful for plain-link downloads from the webapp."""
    return await generate(session_id)
