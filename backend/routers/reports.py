import html
from typing import Any, Dict, List

from fastapi import APIRouter, Body, HTTPException, Query, Request
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
from slowapi import Limiter
from slowapi.util import get_remote_address
from sqlalchemy import select, text

from config import get_settings
from db import get_sessionmaker
from models.report import (
    ReportListResponse,
    ReportMeta,
    ReportRequest,
    ReportScope,
)
from services.elasticsearch import get_es
from services.report_service import get_reports

router = APIRouter(prefix="/api/reports", tags=["reports"])
limiter = Limiter(key_func=get_remote_address)
_SENSITIVE = get_settings().ratelimit_sensitive


@router.post("/generate", response_model=ReportMeta)
@limiter.limit(_SENSITIVE)
async def generate_report(request: Request, req: ReportRequest = Body(...)) -> ReportMeta:
    if req.scope.value == "ip" and not req.ip:
        raise HTTPException(status_code=400, detail="ip required for ip scope")
    if req.scope.value == "session" and not req.session_id:
        raise HTTPException(status_code=400, detail="session_id required for session scope")
    try:
        return await get_reports().generate(req)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"report generation failed: {exc}")


@router.get("", response_model=ReportListResponse)
async def list_reports(limit: int = Query(100, ge=1, le=500)) -> ReportListResponse:
    total, items = await get_reports().list_reports(limit=limit)
    return ReportListResponse(total=total, items=items)


@router.get("/{report_id}/download")
async def download_report(report_id: str):
    svc = get_reports()
    meta = await svc.get_meta(report_id)
    if not meta:
        raise HTTPException(status_code=404, detail="report not found")
    try:
        path = svc.resolve_pdf_path(meta)
    except FileNotFoundError:
        raise HTTPException(status_code=410, detail="report file missing on disk")
    except PermissionError:
        raise HTTPException(status_code=403, detail="report path rejected")
    return FileResponse(
        path=str(path),
        media_type="application/pdf",
        filename=f"{meta.id}.pdf",
        headers={"X-ForenHive-SHA256": meta.sha256},
    )


@router.post("/{report_id}/stix")
async def export_stix(report_id: str):
    bundle = await get_reports().stix_for(report_id)
    if bundle is None:
        raise HTTPException(status_code=404, detail="report not found")
    return JSONResponse(
        bundle,
        headers={"Content-Disposition": f'attachment; filename="{report_id}.stix.json"'},
    )


# ─── Forensic per-session reports (Sprint 4 surface used by the SPA) ────────


def _phase_from_techniques(mitre: List[str]) -> str | None:
    """Coarse kill-chain phase from MITRE technique prefixes."""
    if not mitre:
        return None
    pfx = {t[:5] for t in mitre if isinstance(t, str)}
    if pfx & {"T1595", "T1590", "T1589"}: return "reconnaissance"
    if pfx & {"T1587", "T1588"}:          return "weaponization"
    if pfx & {"T1566"}:                   return "delivery"
    if pfx & {"T1190", "T1110", "T1203"}: return "exploitation"
    if pfx & {"T1547", "T1543"}:          return "installation"
    if pfx & {"T1071", "T1095"}:          return "command_and_control"
    if pfx & {"T1021", "T1550"}:          return "lateral_movement"
    return "actions_on_objectives"


@router.get("/forensic/sessions")
async def forensic_sessions(limit: int = Query(50, ge=1, le=200)) -> List[Dict[str, Any]]:
    """List enriched forensic sessions from PostgreSQL (scored by the forensic engine)."""
    async with get_sessionmaker()() as db:
        result = await db.execute(
            text(
                """
                SELECT session_id, honeypot_type, source_ip, risk_score,
                       kill_chain_phase, kill_chain_stage, primary_technique,
                       started_at, mitre_techniques
                FROM forensic_sessions
                ORDER BY risk_score DESC NULLS LAST, started_at DESC
                LIMIT :limit
                """
            ),
            {"limit": limit},
        )
        rows = result.mappings().all()

    out: List[Dict[str, Any]] = []
    for r in rows:
        mitre = r["mitre_techniques"] or []
        if isinstance(mitre, dict):
            mitre = list(mitre.values())
        out.append({
            "session_id":        r["session_id"],
            "source_ip":         r["source_ip"],
            "honeypot_type":     r["honeypot_type"],
            "risk_score":        r["risk_score"],
            "kill_chain_phase":  r["kill_chain_phase"] or _phase_from_techniques(mitre),
            "kill_chain_stage":  r["kill_chain_stage"],
            "primary_technique": r["primary_technique"] or (mitre[0] if mitre else None),
            "started_at":        r["started_at"].isoformat() if r["started_at"] else None,
        })
    return out


@router.post("/forensic/{session_id}/generate")
async def forensic_generate(request: Request, session_id: str):
    """Generate a forensic PDF for one session (alias to /generate scope=session)."""
    req = ReportRequest(scope=ReportScope.SESSION, session_id=session_id)
    try:
        meta = await get_reports().generate(req)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"report generation failed: {exc}")
    try:
        path = get_reports().resolve_pdf_path(meta)
    except FileNotFoundError:
        raise HTTPException(status_code=410, detail="report file missing on disk")
    except PermissionError:
        raise HTTPException(status_code=403, detail="report path rejected")
    return FileResponse(
        path=str(path),
        media_type="application/pdf",
        filename=f"ForenHive-{session_id}.pdf",
        headers={
            "X-PDF-SHA256": meta.sha256,
            "X-ForenHive-SHA256": meta.sha256,
            "Content-Disposition": f'attachment; filename="ForenHive-{session_id}.pdf"',
        },
    )


@router.get("/forensic/{session_id}/preview")
async def forensic_preview(session_id: str):
    """HTML preview of the forensic dossier for a single session.

    Renders directly from session data — does not require a stored PDF.
    """
    detail = await get_es().session_detail(session_id)
    if not detail:
        raise HTTPException(status_code=404, detail="session not found")
    e = lambda v: html.escape(str(v)) if v is not None else "—"
    cmds = "".join(
        f"<li><code>{e(c.get('input',''))}</code></li>"
        for c in (detail.get("commands") or [])[:50]
    ) or "<li><em>aucune commande capturée</em></li>"
    auth = "".join(
        f"<li>{e(a.get('username',''))} / {e(a.get('password',''))} — "
        f"{'✓' if a.get('success') else '✗'}</li>"
        for a in (detail.get("login_attempts") or [])[:20]
    ) or "<li><em>aucune tentative d'authentification</em></li>"
    body = f"""<!doctype html><html><head><meta charset="utf-8">
<title>ForenHive — Session {e(session_id)}</title>
<style>
 body{{font-family:-apple-system,Segoe UI,sans-serif;background:#fafafa;color:#222;padding:24px;max-width:840px;margin:auto}}
 h1{{color:#8C1A2B;border-bottom:2px solid #F9A825;padding-bottom:6px}}
 h2{{margin-top:22px;color:#444;font-size:16px;border-bottom:1px solid #eee;padding-bottom:4px}}
 table{{border-collapse:collapse;width:100%;font-size:13px}}
 th,td{{text-align:left;padding:6px 10px;border-bottom:1px solid #eee}}
 th{{color:#666;font-weight:600;width:180px}}
 code{{background:#fff3cd;padding:1px 6px;border-radius:3px;font-size:12px}}
 .meta{{color:#888;font-size:12px;margin-bottom:14px}}
 ul{{padding-left:20px;font-size:13px}}
</style></head><body>
<h1>Dossier forensique — Session</h1>
<div class="meta">Aperçu HTML · session <code>{e(session_id)}</code></div>
<h2>Informations</h2>
<table>
 <tr><th>Session ID</th><td>{e(detail.get('session_id'))}</td></tr>
 <tr><th>Honeypot</th><td>{e(detail.get('honeypot'))}</td></tr>
 <tr><th>IP source</th><td>{e(detail.get('source_ip'))}</td></tr>
 <tr><th>Démarrée</th><td>{e(detail.get('started_at'))}</td></tr>
 <tr><th>Terminée</th><td>{e(detail.get('ended_at'))}</td></tr>
 <tr><th>Statut</th><td>{e(detail.get('status'))}</td></tr>
 <tr><th>Commandes</th><td>{e(detail.get('command_count'))}</td></tr>
 <tr><th>Tentatives auth</th><td>{e(detail.get('auth_attempts'))}</td></tr>
</table>
<h2>Commandes exécutées</h2><ul>{cmds}</ul>
<h2>Tentatives d'authentification</h2><ul>{auth}</ul>
</body></html>"""
    return HTMLResponse(body)
