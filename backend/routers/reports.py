import hashlib
import json
import logging
import tempfile
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Body, HTTPException, Query, Request
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
from jinja2 import Environment, FileSystemLoader, select_autoescape
from slowapi import Limiter
from slowapi.util import get_remote_address

from config import get_settings
from models.report import (
    ReportListResponse,
    ReportMeta,
    ReportRequest,
    ReportScope,
)
from services.chain_custody import get_custody
from services.elasticsearch import get_es
from services.profiler import build_profile
from services.report_service import get_reports

log = logging.getLogger(__name__)

TEMPLATE_DIR = Path(__file__).resolve().parent.parent / "templates"

# MITRE ATT&CK technique → (name, tactic)
_MITRE_DB: Dict[str, tuple] = {
    "T1595":     ("Active Scanning",                    "Reconnaissance"),
    "T1595.001": ("Scanning IP Blocks",                 "Reconnaissance"),
    "T1590":     ("Gather Victim Network Info",          "Reconnaissance"),
    "T1589":     ("Gather Victim Identity Info",         "Reconnaissance"),
    "T1110":     ("Brute Force",                        "Credential Access"),
    "T1110.001": ("Brute Force: Password Guessing",     "Credential Access"),
    "T1110.003": ("Password Spraying",                  "Credential Access"),
    "T1078":     ("Valid Accounts",                     "Initial Access"),
    "T1059":     ("Command and Scripting Interpreter",  "Execution"),
    "T1059.004": ("Unix Shell",                         "Execution"),
    "T1552":     ("Unsecured Credentials",              "Credential Access"),
    "T1552.001": ("Credentials In Files",               "Credential Access"),
    "T1105":     ("Ingress Tool Transfer",              "Command & Control"),
    "T1046":     ("Network Service Discovery",          "Discovery"),
    "T1021":     ("Remote Services",                    "Lateral Movement"),
    "T1021.004": ("SSH",                                "Lateral Movement"),
    "T1547":     ("Boot or Logon Autostart Execution",  "Persistence"),
    "T1071":     ("Application Layer Protocol",         "Command & Control"),
    "T1027":     ("Obfuscated Files or Information",    "Defense Evasion"),
    "T1048":     ("Exfiltration Over Alternative Protocol", "Exfiltration"),
    "T1190":     ("Exploit Public-Facing Application",  "Initial Access"),
    "T1566":     ("Phishing",                           "Initial Access"),
    "T1003":     ("OS Credential Dumping",              "Credential Access"),
    "T1082":     ("System Information Discovery",       "Discovery"),
    "T1033":     ("System Owner/User Discovery",        "Discovery"),
}

_MONTHS_FR = ["", "Janvier", "Février", "Mars", "Avril", "Mai", "Juin",
              "Juillet", "Août", "Septembre", "Octobre", "Novembre", "Décembre"]

_KC_LABELS = ["Recon", "Weapon", "Delivery", "Exploit", "Install", "C2", "Lateral", "Actions"]
_KC_STAGES = ["reconnaissance", "weaponization", "delivery", "exploitation",
              "installation", "command_and_control", "lateral_movement", "actions_on_objectives"]


def _risk_label_color(score: int):
    if score >= 80: return "CRITIQUE", "#C62828"
    if score >= 60: return "ÉLEVÉ",    "#b36000"
    if score >= 40: return "MOYEN",    "#1565C0"
    if score >= 20: return "FAIBLE",   "#388E3C"
    return "INFO", "#757575"


def _mitre_lookup(tech_id: str):
    entry = _MITRE_DB.get(tech_id)
    if entry:
        return entry
    parent = tech_id[:5] if len(tech_id) > 5 else tech_id
    return _MITRE_DB.get(parent, (tech_id, "Unknown"))


def _build_score_signals(profile: dict, detail: dict) -> List[dict]:
    signals = []
    abuse = int(profile.get("abuseipdb_score") or 0)
    if abuse:
        pts = min(39, abuse * 39 // 100)
        signals.append({"name": "AbuseIPDB score réputation", "source": "AbuseIPDB", "points": pts, "max": 40, "value": f"{abuse}/100"})

    logins = detail.get("login_attempts") or []
    n_auth = len(logins)
    auth_success = any(a.get("success") for a in logins)
    if auth_success:
        signals.append({"name": "Login réussi / compromission", "source": "Cowrie", "points": 25, "max": 25, "value": "Compromission confirmée"})
    elif n_auth > 0:
        pts = min(25, n_auth * 25 // 500)
        signals.append({"name": f"Volume logins ({n_auth})", "source": "Cowrie", "points": pts, "max": 25, "value": f"{n_auth} tentatives"})

    yara = profile.get("yara_matches") or []
    if yara:
        signals.append({"name": "YARA match — famille critique", "source": "YARA", "points": 30, "max": 30, "value": yara[0]})

    hashes = profile.get("ioc_hashes") or []
    if hashes:
        signals.append({"name": "Malware capturé (SHA-256)", "source": "Dionaea", "points": 20, "max": 30, "value": hashes[0][:20] + "..."})

    if profile.get("is_tor"):
        signals.append({"name": "Nœud Tor exit", "source": "IPLocate", "points": 15, "max": 15, "value": "OUI — exit node"})
    if profile.get("is_vpn"):
        signals.append({"name": "VPN détecté", "source": "IPLocate", "points": 10, "max": 10, "value": "OUI"})

    cmds = detail.get("commands") or []
    if cmds:
        pts = min(10, len(cmds))
        signals.append({"name": "Commandes shell exécutées", "source": "Cowrie", "points": pts, "max": 10, "value": f"{len(cmds)} commandes"})

    mitre = profile.get("mitre_techniques") or []
    if mitre:
        pts = min(15, len(mitre) * 3)
        signals.append({"name": "Techniques MITRE ATT&CK", "source": "Moteur", "points": pts, "max": 15, "value": ", ".join(mitre[:3])})

    if (profile.get("session_count") or 0) > 1:
        signals.append({"name": "Récidivisme (sessions antérieures)", "source": "PostgreSQL", "points": 10, "max": 10, "value": f"{profile.get('session_count')} sessions"})

    return signals


async def _build_forensic_context(session_id: str) -> dict:
    es = get_es()
    detail = await es.session_detail(session_id) or {}
    source_ip: Optional[str] = detail.get("source_ip")

    profile_dict: dict = {}
    if source_ip:
        try:
            p = await build_profile(source_ip)
            profile_dict = p.model_dump(mode="json")
        except Exception as exc:
            log.warning("build_profile failed for %s: %s", source_ip, exc)

    risk_score = int(profile_dict.get("risk_score") or 0)
    risk_label, risk_color = _risk_label_color(risk_score)

    now = datetime.now(tz=timezone.utc)
    report_ref = f"FH-{now.strftime('%Y-%m-%d')}-{session_id[:8]}"
    generated_at_str = f"{now.day} {_MONTHS_FR[now.month]} {now.year} · {now.strftime('%H:%M')} UTC"

    # ── Timeline ──────────────────────────────────────────
    timeline = []
    started = detail.get("started_at")
    if started:
        timeline.append({"ts": str(started), "source": "SESSION", "action": "Session ouverte",
                         "detail": f"Honeypot {(detail.get('honeypot') or 'unknown').upper()}", "mitre": "T1046"})

    logins = detail.get("login_attempts") or []
    for a in logins[:25]:
        ok = a.get("success", False)
        timeline.append({
            "ts": str(a.get("timestamp") or started or ""),
            "source": "AUTH",
            "action": "Tentative auth " + ("✓ SUCCÈS" if ok else "✗ échec"),
            "detail": f"{a.get('username','?')} / {a.get('password','?')}",
            "mitre": "T1078" if ok else "T1110.001",
        })

    cmds = detail.get("commands") or []
    for c in cmds[:25]:
        inp = c.get("input") or c.get("command") or ""
        mitre = "T1059.004"
        if any(x in inp for x in ["wget", "curl", "tftp", "ftp"]):
            mitre = "T1105"
        elif any(x in inp for x in ["cat /etc", "cat /root", "cat /opt"]):
            mitre = "T1552.001"
        elif inp in ["whoami", "id", "uname"]:
            mitre = "T1033"
        timeline.append({"ts": str(c.get("timestamp") or ""), "source": "COMMAND",
                         "action": "Commande exécutée", "detail": inp, "mitre": mitre})

    ended = detail.get("ended_at")
    if ended:
        timeline.append({"ts": str(ended), "source": "SESSION", "action": "Session fermée",
                         "detail": f"Durée : {detail.get('duration_seconds', 0):.1f}s", "mitre": ""})

    try:
        timeline.sort(key=lambda x: x.get("ts") or "")
    except Exception:
        pass

    # ── MITRE rows ────────────────────────────────────────
    auth_success = any(a.get("success") for a in logins)
    mitre_seen: set = set()
    mitre_rows = []

    for t_id in (profile_dict.get("mitre_techniques") or []):
        if t_id in mitre_seen:
            continue
        mitre_seen.add(t_id)
        name, tactic = _mitre_lookup(t_id)
        evidence = "Logs honeypot"
        if "T1110" in t_id:
            evidence = f"{len(logins)} tentatives SSH loggées"
        elif t_id == "T1078":
            evidence = "Login réussi confirmé"
        elif "T1059" in t_id:
            evidence = f"{len(cmds)} commandes — " + ", ".join(c.get("input","")[:20] for c in cmds[:2])
        elif "T1552" in t_id:
            evidence = "Credentials lus"
        elif t_id == "T1105":
            evidence = "wget/curl capturé par Dionaea"
        mitre_rows.append({"id": t_id, "technique": name, "tactic": tactic, "confidence": "100%", "evidence": evidence})

    # Add from commands if not already present
    for c in cmds:
        inp = c.get("input", "")
        if any(x in inp for x in ["wget", "curl", "tftp"]) and "T1105" not in mitre_seen:
            mitre_seen.add("T1105")
            mitre_rows.append({"id": "T1105", "technique": "Ingress Tool Transfer", "tactic": "Command & Control", "confidence": "100%", "evidence": f"wget {inp[:40]}"})
        if any(x in inp for x in ["whoami", "uname", "id"]) and "T1033" not in mitre_seen:
            mitre_seen.add("T1033")
            mitre_rows.append({"id": "T1033", "technique": "System Owner/User Discovery", "tactic": "Discovery", "confidence": "100%", "evidence": inp})

    if logins and "T1110.001" not in mitre_seen and "T1110" not in mitre_seen:
        mitre_seen.add("T1110.001")
        mitre_rows.insert(0, {"id": "T1110.001", "technique": "Brute Force: Password Guessing", "tactic": "Credential Access", "confidence": "100%", "evidence": f"{len(logins)} tentatives SSH loggées"})
    if auth_success and "T1078" not in mitre_seen:
        mitre_seen.add("T1078")
        mitre_rows.insert(1, {"id": "T1078", "technique": "Valid Accounts", "tactic": "Initial Access", "confidence": "100%", "evidence": "Login confirmé"})
    if cmds and "T1059.004" not in mitre_seen:
        mitre_seen.add("T1059.004")
        mitre_rows.append({"id": "T1059.004", "technique": "Unix Shell", "tactic": "Execution", "confidence": "100%", "evidence": f"{len(cmds)} commandes exécutées"})

    # ── Kill chain stage ──────────────────────────────────
    kc_reached = 0
    if logins:
        kc_reached = max(kc_reached, 3)  # exploitation
    if auth_success:
        kc_reached = max(kc_reached, 3)
    if cmds:
        kc_reached = max(kc_reached, 4)  # installation
    for c in cmds:
        if any(x in (c.get("input") or "") for x in ["wget", "curl", "tftp"]):
            kc_reached = max(kc_reached, 5)  # C2

    # ── Score signals ──────────────────────────────────────
    score_signals = _build_score_signals(profile_dict, detail)

    # ── SHA-256 chain of custody ──────────────────────────
    session_bytes = json.dumps(detail, sort_keys=True, default=str).encode()
    sha256_session = hashlib.sha256(session_bytes).hexdigest()

    # ── Organised score (behavioural estimate) ─────────────
    n_cmd = len(cmds)
    org_score_pct = min(90, int(30 + n_cmd * 4 + (20 if auth_success else 0) + (10 if profile_dict.get("is_tor") else 0)))

    return {
        "session_id": session_id,
        "session": detail,
        "profile": profile_dict,
        "report_ref": report_ref,
        "generated_at_str": generated_at_str,
        "now_year": now.year,
        "risk_label": risk_label,
        "risk_color": risk_color,
        "risk_score": risk_score,
        "timeline": timeline,
        "mitre_rows": mitre_rows,
        "score_signals": score_signals,
        "sha256_session": sha256_session,
        "custody_ok": False,
        "kc_reached": kc_reached,
        "kc_stages": _KC_STAGES,
        "kc_stages_labels": _KC_LABELS,
        "org_score_pct": org_score_pct,
        "auth_success": auth_success,
        # Jinja2 helper
        "enumerate": enumerate,
    }

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
    """List sessions in the flat shape the dashboard reconstruction/reporting
    pages expect: session_id, source_ip, honeypot_type, risk_score,
    kill_chain_phase, primary_technique, started_at.

    Backed by /api/sessions data. When the forensic engine has not produced
    enriched fields yet, sensible defaults are used.
    """
    rows = await get_es().sessions(limit=limit, active_only=False)
    out: List[Dict[str, Any]] = []
    for r in rows:
        mitre = r.get("mitre_techniques") or r.get("techniques") or []
        if isinstance(mitre, dict):
            mitre = []
        out.append({
            "session_id":        r.get("session_id"),
            "source_ip":         r.get("source_ip"),
            "honeypot_type":     r.get("honeypot") or r.get("honeypot_type"),
            "risk_score":        r.get("risk_score"),
            "kill_chain_phase":  r.get("kill_chain_phase") or _phase_from_techniques(mitre),
            "kill_chain_stage":  r.get("kill_chain_stage"),
            "primary_technique": (mitre[0] if mitre else r.get("primary_technique")),
            "started_at":        r.get("started_at"),
        })
    return out


@router.post("/forensic/{session_id}/generate")
async def forensic_generate(request: Request, session_id: str):
    """Generate and download a forensic PDF for one session using the rich forensic template."""
    try:
        from weasyprint import HTML as WeasyprintHTML
    except ImportError:
        raise HTTPException(status_code=503, detail="WeasyPrint not installed")

    detail = await get_es().session_detail(session_id)
    if not detail:
        raise HTTPException(status_code=404, detail="session not found")

    try:
        ctx = await _build_forensic_context(session_id)
    except Exception as exc:
        log.exception("forensic context build failed for %s", session_id)
        raise HTTPException(status_code=500, detail=f"context build failed: {exc}")

    env = Environment(
        loader=FileSystemLoader(TEMPLATE_DIR),
        autoescape=select_autoescape(["html"]),
    )
    env.globals["enumerate"] = enumerate
    try:
        html_body = env.get_template("forensic_report.html").render(**ctx)
    except Exception as exc:
        log.exception("template render failed")
        raise HTTPException(status_code=500, detail=f"template render failed: {exc}")

    settings = get_settings()
    out_dir = Path(settings.reports_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    pdf_path = out_dir / f"forensic-{session_id}-{uuid.uuid4().hex[:8]}.pdf"

    try:
        WeasyprintHTML(string=html_body).write_pdf(str(pdf_path))
    except Exception as exc:
        log.exception("WeasyPrint render failed")
        raise HTTPException(status_code=500, detail=f"PDF generation failed: {exc}")

    pdf_bytes = pdf_path.read_bytes()
    sha256 = hashlib.sha256(pdf_bytes).hexdigest()

    return FileResponse(
        path=str(pdf_path),
        media_type="application/pdf",
        filename=f"ForenHive-{ctx['report_ref']}.pdf",
        headers={
            "X-PDF-SHA256": sha256,
            "X-ForenHive-SHA256": sha256,
            "Content-Disposition": f'attachment; filename="ForenHive-{ctx["report_ref"]}.pdf"',
        },
    )


@router.get("/forensic/{session_id}/preview")
async def forensic_preview(session_id: str):
    """Full forensic HTML dossier for a single session (rich preview matching the PDF design)."""
    detail = await get_es().session_detail(session_id)
    if not detail:
        raise HTTPException(status_code=404, detail="session not found")
    try:
        ctx = await _build_forensic_context(session_id)
    except Exception as exc:
        log.exception("forensic context build failed for %s", session_id)
        raise HTTPException(status_code=500, detail=f"context build failed: {exc}")

    env = Environment(
        loader=FileSystemLoader(TEMPLATE_DIR),
        autoescape=select_autoescape(["html"]),
    )
    env.globals["enumerate"] = enumerate
    try:
        html_body = env.get_template("forensic_report.html").render(**ctx)
    except Exception as exc:
        log.exception("template render failed")
        raise HTTPException(status_code=500, detail=f"template render failed: {exc}")
    return HTMLResponse(html_body)
