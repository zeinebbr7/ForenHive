"""Builds the template-variable dict for the forensic PDF report.

Uses the async SQLAlchemy session pattern already in place (db.session_scope).
Queries `forensic_sessions`, `ip_enrichment_cache`, `suspect_profiles`,
`file_analysis`, `forensic_chain_of_custody` + `forensic_coc_batches`,
`forensic_timeline_events`, `forensic_iocs` — all confirmed in
forensic-engine/db/schema.sql.
"""
from __future__ import annotations

import hashlib
import json
import logging
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import text

from db import session_scope

log = logging.getLogger(__name__)

MONTH_FR = {1: "Janvier", 2: "Février", 3: "Mars", 4: "Avril", 5: "Mai", 6: "Juin",
            7: "Juillet", 8: "Août", 9: "Septembre", 10: "Octobre",
            11: "Novembre", 12: "Décembre"}

KC_LABELS = ["Recon", "Weapon", "Delivery", "Exploit", "Install", "C&C", "Latéral", "Actions"]

# NB: zeek is a network IDS (sonde NIDS), not a honeypot.
SOURCE_COLORS = {
    "cowrie": "#F9A825",
    "dionaea": "#c62828",
    "galah": "#5a8dd6",
    "zeek": "#1e3a5f",
}
SOURCE_KIND = {
    "cowrie": "honeypot",
    "dionaea": "honeypot",
    "galah": "honeypot",
    "zeek": "NIDS",
}

MITRE_DB = {
    "T1110.001": ("Brute Force: Password Guessing", "Credential Access",
                  "Tentatives répétées de mots de passe contre un compte connu."),
    "T1110.003": ("Brute Force: Password Spraying", "Credential Access",
                  "Mots de passe communs essayés contre une liste de comptes."),
    "T1078":     ("Valid Accounts", "Initial Access",
                  "Utilisation de credentials valides pour accéder à un système."),
    "T1059.004": ("Unix Shell", "Execution",
                  "Exécution de commandes via un shell Unix interactif."),
    "T1105":     ("Ingress Tool Transfer", "Command & Control",
                  "Téléchargement d'outils ou binaires depuis l'extérieur."),
    "T1552.001": ("Credentials In Files", "Credential Access",
                  "Recherche de secrets dans des fichiers locaux."),
    "T1190":     ("Exploit Public-Facing Application", "Initial Access",
                  "Exploitation d'une application exposée sur internet."),
    "T1210":     ("Exploitation of Remote Services", "Lateral Movement",
                  "Exploitation d'un service distant pour pivoter."),
    "T1021.002": ("SMB/Windows Admin Shares", "Lateral Movement",
                  "Accès à des partages administratifs SMB."),
    "T1046":     ("Network Service Discovery", "Discovery",
                  "Énumération des services réseau accessibles."),
    "T1595.002": ("Active Scanning: Vulnerability Scanning", "Reconnaissance",
                  "Scan actif de vulnérabilités sur la cible."),
    "T1496":     ("Resource Hijacking", "Impact",
                  "Détournement de ressources (CPU, bande passante)."),
    "T1486":     ("Data Encrypted for Impact", "Impact",
                  "Chiffrement de données à des fins d'extorsion."),
}

EVIDENCE_MAP = {
    "T1110.001": "Tentatives brute force SSH loggées",
    "T1078":     "Login réussi confirmé",
    "T1059.004": "Commandes shell exécutées",
    "T1552.001": "Accès fichiers credentials",
    "T1105":     "Fichier capturé par Dionaea",
    "T1190":     "Accès HTTP honeypot Galah",
    "T1210":     "Connexion SMB port 445",
    "T1021.002": "Enumération partages SMB",
    "T1046":     "Scan réseau détecté Zeek",
}


def _risk_level(score: int) -> tuple[str, str]:
    if score >= 80: return "CRITIQUE", "#c62828"
    if score >= 60: return "ÉLEVÉ",    "#e67e22"
    if score >= 40: return "MOYEN",    "#d4a017"
    if score >= 20: return "FAIBLE",   "#5a8dd6"
    return "INFO", "#6b7a90"


def _kc_steps(stage: int) -> list[dict]:
    stage = max(0, min(int(stage or 0), 8))
    return [
        {"label": lab, "done": i < stage, "active": i == stage - 1}
        for i, lab in enumerate(KC_LABELS)
    ]


def _json_field(val: Any) -> Any:
    if val is None:
        return None
    if isinstance(val, (dict, list)):
        return val
    if isinstance(val, str):
        try:
            return json.loads(val)
        except Exception:
            return None
    return val


async def build_report_data(session_id: str) -> dict:
    """Fetch every row needed and return a Jinja2-ready dict."""
    async with session_scope() as db:
        # 1. Session
        row = (await db.execute(text("""
            SELECT session_id, honeypot_type, source_ip, started_at, ended_at,
                   risk_score, mitre_techniques, enrichment_data,
                   kill_chain_phase, kill_chain_stage, primary_technique,
                   forensic_narrative, created_at
              FROM forensic_sessions WHERE session_id = :sid
        """), {"sid": session_id})).mappings().first()
        if not row:
            raise ValueError(f"Session {session_id} not found")
        session = dict(row)

        source_ip = session["source_ip"] or ""
        risk_score = int(session.get("risk_score") or 0)
        risk_level, risk_color = _risk_level(risk_score)

        mitre_raw = _json_field(session.get("mitre_techniques")) or []

        # 2. Enrichment
        enr_row = (await db.execute(text("""
            SELECT data FROM ip_enrichment_cache WHERE ip = :ip
        """), {"ip": source_ip})).mappings().first()
        enrichment = _json_field(enr_row["data"]) if enr_row else {}
        enrichment = enrichment or {}
        geo = enrichment.get("geo") or {}
        privacy = enrichment.get("privacy") or {}
        reputation = enrichment.get("reputation") or {}
        infra = enrichment.get("infrastructure") or {}
        whois = enrichment.get("whois") or {}

        # 3. File analysis (YARA + VT) — scoped to THIS session: only files whose
        #    sha256 appears as an IOC linked to this session's source_ip.
        #    Avoids the dangerous failure mode where every report shows the same
        #    globally-most-recent binary regardless of session relevance.
        malware = None
        fa_rows = (await db.execute(text("""
            SELECT fa.sha256, fa.yara_matches, fa.virustotal_result
              FROM file_analysis fa
              JOIN forensic_iocs i
                ON LOWER(i.ioc_value) = LOWER(fa.sha256)
             WHERE i.source_ip = :ip
               AND i.ioc_type IN ('sha256', 'SHA-256', 'sha-256')
             ORDER BY fa.analyzed_at DESC
             LIMIT 10
        """), {"ip": source_ip})).mappings().all()
        for fa in fa_rows:
            yara_raw = _json_field(fa.get("yara_matches"))
            # yara_matches may be either a list of match dicts OR a dict with {matched, matches}
            if isinstance(yara_raw, list):
                matches = yara_raw
                yara_meta: dict = {}
            elif isinstance(yara_raw, dict):
                if not yara_raw.get("matched") and not yara_raw.get("matches"):
                    continue
                matches = yara_raw.get("matches") or []
                yara_meta = yara_raw
            else:
                continue
            if not matches:
                continue
            vt = _json_field(fa.get("virustotal_result")) or {}
            if not isinstance(vt, dict):
                vt = {}
            m0 = matches[0] if isinstance(matches[0], dict) else {}
            mal_det = int(vt.get("malicious") or 0)
            mal_und = int(vt.get("undetected") or 0)
            malware = {
                "sha256": fa["sha256"],
                "filename": yara_meta.get("filename", "captured_binary"),
                "size": f"{yara_meta.get('size', 'N/A')} octets" if yara_meta.get("size") else "N/A",
                "arch": yara_meta.get("arch", "N/A"),
                "yara_family": m0.get("rule", "Unknown"),
                "yara_rule": (m0.get("namespace") or "unknown") + ".yar",
                "vt_ratio": f"{mal_det} / {mal_det + mal_und}" if (mal_det or mal_und) else "N/A",
                "vt_family": vt.get("family", "N/A"),
                "vt_tags": " · ".join((vt.get("tags") or [])[:4]) or "—",
                "vt_first_seen": str(vt.get("first_seen", ""))[:10] or "N/A",
            }
            break

        # 4. Suspect profile
        prof_row = (await db.execute(text("""
            SELECT profile FROM suspect_profiles
              WHERE source_ip = :ip
              ORDER BY created_at DESC LIMIT 1
        """), {"ip": source_ip})).mappings().first()
        profile = _json_field(prof_row["profile"]) if prof_row else {}
        profile = profile or {}

        # 5. Timeline — query forensic_timeline_events (Postgres), not ES
        tl_rows = (await db.execute(text("""
            SELECT ts, honeypot_type, event_category, event_action, summary
              FROM forensic_timeline_events
              WHERE session_id = :sid
              ORDER BY ts ASC
              LIMIT 40
        """), {"sid": session_id})).mappings().all()
        timeline = []
        for ev in tl_rows:
            hp = (ev["honeypot_type"] or "zeek").lower()
            ts = ev["ts"]
            tstr = ts.strftime("%H:%M:%S.%f")[:-3] if hasattr(ts, "strftime") else str(ts)[-12:]
            action = ev["event_action"] or ""
            warn = None
            if "login.success" in action.lower():
                warn = "COMPROMISSION CONFIRMÉE · login réussi"
            timeline.append({
                "time": tstr,
                "source": hp.capitalize(),
                "source_color": SOURCE_COLORS.get(hp, "#1e3a5f"),
                "message": ev["summary"] or action,
                "sub": f"{ev['event_category']} · {action}",
                "warning": warn,
            })
        if not timeline:
            # Fallback: synthesise a minimal timeline from session columns
            started = session.get("started_at")
            ended = session.get("ended_at")
            hp = (session.get("honeypot_type") or "cowrie").lower()
            col = SOURCE_COLORS.get(hp, "#1e3a5f")
            if started:
                timeline.append({
                    "time": started.strftime("%H:%M:%S.%f")[:-3] if hasattr(started, "strftime") else str(started)[-12:],
                    "source": hp.capitalize(), "source_color": col,
                    "message": f"Session ouverte · IP {source_ip}",
                    "sub": session.get("primary_technique") or "",
                    "warning": None,
                })
            if ended:
                timeline.append({
                    "time": ended.strftime("%H:%M:%S.%f")[:-3] if hasattr(ended, "strftime") else str(ended)[-12:],
                    "source": hp.capitalize(), "source_color": "#6b7a90",
                    "message": "Session fermée", "sub": "", "warning": None,
                })

        # 6. Chain of custody — join forensic_chain_of_custody × forensic_coc_batches
        coc_row = (await db.execute(text("""
            SELECT coc.record_hash, coc.sealed_at, b.tsa_time, b.tsa_provider,
                   b.merkle_root, b.tsa_status
              FROM forensic_chain_of_custody coc
              LEFT JOIN forensic_coc_batches b ON b.id = coc.batch_id
              WHERE coc.session_id = :sid
              LIMIT 1
        """), {"sid": session_id})).mappings().first()
        if coc_row:
            log_sha256 = coc_row["record_hash"]
            tsa_token = f"{coc_row['tsa_provider'] or 'N/A'} · merkle:{(coc_row['merkle_root'] or '')[:24]}…"
            certified_at = str(coc_row["tsa_time"] or coc_row["sealed_at"] or "N/A")
        else:
            log_sha256 = "Non scellé"
            tsa_token = "N/A"
            certified_at = "N/A"

        # 7. IOCs — from forensic_iocs table
        ioc_rows = (await db.execute(text("""
            SELECT ioc_type, ioc_value, first_seen, honeypot_types, occurrences
              FROM forensic_iocs
              WHERE source_ip = :ip
              ORDER BY occurrences DESC, last_seen DESC
              LIMIT 12
        """), {"ip": source_ip})).mappings().all()
        # Confidence is derived from corroboration: cross-source occurrences,
        # enrichment evidence (Tor/VPN/AbuseIPDB), and YARA/VT match — not a
        # blanket "100%" which is misleading.
        def _ioc_confidence(occ: int, n_sources: int) -> tuple[str, str]:
            score = min(100, 40 + occ * 5 + n_sources * 15)
            if score >= 80:
                return f"ÉLEVÉE ({score}%)", "#2e7d32"
            if score >= 60:
                return f"MOYENNE ({score}%)", "#d4a017"
            return f"FAIBLE ({score}%)", "#8a6a40"

        iocs = []
        if source_ip and not source_ip.startswith(("10.", "172.", "192.168.")):
            # IP source: confidence depends on whether enrichment corroborates risk.
            ip_evidence = sum([
                int(reputation.get("abuse_score") or 0) >= 25,
                bool(privacy.get("is_tor") or reputation.get("is_tor")),
                bool(privacy.get("is_vpn")),
                int(reputation.get("total_reports") or 0) >= 10,
            ])
            ip_score = min(100, 40 + ip_evidence * 15)
            ip_label = ("ÉLEVÉE" if ip_score >= 80 else "MOYENNE" if ip_score >= 60 else "FAIBLE")
            ip_color = ("#2e7d32" if ip_score >= 80 else "#d4a017" if ip_score >= 60 else "#8a6a40")
            iocs.append({
                "type": "IPv4", "value": source_ip,
                "context": f"IP source · {geo.get('country') or 'N/A'}",
                "confidence": f"{ip_label} ({ip_score}%)",
                "confidence_color": ip_color,
            })
        for r in ioc_rows:
            hps = r["honeypot_types"] or []
            occ = int(r["occurrences"] or 1)
            label, color = _ioc_confidence(occ, len(hps))
            iocs.append({
                "type": r["ioc_type"],
                "value": (r["ioc_value"] or "")[:80],
                "context": f"{', '.join(hps) or '—'} · {occ}x",
                "confidence": label,
                "confidence_color": color,
            })
        if malware:
            iocs.append({
                "type": "SHA-256", "value": malware["sha256"],
                "context": f"Malware · {malware['yara_family']}",
                "confidence": "ÉLEVÉE (95%)",
                "confidence_color": "#2e7d32",
            })

    # end session_scope

    # ---- derived fields (no DB needed below) ----
    mitre_techniques = []
    for tid in (mitre_raw if isinstance(mitre_raw, list) else []):
        if isinstance(tid, dict):
            tid = tid.get("id") or tid.get("technique_id") or ""
        if not tid:
            continue
        entry = MITRE_DB.get(tid)
        if entry:
            name, tactic, descr = entry
        else:
            name, tactic, descr = ("Technique MITRE", "Unknown", "")
        mitre_techniques.append({
            "id": tid, "name": name, "tactic": tactic,
            "description": descr,
            "confidence": "Élevée",
            "evidence": EVIDENCE_MAP.get(tid, "Évidence dans les logs"),
        })

    # Score signals — synthesised from available fields (no score_breakdown column)
    abuse_score = int(reputation.get("abuse_score") or 0)
    score_signals = []
    if abuse_score:
        pts = min(40, int(abuse_score * 0.4))
        score_signals.append({
            "num": "01", "name": f"Réputation AbuseIPDB ({abuse_score}%)",
            "source": "AbuseIPDB", "pts": pts, "max": 40,
            "pct": int(pts / 40 * 100), "color": "#c62828",
        })
    if privacy.get("is_tor") or reputation.get("is_tor"):
        score_signals.append({
            "num": "02", "name": "Nœud Tor détecté", "source": "IPLocate",
            "pts": 15, "max": 15, "pct": 100, "color": "#c62828",
        })
    if mitre_techniques:
        pts = min(25, len(mitre_techniques) * 8)
        score_signals.append({
            "num": "03", "name": f"Techniques MITRE corrélées ({len(mitre_techniques)})",
            "source": "ForenHive", "pts": pts, "max": 25,
            "pct": int(pts / 25 * 100), "color": "#e67e22",
        })
    if timeline:
        pts = min(10, len(timeline) // 2)
        score_signals.append({
            "num": "04", "name": f"Volume événements ({len(timeline)})",
            "source": "Timeline", "pts": pts, "max": 10,
            "pct": int(pts / 10 * 100), "color": "#d4a017",
        })
    if malware:
        score_signals.append({
            "num": "05", "name": f"Binaire malveillant · {malware['yara_family']}",
            "source": "YARA / VT", "pts": 10, "max": 10, "pct": 100, "color": "#c62828",
        })

    # Recommendations
    recommendations = []
    asn = whois.get("asn") or geo.get("asn")
    asn_org = whois.get("org") or geo.get("org") or reputation.get("isp") or ""
    if asn:
        recommendations.append(f"Bloquer l'ASN {asn} ({asn_org}) au pare-feu périmétrique")
    if source_ip:
        recommendations.append(f"Blacklister {source_ip}" + (f" et son CIDR {whois.get('cidr')}" if whois.get("cidr") else ""))
    if any("login.success" in (e.get("sub", "") or "").lower() or "RÉUSSI" in (e.get("message", "") or "").upper() for e in timeline):
        recommendations.append("Auditer immédiatement les credentials potentiellement compromis")
    if malware:
        recommendations.append("Transmettre le binaire à l'équipe IR pour analyse approfondie")
    recommendations.append("Exporter les IOCs en STIX 2.1 vers SIEM / threat-intel platform")
    if not recommendations:
        recommendations.append("Poursuivre la surveillance passive de la source")

    # Meta
    now_utc = datetime.now(timezone.utc)
    started = session.get("started_at")
    ended = session.get("ended_at")
    duration_s: float = 0
    if started and ended:
        try:
            duration_s = round((ended - started).total_seconds(), 1)
        except Exception:
            duration_s = 0

    ref_date = started.strftime("%Y%m%d") if started and hasattr(started, "strftime") else now_utc.strftime("%Y%m%d")
    ref = f"FH-{ref_date}-{session_id[:12]}"
    generated_at = f"{now_utc.day} {MONTH_FR[now_utc.month]} {now_utc.year} · {now_utc.strftime('%H:%M')} UTC"

    pdf_seed = f"{session_id}|{log_sha256}|{now_utc.isoformat()}"
    pdf_sha256_pre = hashlib.sha256(pdf_seed.encode()).hexdigest()

    confidence_pct = int((profile.get("confidence") or 0.85) * 100)
    organised_score = float(profile.get("organized_score") or profile.get("organised_score") or 0.5)

    # AbuseIPDB display: distinguish "score 0 + many reports" (still risky) from
    # "score 0 + no reports" (clean). Prevents the misleading "0/100" display
    # for IPs that have many community reports but no aggregated score yet.
    total_reports_val = int(reputation.get("total_reports") or 0)
    if abuse_score > 0:
        abuse_display = f"{abuse_score} / 100"
    elif total_reports_val > 0:
        abuse_display = f"non scoré · {total_reports_val} signalement(s)"
    else:
        abuse_display = "0 / 100"

    # Narrative fallback: build a substantive multi-paragraph summary if the
    # session-level forensic_narrative is empty or too short to be useful.
    raw_narrative = (session.get("forensic_narrative") or "").strip()
    if len(raw_narrative) < 80:
        parts = []
        hp = (session.get("honeypot_type") or "").lower()
        hp_kind = SOURCE_KIND.get(hp, "honeypot")
        parts.append(
            f"<p>Session <strong>{session_id}</strong> capturée par "
            f"{hp_kind} <strong>{hp.capitalize() or 'N/A'}</strong> depuis "
            f"<strong>{source_ip or 'N/A'}</strong>"
            f"{' (' + (geo.get('country') or '') + ')' if geo.get('country') else ''}. "
            f"Score de risque calculé : <strong>{risk_score}/100 — {risk_level}</strong>.</p>"
        )
        ev_bits = []
        if mitre_techniques:
            ev_bits.append(f"{len(mitre_techniques)} technique(s) MITRE corrélée(s)")
        if timeline:
            ev_bits.append(f"{len(timeline)} événement(s) sur la timeline")
        if abuse_score >= 25 or total_reports_val >= 25:
            ev_bits.append(f"réputation AbuseIPDB défavorable ({abuse_display})")
        if privacy.get("is_tor") or reputation.get("is_tor"):
            ev_bits.append("nœud Tor confirmé")
        if malware:
            ev_bits.append(f"binaire malveillant détecté ({malware['yara_family']})")
        if ev_bits:
            parts.append("<p>Éléments retenus : " + ", ".join(ev_bits) + ".</p>")
        kc_phase = session.get("kill_chain_phase") or ""
        if kc_phase:
            parts.append(
                f"<p>Position kill-chain estimée : étape "
                f"<strong>{session.get('kill_chain_stage') or 0}/8 — {kc_phase}</strong>.</p>"
            )
        if raw_narrative:
            parts.append(f"<p>{raw_narrative}</p>")
        forensic_narrative_out = "".join(parts)
    else:
        forensic_narrative_out = raw_narrative

    return {
        # meta
        "ref": ref,
        "generated_at": generated_at,
        "classification": "CONFIDENTIEL",

        # session
        "session_id": session_id,
        "honeypot_type": (session.get("honeypot_type") or "N/A").capitalize(),
        "source_ip": source_ip or "N/A",
        "started_at": str(started)[:19] if started else "N/A",
        "ended_at": str(ended)[:19] if ended else "N/A",
        "duration_s": duration_s,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "risk_level_color": risk_color,
        "confidence_pct": confidence_pct,
        "kill_chain_phase": session.get("kill_chain_phase") or "N/A",
        "kill_chain_stage": session.get("kill_chain_stage") or 0,
        "primary_technique": session.get("primary_technique") or "N/A",
        "forensic_narrative": forensic_narrative_out,

        # enrichment
        "geo_country": geo.get("country") or "N/A",
        "geo_city": geo.get("city") or "",
        "asn": str(geo.get("asn") or whois.get("asn") or "N/A"),
        "asn_org": asn_org or "N/A",
        "cidr": whois.get("cidr") or "N/A",
        "open_ports": ", ".join(str(p) for p in (infra.get("open_ports") or [])[:8]) or "—",
        "abuse_score": abuse_score,
        "abuse_display": abuse_display,
        "total_reports": total_reports_val,
        "is_tor": bool(privacy.get("is_tor") or reputation.get("is_tor")),
        "is_vpn": bool(privacy.get("is_vpn")),
        "is_proxy": bool(privacy.get("is_proxy")),

        # mitre + kill chain
        "mitre_techniques": mitre_techniques,
        "kc_steps": _kc_steps(session.get("kill_chain_stage") or 0),

        # timeline
        "timeline": timeline,

        # malware
        "has_malware": malware is not None,
        "malware": malware or {},

        # profile
        "has_profile": bool(profile),
        "organised_score": organised_score,
        "actor_type": str(profile.get("actor_type") or profile.get("primary_objective") or "Inconnu").upper(),
        "sophistication": str(profile.get("sophistication") or "N/A").upper(),
        "profile_confidence": confidence_pct,
        "behavioral_traits": (profile.get("behavioral_traits") or [])[:5],
        "signature_behaviors": (profile.get("signature_indicators") or profile.get("signature_behaviors") or [])[:4],
        "detective_narrative": profile.get("detective_narrative") or "",
        "is_recidivist": (profile.get("similar_past_cases") or 0) > 0 or bool((profile.get("recidivism") or {}).get("seen_before")),
        "previous_sessions": int(profile.get("similar_past_cases") or (profile.get("recidivism") or {}).get("previous_sessions") or 0),

        # score
        "score_signals": score_signals,
        "score_total": risk_score,

        # chain of custody
        "log_sha256": log_sha256,
        "tsa_token": tsa_token,
        "certified_at": certified_at,
        "pdf_sha256": pdf_sha256_pre,  # pre-generation seed; recomputed on write in router

        # IOCs + recos
        "iocs": iocs[:10],
        "recommendations": recommendations,
    }
