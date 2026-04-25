"""Render a Markdown summary report for one or more target IPs.

Pulls already-stored data (enrichment, session, MITRE, profile, IOCs, YARA)
from PostgreSQL and produces a digestible Markdown file.

Usage (inside forensic-engine container):
    python build_md_report.py --ip 193.32.162.157 --out /tmp/report.md
"""
from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone

import psycopg2
import psycopg2.extras

import config


def _pg():
    return psycopg2.connect(
        host=config.PG_HOST, port=config.PG_PORT,
        dbname=config.PG_DB, user=config.PG_USER,
        password=config.PG_PASSWORD,
    )


def _fetch(ip: str) -> dict:
    with _pg() as conn, conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute("SELECT data FROM ip_enrichment_cache WHERE ip=%s", (ip,))
        enr = (cur.fetchone() or {}).get("data") or {}

        cur.execute("""
            SELECT session_id, honeypot_type, started_at, ended_at,
                   risk_score, mitre_techniques, kill_chain_phase,
                   kill_chain_stage, primary_technique, forensic_narrative
              FROM forensic_sessions WHERE source_ip=%s
              ORDER BY started_at DESC
        """, (ip,))
        sessions = [dict(r) for r in cur.fetchall()]

        cur.execute("""
            SELECT profile FROM suspect_profiles WHERE source_ip=%s
              ORDER BY created_at DESC LIMIT 1
        """, (ip,))
        prof_row = cur.fetchone()
        profile = (prof_row or {}).get("profile") or {}

        cur.execute("""
            SELECT ioc_type, ioc_value, occurrences, honeypot_types,
                   first_seen, last_seen
              FROM forensic_iocs WHERE source_ip=%s
              ORDER BY occurrences DESC LIMIT 30
        """, (ip,))
        iocs = [dict(r) for r in cur.fetchall()]

        # YARA hits whose sha256 appears as an IOC for this IP.
        cur.execute("""
            SELECT fa.sha256, fa.yara_matches, fa.virustotal_result, fa.analyzed_at
              FROM file_analysis fa
              JOIN forensic_iocs i
                ON LOWER(i.ioc_value) = LOWER(fa.sha256)
             WHERE i.source_ip = %s
               AND i.ioc_type IN ('sha256','SHA-256','sha-256')
        """, (ip,))
        yara_hits = [dict(r) for r in cur.fetchall()]

    return {
        "enrichment": enr,
        "sessions": sessions,
        "profile": profile,
        "iocs": iocs,
        "yara_hits": yara_hits,
    }


def _md_escape(s) -> str:
    return str(s).replace("|", "\\|")


def render(ip: str, data: dict) -> str:
    enr = data["enrichment"]
    geo = enr.get("geo") or {}
    privacy = enr.get("privacy") or {}
    rep = enr.get("reputation") or {}
    whois = enr.get("whois") or {}
    infra = enr.get("infrastructure") or {}

    sessions = data["sessions"]
    profile = data["profile"]
    iocs = data["iocs"]
    yara_hits = data["yara_hits"]

    out = []
    out.append(f"# ForenHive — Rapport d'analyse forensique\n")
    out.append(f"**IP cible :** `{ip}`  ")
    out.append(f"**Généré :** {datetime.now(timezone.utc).isoformat(timespec='seconds')}  ")
    out.append(f"**Sessions analysées :** {len(sessions)}\n")

    out.append("---\n")

    # ── 1. Enrichment ─────────────────────────────────────────────────────
    out.append("## 1. Enrichissement IP\n")
    out.append("| Champ | Valeur |")
    out.append("|---|---|")
    out.append(f"| Pays | {geo.get('country') or 'N/A'} ({geo.get('country_code') or '—'}) |")
    out.append(f"| Ville | {geo.get('city') or '—'} |")
    out.append(f"| ASN | {geo.get('asn') or whois.get('asn') or 'N/A'} |")
    out.append(f"| Organisation (geo) | {_md_escape(geo.get('org') or '—')} |")
    out.append(f"| Organisation (whois) | {_md_escape(whois.get('org') or '—')} |")
    out.append(f"| CIDR | `{whois.get('cidr') or 'N/A'}` |")
    out.append(f"| Réseau | {_md_escape(whois.get('network') or '—')} |")
    out.append(f"| AbuseIPDB score | {rep.get('abuse_score') if rep.get('abuse_score') is not None else 'N/A'} / 100 |")
    out.append(f"| Signalements | {rep.get('total_reports') if rep.get('total_reports') is not None else 'N/A'} |")
    out.append(f"| Tor exit | {'OUI' if privacy.get('is_tor') else 'non'} |")
    out.append(f"| VPN | {'OUI' if privacy.get('is_vpn') else 'non'} |")
    out.append(f"| Proxy | {'OUI' if privacy.get('is_proxy') else 'non'} |")
    out.append(f"| Hosting | {'OUI' if privacy.get('is_hosting') else 'non'} |")
    open_ports = (infra.get("open_ports") or [])
    out.append(f"| Ports ouverts (Shodan) | {', '.join(map(str, open_ports)) if open_ports else '—'} |")
    out.append(f"| Enrichi le | {enr.get('enriched_at') or '—'} |")
    out.append("")

    # ── 2. YARA matches ──────────────────────────────────────────────────
    out.append("## 2. Analyse malware (YARA + VirusTotal)\n")
    if not yara_hits:
        out.append("Aucun binaire malveillant capturé n'est rattaché à cette IP "
                   "(pas d'IOC SHA-256 corrélant `file_analysis` ↔ `forensic_iocs`).\n")
    else:
        out.append("| SHA-256 | Règles YARA | VT (mal/und) | Famille |")
        out.append("|---|---|---|---|")
        for h in yara_hits:
            ya = h.get("yara_matches") or []
            if isinstance(ya, dict):
                ya = ya.get("matches") or []
            rules = ", ".join(sorted({m.get("rule", "?") for m in ya if isinstance(m, dict)})) or "—"
            vt = h.get("virustotal_result") or {}
            vt_str = (f"{vt.get('malicious', 0)}/{(vt.get('malicious') or 0) + (vt.get('undetected') or 0)}"
                      if isinstance(vt, dict) else "—")
            family = (vt.get("family") if isinstance(vt, dict) else None) or "—"
            out.append(f"| `{h['sha256'][:24]}…` | {rules} | {vt_str} | {family} |")
        out.append("")

    # ── 3. Sessions / Risk score / Kill chain ─────────────────────────────
    out.append("## 3. Sessions forensiques · Risk score · MITRE\n")
    if not sessions:
        out.append("Aucune session honeypot pour cette IP.\n")
    else:
        for s in sessions:
            out.append(f"### Session `{s['session_id']}` — {s['honeypot_type']}\n")
            out.append(f"- **Période :** {s['started_at']} → {s['ended_at']}")
            out.append(f"- **Risk score :** **{s['risk_score']} / 100**")
            out.append(f"- **Kill chain :** étape {s['kill_chain_stage']}/8 — {s['kill_chain_phase']}")
            out.append(f"- **Technique principale :** `{s['primary_technique']}`")
            techs = s.get("mitre_techniques") or []
            if isinstance(techs, str):
                try:
                    techs = json.loads(techs)
                except Exception:
                    techs = []
            if techs:
                out.append(f"- **Techniques MITRE détectées :** " +
                           ", ".join(f"`{t}`" for t in techs))
            narr = s.get("forensic_narrative") or ""
            if narr:
                out.append(f"\n> {narr.strip()[:600]}{'…' if len(narr) > 600 else ''}\n")
            out.append("")

    # ── 4. Profil de suspect ──────────────────────────────────────────────
    out.append("## 4. Profil comportemental (FBI BAU)\n")
    if not profile:
        out.append("Aucun profil LLM disponible pour cette IP "
                   "(profiler.py non exécuté ou Ollama indisponible lors du run).\n")
    else:
        out.append(f"- **Sophistication :** {profile.get('sophistication') or '—'}")
        out.append(f"- **Confiance :** {profile.get('confidence') or '—'}")
        out.append(f"- **Objectif principal :** {profile.get('primary_objective') or '—'}")
        out.append(f"- **Objectif secondaire :** {profile.get('secondary_objective') or '—'}")
        out.append(f"- **Score organisé :** {profile.get('organized_score') or '—'}")
        out.append(f"- **Disguise :** {profile.get('disguise_type') or '—'} "
                   f"({'oui' if profile.get('disguise_used') else 'non'})")
        out.append(f"- **Escalade détectée :** {'oui' if profile.get('escalation_detected') else 'non'}")
        traits = profile.get("behavioral_traits") or []
        if traits:
            out.append("- **Traits comportementaux :**")
            for t in traits:
                out.append(f"  - {t}")
        sigs = profile.get("signature_indicators") or []
        if sigs:
            out.append("- **Signature (Locard) :**")
            for sg in sigs:
                out.append(f"  - {sg}")
        narr = profile.get("detective_narrative") or ""
        if narr:
            out.append(f"\n> {narr.strip()}\n")
    out.append("")

    # ── 5. IOCs ───────────────────────────────────────────────────────────
    out.append("## 5. Indicateurs de compromission\n")
    if not iocs:
        out.append("Aucun IOC extrait pour cette IP.\n")
    else:
        out.append("| Type | Valeur | Occurrences | Sources |")
        out.append("|---|---|---|---|")
        for i in iocs:
            srcs = ", ".join(i.get("honeypot_types") or [])
            out.append(f"| {i['ioc_type']} | `{_md_escape((i['ioc_value'] or '')[:80])}` | "
                       f"{i['occurrences']} | {srcs or '—'} |")
        out.append("")

    return "\n".join(out)


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--ip", required=True)
    p.add_argument("--out", required=True)
    args = p.parse_args()

    data = _fetch(args.ip)
    md = render(args.ip, data)
    with open(args.out, "w", encoding="utf-8") as fh:
        fh.write(md)
    print(f"Wrote {args.out} ({len(md)} chars)")


if __name__ == "__main__":
    main()
