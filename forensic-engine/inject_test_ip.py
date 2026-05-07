"""
inject_test_ip.py — Seed synthetic honeypot sessions for a target IP, then
run the unified risk scorer (risk_score_optimized.py) against it.

Usage (inside forensic-engine container):
  python inject_test_ip.py                          # defaults to 193.32.162.157
  python inject_test_ip.py --ip 193.32.162.157
  python inject_test_ip.py --ip 193.32.162.157 --score-only  # skip injection, just score
"""
import argparse
import json
from datetime import datetime, timezone, timedelta

import db_pool


def inject(source_ip: str) -> None:
    now = datetime.now(timezone.utc)

    sessions = [
        {
            "session_id":        f"test-cowrie-{source_ip}",
            "honeypot_type":     "cowrie",
            "source_ip":         source_ip,
            "started_at":        now - timedelta(hours=2),
            "ended_at":          now - timedelta(hours=1),
            "login_attempts":    320,
            "success_count":     1,
            "attack_velocity":   8.5,
            "kill_chain_stage":  4,
            "kill_chain_phase":  "Installation",
            "primary_technique": "T1110",
            "mitre_techniques":  json.dumps(["T1110", "T1021"]),
            "enrichment_data":   json.dumps({"yara_matches": [], "vt_malicious": 0}),
            "forensic_narrative": f"SSH brute-force from {source_ip} with successful login.",
        },
        {
            "session_id":        f"test-dionaea-{source_ip}",
            "honeypot_type":     "dionaea",
            "source_ip":         source_ip,
            "started_at":        now - timedelta(hours=3),
            "ended_at":          now - timedelta(hours=2, minutes=30),
            "login_attempts":    50,
            "success_count":     0,
            "attack_velocity":   1.2,
            "kill_chain_stage":  1,
            "kill_chain_phase":  "Reconnaissance",
            "primary_technique": "T1046",
            "mitre_techniques":  json.dumps(["T1046"]),
            "enrichment_data":   json.dumps({}),
            "forensic_narrative": f"Port scan from {source_ip} on Dionaea SMB/445.",
        },
    ]

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
                        updated_at       = NOW()
                    """,
                    (
                        s["session_id"],   s["honeypot_type"],    s["source_ip"],
                        s["started_at"],   s["ended_at"],
                        s["login_attempts"], s["success_count"], s["attack_velocity"],
                        s["kill_chain_stage"], s["kill_chain_phase"], s["primary_technique"],
                        s["mitre_techniques"], s["enrichment_data"], s["forensic_narrative"],
                    ),
                )
        conn.commit()

    print(f"[OK] 2 sessions injected for {source_ip}")


def _store_unified_score(score_data: dict) -> None:
    """Write the unified score row into forensic_sessions (same logic as engine Phase 9)."""
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
    print(f"[OK] Unified score stored: {score_data['risk_score']}/{score_data['risk_level']}")


def score(source_ip: str) -> None:
    from risk_score_optimized import RiskScorer
    print(f"\n--- Running RiskScorer for {source_ip} ---")
    result = RiskScorer().calculate_risk_score(source_ip, time_window_hours=24)
    print(json.dumps(result, indent=2, default=str))
    _store_unified_score(result)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Inject test sessions and run unified risk scoring for a target IP"
    )
    parser.add_argument("--ip",         default="193.32.162.157", help="Target IP")
    parser.add_argument("--score-only", action="store_true",      help="Skip injection, just run scorer")
    args = parser.parse_args()

    if not args.score_only:
        inject(args.ip)

    score(args.ip)
