"""
demo_wannacry.py — Simulation d'une attaque WannaCry via Dionaea.

Pipeline complet depuis une seule IP :
  1. Injection session Dionaea (SMB/445 + EternalBlue + capture WannaCry)
  2. Dépôt du sample dans le dossier binaries Dionaea (YARA scan réel)
  3. Enrichissement réel (AbuseIPDB, IPLocate, WHOIS, Shodan)
  4. YARA scan réel → détection WannaCry_Ransomware
  5. VirusTotal résultat pré-chargé (hash réel WannaCry, 60/72 engines)
  6. Rescore final via RiskScorer

Usage :
  docker exec forenhive-forensic-engine python demo_wannacry.py
  docker exec forenhive-forensic-engine python demo_wannacry.py --ip 1.2.3.4
  docker exec forenhive-forensic-engine python demo_wannacry.py --clean
"""

import argparse
import hashlib
import json
import struct
from datetime import datetime, timezone, timedelta
from pathlib import Path

import db_pool
import config

DEFAULT_IP = "194.165.16.11"  # AbuseIPDB=100, Flyservers LT — bulletproof hoster

# Binaires capturés par Dionaea
BINARIES_DIR = Path(config.DIONAEA_BINARIES_PATH)

# Hash SHA-256 réel de WannaCry (tasksche.exe — variante principale)
WANNACRY_REAL_SHA256 = "ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa"


def _build_wannacry_sample() -> bytes:
    """
    Construit un faux binaire PE qui contient les strings WannaCry.
    Déclenche la règle YARA WannaCry_Ransomware (any of $s*).
    PAS un vrai ransomware — juste les marqueurs textuels dans un stub PE.
    """
    # Stub MZ header (PE valide minimal)
    mz_header = b"MZ" + b"\x00" * 58 + struct.pack("<I", 64)  # e_lfanew = 64
    pe_stub   = b"\x00" * 62 + b"PE\x00\x00"  # signature PE au bon offset

    # Strings qui déclenchent la règle YARA
    yara_bait = (
        b"WannaCry\x00"
        b"WannaCryptor\x00"
        b"WNCRY\x00"
        b"@WanaDecryptor@\x00"
        b"tasksche.exe\x00"
        b"mssecsvc.exe\x00"
        b"!Please Read Me!.txt\x00"
        b".wncry\x00"
        b"icacls . /grant Everyone:F /T /C /Q\x00"
        b"Ooops, your files have been encrypted!\x00"
    )

    # EternalBlue SMB marker (présent dans le shellcode DoublePulsar)
    eternal_blue = (
        b"\x00" * 16 +
        b"samba\x00"
    )

    padding = b"\x00" * (512 - len(mz_header) - len(pe_stub))
    return mz_header + pe_stub + padding + yara_bait + eternal_blue


def _drop_sample(ip: str) -> tuple[str, str]:
    """Dépose le sample WannaCry dans le dossier Dionaea et retourne (sha256, filename)."""
    BINARIES_DIR.mkdir(parents=True, exist_ok=True)
    data   = _build_wannacry_sample()
    sha256 = hashlib.sha256(data).hexdigest()
    fname  = sha256  # Dionaea nomme les fichiers par leur hash
    fpath  = BINARIES_DIR / fname
    if not fpath.exists():
        fpath.write_bytes(data)
        print(f"[SAMPLE ] Binaire déposé : {fpath}")
        print(f"[SAMPLE ] SHA-256 : {sha256}")
    else:
        print(f"[SAMPLE ] Déjà présent : {fpath}")
    return sha256, fname


def _seed_vt_result(sha256: str) -> None:
    """
    Pré-charge un résultat VirusTotal réaliste pour le hash du sample.
    Évite de brûler le quota VT (4 req/jour) sur un sample synthétique.
    Le vrai WannaCry (sha256 = ed01eb...) est bien connu — on simule ce que VT retournerait.
    """
    vt_result = {
        "sha256":          sha256,
        "malicious":       60,
        "suspicious":       4,
        "undetected":       8,
        "total_engines":   72,
        "names":           ["WannaCry", "WannaCryptor", "Ransom.WannaCry", "Trojan.Ransom.WannaCrypt"],
        "family":          "WannaCry",
        "type":            "Ransomware",
        "first_seen":      "2017-05-12T00:00:00Z",
        "last_seen":       datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "tags":            ["ransomware", "worm", "eternalblue", "doublepulsar", "smb"],
        "engine_hits": {
            "Kaspersky":         "Trojan-Ransom.Win32.Wanna.m",
            "Bitdefender":       "Trojan.Ransom.WannaCrypt.A",
            "ESET-NOD32":        "Win32/Filecoder.WannaCryptor.D",
            "McAfee":            "Ransom-WannaCry!",
            "Symantec":          "Ransom.Wannacry",
            "Sophos":            "Troj/Ransom-EMB",
            "Microsoft":         "Ransom:Win32/WannaCrypt",
            "CrowdStrike Falcon": "win/malicious_confidence_100%",
            "Malwarebytes":      "Ransom.WannaCrypt",
            "TrendMicro":        "RANSOM_WCRY.I",
        },
        "note": "Pre-seeded — sample synthétique contenant les marqueurs WannaCry. Hash réel : ed01ebfbc9eb5b...",
    }
    with db_pool.pooled_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO file_analysis (sha256, virustotal_result, analyzed_at)
                VALUES (%s, %s::jsonb, NOW())
                ON CONFLICT (sha256) DO UPDATE
                    SET virustotal_result = EXCLUDED.virustotal_result,
                        analyzed_at = NOW()
                """,
                (sha256, json.dumps(vt_result)),
            )
        conn.commit()
    print(f"[VT     ] Résultat pré-chargé : {vt_result['malicious']}/{vt_result['total_engines']} engines détectent WannaCry")


def inject_dionaea_wannacry(ip: str, sha256: str) -> None:
    """Injecte les sessions Dionaea avec capture WannaCry."""
    now = datetime.now(timezone.utc)
    sessions = [
        {
            "session_id":         f"demo-wannacry-smb-{ip}",
            "honeypot_type":      "dionaea",
            "source_ip":          ip,
            "started_at":         now - timedelta(hours=1, minutes=30),
            "ended_at":           now - timedelta(hours=1, minutes=15),
            "login_attempts":     340,
            "success_count":      1,
            "attack_velocity":    11.3,
            "kill_chain_stage":   5,
            "kill_chain_phase":   "Actions on Objectives",
            "primary_technique":  "T1486",
            "mitre_techniques":   json.dumps([
                "T1190",      # Exploit Public-Facing Application (EternalBlue)
                "T1210",      # Exploitation of Remote Services (MS17-010)
                "T1486",      # Data Encrypted for Impact (WannaCry ransomware)
                "T1071.001",  # Web Protocols C2
                "T1078",      # Valid Accounts
            ]),
            "enrichment_data":    json.dumps({
                "yara_matches": ["WannaCry_Ransomware"],
                "vt_malicious": 60,
                "captured_file": sha256,
                "exploit":       "EternalBlue (MS17-010)",
                "smb_probe":     "WannaCry dropper — encrypted SMB payload",
            }),
            "forensic_narrative": (
                f"IP {ip} (hôte bulletproof Flyservers LT) a exploité la vulnérabilité MS17-010 (EternalBlue) "
                f"sur le port SMB/445. Après 340 tentatives de connexion et 1 succès, le ransomware WannaCry "
                f"a été déployé via DoublePulsar. Dionaea a capturé le binaire malveillant (SHA-256: {sha256[:16]}...). "
                f"YARA a identifié la famille WannaCry_Ransomware. VirusTotal : 60/72 moteurs. "
                f"ATT&CK : T1190 → T1210 → T1486 (Ransomware)."
            ),
        },
        {
            "session_id":         f"demo-wannacry-scan-{ip}",
            "honeypot_type":      "dionaea",
            "source_ip":          ip,
            "started_at":         now - timedelta(hours=2),
            "ended_at":           now - timedelta(hours=1, minutes=45),
            "login_attempts":     890,
            "success_count":      0,
            "attack_velocity":    29.7,
            "kill_chain_stage":   2,
            "kill_chain_phase":   "Reconnaissance",
            "primary_technique":  "T1046",
            "mitre_techniques":   json.dumps([
                "T1046",   # Network Service Discovery
                "T1190",   # Exploit Public-Facing Application
            ]),
            "enrichment_data":    json.dumps({
                "yara_matches": [],
                "vt_malicious": 0,
                "smb_probe":    "MS17-010 vulnerability scan",
            }),
            "forensic_narrative": (
                f"Phase de reconnaissance : {ip} a scanné le réseau en cherchant des hôtes vulnérables "
                f"à EternalBlue (MS17-010). 890 connexions SMB testées. "
                f"ATT&CK : T1046 (Network Service Discovery)."
            ),
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
                        enrichment_data  = EXCLUDED.enrichment_data,
                        updated_at       = NOW()
                    """,
                    (
                        s["session_id"], s["honeypot_type"], s["source_ip"],
                        s["started_at"], s["ended_at"],
                        s["login_attempts"], s["success_count"], s["attack_velocity"],
                        s["kill_chain_stage"], s["kill_chain_phase"], s["primary_technique"],
                        s["mitre_techniques"], s["enrichment_data"], s["forensic_narrative"],
                    ),
                )
        conn.commit()
    print(f"[DIONAEA] {ip} — 2 sessions injectées (SMB scan + WannaCry drop)")


def run_yara_scan() -> list:
    """Lance le vrai scan YARA sur les binaires Dionaea."""
    from yara_scanner import YARAScanner
    print("\n[YARA   ] Lancement du scan sur les binaires Dionaea ...")
    scanner = YARAScanner()
    results = scanner.scan_dionaea_downloads()
    matched = [r for r in results if r["matched"]]
    print(f"[YARA   ] {len(matched)}/{len(results)} fichiers détectés")
    for r in matched:
        rules = [m["rule"] for m in r["matches"]]
        print(f"[YARA   ] MATCH → {Path(r['filepath']).name[:16]}... : {rules}")
    return results


def enrich(ip: str) -> None:
    """Enrichissement réel via les APIs (AbuseIPDB, IPLocate, WHOIS, Shodan)."""
    from enricher import enrich_batch
    print(f"\n[ENRICH ] Enrichissement de {ip} (APIs réelles) ...")
    enrich_batch([ip])
    print(f"[ENRICH ] Terminé")


def rescore(ip: str) -> None:
    """Calcule le score de risque final via RiskScorer."""
    from risk_score_optimized import RiskScorer
    from demo_inject import _store_unified_score
    scorer = RiskScorer()
    print(f"\n[SCORE  ] Calcul du risk score pour {ip} ...")
    result = scorer.calculate_risk_score(ip, time_window_hours=4)
    score  = result["risk_score"]
    level  = result["risk_level"]
    breakdown = result.get("signal_breakdown", {})

    with db_pool.pooled_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE forensic_sessions
                SET risk_score       = %s,
                    risk_level       = %s,
                    confidence       = %s,
                    signal_breakdown = %s::jsonb,
                    scored_at        = NOW(), updated_at = NOW()
                WHERE source_ip = %s AND honeypot_type != 'unified'
                """,
                (score, level, result["confidence"], json.dumps(breakdown), ip),
            )
        conn.commit()

    _store_unified_score(result)

    print(f"[SCORE  ] {ip} → {score}/100 {level} (confiance: {result['confidence']})")
    print()
    for k, v in breakdown.items():
        if isinstance(v, dict):
            bar = "█" * int(v.get("points", 0) * 20 // max(v.get("max", 1), 1))
            print(f"  {k:15s} {bar:<20} {v.get('points',0):2d}/{v.get('max',0)} — {v.get('detail','')}")


def clean(ip: str) -> None:
    with db_pool.pooled_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM forensic_sessions WHERE source_ip = %s", (ip,))
            cur.execute("DELETE FROM ip_enrichment_cache WHERE ip = %s", (ip,))
        conn.commit()
    # Supprimer le sample si présent
    for f in BINARIES_DIR.glob("*"):
        sha = f.name
        if len(sha) == 64:
            content = f.read_bytes()
            if b"WannaCry" in content and b"WNCRY" in content:
                f.unlink()
                print(f"[CLEAN  ] Sample supprimé : {f.name[:16]}...")
    print(f"[CLEAN  ] Données supprimées pour {ip}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Simulation attaque WannaCry — ForenHive")
    parser.add_argument("--ip",    default=DEFAULT_IP, help=f"IP source (défaut: {DEFAULT_IP})")
    parser.add_argument("--clean", action="store_true", help="Nettoyer les données de démo")
    args = parser.parse_args()

    if args.clean:
        clean(args.ip)
    else:
        print("=" * 60)
        print("  ForenHive — Simulation WannaCry / EternalBlue")
        print(f"  IP attaquante : {args.ip}")
        print("=" * 60)

        # 1. Déposer le sample
        sha256, _ = _drop_sample(args.ip)

        # 2. Injecter les sessions Dionaea
        inject_dionaea_wannacry(args.ip, sha256)

        # 3. Enrichissement réel
        enrich(args.ip)

        # 4. YARA scan réel
        run_yara_scan()

        # 5. Pré-charger résultat VT
        _seed_vt_result(sha256)

        # 6. Rescore
        rescore(args.ip)

        print("\n" + "=" * 60)
        print("  PIPELINE TERMINÉ")
        print(f"  → Session : unified-{args.ip}")
        print(f"  → Rapport : POST /api/reports/forensic/unified-{args.ip}/generate")
        print("=" * 60)
