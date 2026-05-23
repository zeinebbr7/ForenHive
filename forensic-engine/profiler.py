"""
ForenHive Forensic Engine — Attacker Profiler (Phase 5)

LLM-powered behavioral analysis using criminal profiling methodology (FBI BAU concepts).
Consumes all Phase 1-4 outputs (enrichment, YARA, VT, risk scores, MITRE, timeline) to
generate structured suspect profiles via Ollama/Mistral, with memory system for
similarity-based case comparison.

Each profile is indexed to both Elasticsearch (forenhive-suspect-profiles) and PostgreSQL
(suspect_profiles table) for forensic queries and evidence chain binding.
"""

import json
import logging
import re
from datetime import UTC, datetime

import config
import psycopg2
import psycopg2.extras
import requests
from elasticsearch import Elasticsearch, NotFoundError

log = logging.getLogger("profiler")

# ── Configuration ──────────────────────────────────────────────────────────────

OLLAMA_URL = config.OLLAMA_URL
OLLAMA_MODEL = config.OLLAMA_MODEL
OLLAMA_TEMPERATURE = 0.3
OLLAMA_NUM_CTX = 8192
OLLAMA_TIMEOUT_SEC = 300  # 5 minutes (Mistral on CPU is slow)

ES_PROFILES_INDEX = "forenhive-suspect-profiles"
MEMORY_MAX_CASES = 5

# ── Objectives classification ──────────────────────────────────────────────────

OBJECTIVES_LIST = [
    "credential_harvesting",
    "botnet_recruitment",
    "cryptomining",
    "data_exfiltration",
    "reconnaissance",
    "lateral_movement",
    "ransomware_deployment",
    "persistence_establishment",
    "unknown",
]

# ── MITRE Kill Chain phases (aligned with mitre_mapper.py) ────────────────────

KILL_CHAIN_PHASES = [
    "reconnaissance",
    "weaponization",
    "delivery",
    "exploitation",
    "installation",
    "command_and_control",
    "actions_on_objectives",
]

# ─────────────────────────────────────────────────────────────────────────────
# POSTGRESQL QUERIES
# ─────────────────────────────────────────────────────────────────────────────

import db_pool  # noqa: E402  (import tardif intentionnel — db_pool initialisé après config)


def _pg_conn():
    """Return a pooled PostgreSQL connection (auto-released on .close())."""
    return db_pool.pooled_conn()


def _query_sessions_for_ip(source_ip: str) -> dict:
    """Load aggregated session data for an IP from forensic_sessions table."""
    conn = None
    try:
        conn = _pg_conn()
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(
                """
                SELECT
                    COUNT(*) as session_count,
                    MAX(risk_score) as max_risk_score,
                    MIN(started_at) as first_seen,
                    MAX(ended_at) as last_seen,
                    ARRAY_AGG(DISTINCT honeypot_type) FILTER (WHERE honeypot_type IS NOT NULL) as honeypots,
                    ARRAY_AGG(DISTINCT primary_technique) FILTER (WHERE primary_technique IS NOT NULL) as techniques,
                    MAX(CASE WHEN kill_chain_stage > 0 THEN kill_chain_phase ELSE NULL END) as deepest_kill_chain
                FROM forensic_sessions
                WHERE source_ip = %s
                GROUP BY source_ip
                """,
                (source_ip,),
            )
            row = cur.fetchone()
        if not row:
            return {}
        d = dict(row)
        d["honeypots"] = d.get("honeypots") or []
        d["techniques"] = d.get("techniques") or []
        return d
    except Exception as e:
        log.warning(f"Query sessions for {source_ip} failed: {e}")
        return {}
    finally:
        if conn is not None:
            conn.close()


def _query_enrichment_cache(source_ip: str) -> dict:
    """Load IP enrichment data from cache. Falls back to stale data rather than empty."""
    conn = None
    try:
        conn = _pg_conn()
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            # Prefer fresh row; fall back to stale rather than returning nothing.
            cur.execute(
                """
                SELECT data FROM ip_enrichment_cache
                WHERE ip = %s
                ORDER BY expires_at DESC
                LIMIT 1
                """,
                (source_ip,),
            )
            row = cur.fetchone()
        if row:
            data = row["data"]
            return data if isinstance(data, dict) else json.loads(data)
        return {}
    except Exception as e:
        log.warning(f"Query enrichment for {source_ip} failed: {e}")
        return {}
    finally:
        if conn is not None:
            conn.close()


def _query_timeline_events(source_ip: str, limit: int = 500) -> list:
    """Load timeline events for an IP."""
    conn = None
    try:
        conn = _pg_conn()
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(
                """
                SELECT ts, honeypot_type, event_category, event_action, summary, destination_port
                FROM forensic_timeline_events
                WHERE source_ip = %s
                ORDER BY ts ASC
                LIMIT %s
                """,
                (source_ip, limit),
            )
            rows = cur.fetchall()
        return [dict(row) for row in rows] if rows else []
    except Exception as e:
        log.warning(f"Query timeline for {source_ip} failed: {e}")
        return []
    finally:
        if conn is not None:
            conn.close()


def _store_profile_pg(source_ip: str, profile: dict, risk_score: int) -> bool:
    """Store profile to PostgreSQL suspect_profiles table."""
    conn = None
    try:
        conn = _pg_conn()
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO suspect_profiles (source_ip, profile, risk_score)
                VALUES (%s, %s, %s)
                ON CONFLICT (source_ip) DO UPDATE SET
                    profile    = EXCLUDED.profile,
                    risk_score = EXCLUDED.risk_score,
                    updated_at = NOW()
                """,
                (source_ip, json.dumps(profile), risk_score),
            )
        conn.commit()
        log.debug(f"Stored profile to PG for {source_ip}")
        return True
    except Exception as e:
        log.warning(f"Store profile to PG failed: {e}")
        return False
    finally:
        if conn is not None:
            conn.close()


# ─────────────────────────────────────────────────────────────────────────────
# ELASTICSEARCH QUERIES
# ─────────────────────────────────────────────────────────────────────────────


def _query_smb_profile(es: Elasticsearch, source_ip: str) -> dict:
    """Query SMB analysis profile from forenhive-smb-analysis index."""
    try:
        result = es.get(index="forenhive-smb-analysis", id=source_ip)
        if result.get("found"):
            return result["_source"].get("smb_activity", {})
        return {}
    except NotFoundError:
        return {}
    except Exception as e:
        log.debug(f"SMB profile query for {source_ip} failed: {e}")
        return {}


def _query_similar_profiles(
    es: Elasticsearch, source_ip: str, techniques: list, asn: int, country: str, risk_score: int
) -> list:
    """Query ES memory for similar past profiles."""
    if not techniques and not asn and not country:
        return []

    should_clauses = []
    if techniques:
        should_clauses.append({"terms": {"mitre_techniques.keyword": techniques}})
    if asn:
        should_clauses.append({"term": {"enrichment.geo.asn": asn}})
    if country:
        should_clauses.append({"term": {"enrichment.geo.country_code.keyword": country}})
    should_clauses.append(
        {"range": {"risk_score": {"gte": risk_score - 15, "lte": risk_score + 15}}}
    )

    query = {
        "size": MEMORY_MAX_CASES,
        "query": {
            "bool": {
                "must_not": [{"term": {"source_ip.keyword": source_ip}}],
                "should": should_clauses,
                "minimum_should_match": 1,
            }
        },
        "_source": [
            "source_ip",
            "sophistication",
            "primary_objective",
            "mitre_techniques",
            "enrichment.geo.country_code",
            "risk_score",
            "detective_narrative",
        ],
    }

    try:
        resp = es.search(index=ES_PROFILES_INDEX, body=query)
        cases = []
        for hit in resp.get("hits", {}).get("hits", []):
            src = hit["_source"]
            cases.append(
                {
                    "source_ip": src.get("source_ip"),
                    "sophistication": src.get("sophistication"),
                    "primary_objective": src.get("primary_objective"),
                    "mitre_techniques": src.get("mitre_techniques", []),
                    "country": src.get("enrichment", {}).get("geo", {}).get("country_code"),
                    "risk_score": src.get("risk_score"),
                    "narrative": src.get("detective_narrative"),
                }
            )
        return cases
    except Exception as e:
        log.debug(f"Similar profiles query failed: {e}")
        return []


def _store_profile_es(es: Elasticsearch, profile: dict, source_ip: str) -> bool:
    """Store profile to Elasticsearch forenhive-suspect-profiles index."""
    try:
        doc = {
            **profile,
            "source_ip": source_ip,
            "@timestamp": datetime.now(UTC).isoformat(),
        }
        es.index(
            index=ES_PROFILES_INDEX,
            id=f"profile-{source_ip}",
            body=doc,
        )
        log.debug(f"Stored profile to ES for {source_ip}")
        return True
    except Exception as e:
        log.warning(f"Store profile to ES failed: {e}")
        return False


# ─────────────────────────────────────────────────────────────────────────────
# PROMPT BUILDERS
# ─────────────────────────────────────────────────────────────────────────────


def _build_section1_system_role() -> str:
    """System role: FBI behavioral profiler persona."""
    return """You are a forensic profiler specializing in cyber criminal behavior analysis. Your methodology is grounded in FBI Behavioral Analysis Unit (BAU) principles:

1. Organized vs. Disorganized Typology — predict offender characteristics based on crime scene patterns
2. Modus Operandi (MO) — the method and tools; consistent across attacks
3. Signature Behavior — non-functional patterns revealing psychological needs
4. Locard's Exchange Principle — every contact leaves traces
5. Crime Scene Staging — evidence of deliberate deception or anti-forensics
6. Escalation & Kill Chain — progression through attack phases indicates sophistication
7. Victimology & Target Selection — are targets chosen (sophistication) or random (amateur)?
8. Geographic & Temporal Profiling — behavioral patterns in space and time
9. Inductive vs. Deductive Reasoning — pattern matching and hypothesis refinement

You MUST output a valid JSON object (and ONLY JSON) matching this exact schema. No text before or after."""


def _build_section2_criminology_framework() -> str:
    """Criminology framework: decision rules for classification."""
    return """## CRIMINOLOGY DECISION RULES

### Organized Attacker Indicators
- Targeted credential selection (not default/common passwords)
- Custom or modified tools (evidence of skill/adaptation)
- Reconnaissance before exploitation (planning)
- Anonymization: Tor, VPN, proxy, hosting provider origin
- Anti-forensics behavior: cleanup, evidence elimination attempts
- Long sessions or repeated access (persistence)
- Multi-stage attacks with clear progression
- Adaptive behavior (changing tactics when detected)

### Disorganized Attacker Indicators
- Default credentials (public lists, common passwords)
- Off-the-shelf tools with no modification
- No reconnaissance; immediate or random targeting
- Direct IP usage; no anonymization layers
- No cleanup; leaves obvious forensic traces
- Short, impulsive sessions
- Single-stage or chaotic attacks
- Rigid behavior; repeats same tactics

### Sophistication Levels

**Amateur**: Scripted/automated attacks, public tools, no customization, default credentials, no adaptation, short sessions, minimal planning.
**Intermediate**: Some custom tools or modification, targeted credentials, moderate session length, some evidence of planning, limited anti-forensics.
**Expert**: Custom payloads, multi-stage attacks, evidence of reconnaissance, advanced anti-forensics, adaptive behavior, forensic awareness (Tor/VPN), long campaigns.

### Primary Objectives
Classify as one of: credential_harvesting, botnet_recruitment, cryptomining, data_exfiltration, reconnaissance, lateral_movement, ransomware_deployment, persistence_establishment, unknown.

### Disguise Detection
- Tor/VPN/proxy usage = strong organized indicator (forensic awareness)
- Hosting provider origin = often botnet or compromised infrastructure
- Residential IP = less planning; may suggest opportunistic attacker

### Escalation & Kill Chain
- Single kill chain phase = limited or opportunistic
- Multiple phases = strategic progression, higher sophistication
- Lateral movement = indicates post-compromise objectives (C&C, exfil)

### Signature Behavior
Non-functional patterns that reveal attacker psychology:
- Unusual command ordering (not typical shell flow)
- Repeated failed attempts on specific targets
- Timing patterns (off-hours, regular intervals)
- Unnecessary actions (exploration beyond objective)
- Distinctive error handling or fallback strategies"""


def _build_section3_evidence(
    sessions: dict,
    enrichment: dict,
    timeline: list,
    smb_data: dict,
) -> str:
    """Build Section 3: session evidence in XML-delimited format."""
    section = "<CURRENT_SESSION>\n"

    # Session metadata
    section += "  <SESSION_META>\n"
    section += f"    <session_count>{sessions.get('session_count', 0)}</session_count>\n"
    section += f"    <first_seen>{sessions.get('first_seen', 'unknown')}</first_seen>\n"
    section += f"    <last_seen>{sessions.get('last_seen', 'unknown')}</last_seen>\n"
    section += f"    <honeypots>{', '.join(sessions.get('honeypots', []))}</honeypots>\n"
    section += "  </SESSION_META>\n"

    # Enrichment
    section += "  <ENRICHMENT>\n"
    geo = enrichment.get("geo", {})
    reputation = enrichment.get("reputation", {})
    privacy = enrichment.get("privacy", {})

    section += f"    <country>{geo.get('country', 'unknown')}</country>\n"
    section += f"    <asn>{geo.get('asn', 'unknown')}</asn>\n"
    section += f"    <organization>{geo.get('org', 'unknown')}</organization>\n"
    section += f"    <abuse_score>{reputation.get('abuse_score', 'N/A')}</abuse_score>\n"
    section += f"    <is_tor>{privacy.get('is_tor', False)}</is_tor>\n"
    section += f"    <is_vpn>{privacy.get('is_vpn', False)}</is_vpn>\n"
    section += f"    <is_proxy>{privacy.get('is_proxy', False)}</is_proxy>\n"
    section += "  </ENRICHMENT>\n"

    # MITRE
    section += "  <MITRE>\n"
    techniques = sessions.get("techniques", [])
    kill_chain = sessions.get("deepest_kill_chain", "unknown")
    section += f"    <techniques>{', '.join(techniques)}</techniques>\n"
    section += f"    <kill_chain_phase>{kill_chain}</kill_chain_phase>\n"
    section += "  </MITRE>\n"

    # Timeline summary
    section += "  <TIMELINE>\n"
    section += f"    <event_count>{len(timeline)}</event_count>\n"
    if timeline:
        categories = {}
        for event in timeline:
            cat = event.get("event_category", "unknown")
            categories[cat] = categories.get(cat, 0) + 1
        for cat, count in sorted(categories.items()):
            section += f"    <{cat}>{count}</{cat}>\n"
    section += "  </TIMELINE>\n"

    # SMB data (if present)
    if smb_data:
        section += "  <SMB_ACTIVITY>\n"
        section += f"    <share_enumeration>{smb_data.get('share_enumerated', False)}</share_enumeration>\n"
        section += (
            f"    <epmapper_prescan>{smb_data.get('epmapper_prescan', 0)}</epmapper_prescan>\n"
        )
        ops = smb_data.get("dcerpc_operations", [])
        if ops:
            section += f"    <exploit_attempts>{len(ops)}</exploit_attempts>\n"
        section += "  </SMB_ACTIVITY>\n"

    # Risk score
    risk_score = sessions.get("max_risk_score", 0)
    section += f"  <RISK_SCORE>{risk_score}</RISK_SCORE>\n"

    section += "</CURRENT_SESSION>\n"
    return section


def _build_section4_reference_cases(cases: list) -> str:
    """Build Section 4: similar past cases (only if cases exist)."""
    if not cases:
        return ""

    section = "<REFERENCE_CASES>\n"
    for i, case in enumerate(cases, 1):
        section += f"  <CASE_{i}>\n"
        section += f"    <source_ip>{case.get('source_ip')}</source_ip>\n"
        section += f"    <sophistication>{case.get('sophistication', 'unknown')}</sophistication>\n"
        section += f"    <primary_objective>{case.get('primary_objective')}</primary_objective>\n"
        section += f"    <mitre_techniques>{', '.join(case.get('mitre_techniques', []))}</mitre_techniques>\n"
        section += f"    <country>{case.get('country', 'unknown')}</country>\n"
        section += f"    <risk_score>{case.get('risk_score')}</risk_score>\n"
        section += f"  </CASE_{i}>\n"
    section += "</REFERENCE_CASES>\n"
    return section


# ─────────────────────────────────────────────────────────────────────────────
# OLLAMA INTEGRATION
# ─────────────────────────────────────────────────────────────────────────────


def _call_ollama(prompt: str) -> str | None:
    """Call Ollama/Mistral for profile generation."""
    try:
        resp = requests.post(
            f"{OLLAMA_URL}/api/generate",
            json={
                "model": OLLAMA_MODEL,
                "prompt": prompt,
                "stream": False,
                "options": {
                    "temperature": OLLAMA_TEMPERATURE,
                    "num_ctx": OLLAMA_NUM_CTX,
                },
            },
            timeout=OLLAMA_TIMEOUT_SEC,
        )
        resp.raise_for_status()
        response_text = resp.json().get("response", "")
        return response_text
    except requests.Timeout:
        log.error("Ollama request timeout")
        return None
    except Exception as e:
        log.error(f"Ollama API call failed: {e}")
        return None


def _parse_json_response(response: str) -> dict | None:
    """Extract and parse JSON from Ollama response."""
    if not response:
        return None

    # Strip markdown code blocks
    response = re.sub(r"^```json\s*", "", response, flags=re.MULTILINE)
    response = re.sub(r"^```\s*", "", response, flags=re.MULTILINE)
    response = re.sub(r"\s*```$", "", response, flags=re.MULTILINE)

    # Find first { and last }
    start = response.find("{")
    end = response.rfind("}")
    if start == -1 or end == -1:
        return None

    json_str = response[start : end + 1]
    try:
        return json.loads(json_str)
    except json.JSONDecodeError:
        return None


# ─────────────────────────────────────────────────────────────────────────────
# ATTACKER PROFILER
# ─────────────────────────────────────────────────────────────────────────────


class AttackerProfiler:
    """LLM-powered attacker behavioral profiler."""

    def __init__(self, es: Elasticsearch, pg_conn_factory=None):
        self.es = es
        self.pg_conn_factory = pg_conn_factory

    def profile_ip(self, source_ip: str) -> dict:
        """Generate a behavioral profile for an attacker IP."""

        log.info(f"Profiling {source_ip}")

        # Load all evidence
        sessions = _query_sessions_for_ip(source_ip)
        if not sessions:
            log.warning(f"No sessions found for {source_ip}")
            return self._minimal_profile(source_ip, confidence=0.0)

        enrichment = _query_enrichment_cache(source_ip)
        timeline = _query_timeline_events(source_ip)
        smb_data = _query_smb_profile(self.es, source_ip)

        risk_score = sessions.get("max_risk_score", 0)
        techniques = [t for t in sessions.get("techniques", []) if t]

        # Query similar past profiles
        asn = enrichment.get("geo", {}).get("asn")
        country = enrichment.get("geo", {}).get("country_code")
        similar = _query_similar_profiles(self.es, source_ip, techniques, asn, country, risk_score)

        # Build detective prompt (4 sections)
        section1 = _build_section1_system_role()
        section2 = _build_section2_criminology_framework()
        section3 = _build_section3_evidence(sessions, enrichment, timeline, smb_data)
        section4 = _build_section4_reference_cases(similar) if similar else ""

        prompt = (
            f"{section1}\n\n"
            f"{section2}\n\n"
            f"## CURRENT SESSION EVIDENCE\n\n"
            f"{section3}\n"
            f"## SIMILAR PAST CASES (for comparison)\n\n"
            f"{section4}\n"
            f"Now analyze this attacker profile and output ONLY the JSON object.\n"
            f"JSON schema:\n"
            f'{{"source_ip": "string", "sophistication": "amateur|intermediate|expert|unknown", '
            f'"confidence": 0.0-1.0, "primary_objective": "string", "secondary_objective": "string|null", '
            f'"behavioral_traits": ["..."], "organized_score": 0.0-1.0, "disguise_used": true/false, '
            f'"disguise_type": "tor|vpn|proxy|none", "escalation_detected": true/false, '
            f'"mitre_techniques": ["T-IDs"], "dominant_tactic": "string", "kill_chain_phase": "string", '
            f'"signature_indicators": ["..."], "similar_past_cases": {len(similar)}, '
            f'"risk_score": {risk_score}, "detective_narrative": "3-5 sentences"}}'
        )

        # Call Ollama (with retry)
        log.debug(f"Calling Ollama for {source_ip} (prompt length: {len(prompt)} chars)")
        response = _call_ollama(prompt)
        if not response:
            log.warning(f"Ollama call failed for {source_ip}; retrying...")
            response = _call_ollama(prompt)

        if not response:
            log.error(f"Ollama failed twice for {source_ip}; returning minimal profile")
            return self._minimal_profile(source_ip, confidence=0.0)

        # Parse response
        profile = _parse_json_response(response)
        if not profile:
            log.warning(f"JSON parse failed for {source_ip}; retrying Ollama...")
            response = _call_ollama(prompt)
            profile = _parse_json_response(response)

        if not profile:
            log.error(f"JSON parse failed twice for {source_ip}; returning minimal profile")
            return self._minimal_profile(source_ip, confidence=0.0)

        # Ensure required fields exist
        profile.setdefault("source_ip", source_ip)
        profile.setdefault("risk_score", risk_score)
        profile.setdefault("similar_past_cases", len(similar))
        profile.setdefault("confidence", 0.5)

        log.info(
            f"Profile complete for {source_ip}: "
            f"sophistication={profile.get('sophistication')}, "
            f"confidence={profile.get('confidence')}"
        )

        # Store to both ES and PG
        _store_profile_es(self.es, profile, source_ip)
        _store_profile_pg(source_ip, profile, risk_score)

        return profile

    def _minimal_profile(self, source_ip: str, confidence: float = 0.0) -> dict:
        """Return minimal profile when profiling fails."""
        return {
            "source_ip": source_ip,
            "sophistication": "unknown",
            "confidence": confidence,
            "primary_objective": "unknown",
            "secondary_objective": None,
            "behavioral_traits": [],
            "organized_score": 0.5,
            "disguise_used": False,
            "disguise_type": "none",
            "escalation_detected": False,
            "mitre_techniques": [],
            "dominant_tactic": "unknown",
            "kill_chain_phase": "unknown",
            "signature_indicators": [],
            "similar_past_cases": 0,
            "risk_score": 0,
            "detective_narrative": "Profile generation failed; insufficient data or Ollama unavailable.",
        }


# ─────────────────────────────────────────────────────────────────────────────
# CLI TESTING
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import argparse
    import sys

    logging.basicConfig(
        level=logging.DEBUG,
        format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%SZ",
        handlers=[logging.StreamHandler(sys.stdout)],
    )

    parser = argparse.ArgumentParser(description="Profile an attacker IP")
    parser.add_argument("--ip", required=True, help="Source IP to profile")
    args = parser.parse_args()

    es = Elasticsearch(
        f"http://{config.ES_HOST}:{config.ES_PORT}",
        request_timeout=30,
    )

    profiler = AttackerProfiler(es, _pg_conn)
    result = profiler.profile_ip(args.ip)

    print("\n" + "=" * 80)
    print(f"PROFILE FOR {args.ip}")
    print("=" * 80)
    print(json.dumps(result, indent=2))
