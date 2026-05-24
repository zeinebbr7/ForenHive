# Sprint 3 — Catalogue des extraits de code à citer

Ce document liste, **pour chaque composant**, les 5–10 lignes les plus parlantes à insérer en `\begin{lstlisting}` dans le chapitre 7. Chaque extrait est cité par **fichier + plage de lignes** pour faciliter la recopie depuis le repo.

> **Convention** : les plages de lignes correspondent au repo à l'état `main` au 2026-05-24. Toujours recopier depuis le fichier, jamais reformuler — c'est l'engagement "vrai code, pas du pseudo-code" du chapitre 5.

---

## 1. `docker-compose.yml` — service `forensic-engine` (lignes 206–238)

Ce qui rend l'extrait parlant : le bind-mount des binaires Dionaea en read-only, le passage des clés API en `env_file`, la dépendance ES+PG, la cron interne 5 min.

```yaml
forensic-engine:
  build: ./forensic-engine
  container_name: forenhive-forensic-engine
  restart: unless-stopped
  ports:
    - "8001:8001"
  volumes:
    - dionaea-malware:/opt/dionaea/var/lib/dionaea:ro
    - zeek-logs:/usr/local/zeek/logs:ro
    - ./forensic-engine/yara_rules:/app/yara_rules:ro
    - ./geoip/GeoLite2-City.mmdb:/app/GeoLite2-City.mmdb:ro
    - ./geoip/GeoLite2-ASN.mmdb:/app/GeoLite2-ASN.mmdb:ro
  networks:
    - backend-net
  env_file:
    - .env
  environment:
    - PG_HOST=forenhive-postgresql
    - ENGINE_INTERVAL_MINUTES=5
    - ABUSEIPDB_KEY=${ABUSEIPDB_API_KEY}
    - VIRUSTOTAL_KEY=${VIRUSTOTAL_API_KEY}
  depends_on:
    - elasticsearch
    - postgresql
```

---

## 2. `forensic-engine/Dockerfile` (intégral, 16 lignes)

Parlant : minimalisme `python:3.11-slim`, install gcc + libssl pour `yara-python`, exposition `:8001`.

```dockerfile
FROM python:3.11-slim
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc libssl-dev libmagic1 \
    && rm -rf /var/lib/apt/lists/*
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
EXPOSE 8001
CMD ["python", "server.py"]
```

---

## 3. `forensic-engine/engine.py` — orchestrateur (lignes 1311–1346)

Parlant : voir l'ordre strict des 9 phases en quelques lignes.

```python
# Phase 1 — IP enrichment
enrichment_cache = self.run_enrichment(hours_back)

# Phase 2 — SMB forensic analysis
smb_count = self.run_smb_analysis(enrichment_cache)

# Phase 3a — YARA scan + Phase 3b — VT
self.run_yara_scan()
self.run_vt_from_es(hours_back)

# Phase 4 — Session scoring + MITRE deterministic
vt_ok = not self.vt.is_quota_exhausted()
scored = self.run_session_scoring(hours_back, enrichment_cache, vt_was_available=vt_ok)

# Phase 5 — Per-IP unified timeline
timeline_stats = self.run_timeline_build(hours_back)

# Phase 6 — Structured IoC extraction
ioc_stats = self.run_ioc_extraction(hours_back)

# Phase 7 — Seal forensic_sessions (SHA-256 + Merkle + RFC 3161)
coc_stats = self.run_chain_of_custody()

# Phase 8 — LLM behavioral profiling
profiled = self.run_profiling(scored)

# Phase 9 — Unified risk scoring (per IP across all honeypots)
```

---

## 4. `forensic-engine/db/schema.sql` — table `forensic_sessions` (lignes 22–62)

Parlant : la table-clé du Sprint 3, contraintes `CHECK` sur risk_score, colonnes JSONB pour MITRE + enrichment.

```sql
CREATE TABLE IF NOT EXISTS forensic_sessions (
    session_id          VARCHAR(100) PRIMARY KEY,
    honeypot_type       VARCHAR(20),
    source_ip           VARCHAR(45),
    started_at          TIMESTAMP,
    ended_at            TIMESTAMP,
    risk_score          INTEGER CHECK (risk_score >= 0 AND risk_score <= 100),
    mitre_techniques    JSONB,
    enrichment_data     JSONB,
    kill_chain_phase    VARCHAR(50),
    kill_chain_stage    INTEGER,
    primary_technique   VARCHAR(20),
    forensic_narrative  TEXT,
    created_at          TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_sessions_source_ip  ON forensic_sessions (source_ip);
CREATE INDEX IF NOT EXISTS idx_sessions_risk_score ON forensic_sessions (risk_score DESC);
```

**Variante** — table `forensic_chain_of_custody` (lignes 130–142) :

```sql
CREATE TABLE IF NOT EXISTS forensic_chain_of_custody (
    id              BIGSERIAL    PRIMARY KEY,
    session_id      VARCHAR(100) NOT NULL UNIQUE
                    REFERENCES forensic_sessions(session_id) ON DELETE CASCADE,
    record_hash     CHAR(64)     NOT NULL,
    prev_hash       CHAR(64),
    canonical_json  JSONB        NOT NULL,
    batch_id        BIGINT,
    sealed_at       TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);
```

---

## 5. `forensic-engine/enricher.py` — court-circuit IPs privées (lignes 65–95)

Parlant : la décision de design "private IP = no public API call".

```python
def _is_private(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return True


def _classify_private_ip(ip: str) -> dict:
    """Loopback / Docker bridge / corporate internal."""
    ...
```

Cible alternative — pipeline 5 lookups en parallèle (chercher `_tracker.skip_if_exhausted` dans le fichier).

---

## 6. `forensic-engine/yara_rules/ransomware.yar` — règle LockBit (intégrale)

Parlant : montre une vraie règle YARA avec `meta.severity`, strings, `condition: 2 of them`.

```yara
rule LockBit_Ransomware {
    meta:
        description = "LockBit 2.0/3.0 ransomware"
        severity = "critical"
    strings:
        $s1 = "LockBit" ascii nocase
        $s2 = ".lockbit" ascii nocase
        $s3 = "lockbit3" ascii nocase
        $mutex = "Global\\{F18E8A5C" ascii
    condition:
        2 of them
}
```

---

## 7. `forensic-engine/mitre_mapper.py` — règles déterministes Cowrie (lignes 210–230)

Parlant : la "détection sans LLM" — règles `if` simples, mais avec les vrais IDs ATT&CK.

```python
if honeypot == "cowrie":
    if login_attempts > 1:
        techniques.append("T1110.001")   # Password Guessing
    if login_attempts > 100:
        techniques.append("T1110.003")   # Password Spraying
    if login_success:
        techniques.append("T1078")       # Valid Accounts
    if command_count > 0 or commands:
        techniques.append("T1059.004")   # Unix Shell
    if downloads > 0:
        techniques.append("T1105")       # Ingress Tool Transfer
    if any(any(pat in cmd for pat in _CRED_PATTERNS) for cmd in commands):
        techniques.append("T1552.001")   # Credentials in Files
```

**Variante** — prompt LLM court (lignes 320–329), pour montrer la "narration sans IDs" :

```python
prompt = (
    "Forensic analyst report. Write 2 sentences only. No JSON.\n\n"
    f"Attack: {honeypot} honeypot on port {port}\n"
    f"Source: {src_ip}\n"
    f"Techniques: {', '.join(technique_names)}\n"
    f"Login attempts: {attempts}\n"
    f"Commands: {commands if commands else 'none'}\n"
    f"Malware: {yara}\n\n"
    "Write a concise forensic summary describing this attack and its likely objective."
)
```

---

## 8. `forensic-engine/risk_score.py` — taxonomie WHO/WHAT/HOW (lignes 17–34)

Parlant : la "carte de pondération" du modèle, à citer en docstring extract.

```text
WHO  (33 pts) — Qui est l'attaquant ?
  • reputation      (15)  AbuseIPDB
  • anonymization   (10)  Tor / VPN / proxy
  • threat_history  (8)   récidive + ASN connu

WHAT (43 pts) — Que fait-il ?
  • intent_volume     (10)
  • compromise_depth  (15)
  • exfiltration      (8)
  • lateral_movement  (10)

HOW  (24 pts) — Avec quels moyens ?
  • malware              (15)  YARA + VirusTotal
  • mitre_sophistication (9)   diversité tactiques ATT&CK
```

**Variante code** — signal `reputation` (lignes 186–218) montre la logique de seuils.

---

## 9. `forensic-engine/chain_of_custody.py` — Merkle root (lignes 117–125)

Parlant : 9 lignes de Python = la racine cryptographique de la chaîne de preuves.

```python
def merkle_root(hashes: list[str]) -> str:
    if not hashes:
        return sha256_hex(b"")
    level = [bytes.fromhex(h) for h in hashes]
    while len(level) > 1:
        if len(level) % 2:
            level.append(level[-1])
        level = [hashlib.sha256(level[i] + level[i + 1]).digest()
                 for i in range(0, len(level), 2)]
    return level[0].hex()
```

**Variante** — appel RFC 3161 (lignes 158–177) :

```python
tsq = TimestampRequestBuilder().data(bytes.fromhex(digest_hex)).nonce(nonce=True).build()
resp = requests.post(
    TSA_URL,
    data=tsq.as_bytes(),
    headers={"Content-Type": "application/timestamp-query"},
    timeout=TSA_TIMEOUT,
)
tsr = decode_timestamp_response(resp.content)
result["tsa_time"]     = getattr(tsr.tst_info, "gen_time", None)
result["tsa_response"] = resp.content
```

---

## 10. `forensic-engine/ioc_extractor.py` — régex IoC (lignes 43–53)

Parlant : 7 régex précompilées suffisent à extraire 10 types d'IoC.

```python
RE_URL       = re.compile(r"https?://[^\s'\"<>`]+", re.IGNORECASE)
RE_IPV4      = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
RE_SHA256    = re.compile(r"\b[a-fA-F0-9]{64}\b")
RE_MD5       = re.compile(r"(?<![a-fA-F0-9])[a-fA-F0-9]{32}(?![a-fA-F0-9])")
RE_CVE       = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
RE_EMAIL     = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
RE_FILE_PATH = re.compile(
    r"(?:^|\s)(/(?:bin|sbin|tmp|var|etc|usr|root|home|opt|dev)/[^\s;|&'\"`<>]+)"
)
```

**Variante** — upsert PostgreSQL dédupliquant (lignes 244–262) montre l'idempotence.

---

## 11. `forensic-engine/profiler.py` — schéma JSON cible (lignes 604–612)

Parlant : le contrat de sortie strict imposé à Mistral.

```python
prompt = (
    f"{section1}\n\n{section2}\n\n"
    f"## CURRENT SESSION EVIDENCE\n\n{section3}\n"
    f"## SIMILAR PAST CASES (for comparison)\n\n{section4}\n"
    f"Now analyze this attacker profile and output ONLY the JSON object.\n"
    f"JSON schema:\n"
    f'{{"source_ip": "string", "sophistication": "amateur|intermediate|expert|unknown", '
    f'"confidence": 0.0-1.0, "primary_objective": "string", '
    f'"behavioral_traits": ["..."], "organized_score": 0.0-1.0, '
    f'"disguise_used": true/false, "disguise_type": "tor|vpn|proxy|none", '
    f'"escalation_detected": true/false, "mitre_techniques": ["T-IDs"], '
    f'"dominant_tactic": "string", "kill_chain_phase": "string", '
    f'"signature_indicators": ["..."], "similar_past_cases": {len(similar)}, '
    f'"risk_score": {risk_score}, "detective_narrative": "3-5 sentences"}}'
)
```

**Variante** — settings Ollama immuables (lignes 67–73) :

```python
OLLAMA_TEMPERATURE  = 0.3
OLLAMA_NUM_CTX      = 8192
OLLAMA_TIMEOUT_SEC  = 300  # Mistral 7B on CPU
ES_PROFILES_INDEX   = "forenhive-suspect-profiles"
MEMORY_MAX_CASES    = 5
```

---

## 12. `forensic-engine/profiler.py` — section criminologie (lignes 357–406)

Parlant : c'est le **vrai prompt FBI BAU** envoyé à Mistral — démontre la profondeur méthodologique du Sprint 3.

```text
### Organized Attacker Indicators
- Targeted credential selection (not default/common passwords)
- Custom or modified tools (evidence of skill/adaptation)
- Reconnaissance before exploitation (planning)
- Anonymization: Tor, VPN, proxy, hosting provider origin
- Anti-forensics behavior: cleanup, evidence elimination attempts
- Long sessions or repeated access (persistence)
- Multi-stage attacks with clear progression
- Adaptive behavior (changing tactics when detected)

### Sophistication Levels
Amateur     : Scripted/automated attacks, public tools, no customization.
Intermediate: Some custom tools, targeted credentials, moderate planning.
Expert      : Custom payloads, multi-stage, advanced anti-forensics, Tor/VPN.
```

---

## 13. `forensic-engine/verify_coc.py` — vérification (lignes 49–60)

Parlant : exit code 0/1, audit tiers.

```python
def main() -> int:
    conn = _pg()
    errors = 0
    checked = 0
    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cols = ", ".join(f"s.{c}" for c in SEALED_COLUMNS)
        cur.execute(f"""
            SELECT {cols}, c.record_hash, c.prev_hash, c.batch_id, c.id AS coc_id
            FROM forensic_chain_of_custody c
            JOIN forensic_sessions s ON s.session_id = c.session_id
            ORDER BY c.id
        """)
        ...
```

---

## 14. Tableau récapitulatif — quels listings pour quelle section du chapitre

| Section du chapitre 7 | Listings recommandés |
|---|---|
| §1 Introduction | — |
| §2 Objectif du sprint | — |
| §3 Analyse fonctionnelle / UC | — |
| §4 Diagramme UC | — |
| §5 Backlog | — |
| §6 Arborescence | (cf. `sprint3_arborescence.md`) |
| §7 Conception technique | Listings **3** (orchestration), **4** (schéma SQL) |
| §8 Réalisation — Enrichissement | Listings **1** (compose), **5** (private IP), **2** (Dockerfile) |
| §8 Réalisation — YARA + VT | Listings **6** (LockBit), table file_analysis |
| §8 Réalisation — Scoring + MITRE | Listings **7** (règles déterministes), **8** (taxonomie WHO/WHAT/HOW) |
| §8 Réalisation — Timeline + IoC | Listings **10** (régex), schéma `forensic_timeline_events` |
| §8 Réalisation — Chain of Custody | Listings **9** (Merkle + RFC 3161), **13** (verify) |
| §8 Réalisation — Profiler LLM | Listings **11** (JSON schema), **12** (criminologie) |
| §9 Test/supervision | Listing **13**, requêtes PG du §6 de l'audit |
| §10 Bilan | — |
| §11 Conclusion | — |
