# ForenHive

ForenHive is an automated honeypot-based forensic platform that aggregates multi-source attack telemetry (SSH, SMB, HTTP, network flows) through a five-layer pipeline — honeypots → ETL → forensic engine → REST API → dashboard — and applies FBI Behavioral Analysis Unit criminology methodology to produce structured suspect profiles: MITRE ATT&CK mapping, risk scoring 0–100, YARA/VirusTotal malware triage, RFC 3161 chain-of-custody timestamps, and Mistral-7B-powered attacker behavioral analysis, all without external LLM API dependencies.

## Sprint Status

| Sprint | Scope | Status |
|--------|-------|--------|
| S1 | Honeypots (Cowrie, Dionaea, Galah, Zeek) | ✅ Complete |
| S2 | ETL Pipeline (Filebeat → Logstash → Elasticsearch) | ✅ Complete |
| S3 | Forensic Engine (enrichment, YARA, MITRE, risk scoring, profiling, CoC) | ✅ Complete |
| S4 | Backend (FastAPI) + Frontend SPA | 🔄 In progress |
| S5 | Reporting, STIX export, alerting | ⏳ Pending |

## Quickstart

```bash
make up
docker compose run --rm forensic-engine python db/init_db.py
make logs
```

## Documentation

- [Architecture](docs/architecture.md)
- [Sprint 1 Audit](docs/sprint1_audit.md)
- [Sprint 2 Audit](docs/sprint2_audit.md)
- [Sprint 3 Audit](docs/sprint3_audit.md)

## Authors

Zeineb Benrhouma & Ismail Cherif — ISET Radès PFE 2026
Hosted at Standard Sharing Software (3S), Charguia, Tunis
