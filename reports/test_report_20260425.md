# ForenHive — Rapport d'analyse forensique

**IP cible :** `193.32.162.157`  
**Généré :** 2026-04-25T22:18:24+00:00  
**Sessions analysées :** 1

---

## 1. Enrichissement IP

| Champ | Valeur |
|---|---|
| Pays | Romania (RO) |
| Ville | — |
| ASN | 35478 |
| Organisation (geo) | Bunea TELECOM SRL |
| Organisation (whois) | UNMANAGED-DEDICATED-SERVERS, GB |
| CIDR | `193.32.162.0/24` |
| Réseau | DMZHOST |
| AbuseIPDB score | N/A / 100 |
| Signalements | N/A |
| Tor exit | non |
| VPN | non |
| Proxy | non |
| Hosting | non |
| Ports ouverts (Shodan) | — |
| Enrichi le | 2026-04-25T22:12:04.947879+00:00 |

## 2. Analyse malware (YARA + VirusTotal)

Aucun binaire malveillant capturé n'est rattaché à cette IP (pas d'IOC SHA-256 corrélant `file_analysis` ↔ `forensic_iocs`).

## 3. Sessions forensiques · Risk score · MITRE

### Session `dionaea-193.32.162.157-445` — dionaea

- **Période :** 2026-04-23 19:58:53 → 2026-04-23 19:58:55.500000
- **Risk score :** **5 / 100**
- **Kill chain :** étape 7/8 — lateral_movement
- **Technique principale :** `T1021.002`
- **Techniques MITRE détectées :** `T1021.002`, `T1210`

> The incident involves an unsuccessful attempt to access a system through the SMB protocol on port 445 using the dionaea honeypot, originating from IP address 19


## 4. Profil comportemental (FBI BAU)

Aucun profil LLM disponible pour cette IP (profiler.py non exécuté ou Ollama indisponible lors du run).


## 5. Indicateurs de compromission

Aucun IOC extrait pour cette IP.
