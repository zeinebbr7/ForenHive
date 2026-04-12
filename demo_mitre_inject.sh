#!/bin/bash
# ============================================================
# ForenHive — Injection des résultats MITRE ATT&CK dans PostgreSQL
# Simule l'analyse Mistral 7B pour la démo (évite le délai Ollama)
# ============================================================

BOLD='\033[1m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
NC='\033[0m'

PG="docker exec forenhive-postgresql psql -U forenhive -d forenhive"

echo ""
echo -e "${BOLD}${CYAN}Injection des résultats MITRE ATT&CK (Mistral 7B simulé)...${NC}"
echo ""

docker exec -i forenhive-postgresql psql -U forenhive -d forenhive << 'SQLEOF'

-- ══════════════════════════════════════════════════════════════
-- COWRIE — IPs Publiques
-- ══════════════════════════════════════════════════════════════

-- 185.220.101.55 — Tor exit node, bruteforce massif, login SSH réussi
UPDATE forensic_sessions
SET mitre_techniques = '{
  "kill_chain_phase": "Credential Access → Execution → Persistence",
  "techniques": ["T1110.001","T1078","T1053.003","T1059.004"],
  "tactic": "Initial Access, Execution, Persistence",
  "summary": "Noeud Tor: bruteforce SSH massif (650+ tentatives), login reussi, commandes post-exploitation (uname/wget/chmod), persistance via crontab tentee"
}'::jsonb
WHERE source_ip = '185.220.101.55' AND honeypot_type = 'cowrie';

-- 194.165.16.76 — Scanner Shodan (Pays-Bas)
UPDATE forensic_sessions
SET mitre_techniques = '{
  "kill_chain_phase": "Reconnaissance",
  "techniques": ["T1595.001","T1595.002"],
  "tactic": "Reconnaissance",
  "summary": "Scanner Shodan: sondage actif SSH, collecte banniere OpenSSH, enumeration credentials faibles"
}'::jsonb
WHERE source_ip = '194.165.16.76' AND honeypot_type = 'cowrie';

-- 45.146.164.110 — Botnet Mirai (Russie)
UPDATE forensic_sessions
SET mitre_techniques = '{
  "kill_chain_phase": "Initial Access → Execution",
  "techniques": ["T1190","T1059.004","T1105"],
  "tactic": "Initial Access, Execution",
  "summary": "Botnet Mirai: bruteforce credentials par defaut, injection commandes shell, telechargement payload via wget depuis C2"
}'::jsonb
WHERE source_ip = '45.146.164.110' AND honeypot_type = 'cowrie';

-- ══════════════════════════════════════════════════════════════
-- COWRIE — IPs Privées
-- ══════════════════════════════════════════════════════════════

-- 192.168.1.100 — Poste utilisateur réseau local
UPDATE forensic_sessions
SET mitre_techniques = '{
  "kill_chain_phase": "Lateral Movement",
  "techniques": ["T1021.004","T1078.001"],
  "tactic": "Lateral Movement, Privilege Escalation",
  "summary": "Menace interne: machine du reseau local attaque SSH honeypot, credentials admin testes, mouvement lateral suspect"
}'::jsonb
WHERE source_ip = '192.168.1.100' AND honeypot_type = 'cowrie';

-- 10.0.0.55 — Serveur interne compromis
UPDATE forensic_sessions
SET mitre_techniques = '{
  "kill_chain_phase": "Lateral Movement → Execution",
  "techniques": ["T1021.004","T1059.004","T1105"],
  "tactic": "Lateral Movement, Execution",
  "summary": "Serveur interne compromis: pivot SSH vers honeypot, exfiltration commandes, signe de compromission laterale active"
}'::jsonb
WHERE source_ip = '10.0.0.55' AND honeypot_type = 'cowrie';

-- 172.16.5.22 — Machine VLAN dev
UPDATE forensic_sessions
SET mitre_techniques = '{
  "kill_chain_phase": "Reconnaissance → Lateral Movement",
  "techniques": ["T1595.001","T1021.004"],
  "tactic": "Reconnaissance, Lateral Movement",
  "summary": "Machine VLAN dev: sondage SSH interne, tentatives credentials de developpement, acces non autorise au segment honeypot"
}'::jsonb
WHERE source_ip = '172.16.5.22' AND honeypot_type = 'cowrie';

-- ══════════════════════════════════════════════════════════════
-- DIONAEA — IPs Publiques
-- ══════════════════════════════════════════════════════════════

-- 91.92.251.103 — Scanner (Iran)
UPDATE forensic_sessions
SET mitre_techniques = '{
  "kill_chain_phase": "Reconnaissance",
  "techniques": ["T1046","T1595.001"],
  "tactic": "Reconnaissance",
  "summary": "Scanner iranien: sondage ports SMB/MSSQL/MySQL, enumeration services reseau, pas d exploitation active detectee"
}'::jsonb
WHERE source_ip = '91.92.251.103' AND honeypot_type = 'dionaea';

-- 205.210.31.229 — EternalBlue scanner (USA)
UPDATE forensic_sessions
SET mitre_techniques = '{
  "kill_chain_phase": "Exploitation",
  "techniques": ["T1210","T1588.006","T1203"],
  "tactic": "Initial Access, Exploitation",
  "summary": "Scanner EternalBlue: exploitation MS17-010 tentee sur port 445, payload SMBv1 detecte, CVE-2017-0144 (WannaCry vector)"
}'::jsonb
WHERE source_ip = '205.210.31.229' AND honeypot_type = 'dionaea';

-- 80.82.77.33 — Shodan scanner actif (Pays-Bas)
UPDATE forensic_sessions
SET mitre_techniques = '{
  "kill_chain_phase": "Exploitation → Collection",
  "techniques": ["T1210","T1005","T1046"],
  "tactic": "Initial Access, Collection",
  "summary": "Scanner Shodan actif: exploitation SMB tentee, connexion MSSQL avec credentials par defaut, collecte informations systeme"
}'::jsonb
WHERE source_ip = '80.82.77.33' AND honeypot_type = 'dionaea';

-- ══════════════════════════════════════════════════════════════
-- DIONAEA — IPs Privées
-- ══════════════════════════════════════════════════════════════

-- 10.10.0.200 — Machine interne infectée
UPDATE forensic_sessions
SET mitre_techniques = '{
  "kill_chain_phase": "Lateral Movement → Exfiltration",
  "techniques": ["T1021.002","T1048","T1078"],
  "tactic": "Lateral Movement, Exfiltration",
  "summary": "Machine interne infectee: connexions SMB internes repetees, acces partages reseau, signe de propagation laterale (worm behavior)"
}'::jsonb
WHERE source_ip = '10.10.0.200' AND honeypot_type = 'dionaea';

-- 192.168.0.15 — Poste IT compromis
UPDATE forensic_sessions
SET mitre_techniques = '{
  "kill_chain_phase": "Lateral Movement",
  "techniques": ["T1021.002","T1078.001"],
  "tactic": "Lateral Movement, Privilege Escalation",
  "summary": "Poste IT compromis: acces SMB avec credentials admin domaine, mouvement lateral vers segment honeypot, privilege abuse"
}'::jsonb
WHERE source_ip = '192.168.0.15' AND honeypot_type = 'dionaea';

-- 172.16.1.50 — Serveur de fichiers interne
UPDATE forensic_sessions
SET mitre_techniques = '{
  "kill_chain_phase": "Collection → Lateral Movement",
  "techniques": ["T1039","T1021.002"],
  "tactic": "Collection, Lateral Movement",
  "summary": "Serveur fichiers interne: acces SMB anormal hors heures, enumeration partages, potentielle exfiltration donnees internes"
}'::jsonb
WHERE source_ip = '172.16.1.50' AND honeypot_type = 'dionaea';

-- ══════════════════════════════════════════════════════════════
-- GALAH — IPs Publiques
-- ══════════════════════════════════════════════════════════════

-- 45.142.212.100 — Scanner HTTP Nuclei (Pays-Bas)
UPDATE forensic_sessions
SET mitre_techniques = '{
  "kill_chain_phase": "Reconnaissance",
  "techniques": ["T1595.002","T1083","T1046"],
  "tactic": "Reconnaissance",
  "summary": "Scanner Nuclei: enumeration automatique endpoints HTTP, detection frameworks (WordPress, Laravel), fingerprinting serveur web"
}'::jsonb
WHERE source_ip = '45.142.212.100' AND honeypot_type = 'galah';

-- 89.248.167.131 — Scanner vulnérabilités (Pays-Bas)
UPDATE forensic_sessions
SET mitre_techniques = '{
  "kill_chain_phase": "Reconnaissance → Exploitation",
  "techniques": ["T1190","T1083","T1552.001"],
  "tactic": "Initial Access, Discovery",
  "summary": "Scanner vulns: LFI/RFI tentees, recherche fichiers config (.env, wp-config), vol credentials potentiel, CVE-2021-44228 (Log4Shell) sonde"
}'::jsonb
WHERE source_ip = '89.248.167.131' AND honeypot_type = 'galah';

-- 198.199.70.24 — DigitalOcean VPS attaquant (USA)
UPDATE forensic_sessions
SET mitre_techniques = '{
  "kill_chain_phase": "Initial Access → Discovery",
  "techniques": ["T1190","T1595.002","T1592"],
  "tactic": "Initial Access, Reconnaissance",
  "summary": "VPS DigitalOcean: scan wp-admin (CMS WordPress), tentative acces .env (secrets API), enumeration infrastructure cible"
}'::jsonb
WHERE source_ip = '198.199.70.24' AND honeypot_type = 'galah';

-- ══════════════════════════════════════════════════════════════
-- GALAH — IPs Privées
-- ══════════════════════════════════════════════════════════════

-- 172.20.0.10 — Container interne Docker
UPDATE forensic_sessions
SET mitre_techniques = '{
  "kill_chain_phase": "Lateral Movement → Discovery",
  "techniques": ["T1610","T1083","T1046"],
  "tactic": "Lateral Movement, Discovery",
  "summary": "Container Docker interne: requetes HTTP inter-containers anormales, enumeration services internes, escape container potentiel"
}'::jsonb
WHERE source_ip = '172.20.0.10' AND honeypot_type = 'galah';

-- 192.168.1.77 — Poste développeur réseau local
UPDATE forensic_sessions
SET mitre_techniques = '{
  "kill_chain_phase": "Reconnaissance → Credential Access",
  "techniques": ["T1595.002","T1552.001"],
  "tactic": "Reconnaissance, Credential Access",
  "summary": "Poste dev reseau local: navigation anormale vers honeypot HTTP, tentative acces .env (secrets dev), fuite credentials potentielle"
}'::jsonb
WHERE source_ip = '192.168.1.77' AND honeypot_type = 'galah';

-- 10.0.1.100 — Serveur CI/CD interne
UPDATE forensic_sessions
SET mitre_techniques = '{
  "kill_chain_phase": "Lateral Movement → Exfiltration",
  "techniques": ["T1072","T1552.001","T1048"],
  "tactic": "Lateral Movement, Exfiltration",
  "summary": "Serveur CI/CD: acces HTTP honeypot depuis pipeline, recherche secrets dans .env (tokens CI), vecteur supply chain potentiel"
}'::jsonb
WHERE source_ip = '10.0.1.100' AND honeypot_type = 'galah';

SQLEOF

echo ""
echo -e "${BOLD}${GREEN}✓ MITRE ATT&CK injectés pour les 18 sessions${NC}"
echo ""

# Vérification rapide
docker exec forenhive-postgresql psql -U forenhive -d forenhive -c "
SELECT DISTINCT ON (source_ip) source_ip, honeypot_type,
       mitre_techniques::jsonb->>'kill_chain_phase' AS kill_chain
FROM forensic_sessions
WHERE mitre_techniques::jsonb->>'kill_chain_phase' IS NOT NULL
ORDER BY source_ip, created_at DESC;
" 2>/dev/null
echo ""
