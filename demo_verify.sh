#!/bin/bash
# ============================================================
# ForenHive — Demo Verification Script
# Vérifie que les logs injectés sont arrivés dans Elasticsearch
# ============================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

ES="docker exec forenhive-elasticsearch curl -s"
INDEX="honeypot-logs-*"

pass=0
fail=0

check() {
    local label="$1"
    local count="$2"
    if [ "$count" -gt 0 ] 2>/dev/null; then
        echo -e "  ${GREEN}✓${NC} ${label} → ${BOLD}${count}${NC} document(s)"
        ((pass++))
    else
        echo -e "  ${RED}✗${NC} ${label} → aucun document (pipeline pas encore prêt ?)"
        ((fail++))
    fi
}

echo ""
echo -e "${BOLD}${BLUE}╔══════════════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}${BLUE}║         ForenHive — Vérification Pipeline Demo           ║${NC}"
echo -e "${BOLD}${BLUE}╚══════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "  Index cible : ${CYAN}${INDEX}${NC}"
echo ""

# ── Cowrie ──────────────────────────────────────────────────
echo -e "${BOLD}[Cowrie SSH Honeypot]${NC}"

N=$($ES "http://localhost:9200/${INDEX}/_count?q=honeypot.type:cowrie+AND+source.ip:185.220.101.55" | python3 -c "import sys,json; print(json.load(sys.stdin).get('count',0))" 2>/dev/null)
check "185.220.101.55 → Cowrie (IP publique — Tor exit)" "$N"

N=$($ES "http://localhost:9200/${INDEX}/_count?q=honeypot.type:cowrie+AND+source.ip:192.168.1.100" | python3 -c "import sys,json; print(json.load(sys.stdin).get('count',0))" 2>/dev/null)
check "192.168.1.100  → Cowrie (IP privée)" "$N"

N=$($ES "http://localhost:9200/${INDEX}/_count?q=honeypot.type:cowrie+AND+event.id:cowrie.login.success" | python3 -c "import sys,json; print(json.load(sys.stdin).get('count',0))" 2>/dev/null)
check "Login SUCCESS détecté dans Cowrie" "$N"

N=$($ES "http://localhost:9200/${INDEX}/_count?q=honeypot.type:cowrie+AND+event.category:process" | python3 -c "import sys,json; print(json.load(sys.stdin).get('count',0))" 2>/dev/null)
check "Commandes Linux capturées (CMD: uname / wget)" "$N"

echo ""

# ── Dionaea ─────────────────────────────────────────────────
echo -e "${BOLD}[Dionaea Multi-protocole Honeypot]${NC}"

N=$($ES "http://localhost:9200/${INDEX}/_count?q=honeypot.type:dionaea+AND+source.ip:91.92.251.103" | python3 -c "import sys,json; print(json.load(sys.stdin).get('count',0))" 2>/dev/null)
check "91.92.251.103  → Dionaea (IP publique — scanner)" "$N"

N=$($ES "http://localhost:9200/${INDEX}/_count?q=honeypot.type:dionaea+AND+source.ip:10.10.0.200" | python3 -c "import sys,json; print(json.load(sys.stdin).get('count',0))" 2>/dev/null)
check "10.10.0.200    → Dionaea (IP privée)" "$N"

# Compter les connexions SMB (port 445)
N=$($ES "http://localhost:9200/${INDEX}/_count?q=honeypot.type:dionaea+AND+destination.port:445" | python3 -c "import sys,json; print(json.load(sys.stdin).get('count',0))" 2>/dev/null)
check "Attaques SMB (port 445) détectées" "$N"

N=$($ES "http://localhost:9200/${INDEX}/_count?q=honeypot.type:dionaea+AND+destination.port:1433" | python3 -c "import sys,json; print(json.load(sys.stdin).get('count',0))" 2>/dev/null)
check "Attaques MSSQL (port 1433) détectées" "$N"

echo ""

# ── Galah ───────────────────────────────────────────────────
echo -e "${BOLD}[Galah HTTP/LLM Honeypot]${NC}"

N=$($ES "http://localhost:9200/${INDEX}/_count?q=honeypot.type:galah+AND+source.ip:45.142.212.100" | python3 -c "import sys,json; print(json.load(sys.stdin).get('count',0))" 2>/dev/null)
check "45.142.212.100 → Galah (IP publique — scanner HTTP)" "$N"

N=$($ES "http://localhost:9200/${INDEX}/_count?q=honeypot.type:galah+AND+source.ip:172.20.0.10" | python3 -c "import sys,json; print(json.load(sys.stdin).get('count',0))" 2>/dev/null)
check "172.20.0.10    → Galah (IP privée)" "$N"

N=$($ES "http://localhost:9200/${INDEX}/_count" -H 'Content-Type: application/json' -d '{"query":{"bool":{"must":[{"term":{"honeypot.type":"galah"}},{"wildcard":{"http.request.uri.keyword":"*wp-admin*"}}]}}}' | python3 -c "import sys,json; print(json.load(sys.stdin).get('count',0))" 2>/dev/null)
check "Scan WordPress /wp-admin détecté" "$N"

N=$($ES "http://localhost:9200/${INDEX}/_count" -H 'Content-Type: application/json' -d '{"query":{"bool":{"must":[{"term":{"honeypot.type":"galah"}},{"wildcard":{"http.request.uri.keyword":"*.env*"}}]}}}' | python3 -c "import sys,json; print(json.load(sys.stdin).get('count',0))" 2>/dev/null)
check "Tentative vol .env (secrets) détectée" "$N"

echo ""

# ── Résumé total ─────────────────────────────────────────────
echo -e "${BOLD}[Résumé]${NC}"

TOTAL=$($ES "http://localhost:9200/${INDEX}/_count" | python3 -c "import sys,json; print(json.load(sys.stdin).get('count',0))" 2>/dev/null)
echo -e "  Total documents dans ${CYAN}${INDEX}${NC} : ${BOLD}${TOTAL}${NC}"

ALL_DEMO=$(( $($ES "http://localhost:9200/${INDEX}/_count?q=source.ip:185.220.101.55+OR+source.ip:192.168.1.100+OR+source.ip:91.92.251.103+OR+source.ip:10.10.0.200+OR+source.ip:45.142.212.100+OR+source.ip:172.20.0.10" | python3 -c "import sys,json; print(json.load(sys.stdin).get('count',0))" 2>/dev/null) ))
echo -e "  Documents demo injectés : ${BOLD}${ALL_DEMO}${NC}"

echo ""
if [ "$fail" -eq 0 ]; then
    echo -e "${BOLD}${GREEN}╔══════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BOLD}${GREEN}║  Pipeline 100% opérationnel — ${pass}/${pass} checks passés !   ║${NC}"
    echo -e "${BOLD}${GREEN}╚══════════════════════════════════════════════════════════╝${NC}"
else
    echo -e "${BOLD}${YELLOW}╔══════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BOLD}${YELLOW}║  ${pass} passés / ${fail} en attente — Relance dans 15 secondes ║${NC}"
    echo -e "${BOLD}${YELLOW}╚══════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "  Commande pour surveiller Filebeat : ${CYAN}docker logs forenhive-filebeat --tail 20${NC}"
fi
echo ""
