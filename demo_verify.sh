#!/bin/bash
# ============================================================
# ForenHive — Demo Verification Script
# Vérifie que les logs injectés sont arrivés dans Elasticsearch
# IPs dynamiquement sourcées depuis demo_inject.sh
# ============================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

# ── Charger les IPs depuis demo_inject.sh ───────────────────
eval "$(grep -E '^(COWRIE|DIONAEA|GALAH)_(PUB|PRIV)[0-9]+=' /home/pfe/ForenHive/demo_inject.sh)"

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

for IP in "$COWRIE_PUB1" "$COWRIE_PUB2" "$COWRIE_PUB3"; do
    N=$($ES "http://localhost:9200/${INDEX}/_count?q=honeypot.type:cowrie+AND+source.ip:${IP}" \
        | python3 -c "import sys,json; print(json.load(sys.stdin).get('count',0))" 2>/dev/null)
    check "${IP} → Cowrie (IP publique)" "$N"
done

for IP in "$COWRIE_PRIV1" "$COWRIE_PRIV2" "$COWRIE_PRIV3"; do
    N=$($ES "http://localhost:9200/${INDEX}/_count?q=honeypot.type:cowrie+AND+source.ip:${IP}" \
        | python3 -c "import sys,json; print(json.load(sys.stdin).get('count',0))" 2>/dev/null)
    check "${IP} → Cowrie (IP privée — menace interne)" "$N"
done

N=$($ES "http://localhost:9200/${INDEX}/_count?q=honeypot.type:cowrie+AND+event.id:cowrie.login.success" \
    | python3 -c "import sys,json; print(json.load(sys.stdin).get('count',0))" 2>/dev/null)
check "Login SUCCESS détecté dans Cowrie" "$N"

N=$($ES "http://localhost:9200/${INDEX}/_count?q=honeypot.type:cowrie+AND+event.category:process" \
    | python3 -c "import sys,json; print(json.load(sys.stdin).get('count',0))" 2>/dev/null)
check "Commandes Linux capturées (CMD: uname / wget)" "$N"

echo ""

# ── Dionaea ─────────────────────────────────────────────────
echo -e "${BOLD}[Dionaea Multi-protocole Honeypot]${NC}"

for IP in "$DIONAEA_PUB1" "$DIONAEA_PUB2" "$DIONAEA_PUB3"; do
    N=$($ES "http://localhost:9200/${INDEX}/_count?q=honeypot.type:dionaea+AND+source.ip:${IP}" \
        | python3 -c "import sys,json; print(json.load(sys.stdin).get('count',0))" 2>/dev/null)
    check "${IP} → Dionaea (IP publique)" "$N"
done

for IP in "$DIONAEA_PRIV1" "$DIONAEA_PRIV2" "$DIONAEA_PRIV3"; do
    N=$($ES "http://localhost:9200/${INDEX}/_count?q=honeypot.type:dionaea+AND+source.ip:${IP}" \
        | python3 -c "import sys,json; print(json.load(sys.stdin).get('count',0))" 2>/dev/null)
    check "${IP} → Dionaea (IP privée — menace interne)" "$N"
done

N=$($ES "http://localhost:9200/${INDEX}/_count?q=honeypot.type:dionaea+AND+destination.port:445" \
    | python3 -c "import sys,json; print(json.load(sys.stdin).get('count',0))" 2>/dev/null)
check "Attaques SMB (port 445) détectées" "$N"

N=$($ES "http://localhost:9200/${INDEX}/_count?q=honeypot.type:dionaea+AND+destination.port:1433" \
    | python3 -c "import sys,json; print(json.load(sys.stdin).get('count',0))" 2>/dev/null)
check "Attaques MSSQL (port 1433) détectées" "$N"

echo ""

# ── Galah ───────────────────────────────────────────────────
echo -e "${BOLD}[Galah HTTP/LLM Honeypot]${NC}"

for IP in "$GALAH_PUB1" "$GALAH_PUB2" "$GALAH_PUB3"; do
    N=$($ES "http://localhost:9200/${INDEX}/_count?q=honeypot.type:galah+AND+source.ip:${IP}" \
        | python3 -c "import sys,json; print(json.load(sys.stdin).get('count',0))" 2>/dev/null)
    check "${IP} → Galah (IP publique)" "$N"
done

for IP in "$GALAH_PRIV1" "$GALAH_PRIV2" "$GALAH_PRIV3"; do
    N=$($ES "http://localhost:9200/${INDEX}/_count?q=honeypot.type:galah+AND+source.ip:${IP}" \
        | python3 -c "import sys,json; print(json.load(sys.stdin).get('count',0))" 2>/dev/null)
    check "${IP} → Galah (IP privée — menace interne)" "$N"
done

N=$($ES "http://localhost:9200/${INDEX}/_count" -H 'Content-Type: application/json' \
    -d '{"query":{"bool":{"must":[{"term":{"honeypot.type":"galah"}},{"wildcard":{"http.request.uri.keyword":"*wp-admin*"}}]}}}' \
    | python3 -c "import sys,json; print(json.load(sys.stdin).get('count',0))" 2>/dev/null)
check "Scan WordPress /wp-admin détecté" "$N"

N=$($ES "http://localhost:9200/${INDEX}/_count" -H 'Content-Type: application/json' \
    -d '{"query":{"bool":{"must":[{"term":{"honeypot.type":"galah"}},{"wildcard":{"http.request.uri.keyword":"*.env*"}}]}}}' \
    | python3 -c "import sys,json; print(json.load(sys.stdin).get('count',0))" 2>/dev/null)
check "Tentative vol .env (secrets) détectée" "$N"

echo ""

# ── Résumé total ─────────────────────────────────────────────
echo -e "${BOLD}[Résumé]${NC}"

TOTAL=$($ES "http://localhost:9200/${INDEX}/_count" \
    | python3 -c "import sys,json; print(json.load(sys.stdin).get('count',0))" 2>/dev/null)
echo -e "  Total documents dans ${CYAN}${INDEX}${NC} : ${BOLD}${TOTAL}${NC}"

# Construire la liste de toutes les IPs de demo pour le comptage
ALL_IPS="$COWRIE_PUB1+OR+source.ip:$COWRIE_PUB2+OR+source.ip:$COWRIE_PUB3"
ALL_IPS="$ALL_IPS+OR+source.ip:$COWRIE_PRIV1+OR+source.ip:$COWRIE_PRIV2+OR+source.ip:$COWRIE_PRIV3"
ALL_IPS="$ALL_IPS+OR+source.ip:$DIONAEA_PUB1+OR+source.ip:$DIONAEA_PUB2+OR+source.ip:$DIONAEA_PUB3"
ALL_IPS="$ALL_IPS+OR+source.ip:$DIONAEA_PRIV1+OR+source.ip:$DIONAEA_PRIV2+OR+source.ip:$DIONAEA_PRIV3"
ALL_IPS="$ALL_IPS+OR+source.ip:$GALAH_PUB1+OR+source.ip:$GALAH_PUB2+OR+source.ip:$GALAH_PUB3"
ALL_IPS="$ALL_IPS+OR+source.ip:$GALAH_PRIV1+OR+source.ip:$GALAH_PRIV2+OR+source.ip:$GALAH_PRIV3"

ALL_DEMO=$($ES "http://localhost:9200/${INDEX}/_count?q=source.ip:${ALL_IPS}" \
    | python3 -c "import sys,json; print(json.load(sys.stdin).get('count',0))" 2>/dev/null)
echo -e "  Documents demo injectés (18 IPs) : ${BOLD}${ALL_DEMO}${NC}"

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
