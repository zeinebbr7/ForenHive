#!/usr/bin/env bash
# Update MaxMind GeoLite2 databases and copy them into the project geoip/ folder.
# Usage:
#   MAXMIND_LICENSE_KEY=your_key_here ./scripts/update_geoip.sh
#   or set the variable in your shell before running.

set -euo pipefail

MAXMIND_LICENSE_KEY="${MAXMIND_LICENSE_KEY:?ERROR: MAXMIND_LICENSE_KEY is not set. Export it before running this script.}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
GEOIP_DIR="$PROJECT_ROOT/geoip"
MAXMIND_DEST="/var/lib/GeoIP"

echo "[+] Updating GeoLite2 databases..."

# Write a temporary GeoIP.conf for geoipupdate
CONF_FILE="$(mktemp /tmp/GeoIP.conf.XXXXXX)"
trap 'rm -f "$CONF_FILE"' EXIT

cat > "$CONF_FILE" <<EOF
AccountID 0
LicenseKey ${MAXMIND_LICENSE_KEY}
EditionIDs GeoLite2-City GeoLite2-ASN
DatabaseDirectory ${MAXMIND_DEST}
EOF

geoipupdate -f "$CONF_FILE"

echo "[+] Copying updated databases to $GEOIP_DIR..."
mkdir -p "$GEOIP_DIR"
cp "$MAXMIND_DEST/GeoLite2-City.mmdb" "$GEOIP_DIR/GeoLite2-City.mmdb"
cp "$MAXMIND_DEST/GeoLite2-ASN.mmdb"  "$GEOIP_DIR/GeoLite2-ASN.mmdb"

echo "[+] Done. Restart the backend and forensic-engine containers to pick up the new databases:"
echo "    docker compose restart forenhive-backend forenhive-forensic-engine"
