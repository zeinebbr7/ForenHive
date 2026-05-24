#!/usr/bin/env bash
# dos_burst.sh — short, bounded HTTP burst against a ForenHive honeypot endpoint.
#
# Default target is Dionaea on :80. The burst flows through Filebeat → Logstash
# → Elasticsearch (events visible on the Stats / reconstruction pages). Source
# IP from the Docker bridge is mapped to 185.220.101.5 (Tor exit, expert tier)
# by the Logstash translate filter in pipeline/logstash/config/ip_map.yml, so
# the burst is attributed to the demo's expert attacker.
#
# Note: Zeek runs in network_mode=host and won't see localhost traffic (Linux
# kernel short-circuits self-addressed packets via loopback).
#
# Usage:
#   ./dos_burst.sh                              # default: localhost:80, 60s
#   ./dos_burst.sh http://localhost:80 30       # explicit URL, 30s
#   ./dos_burst.sh http://localhost:80 60 100   # 100 concurrent workers
#
# Uses Apache Bench (`ab`) when available; falls back to a parallel curl loop.

set -euo pipefail

TARGET="${1:-http://localhost:80/index.html}"
DURATION="${2:-60}"
CONCURRENCY="${3:-50}"

echo "[dos_burst] target=$TARGET duration=${DURATION}s concurrency=$CONCURRENCY"

if command -v ab >/dev/null 2>&1; then
    echo "[dos_burst] using Apache Bench (ab)"
    # -n: cap requests, -c: concurrency, -t: time limit, -r: don't exit on socket errors.
    ab -n 100000 -c "$CONCURRENCY" -t "$DURATION" -r -q "$TARGET"
    exit 0
fi

echo "[dos_burst] ab not found; using parallel curl loop"
echo "[dos_burst] install with: sudo apt-get install -y apache2-utils  (for true rate control)"

# Bash fallback: $CONCURRENCY background workers, each loops curl until DURATION elapses.
END=$(( $(date +%s) + DURATION ))
PIDS=()
COUNTER_FILE="$(mktemp)"
echo 0 > "$COUNTER_FILE"

worker() {
    local count=0
    while [ "$(date +%s)" -lt "$END" ]; do
        curl -s -o /dev/null -m 2 "$TARGET" || true
        count=$((count + 1))
    done
    flock "$COUNTER_FILE" -c "echo \$(( \$(cat $COUNTER_FILE) + $count )) > $COUNTER_FILE"
}

for _ in $(seq 1 "$CONCURRENCY"); do
    worker &
    PIDS+=($!)
done

trap 'kill ${PIDS[@]} 2>/dev/null || true; rm -f "$COUNTER_FILE"' EXIT
wait

TOTAL=$(cat "$COUNTER_FILE")
echo "[dos_burst] done — $TOTAL requests in ${DURATION}s (~$((TOTAL / DURATION)) req/s)"
