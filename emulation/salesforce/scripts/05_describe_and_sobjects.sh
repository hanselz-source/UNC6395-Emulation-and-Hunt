#!/usr/bin/env bash
# 05_describe_and_sobjects.sh
# Issue the three flat REST recon calls UNC6395 used during enumeration:
#   GET /services/data/<v>/sobjects/                        object inventory
#   GET /services/data/<v>/sobjects/Account/describe/       schema metadata
#   GET /services/data/<v>/limits/                          tenant limits / fingerprint
# All three carry User-Agent: truffleHog for R1 attribution.
#
# Mirrors:
#   - Cloudflare 2025-08-12 22:14:09 (sobjects listing)
#   - Cloudflare 2025-08-13 19:33:07 to 19:33:09 (Case/describe; Account in lab because Case is empty in DE)
#   - Cloudflare 2025-08-14 11:09:22 (limits)

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
META="$OUTPUT_DIR/request_metadata.txt"

call () {
  local path="$1"
  local outfile="$2"
  echo "[$(date -u +%FT%TZ)] GET $path  UA=$UA  out=$outfile" >> "$META"
  curl -sS -A "$UA" \
    -H "Authorization: Bearer $ACCESS" \
    "$INSTANCE$path" \
    > "$outfile"
  echo "  wrote $outfile"
}

call "/services/data/$API_VERSION/sobjects/"                  "$OUTPUT_DIR/sobjects_listing.json"
call "/services/data/$API_VERSION/sobjects/Account/describe/" "$OUTPUT_DIR/account_describe.json"
call "/services/data/$API_VERSION/limits/"                    "$OUTPUT_DIR/limits.json"

echo "Done. Three recon responses captured. Run scripts/04_recon_burst.sh next for the SOQL volume signal."
