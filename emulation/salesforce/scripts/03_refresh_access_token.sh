#!/usr/bin/env bash
# 03_refresh_access_token.sh
# Trade the saved refresh token for a fresh access token.
# Use this when the access token has aged out (~2 hours) but the refresh token is still valid.
#
# Mirrors UNC6395 reusing a long-lived refresh token to mint short-lived access tokens (T1528).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BASE_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
KEYS_DIR="$BASE_DIR/keys"
OUTPUT_DIR="$BASE_DIR/output"

if [ ! -f "$KEYS_DIR/refresh_token" ]; then
  echo "ERROR: $KEYS_DIR/refresh_token not found. Run 02_exchange_code.sh first," >&2
  echo "       or drop your existing refresh token into $KEYS_DIR/refresh_token." >&2
  exit 1
fi

CONSUMER_KEY="$(cat "$KEYS_DIR/consumer_key")"
CONSUMER_SECRET="$(cat "$KEYS_DIR/consumer_secret")"
REFRESH="$(cat "$KEYS_DIR/refresh_token")"

mkdir -p "$OUTPUT_DIR"

RESPONSE="$(curl -sS -X POST https://login.salesforce.com/services/oauth2/token \
  -d "grant_type=refresh_token" \
  -d "client_id=$CONSUMER_KEY" \
  -d "client_secret=$CONSUMER_SECRET" \
  -d "refresh_token=$REFRESH")"

if echo "$RESPONSE" | grep -q '"error"'; then
  echo "Refresh failed:" >&2
  echo "$RESPONSE" >&2
  exit 1
fi

ACCESS="$(echo "$RESPONSE" | python3 -c 'import json,sys; print(json.load(sys.stdin)["access_token"])')"
INSTANCE="$(echo "$RESPONSE" | python3 -c 'import json,sys; print(json.load(sys.stdin)["instance_url"])')"

printf '%s' "$ACCESS"   > "$KEYS_DIR/access_token"
printf '%s' "$INSTANCE" > "$KEYS_DIR/instance_url"
chmod 600 "$KEYS_DIR/access_token" "$KEYS_DIR/instance_url"

{
  echo "[$(date -u +%FT%TZ)] OAuth refresh_token grant complete"
  echo "  instance_url:  $INSTANCE"
  echo "  access_token:  refreshed in keys/access_token"
} >> "$OUTPUT_DIR/request_metadata.txt"

echo "Access token refreshed. Instance URL: $INSTANCE"
