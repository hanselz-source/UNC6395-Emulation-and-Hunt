#!/usr/bin/env bash
# 02_exchange_code.sh <AUTH_CODE>
# Exchange a one-shot Salesforce OAuth authorization code for an access token,
# refresh token, and instance URL. Tokens land in keys/ and are gitignored.
#
# Mirrors UNC6395 obtaining a long-lived OAuth refresh token (T1528).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BASE_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
KEYS_DIR="$BASE_DIR/keys"
OUTPUT_DIR="$BASE_DIR/output"

if [ $# -lt 1 ]; then
  echo "Usage: $0 <AUTH_CODE>" >&2
  echo "  Run 01_oauth_authcode.sh first to get the consent URL." >&2
  exit 1
fi

AUTH_CODE="$1"
CONSUMER_KEY="$(cat "$KEYS_DIR/consumer_key")"
CONSUMER_SECRET="$(cat "$KEYS_DIR/consumer_secret")"
REDIRECT_URI="http://localhost:8080/callback"

mkdir -p "$OUTPUT_DIR"

RESPONSE="$(curl -sS -X POST https://login.salesforce.com/services/oauth2/token \
  -d "grant_type=authorization_code" \
  -d "client_id=$CONSUMER_KEY" \
  -d "client_secret=$CONSUMER_SECRET" \
  -d "redirect_uri=$REDIRECT_URI" \
  -d "code=$AUTH_CODE")"

if echo "$RESPONSE" | grep -q '"error"'; then
  echo "Token exchange failed:" >&2
  echo "$RESPONSE" >&2
  exit 1
fi

ACCESS="$(echo "$RESPONSE" | python3 -c 'import json,sys; print(json.load(sys.stdin)["access_token"])')"
REFRESH="$(echo "$RESPONSE" | python3 -c 'import json,sys; print(json.load(sys.stdin)["refresh_token"])')"
INSTANCE="$(echo "$RESPONSE" | python3 -c 'import json,sys; print(json.load(sys.stdin)["instance_url"])')"

printf '%s' "$ACCESS"   > "$KEYS_DIR/access_token"
printf '%s' "$REFRESH"  > "$KEYS_DIR/refresh_token"
printf '%s' "$INSTANCE" > "$KEYS_DIR/instance_url"
chmod 600 "$KEYS_DIR/access_token" "$KEYS_DIR/refresh_token" "$KEYS_DIR/instance_url"

{
  echo "[$(date -u +%FT%TZ)] OAuth authorization_code exchange complete"
  echo "  instance_url:  $INSTANCE"
  echo "  access_token:  saved to keys/access_token (chmod 600)"
  echo "  refresh_token: saved to keys/refresh_token (chmod 600)"
  echo "  consumer_key:  $CONSUMER_KEY"
} >> "$OUTPUT_DIR/request_metadata.txt"

echo
echo "Tokens written to keys/. Instance URL: $INSTANCE"
echo "Capture the Setup Audit Trail and Login History screenshots now while the consent event is fresh."
