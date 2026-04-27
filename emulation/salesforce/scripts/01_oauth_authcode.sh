#!/usr/bin/env bash
# 01_oauth_authcode.sh
# Print the Salesforce OAuth 2.0 Web Server Flow consent URL.
# Open it in a browser, sign in as the test user, approve consent,
# then read the authorization code out of the redirect URL and feed it
# to 02_exchange_code.sh.
#
# Mirrors UNC6395's downstream consent-grant moment (T1528 evidence).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BASE_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
KEYS_DIR="$BASE_DIR/keys"

if [ ! -f "$KEYS_DIR/consumer_key" ]; then
  echo "ERROR: $KEYS_DIR/consumer_key not found." >&2
  echo "  Get it from Salesforce Setup -> External Client App Manager -> Drift_Integration -> Manage Consumer Details" >&2
  exit 1
fi

CONSUMER_KEY="$(cat "$KEYS_DIR/consumer_key")"
LOGIN_URL="https://login.salesforce.com"
REDIRECT_URI="http://localhost:8080/callback"
SCOPE="api refresh_token offline_access"

ENCODED_REDIRECT="$(python3 -c 'import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1], safe=""))' "$REDIRECT_URI")"
ENCODED_SCOPE="$(python3 -c 'import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1], safe=""))' "$SCOPE")"

CONSENT_URL="${LOGIN_URL}/services/oauth2/authorize?response_type=code&client_id=${CONSUMER_KEY}&redirect_uri=${ENCODED_REDIRECT}&scope=${ENCODED_SCOPE}&prompt=login%20consent"

cat <<EOF
Open this URL in your browser:

  $CONSENT_URL

After you approve consent, Salesforce will redirect to:
  http://localhost:8080/callback?code=<AUTH_CODE>

Copy the value of code= (everything between code= and the next & or end of URL).
The auth code is single-use and expires in ~10 minutes.

Then run:
  bash scripts/02_exchange_code.sh '<AUTH_CODE>'

EOF
