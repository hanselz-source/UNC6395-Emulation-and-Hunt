#!/usr/bin/env bash
# run_trufflehog.sh
#
# Emulation 1, step 2. Scans a target git repo with TruffleHog v3 and
# writes JSON output plus a short summary into ../output/.
#
# Usage:
#   ./run_trufflehog.sh /absolute/path/to/threathunter-truffle-target
#
# The synthetic bait values in this lab are not verifiable secrets, so
# we run with --no-verification by default. That ensures we capture
# unverified findings (like the AKIA-shaped key and high-entropy
# refresh token) instead of TruffleHog silently dropping them.
#
# To match how UNC6395 would actually use the tool against a target
# they intend to verify against a live API, see the comment block
# at the bottom of this file.

set -euo pipefail

if [[ $# -lt 1 ]]; then
  echo "Usage: $0 /absolute/path/to/repo" >&2
  exit 64
fi

# Tolerate an unquoted path that contains spaces. If the resulting
# concatenation does not point at a real directory we'll fall through
# to the "Target repo path does not exist" check below.
if [[ $# -gt 1 ]]; then
  joined="$*"
  if [[ -d "$joined" ]]; then
    echo "[!] Path contains spaces and was passed unquoted. Reassembled as:" >&2
    echo "    $joined" >&2
    echo "    Tip: quote the path next time, e.g. \"\$HOME/Some Folder/repo\"" >&2
    set -- "$joined"
  else
    echo "Got $# arguments. Did you forget to quote a path with spaces?" >&2
    echo "Received: $*" >&2
    echo "Usage: $0 /absolute/path/to/repo" >&2
    exit 64
  fi
fi

TARGET_REPO="$1"
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
EMU_DIR="$( cd "$SCRIPT_DIR/.." && pwd )"
OUT_DIR="$EMU_DIR/output"
OUT_JSON="$OUT_DIR/truffle.json"
OUT_SUMMARY="$OUT_DIR/truffle.summary.txt"

if [[ ! -d "$TARGET_REPO" ]]; then
  echo "Target repo path does not exist: $TARGET_REPO" >&2
  exit 66
fi

if [[ ! -d "$TARGET_REPO/.git" ]]; then
  echo "[!] Note: $TARGET_REPO is not a git repo. Filesystem mode will still" >&2
  echo "    scan it, but you lose the supply-chain narrative." >&2
  echo "    To git-init the target, run:" >&2
  echo "      cd '$TARGET_REPO' && git init -b main && git add . && git commit -m 'init'" >&2
fi

if ! command -v trufflehog >/dev/null 2>&1; then
  cat >&2 <<'MSG'
trufflehog binary not found on PATH.

Install one of:
  macOS:   brew install trufflehog
  Linux:   curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sudo sh -s -- -b /usr/local/bin
  Release: https://github.com/trufflesecurity/trufflehog/releases
MSG
  exit 127
fi

mkdir -p "$OUT_DIR"

echo "[*] Target repo:   $TARGET_REPO"
echo "[*] Output JSON:   $OUT_JSON"
echo "[*] Output summary: $OUT_SUMMARY"
echo "[*] TruffleHog:    $(trufflehog --version 2>&1 | head -n1)"
echo

# Mode notes:
#   - We run trufflehog in `filesystem` mode against the working tree.
#     `git` mode also works but in v3.95+ the temp-checkout rewrite makes
#     the file path in the JSON less readable.
#   - --no-verification: do not call vendor APIs against synthetic creds.
#   - --results: v3 defaults filter low-confidence candidates. We force
#     emission of every class so the lab's clearly-fake values still
#     surface (especially the PrivateKey block, which is regex-only).
#   - --json: NDJSON output, one finding per line.
trufflehog filesystem "${TARGET_REPO}" \
  --json \
  --no-verification \
  --results=verified,unknown,unverified,filtered_unverified \
  > "$OUT_JSON" 2> "$OUT_DIR/truffle.stderr.log"

FOUND_COUNT=$(grep -c '"DetectorName"' "$OUT_JSON" || true)

{
  echo "TruffleHog scan summary"
  echo "Target:    $TARGET_REPO"
  echo "Findings:  $FOUND_COUNT"
  echo
  echo "Detectors and files matched:"
  if [[ "$FOUND_COUNT" -gt 0 ]]; then
    # Pull DetectorName + SourceMetadata.Data.Git.file out of the NDJSON
    python3 - "$OUT_JSON" <<'PY'
import json, sys
with open(sys.argv[1]) as f:
    for line in f:
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        det = obj.get("DetectorName", "?")
        data = obj.get("SourceMetadata", {}).get("Data", {})
        # filesystem mode -> .Filesystem; git mode -> .Git
        meta = data.get("Filesystem") or data.get("Git") or {}
        path = meta.get("file", "?")
        commit = (meta.get("commit") or "")[:8]
        verified = obj.get("Verified", False)
        flag = "verified" if verified else "unverified"
        suffix = f"  @ {commit}" if commit else ""
        print(f"  - {det:<22} [{flag:<10}] {path}{suffix}")
PY
  else
    echo "  (no findings)"
  fi
} | tee "$OUT_SUMMARY"

echo
if [[ "$FOUND_COUNT" -eq 0 ]]; then
  cat <<'MSG'
[!] No findings. Common causes:
    - bait/ files were not git add + git commit'ed (TruffleHog scans
      git history by default, uncommitted files are invisible).
    - You scanned a different directory than the bait repo.
    - Detector regexes have moved on. Try `trufflehog filesystem` mode:
        trufflehog filesystem --no-verification --json '<path>'
MSG
  exit 1
fi

echo "[+] Done. Findings written to $OUT_JSON"

# --------------------------------------------------------------------
# UNC6395 reproduction notes
# --------------------------------------------------------------------
# In the real campaign GTIG and Cloudflare both observed the literal
# User-Agent "truffleHog" hitting Salesforce token-verification
# endpoints during August 2025. That is TruffleHog's default UA when
# its detectors do live verification.
#
# We pass --no-verification here on purpose so the lab does not emit
# outbound requests to Salesforce, AWS STS, or Snowflake against
# synthetic credentials. The verification leg is reproduced separately
# by scripts/verify_useragent.py against a self-owned listener.
# --------------------------------------------------------------------
