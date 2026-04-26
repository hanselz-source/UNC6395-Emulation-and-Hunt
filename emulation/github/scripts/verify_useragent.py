#!/usr/bin/env python3
"""
verify_useragent.py

Emulation 1, step 3. Reproduces UNC6395's token-verification probe.

UNC6395 was observed by GTIG and Cloudflare hitting SaaS token
verification endpoints with the literal HTTP header

    User-Agent: truffleHog

(camelCase, capital H. This is TruffleHog v3's default UA when its
detectors live-verify a candidate secret against the vendor's API.)

This script issues the same shape of request against a target you
control. Default target is a local listener on http://127.0.0.1:8089.
The point is to produce a captured request log that detection rule R1
can fire on.

SAFETY
------
The script will refuse to send any request to a host that looks like a
real production endpoint (salesforce.com, force.com, microsoftonline.com,
graph.microsoft.com, googleapis.com, snowflakecomputing.com, etc.)
unless you pass --i-own-this-target to acknowledge that the URL points
at a tenant or service you own and have authorization to test against.

The Authorization header is constructed from a token loaded out of the
bait secrets.yaml file by default, so the request payload visually
matches what an attacker scanning that file and verifying its findings
would emit.

Usage
-----
Local listener (default, recommended):

    python3 -m http.server 8089 --bind 127.0.0.1     # in another terminal
    python3 verify_useragent.py

Custom target you own:

    python3 verify_useragent.py \\
        --url https://your-lab-tenant.example.com/verify \\
        --token-file /tmp/threathunter-truffle-target/config/secrets.yaml \\
        --i-own-this-target

Output
------
- Writes ../output/verify_request.log with the full request line, headers,
  and the response status + body.
- Echoes the same to stdout.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import socket
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

# Literal IOC. Camel-case, capital H. Do not "fix" this.
TRUFFLEHOG_UA = "truffleHog"

# Production-looking hostnames we refuse to hit without explicit override.
BLOCKED_HOST_PATTERNS = [
    r"(^|\.)salesforce\.com$",
    r"(^|\.)force\.com$",
    r"(^|\.)my\.salesforce\.com$",
    r"(^|\.)lightning\.force\.com$",
    r"(^|\.)microsoftonline\.com$",
    r"(^|\.)graph\.microsoft\.com$",
    r"(^|\.)login\.microsoft\.com$",
    r"(^|\.)googleapis\.com$",
    r"(^|\.)snowflakecomputing\.com$",
    r"(^|\.)okta\.com$",
    r"(^|\.)cloudflare\.com$",
]
BLOCKED_HOST_REGEX = re.compile("|".join(BLOCKED_HOST_PATTERNS), re.IGNORECASE)

# Safe-by-default lab targets.
ALLOWED_DEFAULT_HOSTS = {"127.0.0.1", "localhost", "::1"}

DEFAULT_URL = "http://127.0.0.1:8089/verify"

SCRIPT_DIR = Path(__file__).resolve().parent
EMU_DIR = SCRIPT_DIR.parent
OUTPUT_DIR = EMU_DIR / "output"
DEFAULT_TOKEN_FILE = EMU_DIR / "bait" / "config" / "secrets.yaml"
LOG_FILE = OUTPUT_DIR / "verify_request.log"


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="UNC6395-style token verification probe. Emits User-Agent: truffleHog."
    )
    p.add_argument(
        "--url",
        default=DEFAULT_URL,
        help=f"Target URL. Default: {DEFAULT_URL} (safe local listener).",
    )
    p.add_argument(
        "--token-file",
        type=Path,
        default=DEFAULT_TOKEN_FILE,
        help="Path to a YAML file containing a refresh_token field. "
             "Default: the bait secrets.yaml shipped with this emulation.",
    )
    p.add_argument(
        "--method",
        default="GET",
        choices=["GET", "POST"],
        help="HTTP method. Default: GET.",
    )
    p.add_argument(
        "--i-own-this-target",
        action="store_true",
        help="Acknowledge that --url points at infrastructure you own and "
             "have authorization to probe. Required for any non-local host.",
    )
    p.add_argument(
        "--timeout",
        type=float,
        default=8.0,
        help="HTTP timeout in seconds. Default: 8.",
    )
    return p.parse_args()


def load_token(token_file: Path) -> str:
    """Pull the salesforce refresh_token out of the bait yaml.

    We deliberately avoid pyyaml so the script has no third-party
    dependencies. The bait file shape is well known.
    """
    if not token_file.exists():
        return "FAKETESTVALUE_NO_TOKEN_FILE_FOUND"
    text = token_file.read_text(encoding="utf-8")
    m = re.search(r'refresh_token:\s*"([^"]+)"', text)
    if m:
        return m.group(1)
    m = re.search(r"refresh_token:\s*'([^']+)'", text)
    if m:
        return m.group(1)
    m = re.search(r"refresh_token:\s*([^\s#]+)", text)
    if m:
        return m.group(1)
    return "FAKETESTVALUE_TOKEN_NOT_PARSED"


def host_is_blocked(host: str) -> bool:
    if host in ALLOWED_DEFAULT_HOSTS:
        return False
    return bool(BLOCKED_HOST_REGEX.search(host or ""))


def safety_check(url: str, override: bool) -> None:
    parsed = urllib.parse.urlparse(url)
    host = (parsed.hostname or "").lower()
    if host_is_blocked(host) and not override:
        sys.stderr.write(
            f"[SAFETY] Refusing to send to {host}. This looks like a real production\n"
            f"         endpoint. If you actually own this target and have authorization\n"
            f"         to probe it, re-run with --i-own-this-target.\n"
        )
        sys.exit(2)
    if host not in ALLOWED_DEFAULT_HOSTS and not override:
        sys.stderr.write(
            f"[SAFETY] Target host '{host}' is not 127.0.0.1/localhost. If you\n"
            f"         own this target, re-run with --i-own-this-target.\n"
        )
        sys.exit(2)


def build_request(url: str, method: str, token: str) -> urllib.request.Request:
    headers = {
        "User-Agent": TRUFFLEHOG_UA,
        "Authorization": f"Bearer {token}",
        "Accept": "application/json",
        "X-Lab-Emulation": "Emulation-1-T1552.001",
    }
    data = None
    if method == "POST":
        data = json.dumps({"verify": "refresh_token"}).encode("utf-8")
        headers["Content-Type"] = "application/json"
    return urllib.request.Request(url=url, data=data, method=method, headers=headers)


def _canonicalize_header_name(name: str) -> str:
    """Render header names in canonical Title-Case-With-Hyphens form.

    urllib stores header names with only the first letter capitalized
    ("User-agent"). HTTP itself is case-insensitive on header names,
    but for the captured log we want the canonical form ("User-Agent")
    so that detection rule R1 matches what a defender would actually
    grep for.
    """
    return "-".join(part.capitalize() for part in name.split("-"))


def render_request(req: urllib.request.Request) -> str:
    parsed = urllib.parse.urlparse(req.full_url)
    path = parsed.path or "/"
    if parsed.query:
        path = f"{path}?{parsed.query}"
    lines = [f"{req.get_method()} {path} HTTP/1.1",
             f"Host: {parsed.netloc}"]
    for k, v in req.header_items():
        lines.append(f"{_canonicalize_header_name(k)}: {v}")
    if req.data:
        lines.append("")
        lines.append(req.data.decode("utf-8", errors="replace"))
    return "\n".join(lines)


def render_response(resp_or_err) -> str:
    if isinstance(resp_or_err, urllib.error.HTTPError):
        status = resp_or_err.code
        reason = resp_or_err.reason
        headers = dict(resp_or_err.headers)
        body = resp_or_err.read().decode("utf-8", errors="replace")
    elif isinstance(resp_or_err, urllib.error.URLError):
        return f"HTTP/1.1 000 No Response\nReason: {resp_or_err.reason}\n"
    else:
        status = resp_or_err.status
        reason = resp_or_err.reason
        headers = dict(resp_or_err.headers)
        body = resp_or_err.read().decode("utf-8", errors="replace")
    lines = [f"HTTP/1.1 {status} {reason}"]
    for k, v in headers.items():
        lines.append(f"{k}: {v}")
    lines.append("")
    lines.append(body[:1024])
    if len(body) > 1024:
        lines.append(f"... [truncated {len(body) - 1024} more bytes]")
    return "\n".join(lines)


def main() -> int:
    args = parse_args()
    safety_check(args.url, args.i_own_this_target)
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    token = load_token(args.token_file)
    req = build_request(args.url, args.method, token)
    rendered_req = render_request(req)

    started = datetime.now(timezone.utc)
    t0 = time.perf_counter()
    response_str: str
    try:
        with urllib.request.urlopen(req, timeout=args.timeout) as resp:
            response_str = render_response(resp)
    except urllib.error.HTTPError as e:
        response_str = render_response(e)
    except urllib.error.URLError as e:
        response_str = render_response(e)
    except (TimeoutError, socket.timeout) as e:
        response_str = f"HTTP/1.1 000 Timeout\nReason: {e}\n"
    elapsed_ms = (time.perf_counter() - t0) * 1000.0

    block = []
    block.append("=" * 72)
    block.append(f"# Emulation 1 verification probe")
    block.append(f"# Time:       {started.isoformat()}")
    block.append(f"# Target:     {args.url}")
    block.append(f"# Token file: {args.token_file}")
    block.append(f"# Latency:    {elapsed_ms:.1f} ms")
    block.append("=" * 72)
    block.append("")
    block.append("--- REQUEST ---")
    block.append(rendered_req)
    block.append("")
    block.append("--- RESPONSE ---")
    block.append(response_str)
    block.append("")

    payload = "\n".join(block) + "\n"
    print(payload)

    with LOG_FILE.open("a", encoding="utf-8") as f:
        f.write(payload)

    print(f"[+] Appended to {LOG_FILE}")
    print(f"[+] User-Agent emitted: {TRUFFLEHOG_UA!r}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
