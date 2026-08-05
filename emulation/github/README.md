# Emulation 1: T1552.001 Unsecured Credentials in Files (GitHub + TruffleHog)

> **MITRE:** T1552.001 (Unsecured Credentials: Credentials In Files), supported by T1195.002 and T1199 as the documented narrative
> **Maps to detection:** R1 (TruffleHog User-Agent)

## Background

UNC6395's initial-access leg ran March to June 2025.

The actor reached Salesloft's GitHub organization, then pulled Drift OAuth refresh tokens from source and from AWS Secrets Manager and SSM Parameter Store.
Cloudflare recorded `User-Agent: truffleHog` at 2025-08-09 11:51:13 UTC, verifying a harvested token against a customer tenant.
See `profile/README.md` section 11.

GTIG lists four separate User-Agents for the campaign: `Salesforce-Multi-Org-Fetcher/1.0`, `Salesforce-CLI/1.0`, `python-requests/2.32.4` and `Python/3.11 aiohttp/3.12.15`.
No rule in this package covers them, because nothing here records a User-Agent.

This folder reproduces the Cloudflare one, the only one tied to credential verification.

## Hypothesis

> An attacker with access to a software vendor's source repositories scans the working tree with TruffleHog to recover OAuth refresh tokens.
> They then verify a recovered token against the SaaS API, carrying TruffleHog's default User-Agent.

## Scope and Limitations

- Detecting this needs a log carrying the `User-Agent` header: the `RestApi` event, or a gateway log. The lab has neither, so `output/verify_request.log` records the outbound request instead. That shows the emulation is faithful. It is not a detection.

## Folder Layout

```
emulation/github/
  README.md                        this file
  bait/                            mirrored to private repo threathunter-truffle-target
    README.md
    config/
      secrets.yaml                 planted credentials in YAML config
      signing_key.pem              planted private key (real RSA, lab-only, never used)
      app.example.yaml             innocuous neighbor file
    .gitignore                     intentionally does NOT exclude config/secrets.yaml
  scripts/
    run_trufflehog.sh              filesystem scan, writes output/truffle.json
    verify_useragent.py            HTTP client that emits User-Agent: truffleHog
  output/
    truffle.json                   raw scan output (NDJSON)
    truffle.summary.txt            parsed summary
    trufflehog_console.png         screenshot of scan output
    verify_request.log             request/response capture from verify_useragent.py
    verify_response.png            screenshot of the receiving listener
```

## Artifacts Captured

| File | What it shows |
|---|---|
| `output/truffle.json` | TruffleHog v3 NDJSON findings against the bait repo |
| `output/truffle.summary.txt` | Detector / file / verification-status summary, one line per finding |
| `output/trufflehog_console.png` | Terminal output of the scan, evidence the find is reproducible |
| `output/verify_request.log` | Raw HTTP request emitted by `verify_useragent.py`, including the `User-Agent: truffleHog` header and the planted Bearer token |
| `output/verify_response.png` | Screenshot of the listener receiving the inbound probe |

The `bait/` directory mirrors the contents of the private repo `threathunter-truffle-target` that was the scan target.

Mirroring it here makes the deliverable reproducible without requiring access to the private repo.

## IOC Mapping

| Lab artifact | Real-world IOC | Source |
|---|---|---|
| `User-Agent: truffleHog` in `verify_request.log` | Cloudflare 2025-08-09 11:51:13 token verification | `profile/README.md` section 11 |
| `truffle.json` finding for `config/secrets.yaml` | Salesloft GitHub access between March and June 2025; OAuth tokens recovered from source and AWS Secrets Manager | `profile/README.md` section 6 |
| Synthetic refresh token shape (`5Aep...`) | Salesforce Connected App refresh-token format | Salesforce Connected App OAuth 2.0 Web Server Flow |

## Detection Notes

- TruffleHog writes `truffleHog`, lowercase t and uppercase H. Match case-insensitively so an actor who changes the casing is still caught.
- TruffleHog defaults this User-Agent on verification probes. The actor kept the default rather than rewriting it, which is what makes it usable.
- Detection field mapping:
	- Salesforce Event Monitoring: `RestApi` event, `USER_AGENT` field. The Setup Audit Trail carries no User-Agent, so the free-tier lab cites the field but cannot fire the rule.
	- Microsoft Sentinel: `MicrosoftGraphActivityLogs` and `SigninLogs` both expose `UserAgent`.
	- Generic WAF / API gateway: HTTP `User-Agent` header.
- False positives: security teams running TruffleHog against their own SaaS APIs. Tie the rule to token-bearing requests and to source ASNs outside your egress.

## Notes on the Bait

- Every value in `bait/config/secrets.yaml` carries the substring `FAKETESTVALUE` and an inline comment marking it synthetic.
- `bait/config/signing_key.pem` is a real RSA-2048 key pair from an isolated sandbox, tied to no account or service. It is committed so TruffleHog's `PrivateKey` detector fires against the bait. It is worthless.
- The scan result is half the point. The other half is the verification request that follows. R1 through R3 cover what happens once the token reaches a real OAuth endpoint.

## References

- GTIG, "Widespread Data Theft Targets Salesforce Instances via Salesloft Drift," August 2025
- Cloudflare, "The impact of the Salesloft Drift breach on Cloudflare and our customers," August 2025 (timeline entry 2025-08-09 11:51:13 UTC)
- permiso.io, "Anatomy of the Salesloft Breach"
- TruffleHog v3, `trufflesecurity/trufflehog` GitHub repository
- MITRE ATT&CK T1552.001
