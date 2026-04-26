# Emulation 1: T1552.001 Unsecured Credentials in Files (GitHub + TruffleHog)

> **MITRE:** T1552.001 (Unsecured Credentials: Credentials In Files), supported by T1195.002 and T1199 as the documented narrative
> **Maps to detection:** R1 (TruffleHog User-Agent)

## Why This Exists

UNC6395's initial-access leg, between March and June 2025, was access to Salesloft's GitHub organization and extraction of OAuth refresh tokens for the Drift application from source and AWS Secrets Manager / SSM Parameter Store. The most quotable single IOC from the campaign is the literal HTTP `User-Agent: truffleHog` that GTIG and Cloudflare both observed when the actor verified harvested tokens against API endpoints. See `profile/README.md` section 11 (Indicators of Compromise) and the Cloudflare timeline entry at 2025-08-09 11:51:13 UTC.

This emulation reproduces the supply-chain harvesting behavior in a controlled, self-owned GitHub repo. We are not breaching a real third-party SaaS vendor. We are demonstrating that:

1. A repo containing a credential in a config file gets flagged by an attacker running TruffleHog v3.
2. The default User-Agent that TruffleHog (and a UNC6395-style verification client) emits against a verification endpoint is a high-fidelity IOC for detection rule R1.

## Hypothesis

> An attacker who has obtained access to a software vendor's source repositories scans the working tree with TruffleHog (or an equivalent secret scanner) to recover OAuth refresh tokens, then verifies a recovered token against the SaaS API using TruffleHog's default User-Agent.

## Scope and Limitations

- Detection rule R1 will fire on any inbound request with `User-Agent` matching `truffleHog`. In production this would be tied to Salesforce Event Monitoring's `RestApi` event or to a WAF / API gateway log. In the lab, we capture the request locally as proof.

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

The `bait/` directory mirrors the contents of the private repo `threathunter-truffle-target` that was the scan target. Mirroring it here makes the deliverable reproducible without requiring access to the private repo.

## IOC Mapping

| Lab artifact | Real-world IOC | Source |
|---|---|---|
| `User-Agent: truffleHog` in `verify_request.log` | Cloudflare 2025-08-09 11:51:13 token verification, GTIG advisory section on UNC6395 tradecraft | `profile/README.md` section 11 |
| `truffle.json` finding for `config/secrets.yaml` | Salesloft GitHub access between March and June 2025; OAuth tokens recovered from source and AWS Secrets Manager | `profile/README.md` section 6 |
| Synthetic refresh token shape (`5Aep...`) | Salesforce Connected App refresh-token format | Salesforce Connected App OAuth 2.0 Web Server Flow |

## Detection Notes (feeds into R1)

- The User-Agent string is exactly `truffleHog`. Lowercase t, uppercase H. Case-sensitive in the Sigma rule.
- TruffleHog defaults this User-Agent on its verification probes. The actor reused the default rather than rewriting it, which is the entire reason this is a usable IOC.
- Detection field mapping:
  - Salesforce Event Monitoring: `RestApi` event, `USER_AGENT` field. Setup Audit Trail does not surface User-Agent, so in the free-tier lab you cite the field but cannot fire the rule from Salesforce alone.
  - Microsoft Sentinel: `MicrosoftGraphActivityLogs` has `UserAgent`. `SigninLogs` does too, on `UserAgent`.
  - Generic WAF / API gateway: HTTP `User-Agent` header.
- False positives: legitimate security teams running TruffleHog against their own SaaS APIs as a hygiene check. Suppress by tying the rule to OAuth-token-bearing requests and to source ASNs that are not the org's own egress.

## Notes on the Bait

- This is a structural emulation of T1552.001 inside an owned repo. It is not a real exploitation of Salesloft. The narrative remains anchored on UNC6395; the lab demonstrates the same attacker behavior against synthetic infrastructure.
- All values in `bait/config/secrets.yaml` carry the literal substring `FAKETESTVALUE` and an inline comment marking them as synthetic.
- `bait/config/signing_key.pem` is a real RSA-2048 key pair, but generated in an isolated sandbox with no association to any account, service, or certificate. It is committed solely so TruffleHog's `PrivateKey` detector (which calls `x509.ParsePKCS8PrivateKey`) actually fires against the bait. Treat it as worthless.
- The TruffleHog match alone is not the deliverable. The deliverable is the pair: a repo that yields the secret, plus the verification request that demonstrates the next move. R1 detects the verification probe. R2 through R5 detect what happens after the verified token is presented to a real OAuth endpoint.

## References

- GTIG, "Widespread Data Theft Targets Salesforce Instances via Salesloft Drift," August 2025
- Cloudflare, "The impact of the Salesloft Drift breach on Cloudflare and our customers," August 2025 (timeline entry 2025-08-09 11:51:13 UTC)
- permiso.io, "Anatomy of the Salesloft Breach"
- TruffleHog v3, `trufflesecurity/trufflehog` GitHub repository
- MITRE ATT&CK T1552.001
