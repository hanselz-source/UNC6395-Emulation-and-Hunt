# Emulation 2 + 3: T1528 OAuth Consent + T1550.001 Token Replay (Salesforce External Client App)

**MITRE:** T1528 Steal Application Access Token, T1550.001 Use Alternate Auth Material, T1087.004 Account Discovery.
**Detections:** R1, R2, R3.

## Background

UNC6395 took Drift's OAuth refresh tokens upstream and replayed them against downstream Salesforce tenants.

From the victim side it looked like Drift calling Drift's own API.

- Three anomalies carry signal.
- The consent grant itself (R1).
- The service-principal sign-in with no preceding human auth for the same `AppId` (R2).
- The volume signature of the schema-then-bulk recon burst (R3).
- Cloudflare's timeline anchors all three, in `profile/README.md` section 5.

This folder covers the downstream half of the kill chain in an owned Developer Edition tenant.

The Drift stand-in is `Drift_Integration` and never leaves that org.
Captured tokens never leave the lab.

Developer Edition orgs from 2024 default to External Client Apps rather than the legacy Connected App.

- This emulation uses External Client Apps throughout.
- Detection logic is unchanged either way.
- Salesforce surfaces both in `LoginHistory` and the Setup Audit Trail, so production rules cite both sObjects.

## Hypothesis

> An attacker holding stolen OAuth credentials for a pre-approved External Client App authenticates through the OAuth Web Server Flow.
> A recon burst follows: object enumeration, COUNT probes, schema describes, then progressively wider SOQL pulls.
> Three signals combine into a high-confidence cluster: the burst's volume signature, an app sign-in with no human precursor, and TruffleHog as the User-Agent on a verification probe.

## Scope and Limitations

- Developer Edition has no Event Monitoring (Shield). The lab substitutes the Setup Audit Trail, Login History and System Overview API Usage tile. Each rule still cites the Event Monitoring field it targets.
- The Connected Apps OAuth Usage page is not exposed for External Client Apps here. R3's only defender-side evidence is the org-level counter in `output/system_overview_api_usage.png`. It confirms the volume but cannot attribute it to one app or resolve 5 minutes. Production maps to `ApiEvent` grouped by `CONNECTED_APP_ID`.
- `User-Agent: truffleHog` rides every request from `scripts/04_recon_burst.sh` and `scripts/05_describe_and_sobjects.sh`. No free-tier surface records a User-Agent, so no rule in this package keys on it. The header goes out and nothing on the tenant side sees it.
- The External Client App carries Drift's scope set (`api`, `refresh_token`, `offline_access`) and callback pattern. Its **Refresh Token Policy is Infinite**, matching Drift. That policy is why dormant tokens stayed usable through August 2025.

## Folder Layout

```
emulation/salesforce/
  README.md                         this file
  keys/                             all ignored by the top-level .gitignore
    README.md                       how to fill this folder in
    consumer_key.example            placeholder, copy to consumer_key
    consumer_key                    you create this, External Client App OAuth client_id
    consumer_secret                 you create this, External Client App OAuth client_secret
    access_token                    written at runtime by script 02 or 03
    refresh_token                   written at runtime by script 02
    instance_url                    written at runtime by script 02 or 03
  scripts/
    01_oauth_authcode.sh            prints the consent URL to paste into the browser
    02_exchange_code.sh             POST authorization_code, writes keys/access_token + refresh_token + instance_url
    03_refresh_access_token.sh      POST refresh_token, refreshes keys/access_token in place
    04_recon_burst.sh               COUNT() sweep + progressive LIMIT pulls with User-Agent: truffleHog
    05_describe_and_sobjects.sh     GET /sobjects/, /sobjects/Account/describe/, /limits/ with User-Agent: truffleHog
  output/
    recon_burst.log                 stdout of script 04, 51 timestamped queries with full responses
    sobjects_listing.json           response from GET /sobjects/ (1330 sObjects)
    account_describe.json           response from GET /sobjects/Account/describe/ (70 fields)
    limits.json                     response from GET /limits/
    request_metadata.txt            UTC timestamps for the three flat REST recon calls
    consent_audit_trail.png         Setup Audit Trail screenshot, Drift_Integration full lifecycle (T1528 + R2)
    login_history_oauth.png         Login History screenshot, OAuth + interactive rows (T1550.001 + R2)
    recon_burst_terminal.png        terminal screenshot of recon_burst.log, 51 GET lines with UA=truffleHog
    system_overview_api_usage.png   API Usage tile, 55/15000 daily counter post-burst (R3 volume substitute)
```

## Run

```
bash scripts/01_oauth_authcode.sh          # prints the consent URL
bash scripts/02_exchange_code.sh '<CODE>'  # code= from the callback redirect
bash scripts/05_describe_and_sobjects.sh
bash scripts/04_recon_burst.sh
```

Auth codes expire in about 10 minutes.
`03_refresh_access_token.sh` replaces steps 01 and 02 if you already hold a refresh token.

Under `zsh` the access token's `!` triggers history expansion.
Single-quote the bearer header or `setopt no_bang_hist`.

`04` issues 51 SOQL queries.
5 COUNT probes across Account, Contact, User, Case and Opportunity.
Then 5 passes of 3 objects against 3 LIMIT clauses.
Then 1 detailed User enumeration mirroring Cloudflare's 2025-08-14 11:09:21 query.
`05` adds the `/sobjects/`, `/describe/` and `/limits/` calls matching Cloudflare's 2025-08-12 and 2025-08-13 entries.
Every request carries `User-Agent: truffleHog`.

The validation run produced 51 queries in 31 seconds, one event above R3's threshold of 50.

## Evidence to Capture

Screenshots, because Developer Edition exposes no export for these surfaces.
The legacy Connected Apps OAuth Usage page is not available for External Client Apps at all.

| Salesforce UI | Crop to | Save as |
|---|---|---|
| Setup, View Setup Audit Trail, filtered to the test user | The `Drift_Integration` lifecycle rows: creation, OAuth policy binding, key and secret generation, refresh token policy change | `output/consent_audit_trail.png` |
| Setup, Login History, filtered to the test user | The interactive browser row and the OAuth `Remote Access 2.0` rows where Application is `Drift Integration` | `output/login_history_oauth.png` |
| Setup, System Overview | The API Usage tile, which read `55 / 15,000` on the validation run: 51 queries, 3 flat REST calls, 1 token exchange | `output/system_overview_api_usage.png` |
| A terminal running `grep '^\[' recon_burst.log \| head -55` | The 51 timestamped queries showing `UA=truffleHog` | `output/recon_burst_terminal.png` |

The first three are defender-side. The terminal capture is not.
See [`../../validation/Validation.md`](../../validation/Validation.md).

## Artifacts Captured

| File | What it shows |
|---|---|
| `output/recon_burst.log` | 51 SOQL queries with UTC timestamps, the User-Agent header, and the full response body. Attacker-side |
| `output/recon_burst_terminal.png` | Terminal screenshot of the 51 timestamped GET lines from `recon_burst.log`, every line showing `UA=truffleHog`. Attacker-side |
| `output/system_overview_api_usage.png` | API Usage tile from System Overview, `55 / 15,000` API requests over the last 24 hours. Org-level proxy for the missing Connected Apps OAuth Usage page (R3) |
| `output/sobjects_listing.json` | Object enumeration response, 1330 sObjects, mirrors Cloudflare 2025-08-12 22:14:09 entry |
| `output/account_describe.json` | Schema describe response, 70 Account fields, mirrors Cloudflare 2025-08-13 19:33:07 entry |
| `output/limits.json` | Limits endpoint response (`DailyApiRequests: 14998/15000` pre-burst), mirrors Cloudflare 2025-08-14 11:09:22 entry |
| `output/consent_audit_trail.png` | Setup Audit Trail showing full External Client App lifecycle for `Drift_Integration`. T1528 evidence including the Refresh Token Policy change to Infinite |
| `output/login_history_oauth.png` | Login History showing browser interactive sign-in at 10:21:29 PDT, OAuth Drift Integration success at 10:50:55 PDT, failed nonce retry at 10:51:16 PDT. T1550.001 + R2 evidence in one frame |
| `output/request_metadata.txt` | UTC timestamps for the three flat REST recon calls (sobjects listing, Account describe, limits), each tagged `UA=truffleHog` |

## IOC Mapping

| Lab artifact | Real-world IOC | Source |
|---|---|---|
| `User-Agent: truffleHog` in `recon_burst.log` and `request_metadata.txt` | Cloudflare 2025-08-09 11:51:13 token verification probe | `profile/README.md` section 11 |
| `GET /services/data/v60.0/sobjects/` in `sobjects_listing.json` | Cloudflare 2025-08-12 22:14:09 `GET /services/data/v58.0/sobjects/` | `profile/README.md` section 5 |
| `GET /services/data/v60.0/sobjects/Account/describe/` in `account_describe.json` | Cloudflare 2025-08-13 19:33:07 `GET /services/data/v58.0/sobjects/Case/describe/` | `profile/README.md` section 5 |
| `SELECT Count() FROM Account/Contact/User` burst in `recon_burst.log` | Cloudflare 2025-08-14 00:17:47 to 00:18:00 COUNT() sequence | `profile/README.md` section 5 |
| 55-call API Usage delta in `system_overview_api_usage.png` | Bulk SOQL volume preceding Bulk API exfil on 2025-08-17 | `profile/README.md` section 5 |
| External Client App scope set (`api`, `refresh_token`, `offline_access`) | Drift Connected App OAuth scopes | GTIG advisory section on token architecture |
| Refresh Token Policy = Infinite (visible in `consent_audit_trail.png`) | Drift's per-user refresh token model with no rotation | `profile/README.md` section 6, "Per-user OAuth token abuse" |
| `Application Type == Remote Access 2.0` rows in `login_history_oauth.png` | OAuth-token-bearing access against victim Salesforce tenants, no MFA prompt | Cloudflare 2025-08-12 to 2025-08-17 login entries |

## Detection Notes

- **R1 (T1528):** a Setup Audit Trail row generating an app's consumer secret, or changing its Refresh Token Policy Type. The lab reads the audit trail directly. Production joins `EventLogFile` against the `ConnectedApplication` and `ExternalClientApplication` sObjects.
- **R2 (T1550.001 / T1078.004):** a Login History row with `Application Type == Remote Access 2.0` where that app has no interactive row in the prior 24 hours. The lab does **not** fire this, and should not. The test user signed in interactively 29 minutes earlier, so the precursor exists. In a real tenant its absence is the detection, because consent was granted months before.
- **R3 (T1087.004 / T1213.006):** more than 50 SOQL calls from one app inside 5 minutes. Fires partially here. `system_overview_api_usage.png` confirms 55 calls but is org-wide over 24 hours. `recon_burst_terminal.png` shows 51 queries in 31 seconds and is the attack script's own output. See `../../validation/Validation.md`.
- False positives: admins testing new External Client Apps, security teams running TruffleHog against their own APIs, scheduled bulk integrations. Tie R3 to apps with no 30-day baseline.

## Notes on the External Client App

- Name in lab: `Drift_Integration`. Consumer ID `888g5000000OC3G`.
- OAuth scopes: `api`, `refresh_token`, `offline_access`. Same as Drift.
- Callback URL: `http://localhost:8080/callback`. Salesforce rejects `localhost:8080` without the scheme.
- **Refresh Token Policy: Infinite**, changed from the SpecificLifetime default at 10:28:40 PDT in `consent_audit_trail.png`. This mirrors Drift and is why dormant tokens stayed usable from March to August 2025.
- The consumer secret was read 6 times during testing, at 10:45:41 to 10:45:42 PDT. That copies how an attacker with repo access pulls the same secret repeatedly. The secret is not in this repo. Keep it that way: a live client secret stays readable in git history long after the file is deleted.
- Developer Edition orgs from 2024 default to External Client Apps. The legacy Connected App framework still works. Both surface identically in `LoginHistory.Application` and the Setup Audit Trail, so production rules should query both sObjects.

## References

- GTIG, "Widespread Data Theft Targets Salesforce Instances via Salesloft Drift," August 2025
- Cloudflare, "The impact of the Salesloft Drift breach on Cloudflare and our customers," August 2025 (timeline entries 2025-08-09 11:51:13 through 2025-08-17 11:15:42)
- permiso.io, "Anatomy of the Salesloft Breach"
- Salesforce Help, "OAuth 2.0 Web Server Flow for Web App Integration"
- Salesforce Help, "External Client Apps Overview" (Spring 2024 release)
- MITRE ATT&CK T1528, T1550.001, T1087.004
