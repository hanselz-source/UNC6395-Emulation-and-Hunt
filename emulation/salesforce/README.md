# Emulation 2 + 3: T1528 OAuth Consent + T1550.001 Token Replay (Salesforce External Client App)

> **MITRE:** T1528 (Steal Application Access Token), T1550.001 (Use Alternate Auth Material: App Access Token), T1087.004 (Account Discovery: Cloud Account)
> **Maps to detections:** R2 (Salesforce-side OAuth consent), R4 (service-principal sign-in with no preceding human sign-in), R5 (volume-based cloud account enumeration), R1 (TruffleHog User-Agent on a verification probe)

## Why This Exists

UNC6395 obtained Drift's OAuth refresh tokens upstream, then used them as valid app credentials against ~700 downstream Salesforce tenants. From the victim side this looked like Drift calling Drift's API. The high-signal anomalies are the consent grant itself (R2, R3), the service-principal sign-in with no preceding human auth for the same `AppId` (R4), and the volume signature of the schema-then-bulk recon burst (R5). Cloudflare's timeline (`profile/README.md` section 5) anchors all three.

This emulation reproduces the downstream half of the kill chain inside an owned Salesforce Developer Edition tenant. We are not breaching a real third-party SaaS vendor. The "Drift" app in this lab is named `Drift_Integration` and lives entirely in the test org. The captured tokens never leave the lab.

**Note on framework:** Salesforce Developer Edition orgs created in 2024 and later default to the **External Client App** framework. The legacy Connected App framework is no longer the default for new dev orgs. This emulation uses External Client App throughout. The detection logic is identical because Salesforce surfaces both frameworks in `LoginHistory` (`Application Type == Remote Access 2.0`) and Setup Audit Trail. Production Sigma rules cite both `ConnectedApplication` and `ExternalClientApplication` sObject lookups.

## Hypothesis

> An attacker with stolen OAuth credentials for a pre-approved External Client App authenticates against the customer Salesforce tenant via the OAuth Web Server Flow, then issues a recon burst (object enumeration, COUNT probes, schema describes) followed by progressively wider SOQL pulls. The volume signature of the recon burst, the service-principal sign-in with no preceding human sign-in for the same AppId, and the use of TruffleHog as the User-Agent on at least one verification probe combine to a high-confidence detection cluster.

## Scope and Limitations

- Salesforce Developer Edition does not include Event Monitoring (Shield). The lab uses **Setup Audit Trail**, **Login History**, and the **System Overview API Usage tile** as honest free-tier proxies. The Sigma rules in `../detections/sigma/` cite Event Monitoring fields (`USER_AGENT`, `URI`, `CLIENT_IP`, `EVENT_TYPE`) explicitly so the production detection design is preserved.
- The legacy "Connected Apps OAuth Usage" page and its "OAuth and OpenID Connect Usage" successor are not exposed for External Client Apps in the free-tier dev org. R5 evidence is anchored to the captured client-side request log (`output/recon_burst.log`) and the org-level API counter (`output/system_overview_api_usage.png`) as substitutes. Production rule field-maps to Salesforce Event Monitoring `ApiEvent` aggregated by `CONNECTED_APP_ID` over a tumbling 5-minute window.
- `User-Agent: truffleHog` appears on every request crafted by `scripts/04_recon_burst.sh` and `scripts/05_describe_and_sobjects.sh`. Setup Audit Trail does not surface User-Agent at all, so R1 is anchored to the local request log with the production data source noted as Salesforce Event Monitoring `RestApi.USER_AGENT`.
- The External Client App is configured with the same OAuth scope set Drift requested (`api`, `refresh_token`, `offline_access`), the same callback URL pattern (`http://localhost:8080/callback`), and a **Refresh Token Policy of Infinite**, which mirrors Drift's actual posture and is the entire reason dormant Drift tokens stayed weaponizable across the August 2025 campaign.

## Folder Layout

```
emulation/salesforce/
  README.md                         this file
  .gitignore                        excludes runtime tokens
  keys/
    consumer_key                    External Client App OAuth client_id
    consumer_secret                 External Client App OAuth client_secret (rotate after lab)
    access_token                    captured at runtime, gitignored
    refresh_token                   captured at runtime, gitignored
    instance_url                    captured at runtime, gitignored
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
    login_history_oauth.png         Login History screenshot, OAuth + interactive rows (T1550.001 + R4)
    recon_burst_terminal.png        terminal screenshot of recon_burst.log, 51 GET lines with UA=truffleHog (R1 + R5)
    system_overview_api_usage.png   API Usage tile, 55/15000 daily counter post-burst (R5 volume substitute)
```

## Walkthrough

### 1. Run the OAuth Web Server Flow

```
bash scripts/01_oauth_authcode.sh
# open the printed URL, sign in as the test user, approve consent
# the browser will redirect to http://localhost:8080/callback?code=<AUTH_CODE>
# copy the value of code= (everything between code= and the next & or end of URL)
bash scripts/02_exchange_code.sh '<AUTH_CODE>'
```

Auth codes expire in ~10 minutes. `02_exchange_code.sh` will write `keys/access_token`, `keys/refresh_token`, and `keys/instance_url`, all `chmod 600`.

If you already have a working refresh token, skip 01 and 02 and run `bash scripts/03_refresh_access_token.sh` to mint a fresh access token. You will need to drop the existing `refresh_token` and `instance_url` into `keys/` first.

**zsh gotcha:** the access token contains `!`, which triggers history expansion. Single-quote the bearer header (`-H 'Authorization: Bearer 00Dg...'`) or use `setopt no_bang_hist` for the session. Backslash-escaping works but single quotes are cleaner.

### 2. Capture T1528 evidence (consent + login)

After step 1, in the Salesforce UI:

1. Setup -> Quick Find -> "View Setup Audit Trail". Filter by your test user. The full External Client App lifecycle is visible: creation, OAuth policy binding, consumer key/secret generation, refresh token policy change. Save as `output/consent_audit_trail.png`.
2. Setup -> Quick Find -> "Login History". Filter on the test user. Crop to the rows showing the browser interactive login and the OAuth `Remote Access 2.0` rows (Application column = `Drift Integration`). Save as `output/login_history_oauth.png`.

### 3. Run the recon burst (T1087.004 / R5)

```
bash scripts/05_describe_and_sobjects.sh
bash scripts/04_recon_burst.sh
```

`04` issues 51 SOQL queries: 5 COUNT probes across Account, Contact, User, Case, Opportunity, then 5 passes of (3 objects x 3 LIMIT clauses) progressive pulls, then 1 detailed User enumeration mirroring Cloudflare's 2025-08-14 11:09:21 query. Every request carries `User-Agent: truffleHog`. `05` adds the `/sobjects/`, `/describe/`, and `/limits/` calls that mirror Cloudflare's 2025-08-12 and 2025-08-13 entries.

Total post-burst should sit comfortably above R5's >50-in-5-minutes threshold. Validation run hit 51 queries in 31 seconds, ~99x the threshold rate.

### 4. Capture R5 evidence (substitute for OAuth Usage page)

The legacy "Connected Apps OAuth Usage" page is not exposed for External Client Apps in Developer Edition. Two substitutes:

1. Open a terminal in `output/`, run `grep '^\[' recon_burst.log | head -55`, screenshot the pane. Save as `output/recon_burst_terminal.png`. This is the volume signature, 51 timestamped queries with `UA=truffleHog` visible on each line.
2. Setup -> Quick Find -> "System Overview". Crop to the API Usage tile. Save as `output/system_overview_api_usage.png`. The validation run shows `55 / 15,000 (0%)`, which is 51 queries + 3 flat REST calls + 1 token exchange.

### 5. Commit hygiene

`git status` should show no token files. The `.gitignore` excludes `keys/access_token`, `keys/refresh_token`, `keys/instance_url`, and any `*.token` / `*token.txt`. Before `git commit`, run:

```
git diff --cached | grep -E '00Dg|5Aep|AQEAQE|aPrxd|888g5000000OC3G'
```

Anything that hits, unstage. The External Client App `consumer_secret` and `consumer_key` are committed in `keys/`; rotate the External Client App secret in Salesforce after the package is graded (Setup -> External Client App Manager -> Drift_Integration -> Manage Consumer Details -> Reset).

## Artifacts Captured

| File | What it shows |
|---|---|
| `output/recon_burst.log` | 51 SOQL queries with UTC timestamps, the User-Agent header, and the full response body. R1 IOC + R5 volume signal |
| `output/recon_burst_terminal.png` | Terminal screenshot of the 51 timestamped GET lines from `recon_burst.log`, every line showing `UA=truffleHog`. R1 IOC + R5 volume signature in one frame |
| `output/system_overview_api_usage.png` | API Usage tile from System Overview, `55 / 15,000` API requests over the last 24 hours. Org-level proxy for the missing Connected Apps OAuth Usage page (R5) |
| `output/sobjects_listing.json` | Object enumeration response, 1330 sObjects, mirrors Cloudflare 2025-08-12 22:14:09 entry |
| `output/account_describe.json` | Schema describe response, 70 Account fields, mirrors Cloudflare 2025-08-13 19:33:07 entry |
| `output/limits.json` | Limits endpoint response (`DailyApiRequests: 14998/15000` pre-burst), mirrors Cloudflare 2025-08-14 11:09:22 entry |
| `output/consent_audit_trail.png` | Setup Audit Trail showing full External Client App lifecycle for `Drift_Integration`. T1528 evidence including the Refresh Token Policy change to Infinite |
| `output/login_history_oauth.png` | Login History showing browser interactive sign-in at 10:21:29 PDT, OAuth Drift Integration success at 10:50:55 PDT, failed nonce retry at 10:51:16 PDT. T1550.001 + R4 evidence in one frame |
| `output/request_metadata.txt` | UTC timestamps for the three flat REST recon calls plus instance URL and consumer ID |

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

## Detection Notes (feeds into R2, R4, R5)

- **R2 (T1528, Salesforce side):** Setup Audit Trail row "Generated the consumer secret for the External Client App" or "Updated External Client App OAuth Policies... Refresh Token Policy Type" within the last N hours, where the External Client App requests `api` + `refresh_token` scopes. Lab uses Setup Audit Trail directly. Production rule cites Salesforce Event Monitoring `EventLogFile` event type `LoginAs` and a JOIN against the `ConnectedApplication` and `ExternalClientApplication` sObjects.
- **R4 (T1550.001 / T1078.004):** Login History row with `Application Type == Remote Access 2.0` (OAuth) where the same `UserId` has no `Application Type == Application` (interactive browser) row in the prior 24 hours. The lab fires this on a single OAuth login because the test user's prior interactive sign-in was 29 minutes earlier, well inside the 24-hour window. In a real victim tenant, the absence of a preceding human sign-in is the detection. Production rule field-maps to `LoginEvent.LoginType == "Remote Access 2.0"` plus the absence of a recent `LoginEvent.LoginType == "Application"`.
- **R5 (T1087.004 / T1213.006):** Connected/External Client App SOQL call count >50 within a 5-minute window for a single app. The lab fires this from the `recon_burst_terminal.png` (client-side capture of 51 queries in 31 seconds) and the `system_overview_api_usage.png` (55-call org-level counter delta). Production rule field-maps to Salesforce Event Monitoring `ApiEvent` aggregated by `CONNECTED_APP_ID` over a tumbling 5-minute window. The free-tier substitution is documented as a known gap in `06 Validation.md`.
- **R1 (T1552.001):** request with `User-Agent` matching `truffleHog`. The lab captures the request locally because Setup Audit Trail does not surface User-Agent. Production rule field-maps to `RestApi.USER_AGENT == "truffleHog"`. Capitalization matters: lowercase t, uppercase H.
- False positives: legitimate admins testing newly created External Client Apps, security teams running TruffleHog for credential hygiene against their own APIs, scheduled bulk integrations during their daily window. Tune by tying R5 to External Client Apps with no prior 30-day baseline and R1 to OAuth-token-bearing requests originating from non-corporate egress.

## Notes on the External Client App

- Name in lab: `Drift_Integration`. Consumer ID `888g5000000OC3G`.
- OAuth scopes: `api`, `refresh_token`, `offline_access`. Same as Drift.
- Callback URL: `http://localhost:8080/callback`. Salesforce rejects `localhost:8080` without the scheme.
- **Refresh Token Policy: Infinite** (changed from the SpecificLifetime default during setup, visible at 10:28:40 PDT in `consent_audit_trail.png`). This mirrors Drift's actual posture and is why dormant Drift tokens stayed weaponizable across the entire March-to-August 2025 campaign window. Mention this explicitly in the threat profile.
- The `consumer_secret` in `keys/consumer_secret` is the live secret for this lab External Client App. It was retrieved 6 times during testing (visible at 10:45:41 to 10:45:42 PDT in `consent_audit_trail.png`), mirroring how an attacker with GitHub access would pull the same secret repeatedly. After grading, rotate the secret via Setup -> External Client App Manager -> Drift_Integration -> Manage Consumer Details -> Reset.
- Salesforce Developer Edition orgs created in 2024+ default to the External Client App framework. The legacy Connected App framework is still supported but no longer the default. Both surface identically in `LoginHistory.Application` and Setup Audit Trail; production detection rules should query both `ConnectedApplication` and `ExternalClientApplication` sObjects.

## References

- GTIG, "Widespread Data Theft Targets Salesforce Instances via Salesloft Drift," August 2025
- Cloudflare, "The impact of the Salesloft Drift breach on Cloudflare and our customers," August 2025 (timeline entries 2025-08-09 11:51:13 through 2025-08-17 11:15:42)
- permiso.io, "Anatomy of the Salesloft Breach"
- Salesforce Help, "OAuth 2.0 Web Server Flow for Web App Integration"
- Salesforce Help, "External Client Apps Overview" (Spring 2024 release)
- MITRE ATT&CK T1528, T1550.001, T1087.004
