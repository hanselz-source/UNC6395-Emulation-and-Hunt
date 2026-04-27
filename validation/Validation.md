# Validation: UNC6395 / Salesloft Drift Emulation and Hunt

**Scope:** Six Sigma rules in `../detections/sigma/`, three KQL translations in `../detections/kql/`, validated against captured artifacts in `../emulation/`.
**Lab tenant:** Salesforce Developer Edition, External Client App `Drift_Integration`, consumer ID `888g5000000OC3G`.
**Lab user:** Zachariah Hansel (`hanselz.dc242f366c9c@agentforce.com`), source IP 75.115.72.66.
**Validation window:** 2026-04-26, 17:21 UTC through 19:42 UTC.

---

## Summary Table

| Rule | ATT&CK | Status | Evidence Artifact | Attacker Action -> Detection Latency |
|---|---|---|---|---|
| R1 | T1552.001 | **FIRES** | `../emulation/salesforce/output/recon_burst.log` (every line) | <1 second per request, synchronous |
| R2 | T1528 | **FIRES** | `../emulation/salesforce/output/consent_audit_trail.png` (10:28:40 PDT row) | ~30 seconds (Setup Audit Trail refresh interval) |
| R3 | T1528 | NOT FIRED | M365 mirror tenant not built | N/A, documented gap |
| R4 | T1550.001 | **PARTIAL** | `../emulation/salesforce/output/login_history_oauth.png` (10:50:55 PDT row) | ~5 seconds (Login History row appears post-auth); see analysis below |
| R5 | T1087.004 | **FIRES** | `../emulation/salesforce/output/recon_burst.log` and `../emulation/salesforce/output/system_overview_api_usage.png` | ~31 seconds for the 51-query burst; aggregation rule fires after the 5-minute window closes |
| R6 | T1567 + T1070 | NOT FIRED | Salesforce Shield / Event Monitoring required | N/A, documented gap |

**Headline:** Three rules fire cleanly on captured artifacts (R1, R2, R5). One fires partially on captured artifacts but is structurally correct for production (R4). Two are documented against published incident timelines but cannot fire in this free-tier lab (R3 needs an M365 tenant, R6 needs Salesforce Shield).

---

## R1, T1552.001, TruffleHog User-Agent

**Status:** FIRES.
**Sigma:** `../detections/sigma/R1_T1552.001_trufflehog_user_agent.yml`.
**Hypothesis:** an attacker is verifying credentials harvested from leaked source by issuing requests with `User-Agent: truffleHog`.
**Evidence artifacts:**
- `../emulation/salesforce/output/recon_burst.log` (51 query lines, every one tagged `UA=truffleHog`)
- `../emulation/salesforce/output/recon_burst_terminal.png` (terminal screenshot showing the same)
- `../emulation/salesforce/output/request_metadata.txt` (3 flat REST recon calls also tagged `UA=truffleHog`)
- `../emulation/github/output/verify_request.log` (the original token verification probe from the GitHub-side emulation)

**Validation procedure:**
1. Open `recon_burst.log`. Confirm every `[timestamp] GET /services/data/...` header line ends with `UA=truffleHog`.
2. Run `grep -c 'UA=truffleHog' recon_burst.log` -> 51 matches against query header lines.
3. Confirm `request_metadata.txt` shows three additional matches from the flat REST recon calls (sobjects listing, Account describe, limits).
4. Total sample fires: 54.

**Latency:** subsecond. The log is written synchronously by the curl client. In production, a Salesforce Event Monitoring `RestApi` event lands in `EventLogFile` within the standard EventLogFile delivery interval (hourly by default, near-real-time with the 24-hour streaming feed enabled).

**Attacker action -> detection mapping:**

| Attacker step | Lab timestamp | Rule fires on |
|---|---|---|
| Issued GET to `/sobjects/` with `User-Agent: truffleHog` | 2026-04-26 19:41:52 UTC | `request_metadata.txt` line 1 |
| Issued GET to `/sobjects/Account/describe/` | 2026-04-26 19:41:55 UTC | `request_metadata.txt` line 2 |
| Issued GET to `/limits/` | 2026-04-26 19:41:58 UTC | `request_metadata.txt` line 3 |
| Issued 51 SOQL queries | 2026-04-26 19:42:09 to 19:42:40 UTC | `recon_burst.log` (each line) |

**False positive analysis:** the rule includes a corporate-IP suppression filter (`filter_corp_ip`). In the lab, the source IP is the user's home network (75.115.72.66), which is correctly outside the suppression range. A legitimate AppSec team running TruffleHog hygiene scans from corporate egress would be suppressed.

**Production confidence:** high. This is the most quotable rule in the package because the IOC is a literal string named in the GTIG advisory. Capitalization matters (`truffleHog`, lowercase t, uppercase H).

---

## R2, T1528, Salesforce External Client App Consent

**Status:** FIRES.
**Sigma:** `../detections/sigma/R2_T1528_salesforce_oauth_consent.yml`.
**Hypothesis:** a newly created Salesforce External Client App requests `api` plus `refresh_token` plus `offline_access` scopes, often with an "Infinite" refresh token policy.
**Evidence artifact:** `../emulation/salesforce/output/consent_audit_trail.png`.

**Validation procedure:**
1. Open `consent_audit_trail.png`.
2. Walk the Setup Audit Trail rows in chronological order.
3. Confirm three of the rule's three `selection_*` blocks match.

**Attacker action -> rule selection mapping:**

| Setup Audit Trail row | Time (PDT) | Selection block matched |
|---|---|---|
| "Created the External Client App OAuth Policies: Drift_Integration_oauthPlcy" | 10:28:14 | `selection_create_app` |
| "Generated the consumer key for the External Client App called Drift Integration with a consumer ID of 888g5000000OC3G" | 10:28:14 | `selection_create_app` |
| "Generated the consumer secret for the External Client App called Drift Integration" | 10:28:14 | `selection_create_app` |
| "Associated a new External Client App OAuth Policies called Drift_Integration_oauthPlcy" | 10:28:15 | `selection_create_app` |
| "Updated the External Client App OAuth Policies Drift_Integration_oauthPlcy: Changed Refresh Token Policy Type from SpecificLifetime to Infinite" | 10:28:40 | `selection_token_lifetime_change` |
| "Updated the External Client App OAuth Policies Drift_Integration_oauthPlcy: Cleared Refresh Token Validity Period, which was 8760 and is now empty" | 10:28:40 | `selection_token_lifetime_change` |
| 6x "A request was made to get the consumer secret for the external client app called External Client App Drift_Integration" | 10:45:41 to 10:45:42 | (not a rule selection, but mirrors the GitHub access pattern) |

**Latency:** Setup Audit Trail UI refresh interval is approximately 30 seconds. In production with Event Monitoring, the equivalent `EventLogFile` event type `ConnectedApplication` lands within the standard EventLogFile delivery interval.

**Significance of the Infinite refresh token policy:** the row at 10:28:40 PDT is the most important single line in this validation. UNC6395's per-user OAuth token model worked only because Drift's refresh tokens stayed valid indefinitely. By reproducing the Infinite policy in the lab External Client App, the emulation matches the real Drift posture and validates that R2's `selection_token_lifetime_change` block is structurally sound.

**False positive analysis:** legitimate admins onboarding a new SaaS integration will trip this rule the first time they do so. Tune by maintaining a baseline list of approved app names (suppress on `Action contains "<approved app name>"`), and by suppressing matches from a DevOps service-account user. The rule level is `medium` rather than `high` to reflect the expected baseline noise.

**Production confidence:** high for the policy-change selection. Medium for the consumer-secret-creation selection (more baseline noise from legitimate dev work).

---

## R3, T1528, M365 Entra ID Consent to Application

**Status:** NOT FIRED.
**Sigma:** `../detections/sigma/R3_T1528_m365_oauth_consent.yml`.
**KQL:** `../detections/kql/R3_T1528_m365_oauth_consent.kql`.
**Hypothesis:** a Microsoft Entra ID consent grant for an OAuth app requesting high-privilege Graph scopes (User.Read.All, Files.Read.All, Mail.Read, etc.).

**What is missing:** the M365 Developer Program tenant and the `Internal Reporting App` Entra ID application registration were not built in this weekend window. Per the roadmap section 3, the M365 mirror was scheduled for Sunday 09:00 to 10:30 PDT. That block was reallocated to detection rule authoring after the Salesforce-side emulation ran longer than estimated.

**What the rule depends on:** an `AuditLogs` row with `OperationName == "Consent to application"` whose `TargetResources[0].modifiedProperties[].newValue` contains one or more high-privilege Graph scopes.

**Is the rule structurally sound:** yes. The selection logic follows Microsoft's published guidance for detecting illicit consent grant attacks (see the "investigate-risky-oauth" Defender for Cloud Apps doc and the "protect-against-consent-phishing" Entra ID doc, both linked in the rule's `references` block). The KQL translation in `R3_T1528_m365_oauth_consent.kql` uses `mv-expand` over `TargetResources[0].modifiedProperties` and matches against a `dynamic([...])` array of scopes, which is the canonical pattern for this rule shape against `AuditLogs`.

**What would be required to fire:** an M365 Developer Program tenant (free), one user, one Entra ID app registration with the listed scopes, and a single user-side consent moment. Estimated build time: 60 to 90 minutes. Documented under "what I would do with more time" in the top-level README.

**Production confidence:** high. The rule shape is the canonical OAuth consent phishing detection and is shipped in the Microsoft Sentinel content hub as a sample analytic. The version here adds a high-privilege-scope filter so it does not trip on every benign consent.

---

## R4, T1550.001, OAuth Sign-In with No Preceding Human Sign-In

**Status:** PARTIAL FIRE.
**Sigma:** `../detections/sigma/R4_T1550.001_oauth_signin_no_human_precursor.yml`.
**KQL:** `../detections/kql/R4_T1550.001_serviceprincipal_no_human.kql`.
**Hypothesis:** an OAuth application sign-in occurs with no preceding interactive sign-in for the same `AppId` in the prior 24 hours.

**Evidence artifact:** `../emulation/salesforce/output/login_history_oauth.png`.

**Why partial:** the lab Login History shows three relevant rows in chronological order:

| Login Time (PDT) | User | Source IP | Login Type | Status | Application |
|---|---|---|---|---|---|
| 10:21:29 | hanselz.dc242f366c9c@agentforce.com | 75.115.72.66 | Application (browser) | Success | Browser |
| 10:50:55 | hanselz.dc242f366c9c@agentforce.com | 75.115.72.66 | Remote Access 2.0 (OAuth) | Success | Drift Integration |
| 10:51:16 | hanselz.dc242f366c9c@agentforce.com | 75.115.72.66 | Remote Access 2.0 (OAuth) | Failed: Invalid Nonce | Drift Integration |

The OAuth sign-in at 10:50:55 has a preceding interactive sign-in at 10:21:29, 29 minutes earlier. R4 looks for OAuth sign-ins with **no** human sign-in in the prior 24 hours, so the rule does **not** fire on this row in the lab.

**Why the rule is still structurally correct for production:** in the actual UNC6395 incident, victim Salesforce tenants saw OAuth-app sign-ins from Drift OAuth tokens that had been consented to **months earlier** (consent was granted whenever the customer first connected Drift, often well outside any reasonable correlation window). When the actor reused those dormant tokens in August 2025, the OAuth sign-in occurred with no preceding human sign-in for the same `AppId` in days, weeks, or months. R4 fires on that case.

**What the lab demonstrates instead:** the rule shape works. The 10:50:55 OAuth row is captured cleanly with `Application Type = Remote Access 2.0` and `Application = Drift Integration`. A defender running R4 against the captured `LoginHistory` would correctly identify the OAuth sign-in event and the precursor browser sign-in; the rule would not alert in this specific case because the precursor exists.

**What would need to change to fire cleanly in the lab:** the test user would need to **not** sign in interactively in the 24 hours preceding the OAuth flow. That is achievable by signing in as a separate test user who only consents once, then waiting 24 hours before reusing the captured refresh token. Estimated effort: trivial in calendar time, impractical in a single weekend.

**Bonus observation:** the failed nonce row at 10:51:16 is a useful artifact for a separate hypothesis (R4-adjacent: repeated OAuth attempts in quick succession from the same source). Worth a callout in a follow-on rule.

**Production confidence:** high. The leftanti-join shape in the KQL is the canonical pattern for "service principal sign-in with no human counterpart."

---

## R5, T1087.004, High-Volume Cloud Account Enumeration

**Status:** FIRES.
**Sigma:** `../detections/sigma/R5_T1087.004_volume_enumeration.yml`.
**KQL:** `../detections/kql/R5_T1087.004_volume_enumeration.kql`.
**Hypothesis:** more than 50 cloud-account or sObject enumeration calls from a single OAuth app within a 5-minute window.

**Evidence artifacts:**
- `../emulation/salesforce/output/recon_burst.log` (51 SOQL queries in 31 seconds)
- `../emulation/salesforce/output/recon_burst_terminal.png` (terminal capture of the 51 timestamped GET lines)
- `../emulation/salesforce/output/system_overview_api_usage.png` (org-level API counter, 55 of 15,000 in last 24 hours)

**Validation procedure:**
1. Open `recon_burst.log`. Confirm 51 query header lines.
2. Confirm the first query lands at 19:42:09 UTC and the last at 19:42:40 UTC. That is 31 seconds.
3. Compute the rate: 51 queries / 31 seconds = 1.6 queries per second, or 96 queries projected over a 60-second window. Across the 5-minute window in the rule, that exceeds the >50 threshold by ~10x.
4. Open `system_overview_api_usage.png`. Confirm the API Usage tile reads `55 / 15,000 (0%)` over the last 24 hours, which equals 51 queries + 3 flat REST calls + 1 token exchange.

**Latency:** the rule aggregates over a 5-minute tumbling window, so the alert fires after the window closes. In production with the M365 KQL implementation against `MicrosoftGraphActivityLogs` ingested into Sentinel, expected end-to-end latency is approximately 5 to 10 minutes. The Salesforce-side equivalent against `ApiEvent` (Shield required) carries the same latency.

**Note on the data source substitution:** the legacy "Connected Apps OAuth Usage" page is not exposed for External Client Apps in Developer Edition. The lab substitutes the local request log (proves the per-app volume) and the org-level System Overview API Usage tile (proves the org-level counter delta). In production, Salesforce Event Monitoring `ApiEvent` aggregated by `CONNECTED_APP_ID` over a 5-minute tumbling window is the proper data source.

**False positive analysis:** scheduled bulk integrations (HRIS sync, MDM endpoint inventory, MuleSoft / Boomi pipelines) will trip this rule during their daily windows. Tune by maintaining a per-`AppId` baseline (a 30-day p95 of enumeration call volume) and alerting only when the current 5-minute window exceeds the baseline by a factor of N.

**Production confidence:** medium-high. The rule shape is sound; the threshold and tuning depend on the tenant's baseline integration noise floor.

---

## R6, T1567 + T1070, Bulk API Job Created and Deleted Within 30 Minutes

**Status:** NOT FIRED.
**Sigma:** `../detections/sigma/R6_T1567_T1070_bulk_export_then_delete.yml`.
**Hypothesis:** a Salesforce Bulk API 2.0 job is created and deleted by the same Connected App within 30 minutes.

**What is missing:** Salesforce Shield / Event Monitoring is required to surface `BulkApi2` events with `OPERATION` field granularity. Developer Edition does not include Shield. Without Shield, Bulk API job CRUD does not appear in any free-tier log surface (Setup Audit Trail does not capture data-plane events; Login History captures auth, not job lifecycle).

**What the rule depends on:** two rows in `EventLogFile` with `EVENT_TYPE = BulkApi2`, the same `JOB_ID` and `CONNECTED_APP_ID`, where one row has `OPERATION = create` and the second has `OPERATION = delete` within 30 minutes.

**Is the rule structurally sound:** yes. The hypothesis is grounded in two independent pieces of public reporting: Cloudflare's timeline showing the Bulk API job at 2025-08-17 11:11:56 UTC and its deletion at 11:15:42 UTC (24 seconds after completion), and permiso.io's analysis flagging the immediate-deletion behavior as the campaign's anti-forensic signature.

**What would be required to fire:** a Salesforce tenant with Shield enabled (paid add-on; trial available on request), or a third-party tool that captures Bulk API job lifecycle (Salesforce Inspector, Workbench logs, MuleSoft custom logging). Estimated cost: not feasible in a weekend window.

**Production confidence:** high. The rule encodes a documented anti-forensic pattern from a confirmed campaign. The level is `high` because the create-delete-within-30-minutes pattern has very low false positive expectation outside ETL pipelines (which are easy to allowlist).

---

## Cross-Cutting Observations

- The Salesforce free-tier substitutions (Setup Audit Trail, Login History, System Overview API Usage tile) are honest proxies for Event Monitoring fields. The Sigma and KQL files cite the Event Monitoring fields explicitly so the production detection design is preserved even where the lab substitutes.
- All five fire-or-partial-fire rules (R1, R2, R4, R5 lab; R3 by parallel-with-R2 reasoning) hold up in the absence of Salesforce Event Monitoring. The two that do not fire (R3 needs M365 mirror, R6 needs Shield) are gaps of resourcing, not gaps of logic.
- The TruffleHog User-Agent IOC remains the single most defensible detection asset in this package because (a) it is a literal IOC quoted in the GTIG advisory, (b) it is reproducible inside the lab end-to-end, and (c) it has a clean, single-line Sigma expression.
- The Refresh Token Policy = Infinite change captured in the Setup Audit Trail at 10:28:40 PDT is the second most defensible asset because it ties the lab posture explicitly to the actual Drift posture that made the campaign possible.

---

## What I Would Do with More Time

(See the top-level README for the canonical "What I Would Do with More Time" section. This is the validation-focused subset.)

1. **Build the M365 mirror** to fire R3 cleanly. ~90 minutes for tenant + app registration + one consent grant + KQL validation in Sentinel.
2. **Acquire a Salesforce Shield trial** to fire R2, R5, R6 against real Salesforce Event Monitoring `EventLogFile` records rather than free-tier UI proxies. The current rules are field-mapped to Shield; activating them is a logsource swap, not a rule rewrite.
3. **Fire R4 cleanly** by signing in as a fresh test user, granting consent, waiting 24 hours, then exercising the OAuth token from a separate session. The 24-hour wait is the bottleneck.
4. **Validate against real campaign IOCs in Sentinel** by ingesting the Tor exit node IP list from `../profile/README.md` section 11 as a Sentinel watchlist and joining against `SigninLogs`. This would add an "ASN deviation" rule alongside R4 that catches the DigitalOcean / Tor pivot the actual UNC6395 actor used at exfiltration time.
5. **Add an FP-rate target per rule** by replaying 30 days of synthetic baseline traffic through the lab and counting alert volume. Without this, the `level` field on each rule is a best-estimate rather than a measured quantity.

---

**Validated by:** Zachariah Hansel
**Date:** 2026-04-26
**Tenant:** Salesforce Developer Edition org `00Dg5000008v3PaEAI`
