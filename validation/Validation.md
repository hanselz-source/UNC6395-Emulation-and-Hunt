# Validation: UNC6395 / Salesloft Drift Emulation and Hunt

## 1. Scope

| Field | Value |
|---|---|
| Rules checked | 3 Sigma in `../detections/sigma/`, 1 KQL in `../detections/kql/` |
| Artifacts | `../emulation/` |
| Lab tenant | Salesforce Developer Edition, org `00Dg5000008v3PaEAI` |
| Lab app | External Client App `Drift_Integration`, consumer ID `888g5000000OC3G` |
| Lab user | One Developer Edition user, home broadband address |
| Validation window | 2026-04-26, 17:21 to 19:42 UTC |

The source address and the user's personal email are redacted in this file.
Both are still legible in the Login History screenshot. That is a known gap.

Every rule in the package targets a log source this tenant produces.
Rules that would need Salesforce Shield or an Entra ID tenant are not shipped here.
The techniques they would have covered are still documented in `../matrix/README.md`.

---

## 2. Evidence Classes

Only defender-side telemetry validates a rule.

| Class | Artifacts | Counts as evidence |
|---|---|---|
| Defender-side | Setup Audit Trail, Login History, System Overview API Usage tile | Yes |
| Attacker-side | `recon_burst.log`, `request_metadata.txt`, `verify_request.log` | No |

Defender-side artifacts are produced by the tenant whether or not the attacker cooperates.

Attacker-side artifacts are written by the emulation about itself.
`04_recon_burst.sh` writes `UA=truffleHog` into its own log because it was told to.
They prove the emulation ran and show the request shape a production rule must match.
They detect nothing.

A rule that correctly stays silent counts as a result. R2 is one.

---

## 3. Summary

| Rule | ATT&CK | Result | Evidence class | Basis |
|---|---|---|---|---|
| R1 | T1528 | **ALERTED** | defender-side | Setup Audit Trail, `consent_audit_trail.png`, 10:28:40 PDT |
| R2 | T1550.001 | **DID NOT ALERT**, correctly | defender-side | Login History, a human sign-in existed 29 minutes earlier |
| R3 | T1087.004 | **PARTIAL** | defender-side, coarse | API Usage tile confirms volume, but org-wide with no time window |

Two rules returned a decision against real tenant telemetry, in opposite directions.
One alerted on activity that warranted it. One stayed silent on activity that did not.
Results in both directions are a better signal than several alerts in one.

---

## 4. R1, T1528, Salesforce External Client App Consent

| Field | Value |
|---|---|
| Result | **ALERTED** |
| Sigma | `../detections/sigma/R1_T1528_salesforce_oauth_consent.yml` |
| Hypothesis | An External Client App is created, or its refresh token policy widened to Infinite |
| Evidence | `../emulation/salesforce/output/consent_audit_trail.png` |
| Evidence class | Defender-side |
| Production confidence | High on the policy change, medium on app creation |

### Rows Matched

| Setup Audit Trail row | Time (PDT) | Selection matched |
|---|---|---|
| "Created the External Client App OAuth Policies: Drift_Integration_oauthPlcy" | 10:28:14 | `selection_app_lifecycle` |
| "Generated the consumer key for the External Client App called Drift Integration with a consumer ID of 888g5000000OC3G" | 10:28:14 | `selection_app_lifecycle` |
| "Generated the consumer secret for the External Client App called Drift Integration" | 10:28:14 | `selection_app_lifecycle` |
| "Associated a new External Client App OAuth Policies called Drift_Integration_oauthPlcy" | 10:28:15 | `selection_app_lifecycle` |
| "Updated the External Client App OAuth Policies Drift_Integration_oauthPlcy: Changed Refresh Token Policy Type from SpecificLifetime to Infinite" | 10:28:40 | `selection_token_lifetime_change` |
| "Updated the External Client App OAuth Policies Drift_Integration_oauthPlcy: Cleared Refresh Token Validity Period, which was 8760 and is now empty" | 10:28:40 | `selection_token_lifetime_change` |
| 6x "A request was made to get the consumer secret for the external client app called External Client App Drift_Integration" | 10:45:41 to 10:45:42 | none, see below |

### The Unmatched Rows

The six consumer-secret reads at 10:45:41 match no rule block.
They are worth a rule of their own.
Repeated programmatic reads of an app's consumer secret are what an attacker with repo access does.
The Setup Audit Trail records them for free.

### Why the Infinite Policy Matters

The 10:28:40 PDT row is the most important line in this validation.
UNC6395's access model worked because Drift's refresh tokens stayed valid indefinitely.
Reproducing the Infinite policy makes the lab app match the real Drift posture.

### Tuning

Latency is roughly 30 seconds, the Setup Audit Trail UI refresh interval.
In production the equivalent event type is `ConnectedApplication`.

An admin onboarding any new SaaS integration trips this rule the first time.
Tune with a baseline list of approved app names.
Suppress the DevOps service account that runs Salesforce CLI.
The rule level is `medium` to reflect that.

### What It Does Not Do

The rule does not read OAuth scopes.
The Setup Audit Trail carries one free-text `Action` per row and no scope list.
Scopes live on `OAuthConfig.Scopes` on the `ExternalClientApplication` sObject.
Treat an alert here as the trigger for that lookup.

---

## 5. R2, T1550.001, OAuth Sign-In with No Preceding Human Sign-In

| Field | Value |
|---|---|
| Result | **DID NOT ALERT**, and that is correct |
| Sigma | `../detections/sigma/R2_T1550.001_oauth_signin_no_human_precursor.yml` |
| KQL | `../detections/kql/R2_T1550.001_serviceprincipal_no_human.kql` |
| Hypothesis | An app sign-in with no interactive sign-in for the same app in 24 hours |
| Evidence | `../emulation/salesforce/output/login_history_oauth.png` |
| Evidence class | Defender-side |

### The Rows

| Login time (PDT) | Login type | Status | Application |
|---|---|---|---|
| 10:21:29 | Application (browser) | Success | Browser |
| 10:50:55 | Remote Access 2.0 (OAuth) | Success | Drift Integration |
| 10:51:16 | Remote Access 2.0 (OAuth) | Failed: Invalid Nonce | Drift Integration |

The OAuth sign-in at 10:50:55 has an interactive sign-in 29 minutes before it.
R2 looks for OAuth sign-ins with no human sign-in in the prior 24 hours.
A precursor exists, so the rule does not alert.

This is a true negative. A rule that alerted here would be wrong.

### Why It Still Matters in Production

Victim tenants saw sign-ins from Drift tokens consented to months earlier.
When the actor reused those dormant tokens in August 2025, no human sign-in existed for that app in days or weeks.

That is the case R2 is built for.
The lab cannot reproduce it without a 24-hour wait between consent and token reuse.

### What the Lab Confirms

The rule reads the right rows.
The OAuth sign-in is captured with `Application Type = Remote Access 2.0` and `Application = Drift Integration`.
The precursor browser sign-in is captured too.

Both halves of the correlation are present and correctly typed.
Only the timing that would make it alert is absent.

The failed nonce row at 10:51:16 suits a different hypothesis: repeated OAuth attempts in quick succession from one source.
Worth a follow-on rule.

### On the Sigma File

Sigma has no correlation type for the absence of an event.
The YAML is the trigger half only and matches every successful service-principal sign-in on its own.
The `leftanti` join in the KQL is the rule. Do not deploy the YAML alone.

---

## 6. R3, T1087.004, High-Volume Salesforce Object Enumeration

| Field | Value |
|---|---|
| Result | **PARTIAL** |
| Sigma | `../detections/sigma/R3_T1087.004_salesforce_volume_enumeration.yml` |
| Hypothesis | More than 50 enumeration or SOQL calls from one app within 5 minutes |
| Evidence class | Defender-side, coarse |
| Production confidence | Medium |

### Evidence

| Artifact | Class | Shows |
|---|---|---|
| `system_overview_api_usage.png` | Defender-side | Org-level counter, 55 of 15,000 over 24 hours |
| `recon_burst.log` | Attacker-side | 51 queries in 31 seconds |
| `recon_burst_terminal.png` | Attacker-side | Terminal capture of the same |

### Why Partial

The API Usage tile is real defender-side evidence and corroborates the volume.
55 calls is 51 SOQL queries plus 3 flat REST calls plus 1 token exchange. The count is exactly right.

But the tile is missing two of the three things the rule needs.
It has no per-application attribution, so a burst from `Drift_Integration` looks identical to the same volume spread across every app.
It has no resolution finer than 24 hours, so a 5-minute window cannot be evaluated.

The per-app, per-window view is `recon_burst.log`, which is attacker-side.

### On the Burst Rate

The 51 queries ran 19:42:09 to 19:42:40 UTC, which is 31 seconds.
Against a threshold of 50 the burst clears by one event.

Extrapolating that rate across a full 5-minute window would put it far higher.
The emulation never sustained that rate, so the projection is not a result.

A threshold that a deliberately aggressive burst only just exceeds sits close to the edge.
Baseline it before trusting it.

### Tuning

The legacy Connected Apps OAuth Usage page is not exposed for External Client Apps here.
In production the right source is `ApiEvent` aggregated by `CONNECTED_APP_ID` over a 5-minute tumbling window.

Scheduled bulk integrations will trip this rule during their daily windows.
Tune with a per-app 30-day p95 of enumeration volume and alert on deviation, not on a fixed count.

---

## 7. Cross-Cutting Observations

- The free-tier substitutions are uneven. The Setup Audit Trail genuinely replaces `ConnectedApplication`. The API Usage tile is far coarser than `ApiEvent`.
- R1 and R2 both returned decisions against real tenant telemetry, in opposite directions. That is a stronger signal than several alerts in one direction.
- The Refresh Token Policy change at 10:28:40 PDT ties the lab posture to the real Drift posture. It is the most defensible artifact in the repo.
- R3's threshold is the weakest number in the package. It is a guess until measured against a baseline.

Roadmap: [`../README.md`](../README.md).
