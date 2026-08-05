# Sigma Detections, UNC6395 / Salesloft Drift Package

Three rules. Each one runs against a log source this Salesforce Developer Edition tenant actually produces.

## Rule Index

| ID | File | Hypothesis | Result |
|---|---|---|---|
| R1 | `R1_T1528_salesforce_oauth_consent.yml` | An External Client App is created, or its refresh token policy widened to Infinite | **ALERTED** on the Setup Audit Trail, `consent_audit_trail.png`, 10:28:40 PDT |
| R2 | `R2_T1550.001_oauth_signin_no_human_precursor.yml` | An app sign-in with no interactive sign-in for the same `AppId` in 24 hours | **DID NOT ALERT**, correctly. A human sign-in existed 29 minutes earlier |
| R3 | `R3_T1087.004_salesforce_volume_enumeration.yml` | More than 50 object enumeration or SOQL calls from one app within 5 minutes | **PARTIAL**. The API Usage tile confirms 55 calls, but org-wide over 24 hours |

Both outcomes count.
A rule that correctly stays silent is as much a result as one that alerts.

## Data Source Mapping

| Rule | Production source | Used in the lab |
|---|---|---|
| R1 | Event Monitoring `ConnectedApplication`, plus an sObject query for `OAuthConfig.Scopes` | Setup Audit Trail |
| R2 | Entra ID `AADServicePrincipalSignInLogs` joined to `SigninLogs`. Salesforce `LoginEvent.LoginType` | Login History |
| R3 | Event Monitoring `ApiEvent` grouped by `CONNECTED_APP_ID` | System Overview API Usage tile, org-level only |

## Checking the Rules

`sigma check detections/sigma/` reports 0 errors, 0 condition errors, 0 issues.

R3 is a correlation rule and Splunk renders it.
The Kusto backend does not implement correlations, which is why the KQL in `../kql/` is hand-written.

## Known Limits

**R3 is partial.** The API Usage tile confirms the 55-call volume, which is the right number. But it is org-wide and reports over 24 hours. The rule asks about one app in one 5-minute window and the tile cannot answer that. The per-app, per-window view exists only in `recon_burst.log`, which the attack script writes about itself and which therefore proves nothing.

**R3's threshold is an estimate.** The lab burst produced 51 events against a threshold of 50. It clears by one. Baseline against real traffic before deploying.

**R1 does not read OAuth scopes.** The Setup Audit Trail carries one free-text `Action` per row and no scope list. Scopes live on the `ExternalClientApplication` sObject. Treat an alert as the trigger for that lookup.

**R2's Sigma file is only the trigger half.** Sigma has no correlation type for the absence of an event, so the YAML matches every successful service-principal sign-in on its own. The anti-join is in `../kql/`.

## Next Steps

- Measure a baseline before trusting R3's threshold.
- Write a rule for the six consumer-secret reads at 10:45:41 PDT in `consent_audit_trail.png`. The Setup Audit Trail records them for free and no rule uses them.
