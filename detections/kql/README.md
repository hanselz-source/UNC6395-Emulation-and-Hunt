# KQL Translations, UNC6395 / Salesloft Drift Package

KQL ("Kusto Query Language") translations of the three Sigma rules whose data sources live in Microsoft Sentinel. R3 and R5 also include commented Salesforce-side equivalents because the same hypothesis applies on both platforms (the lab proves the detection logic generalizes).

| File | Sigma Source | Sentinel Table | Notes |
|---|---|---|---|
| `R3_T1528_m365_oauth_consent.kql` | `R3_T1528_m365_oauth_consent.yml` | `AuditLogs` | Filters on `OperationName == "Consent to application"` and high-privilege Graph scopes. Validate inside the Sentinel query editor against a captured consent event. |
| `R4_T1550.001_serviceprincipal_no_human.kql` | `R4_T1550.001_oauth_signin_no_human_precursor.yml` | `AADServicePrincipalSignInLogs` joined to `SigninLogs` | Uses `leftanti` join to find service-principal sign-ins for AppIds with no human counterpart in the last 24h. |
| `R5_T1087.004_volume_enumeration.kql` | `R5_T1087.004_volume_enumeration.yml` | `MicrosoftGraphActivityLogs` | Bins Graph enumeration calls into 5-minute buckets and alerts on >50 per AppId. Includes a commented Salesforce Event Monitoring equivalent. |

## Why Only Three KQL Files

R1, R2, and R6 target Salesforce-native data sources (Salesforce Event Monitoring, Setup Audit Trail, BulkApi2 event type). KQL is Microsoft Sentinel's query language. The Salesforce-side rules would translate to SOQL or to a Salesforce Event Monitoring console query, not KQL. The roadmap deliberately scopes KQL to R3, R4, R5 for this reason.

If the package needed to ingest Salesforce Event Monitoring into Sentinel (via the Salesforce data connector or a custom Logic App), R1, R2, R6 would gain KQL translations. That extension is documented under "what I would do with more time" in the top-level README.

## Validation Approach

For each KQL file:

1. Open Microsoft Sentinel, paste the query into the Logs blade.
2. Run against the time range covering the corresponding emulation event.
3. Confirm the expected row(s) come back.
4. Screenshot the results pane plus the surrounding context (table name, time range), crop tight, save in `../../validation/`.

R3 and R5 should return clean results once the M365 mirror is built. R4 will return service-principal sign-ins from any tenant; the leftanti-join filter is what isolates the suspicious ones.
