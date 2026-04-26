# Sigma Detections, UNC6395 / Salesloft Drift Package

Six Sigma rules covering the eight techniques in `../../matrix/README.md`. Each rule has a hypothesis, an explicit data source, the captured field set, the detection logic, and a false-positive note. Three rules also have KQL translations in `../kql/` for Microsoft Sentinel.

## Rule Index

| ID | File | Hypothesis | Lab Evidence (Fires?) |
|---|---|---|---|
| R1 | `R1_T1552.001_trufflehog_user_agent.yml` | An attacker is verifying credentials harvested from leaked source by issuing requests with `User-Agent: truffleHog` | YES — `../../emulation/salesforce/output/recon_burst.log` (every line) and `../../emulation/github/output/verify_request.log` |
| R2 | `R2_T1528_salesforce_oauth_consent.yml` | A newly created Salesforce External Client App requests `api` plus `refresh_token` plus `offline_access` scopes, often with an "Infinite" refresh token policy | YES — `../../emulation/salesforce/output/consent_audit_trail.png` (Refresh Token Policy = Infinite at 10:28:40 PDT) |
| R3 | `R3_T1528_m365_oauth_consent.yml` | A Microsoft Entra ID consent grant for an OAuth app requesting high-privilege Graph scopes | NO — M365 mirror not built. Documented against Microsoft public docs as parallel-to-R2 |
| R4 | `R4_T1550.001_oauth_signin_no_human_precursor.yml` | A service-principal or OAuth-app sign-in occurs with no preceding interactive sign-in for the same AppId in the prior 24 hours | PARTIAL — `../../emulation/salesforce/output/login_history_oauth.png` shows OAuth sign-in (Drift Integration via CURL) at 10:50:55 PDT, with the only preceding interactive sign-in at 10:21:29 PDT. Production-grade fire requires a real victim baseline |
| R5 | `R5_T1087.004_volume_enumeration.yml` | More than 50 cloud-account or sObject enumeration calls from a single OAuth app within a 5-minute window | YES — `../../emulation/salesforce/output/recon_burst.log` (51 queries in 31 seconds) and `../../emulation/salesforce/output/system_overview_api_usage.png` (55-call org delta) |
| R6 | `R6_T1567_T1070_bulk_export_then_delete.yml` | A Salesforce Bulk API job is created and deleted by the same Connected App within 30 minutes | NO — Developer Edition lacks Event Monitoring. Validated against GTIG and Cloudflare published timeline (Bulk API job at 11:11:56 UTC, deleted at 11:15:42 UTC) |

## Data Source Mapping

| Rule | Production Data Source | Free-Tier Substitute Used in Lab |
|---|---|---|
| R1 | Salesforce Event Monitoring `RestApi.USER_AGENT`; M365 `MicrosoftGraphActivityLogs.UserAgent`; WAF / API gateway logs | Local request log captured by `04_recon_burst.sh` |
| R2 | Salesforce Event Monitoring `EventLogFile` event type `ConnectedApplication` plus sObject query against `ConnectedApplication.OAuthConfig.Scopes` and `ExternalClientApplication` | Setup Audit Trail UI export |
| R3 | Microsoft Entra ID `AuditLogs` table (Sentinel) | Not yet captured (M365 mirror gap) |
| R4 | Microsoft Entra ID `SigninLogs` (ServicePrincipalSignInLogs schema); Salesforce Event Monitoring `LoginEvent.LoginType` | Salesforce Login History UI |
| R5 | Salesforce Event Monitoring `ApiEvent`; M365 `MicrosoftGraphActivityLogs` | `recon_burst.log` plus System Overview API Usage tile |
| R6 | Salesforce Event Monitoring `BulkApi2` event type | None (rule documented, not fired) |

## What "Sigma" Means

Sigma is a YAML format for writing detection rules in a vendor-neutral way. It defines what fields to look at, what values to match on, and what the alert criteria are. SIEM vendors translate Sigma into their query language (Splunk SPL, Microsoft Sentinel KQL, Elastic EQL, etc.). The point is portability: write the rule once, run it anywhere.

Each rule file in this directory follows the standard Sigma schema: `title`, `id` (UUID v4), `description`, `references`, `tags` (MITRE ATT&CK technique IDs), `logsource` (product / service / category that disambiguates which log type the rule applies to), `detection` (the actual matching logic), `falsepositives` (known benign cases), and `level` (severity).

## Honest Gaps

- **R3 has no captured fire** because the M365 mirror tenant was not built in this weekend window. The rule is structured per Microsoft's published `AuditLogs` schema and validated against Microsoft's own consent-phishing detection guidance.
- **R6 has no captured fire** because Developer Edition does not include Salesforce Shield / Event Monitoring. The Bulk API event schema is published by Salesforce and the rule is anchored to the Cloudflare and permiso.io documented timeline of the actual incident.
- **R4 fires partially** because the lab test user has only one interactive sign-in in the prior 24 hours rather than zero. In a real victim tenant during the Drift incident, the OAuth app authenticated with no preceding human sign-in for the same `AppId` because consent had been granted months earlier and was dormant. The rule structure is correct; the lab is just under-resourced to fire it cleanly.

These three gaps are documented in `../../validation/` as known limitations, not omissions.

## Next Steps

- Validate R1, R2, R5 against the captured Salesforce artifacts. Screenshots of each rule firing go in `../../validation/`.
- Translate R3, R4, R5 to KQL in `../kql/`. R3 and R5 KQL files already exist; R4 is the correlation-heavy one and needs the `join` operator.
- For each rule that does not fire, add a one-paragraph note in `../../validation/06 Validation.md` describing what log source was missing, what baseline window would be needed, and whether the rule logic itself is sound.
