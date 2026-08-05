# TTP Matrix: UNC6395 / GRUB1 / ShinyHunters

**Campaign:** Salesloft Drift OAuth Compromise and Salesforce Mass Exfiltration (August 2025) **Source threat profile:** [UNC6395 Profile](../profile/README.md) **Navigator layer:** [UNC6395-layer.json](UNC6395-layer.json), [UNC6395-layer.svg](UNC6395-layer.svg)

---

## Scope

Ten ATT&CK techniques mapped across the kill chain.
Each technique is marked **Emulate** (reproduced in the lab) or **Document** (cited from primary sources, not reproduced).
Initial-access techniques against the upstream vendor (T1195.002, T1199) are Document-only
because the lab does not breach a real third-party SaaS provider.
The four Emulate techniques (T1552.001, T1528, T1550.001, T1087.004) form the lab's emulation triplet plus the discovery anchor and drive the detection package.

The Evidence column cites the specific timeline event or source statement that proves the actor used the technique.
The Detection Rule column names the rule that covers the technique, or says the detection was not built.
Rule files live in `../detections/sigma/`.

The matrix is deliberately scoped at ten rows.
Five additional techniques were considered and cut.
Reasoning provided under the matrix.

---

## Matrix

| # | ATT&CK ID | Technique | Tactic | Plan | Evidence | Detection Rule |
|---|---|---|---|---|---|---|
| 1 | [T1195.002](https://attack.mitre.org/techniques/T1195/002/) | Supply Chain Compromise: Software Supply Chain | Initial Access | Document | Salesloft Drift application compromised upstream; trust relationship abused into downstream Salesforce tenants (GTIG; permiso.io) | (none, document only) |
| 2 | [T1199](https://attack.mitre.org/techniques/T1199/) | Trusted Relationship (Salesloft Drift connected app) | Initial Access | Document | Pre-existing OAuth trust between Drift and customer Salesforce orgs reused with stolen tokens (GTIG; Cloudflare) | (none, document only) |
| 3 | [T1552.001](https://attack.mitre.org/techniques/T1552/001/) | Unsecured Credentials: Credentials In Files (GitHub, AWS SSM) | Credential Access | **Emulate** | Salesloft GitHub repos accessed March to June 2025; OAuth tokens extracted from AWS Secrets Manager / SSM Parameter Store (permiso.io); TruffleHog observed verifying a Cloudflare token on 2025-08-09 11:51:13 (Cloudflare) | not built, needs a User-Agent log source |
| 4 | [T1528](https://attack.mitre.org/techniques/T1528/) | Steal Application Access Token (OAuth refresh token) | Credential Access | **Emulate** | Drift OAuth refresh tokens stolen from Salesloft's AWS environment and used as Drift against victim tenants (GTIG; permiso.io) | R1 |
| 5 | [T1078.004](https://attack.mitre.org/techniques/T1078/004/) | Valid Accounts: Cloud Accounts | Defense Evasion | Document | Stolen Drift OAuth tokens reused as valid app credentials against Cloudflare's Salesforce tenant on 2025-08-12, 08-13, 08-16, 08-17 (Cloudflare timeline) | R2, secondary signal |
| 6 | [T1550.001](https://attack.mitre.org/techniques/T1550/001/) | Use Alternate Auth Material: App Access Token | Lateral Movement | **Emulate** | Logins to Cloudflare's Salesforce tenant from 44.215.108.109 (AWS) and 208.68.36.90 (DigitalOcean) using the Drift app token, no preceding human interactive sign-in (Cloudflare) | R2 |
| 7 | [T1087.004](https://attack.mitre.org/techniques/T1087/004/) | Account Discovery: Cloud Account (object enumeration) | Discovery | **Emulate** | `GET /services/data/v58.0/sobjects/` enumeration on 2025-08-12 22:14:09; `SELECT COUNT()` against Account, Contact, User on 2025-08-14 00:17:47 to 00:18:00 (Cloudflare) | R3 |
| 8 | [T1213.006](https://attack.mitre.org/techniques/T1213/006/) | Data from Information Repositories: Databases (Salesforce objects) | Collection | Document | SOQL queries against `User`, `Case`, `CaseTeamMemberHistory__c`, `Organization` on 2025-08-13 to 08-16 (Cloudflare); GTIG documents the SELECT/LIMIT pattern across Account, Opportunity, User, Case | R3, partial |
| 9 | [T1567](https://attack.mitre.org/techniques/T1567/) | Exfiltration Over Web Service | Exfiltration | Document | Salesforce Bulk API 2.0 job from 208.68.36.90 (DigitalOcean) executed 2025-08-17 11:11:56 to 11:15:18 to exfiltrate the Cases object; broader exfil 2025-08-17 to 08-20 via Tor (Cloudflare; GTIG) | not built, needs Shield |
| 10 | [T1070](https://attack.mitre.org/techniques/T1070/) | Indicator Removal (deleted Salesforce query jobs) | Defense Evasion | Document | Bulk API 2.0 export job deleted at 2025-08-17 11:15:42, ~24 seconds after completion (Cloudflare); permiso.io flags the immediate-deletion pattern as the campaign's anti-forensic signature | not built, needs Shield |

**Counts:** 10 techniques total.
4 Emulate.
6 Document.
3 Sigma rules cover 4 of the 10 techniques. R3 covers an Emulate row plus a Document row.

---

## Scope Decisions

The matrix is deliberately capped at ten techniques.
The wider Section 7 mapping in the threat profile contains five additional techniques that were considered, sourced, and cut from the matrix on purpose.

Every row is backed by a sourced timeline event. Four are backed by a shipped rule as well.

Where the Detection Rule column says "not built", the rule would need a log source this tenant cannot produce, so no rule was written.

The five excluded techniques are listed below with the cut rationale.

Each is still represented elsewhere in the package (IOC table, threat profile body, or source notes), so nothing observed in the campaign is lost.

The same five become the spine of the README's "What I Would Do With More Time" section, which is where reviewer attention concentrates.

### Considered and Excluded

| ATT&CK ID | Technique | Cut rationale |
|---|---|---|
| [T1195.001](https://attack.mitre.org/techniques/T1195/001/) | Supply Chain Compromise: Compromise Software Dependencies and Development Tools | Wrong sub-technique. Drift ships as a software component to customers; it is not a dependency in the victim build pipeline. Replaced by T1195.002 (Software Supply Chain) which is in the matrix. |
| [T1098.001](https://attack.mitre.org/techniques/T1098/001/) | Account Manipulation: Additional Cloud Credentials | Real and sourced (guest user added to Salesloft's GitHub org for upstream persistence), but sits inside Salesloft's environment rather than the Drift to Salesforce detection plane the lab covers. The supply-chain leg is represented by T1195.002 and T1552.001. |
| [T1538](https://attack.mitre.org/techniques/T1538/) | Cloud Service Dashboard | Maps the `GET /sobjects/` and `/limits/` enumeration calls. Consolidated into T1087.004 to avoid double-counting the same activity under three IDs. T1087.004 is the cleaner sub-technique for SaaS object enumeration. |
| [T1580](https://attack.mitre.org/techniques/T1580/) | Cloud Infrastructure Discovery | Maps the `SELECT COUNT()` probes. Same consolidation as T1538. |
| [T1090.003](https://attack.mitre.org/techniques/T1090/003/) | Proxy: Multi-hop Proxy | Tor egress during exfiltration. Reads as an IOC-class observation rather than a behavior-cluster TTP. The Tor exit list lives in the threat profile IOC table (Section 11) and feeds the `Tor egress to Salesforce` detection in profile Section 12, which sits outside the shipped rule set. |

## Per-Technique Detail

### 1. T1195.002, Supply Chain Compromise: Software Supply Chain

| Field | Value |
|---|---|
| Plan | Document |
| Tactic | Initial Access |
| Evidence | GTIG advisory, Cloudflare blog naming the upstream vector, permiso.io anatomy writeup |
| Detection rule | None |

Salesloft's Drift application was compromised.
The per-user OAuth tokens Drift issued to downstream Salesforce customers became valid app credentials.
A single upstream foothold yielded admin-equivalent reach across hundreds of victim tenants.

Not emulated: reproducing it would mean breaching a real SaaS vendor.
The lab covers the downstream effect through T1528 and T1550.001.

### 2. T1199, Trusted Relationship

| Field | Value |
|---|---|
| Plan | Document |
| Tactic | Initial Access |
| Evidence | Drift listed in the Salesforce AppExchange until removal on 2025-08-20 (GTIG) |
| Detection rule | None |

The Drift Connected App sat in customer tenants as a pre-approved integration.
The actor reused that trust path with stolen refresh tokens. No consent prompt, no MFA challenge.

Not emulated, same reason as T1195.002.
The lab's OAuth consent leg (T1528) shows how the trust gets established in the first place.

### 3. T1552.001, Unsecured Credentials: Credentials In Files

| Field | Value |
|---|---|
| Plan | Emulate |
| Tactic | Credential Access |
| Evidence | permiso.io anatomy writeup (GitHub access window, AWS storage hypothesis). Cloudflare timeline, TruffleHog User-Agent at 2025-08-09 11:51:13 from 44.215.108.109 |
| Detection rule | R1 |

Between March and June 2025 the actor reached Salesloft's GitHub organization, pulled repositories, and added a guest user for persistence.
Drift's OAuth refresh tokens were extracted, likely from source, AWS Secrets Manager or SSM Parameter Store.

At 2025-08-09 11:51:13 the actor used TruffleHog as the User-Agent against Cloudflare's token verification endpoint.
That is the live-fire moment tying this technique to a quotable indicator.

**Lab emulation:**

- Private GitHub repo `threathunter-truffle-target`.
- Plant a clearly-marked fake refresh token in `config/secrets.yaml` (`# FAKE TEST VALUE`).
- Run `trufflehog git file:///path/to/repo --json > truffle.json`.
- Capture `truffle.json` and a console screenshot.
- Craft an HTTP client that issues a request with `User-Agent: truffleHog` to verify a token, mirroring the actor's exact behavior.
- Lab folder: `../emulation/github/`.

### 4. T1528, Steal Application Access Token

| Field | Value |
|---|---|
| Plan | Emulate |
| Tactic | Credential Access |
| Evidence | GTIG advisory, permiso.io section on per-user token architecture |
| Detection rules | R2 (Salesforce), R3 (M365 mirror) |

Refresh tokens stolen from Salesloft's AWS environment were exchanged for access tokens across downstream tenants.
Drift's per-user token model meant the token inherited whatever privilege the connecting user held.
Admins handed over admin-level reach.

**Lab emulation:**

- Salesforce Setup, App Manager, New External Client App `Drift_Integration`. Scopes `api`, `refresh_token`, `offline_access`. Callback `http://localhost:8080/callback`.
- Run the OAuth 2.0 Web Server Flow with a Python script. Capture access and refresh tokens.
- Verify the Setup Audit Trail shows the Connected App authorization entry. Screenshot.
- Verify Login History shows the OAuth Application Type row. Screenshot.
- Mirror against Microsoft Graph: register `Internal Reporting App` in Entra ID with `User.Read.All` and `Files.Read.All`, drive the consent URL with `prompt=consent`, capture tokens via `roadtx`. Verify `AuditLogs` shows `OperationName == "Consent to application"`.
- Lab folders: `../emulation/salesforce/` and `../emulation/m365/`.

### 5. T1078.004, Valid Accounts: Cloud Accounts

| Field | Value |
|---|---|
| Plan | Document |
| Tactic | Defense Evasion |
| Evidence | Cloudflare timeline login events |
| Detection rule | R2, as a secondary signal |

With Drift tokens in hand the actor authenticated as a fully valid cloud identity.
No MFA prompt fired, because token-based access bypasses interactive auth paths.

Cloudflare logged repeat logins from 44.215.108.109 (AWS) on 2025-08-12, 08-13 and 08-16.
Then from 208.68.36.90 (DigitalOcean) on 2025-08-17.

Not separately emulated. Using stolen tokens is covered by T1550.001 below.
Splitting "valid account" from "alternate auth material" in the lab would be cosmetic.

### 6. T1550.001, Use Alternate Auth Material: App Access Token

| Field | Value |
|---|---|
| Plan | Emulate |
| Tactic | Lateral Movement |
| Evidence | Cloudflare timeline, Bulk API exfil 2025-08-17 11:11:56 to 11:15:18 from 208.68.36.90. GTIG on the token-driven access pattern |
| Detection rule | R2 |

The Drift app's access token was used to call Salesforce REST and Bulk APIs.
From the tenant's perspective it looked like a known integration calling the API.
The high-signal anomaly is that no human sign-in preceded it for the same `AppId` in 24 hours.

**Lab emulation:**

- Use the access token captured in T1528 to hit `/services/data/v58.0/sobjects/`, then `/services/data/v58.0/query/?q=SELECT+Id,Name+FROM+Account+LIMIT+10`.
- Set HTTP `User-Agent: truffleHog` on at least one request to mirror the actor's verification behavior.
- Capture in Login History (token use as a new row) and Connected App OAuth Usage (call counts).
- M365 mirror: hit `https://graph.microsoft.com/v1.0/me` and `/v1.0/users` with the captured token. Verify `SigninLogs` shows the service-principal sign-in.
- Lab folders: `../emulation/salesforce/` and `../emulation/m365/`.

### 7. T1087.004, Account Discovery: Cloud Account

| Field | Value |
|---|---|
| Plan | Emulate |
| Tactic | Discovery |
| Evidence | Cloudflare timeline. Object enumeration 2025-08-12 22:14:09, COUNT() queries 2025-08-14 00:17:47 to 00:18:00, detailed User query 2025-08-14 11:09:21 |
| Detection rule | R3 |

Schema-then-bulk reconnaissance.
Object enumeration through `GET /services/data/v58.0/sobjects/`, then metadata via `/sobjects/Case/describe/`.
Then `SELECT COUNT()` probes against Account, Contact, User and Case, before sample LIMIT 20 queries.

The volume signature of the burst is the clearest detection target.

**Lab emulation:**

- Salesforce: enumerate Account, Contact, User and Opportunity with growing LIMIT clauses (10, 100, 1000). Capture the OAuth Usage call counts.
- M365 mirror: same pattern via Graph `/v1.0/users`, `/v1.0/groups` and `/v1.0/applications`. Capture `MicrosoftGraphActivityLogs`.
- Tune the request rate so the volume signature shows without being absurd. R3 fires above 50 enumeration calls in 5 minutes from one app.
- Lab folder: `../emulation/salesforce/`, `../emulation/m365/`.

### 8. T1213.006, Data from Information Repositories: Databases

| Field | Value |
|---|---|
| Plan | Document |
| Tactic | Collection |
| Evidence | Cloudflare timeline queries on 2025-08-13 19:33:11, 2025-08-14 04:34:39, 11:09:14 and 11:09:21. GTIG sample queries |
| Detection coverage | R3 (volume), partial |

Substantive SOQL pulls against User with the full PII column set, Case at LIMIT 10000, `CaseTeamMemberHistory__c` at LIMIT 5000, and Organization for a tenant fingerprint.
GTIG documents the same pattern across Account, Opportunity, User and Case.

Not separately emulated.
T1087.004 covers the discovery queries and T1567 covers the bulk export.
A third lab variant would not produce a distinct rule.

### 9. T1567, Exfiltration Over Web Service

| Field | Value |
|---|---|
| Plan | Document |
| Tactic | Exfiltration |
| Evidence | Cloudflare timeline (Bulk API job execution). GTIG advisory (exfiltration window, Tor IOCs) |
| Detection rule | Not built, needs Salesforce Shield |

Bulk API 2.0 jobs created from 208.68.36.90 exfiltrated the Cases object on 2025-08-17, 11:11:56 to 11:15:18.
The broader exfiltration phase ran 2025-08-17 to 08-20 with egress through Tor exit nodes.

Not emulated.
Developer Edition can issue Bulk API jobs, but not against a populated multi-tenant target.
The detection logic is the value here, not the egress action.

### 10. T1070, Indicator Removal

| Field | Value |
|---|---|
| Plan | Document |
| Tactic | Defense Evasion |
| Evidence | Cloudflare timeline (deletion event). permiso.io signal-detection section |
| Detection rule | Not built, needs Salesforce Shield |

The Bulk API 2.0 export job created at 2025-08-17 11:11:56 was deleted at 11:15:42.
That is roughly 24 seconds after completion.
permiso.io reads the immediate deletion as the campaign's anti-forensic signature.

The deletion does not affect Event Monitoring records, which is what keeps the pattern detectable.

Not emulated.
Developer Edition can create and delete a Bulk API job, but the Setup Audit Trail does not capture job-level CRUD without Event Monitoring.
Covered by the same rule as T1567.

---

## Detection Rule Cross-Reference

| Rule | ATT&CK | Hypothesis | Production data source |
|---|---|---|---|
| R1 | T1528 | An External Client App is created, or its refresh token policy widened to Infinite | `EventLogFile` `ConnectedApplication`, plus an sObject query for `OAuthConfig.Scopes` |
| R2 | T1550.001 / T1078.004 | An app sign-in for an `AppId` with no user-interactive sign-in in the prior 24 hours | `AADServicePrincipalSignInLogs` joined to `SigninLogs`. Salesforce `LoginEvent.LoginType` |
| R3 | T1087.004 / T1213.006 | More than 50 object enumeration or SOQL calls from one app within 5 minutes | `EventLogFile` `ApiEvent`, grouped by `CONNECTED_APP_ID` |

The KQL half of R2 lands in `../detections/kql/`.
Sigma sources of truth land in `../detections/sigma/`.

### Detections Not Built

| Technique | Would need |
|---|---|
| T1552.001, and the GTIG campaign User-Agents | `RestApi.USER_AGENT`, which requires Salesforce Shield or a proxy access log |
| T1528, Entra ID side | An M365 tenant and `AuditLogs` |
| T1567, T1070 | `BulkApi2` job lifecycle, which requires Salesforce Shield |

---

## Source Library

| Source | Title | Link |
|---|---|---|
| Google Threat Intelligence Group (Google Cloud Blog) | Widespread Data Theft Targets Salesforce Instances via Salesloft Drift | https://cloud.google.com/blog/topics/threat-intelligence/data-theft-salesforce-instances-via-salesloft-drift |
| Cloudflare Blog | The impact of the Salesloft Drift breach on Cloudflare and our customers | https://blog.cloudflare.com/response-to-salesloft-drift-incident/ |
| Permiso Security | Anatomy of the Salesloft Breach: Detection, Response, and Lessons Learned | https://permiso.io/blog/anatomy-of-the-salesloft-breach |
| Project | Threat Profile (this repo) | [`../profile/README.md`](../profile/README.md) |
