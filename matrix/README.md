# TTP Matrix: UNC6395 / GRUB1 / ShinyHunters

**Campaign:** Salesloft Drift OAuth Compromise and Salesforce Mass Exfiltration (August 2025)
**Source threat profile:** [UNC6395 Profile](../profile/README.md)
**Navigator layer: **[UNC6395-layer.json](UNC6395-layer.json), [UNC6395-layer.svg](UNC6395-layer.svg)

---

## Scope

Ten ATT&CK techniques mapped across the kill chain. Each technique is marked **Emulate** (reproduced in the lab) or **Document** (cited from primary sources, not reproduced). Initial-access techniques against the upstream vendor (T1195.002, T1199) are Document-only because the lab does not breach a real third-party SaaS provider. The four Emulate techniques (T1552.001, T1528, T1550.001, T1087.004) form the lab's emulation triplet plus the discovery anchor and drive the detection package.

The Evidence column cites the specific timeline event or source statement that proves the actor used the technique. The Detection Rule column references the Sigma rule ID (R1 to R6) that covers it; rule files live in `../detections/sigma/` once authored.

The matrix is deliberately scoped at ten rows. Five additional techniques were considered and cut. Reasoning provided under the matrix.

---

## Matrix

| # | ATT&CK ID | Technique | Tactic | Plan | Evidence | Detection Rule |
|---|---|---|---|---|---|---|
| 1 | [T1195.002](https://attack.mitre.org/techniques/T1195/002/) | Supply Chain Compromise: Software Supply Chain | Initial Access | Document | Salesloft Drift application compromised upstream; trust relationship abused into ~700 downstream Salesforce tenants (GTIG; permiso.io) | (none, document only) |
| 2 | [T1199](https://attack.mitre.org/techniques/T1199/) | Trusted Relationship (Salesloft Drift connected app) | Initial Access | Document | Pre-existing OAuth trust between Drift and customer Salesforce orgs reused with stolen tokens (GTIG; Cloudflare) | (none, document only) |
| 3 | [T1552.001](https://attack.mitre.org/techniques/T1552/001/) | Unsecured Credentials: Credentials In Files (GitHub, AWS SSM) | Credential Access | **Emulate** | Salesloft GitHub repos accessed March to June 2025; OAuth tokens extracted from AWS Secrets Manager / SSM Parameter Store (permiso.io); TruffleHog observed verifying a Cloudflare token on 2025-08-09 11:51:13 (Cloudflare) | R1 |
| 4 | [T1528](https://attack.mitre.org/techniques/T1528/) | Steal Application Access Token (OAuth refresh token) | Credential Access | **Emulate** | Drift OAuth refresh tokens stolen from Salesloft's AWS environment and used as Drift against victim tenants (GTIG; permiso.io) | R2 (Salesforce), R3 (M365 mirror) |
| 5 | [T1078.004](https://attack.mitre.org/techniques/T1078/004/) | Valid Accounts: Cloud Accounts | Defense Evasion | Document | Stolen Drift OAuth tokens reused as valid app credentials against Cloudflare's Salesforce tenant on 2025-08-12, 08-13, 08-16, 08-17 (Cloudflare timeline) | (covered by R4 secondary signal) |
| 6 | [T1550.001](https://attack.mitre.org/techniques/T1550/001/) | Use Alternate Auth Material: App Access Token | Lateral Movement | **Emulate** | Logins to Cloudflare's Salesforce tenant from 44.215.108.109 (AWS) and 208.68.36.90 (DigitalOcean) using the Drift app token, no preceding human interactive sign-in (Cloudflare) | R4 |
| 7 | [T1087.004](https://attack.mitre.org/techniques/T1087/004/) | Account Discovery: Cloud Account (object enumeration) | Discovery | **Emulate** | `GET /services/data/v58.0/sobjects/` enumeration on 2025-08-12 22:14:09; `SELECT COUNT()` against Account, Contact, User on 2025-08-14 00:17:47 to 00:18:00 (Cloudflare) | R5 |
| 8 | [T1213.006](https://attack.mitre.org/techniques/T1213/006/) | Data from Information Repositories: Databases (Salesforce objects) | Collection | Document | SOQL queries against `User`, `Case`, `CaseTeamMemberHistory__c`, `Organization` on 2025-08-13 to 08-16 (Cloudflare); GTIG documents the SELECT/LIMIT pattern across Account, Opportunity, User, Case | (covered by R5 + R6) |
| 9 | [T1567](https://attack.mitre.org/techniques/T1567/) | Exfiltration Over Web Service | Exfiltration | Document | Salesforce Bulk API 2.0 job from 208.68.36.90 (DigitalOcean) executed 2025-08-17 11:11:56 to 11:15:18 to exfiltrate the Cases object; broader exfil 2025-08-17 to 08-20 via Tor (Cloudflare; GTIG) | R6 |
| 10 | [T1070](https://attack.mitre.org/techniques/T1070/) | Indicator Removal (deleted Salesforce query jobs) | Defense Evasion | Document | Bulk API 2.0 export job deleted at 2025-08-17 11:15:42, ~24 seconds after completion (Cloudflare); permiso.io flags the immediate-deletion pattern as the campaign's anti-forensic signature | R6 |

**Counts:** 10 techniques total. 4 Emulate. 6 Document. 6 Sigma rules cover 8 of the 10 techniques (R5 / R6 each cover an Emulate row plus a Document row).

---

## Scope Decisions

The matrix is deliberately capped at ten techniques. The wider Section 7 mapping in the threat profile contains five additional techniques that were considered, sourced, and cut from the matrix on purpose. This is scope discipline, not omission: every row in the matrix is backed by either a Sigma rule, a lab artifact, or both. Adding rows that are not backed by a defender-side artifact would weaken the package, because the package is a detection deliverable rather than a TTP catalog.

The five excluded techniques are listed below with the cut rationale. Each is still represented elsewhere in the package (IOC table, threat profile body, or source notes), so nothing observed in the campaign is lost. The same five become the spine of the README's "What I Would Do With More Time" section, which is where reviewer attention concentrates.

### Considered and Excluded

| ATT&CK ID | Technique | Cut rationale |
|---|---|---|
| [T1195.001](https://attack.mitre.org/techniques/T1195/001/) | Supply Chain Compromise: Compromise Software Dependencies and Development Tools | Wrong sub-technique. Drift ships as a software component to customers; it is not a dependency in the victim build pipeline. Replaced by T1195.002 (Software Supply Chain) which is in the matrix. |
| [T1098.001](https://attack.mitre.org/techniques/T1098/001/) | Account Manipulation: Additional Cloud Credentials | Real and sourced (guest user added to Salesloft's GitHub org for upstream persistence), but sits inside Salesloft's environment rather than the Drift to Salesforce detection plane the lab covers. The supply-chain leg is represented by T1195.002 and T1552.001. |
| [T1538](https://attack.mitre.org/techniques/T1538/) | Cloud Service Dashboard | Maps the `GET /sobjects/` and `/limits/` enumeration calls. Consolidated into T1087.004 to avoid double-counting the same activity under three IDs. T1087.004 is the cleaner sub-technique for SaaS object enumeration. |
| [T1580](https://attack.mitre.org/techniques/T1580/) | Cloud Infrastructure Discovery | Maps the `SELECT COUNT()` probes. Same consolidation as T1538. |
| [T1090.003](https://attack.mitre.org/techniques/T1090/003/) | Proxy: Multi-hop Proxy | Tor egress during exfiltration. Reads as an IOC-class observation rather than a behavior-cluster TTP. The Tor exit list lives in the threat profile IOC table (Section 11) and feeds the `Tor egress to Salesforce` detection in profile Section 12, which sits outside the R1 to R6 set. |

## Per-Technique Detail

### 1. T1195.002, Supply Chain Compromise: Software Supply Chain

**Plan:** Document.
**Tactic:** Initial Access.
**What happened:** Salesloft's Drift application was compromised, and the per-user OAuth tokens issued by Drift to ~700 downstream Salesforce customers were operationalized as valid app credentials. This is a textbook software supply chain compromise: a single upstream foothold yielded admin-equivalent reach across hundreds of victim tenants.
**Evidence:** GTIG advisory; Cloudflare blog naming the upstream vector; permiso.io anatomy writeup.
**Why not emulated:** Reproducing this would require breaching a real third-party SaaS vendor. Out of scope. The lab covers the downstream effect via T1528 / T1550.001.

### 2. T1199, Trusted Relationship

**Plan:** Document.
**Tactic:** Initial Access.
**What happened:** The Drift Connected App existed in customer Salesforce tenants as a pre-approved integration. The actor reused that established trust path with stolen OAuth refresh tokens, no consent prompt, no MFA challenge.
**Evidence:** Drift listed in Salesforce AppExchange until removal on 2025-08-20 (GTIG).
**Why not emulated:** Same reason as T1195.002. The OAuth-consent leg of the lab (T1528) demonstrates how this trust gets established in the first place.

### 3. T1552.001, Unsecured Credentials: Credentials In Files

**Plan:** Emulate.
**Tactic:** Credential Access.
**What happened:** Between March and June 2025 the actor accessed Salesloft's GitHub organization, downloaded multiple repositories, and added a guest user for persistence. OAuth refresh tokens for the Drift integration were extracted, likely from source code, AWS Secrets Manager, or SSM Parameter Store. On 2025-08-09 11:51:13 the actor was observed using TruffleHog as the User-Agent against the Cloudflare token verification endpoint, the live-fire moment that ties this technique to a quotable IOC.
**Evidence:** permiso.io anatomy writeup (GitHub access window; AWS storage hypothesis); Cloudflare timeline (TruffleHog User-Agent at 2025-08-09 11:51:13 from 44.215.108.109).
**Lab emulation:**

- Private GitHub repo `threathunter-truffle-target`.
- Plant a clearly-marked fake refresh token in `config/secrets.yaml` (`# FAKE TEST VALUE`).
- Run `trufflehog git file:///path/to/repo --json > truffle.json`.
- Capture `truffle.json` and a console screenshot.
- Craft an HTTP client that issues a request with `User-Agent: truffleHog` to verify a token, mirroring the actor's exact behavior.
- Lab folder: `../emulation/github/`.

**Detection rule:** R1.

### 4. T1528, Steal Application Access Token

**Plan:** Emulate.
**Tactic:** Credential Access.
**What happened:** OAuth refresh tokens for the Drift application, stolen from Salesloft's AWS environment, were used to obtain access tokens against ~700 Salesforce tenants. Drift's per-user token architecture meant any user who connected the integration handed over a token with their own privilege; admins handed over admin-level reach.
**Evidence:** GTIG advisory; permiso.io section on per-user token architecture.
**Lab emulation:**

- Salesforce Setup, App Manager, New Connected App `Internal Drift Analog`. OAuth scopes `api`, `refresh_token`, `offline_access`. Callback `http://localhost:8080/callback`.
- Run the OAuth 2.0 Web Server Flow with a Python script. Capture access and refresh tokens.
- Verify Setup, Security, View Setup Audit Trail shows the Connected App authorization entry. Screenshot.
- Verify Setup, Security, Identity, Login History shows the OAuth Application Type row. Screenshot.
- Mirror against Microsoft Graph: register `Internal Reporting App` in Entra ID (`User.Read.All`, `Files.Read.All`), drive the consent URL with `prompt=consent`, capture tokens via `roadtx`. Verify `AuditLogs` shows `OperationName == "Consent to application"`.
- Lab folders: `../emulation/salesforce/` and `../emulation/m365/`.

**Detection rules:** R2 (Salesforce side), R3 (M365 mirror).

### 5. T1078.004, Valid Accounts: Cloud Accounts

**Plan:** Document.
**Tactic:** Defense Evasion.
**What happened:** With Drift OAuth tokens in hand, the actor authenticated to victim Salesforce tenants as a fully valid cloud identity. No MFA prompt fired because OAuth-token-based access bypasses interactive auth paths. Cloudflare logged repeat logins from 44.215.108.109 (AWS) on 2025-08-12, 08-13, 08-16 and from 208.68.36.90 (DigitalOcean) on 2025-08-17.
**Evidence:** Cloudflare timeline (login events).
**Why not separately emulated:** The act of using stolen OAuth tokens is captured by T1550.001 below. Separating "valid account" from "alternate auth material" in the lab would be cosmetic.
**Detection rule:** R4 picks up the secondary signal (service-principal sign-in with no preceding human sign-in).

### 6. T1550.001, Use Alternate Auth Material: App Access Token

**Plan:** Emulate.
**Tactic:** Lateral Movement.
**What happened:** The Drift app's OAuth access token was used to call Salesforce REST and Bulk APIs. From a victim tenant's perspective the activity looked like a known integration calling the API; from a defender's perspective the high-signal anomaly is that there was no preceding human sign-in for the same `AppId` in the prior 24 hours.
**Evidence:** Cloudflare timeline (Bulk API exfil on 2025-08-17 11:11:56 to 11:15:18 from 208.68.36.90); GTIG documentation of OAuth-token-driven access pattern.
**Lab emulation:**

- Use the access token captured in T1528 to hit `/services/data/v58.0/sobjects/`, then `/services/data/v58.0/query/?q=SELECT+Id,Name+FROM+Account+LIMIT+10`.
- Set HTTP `User-Agent: truffleHog` on at least one request to mirror the actor's verification behavior.
- Capture in Login History (token use as a new row) and Connected App OAuth Usage (call counts).
- M365 mirror: hit `https://graph.microsoft.com/v1.0/me` and `/v1.0/users` with the captured token. Verify `SigninLogs` shows the service-principal sign-in.
- Lab folders: `../emulation/salesforce/` and `../emulation/m365/`.

**Detection rule:** R4.

### 7. T1087.004, Account Discovery: Cloud Account

**Plan:** Emulate.
**Tactic:** Discovery.
**What happened:** Schema-then-bulk reconnaissance. Object enumeration via `GET /services/data/v58.0/sobjects/`, metadata pulls via `/sobjects/Case/describe/`, then `SELECT COUNT()` probes against Account, Contact, User, Case before sample LIMIT 20 queries. The volume signature of the enumeration burst is the clearest detection target.
**Evidence:** Cloudflare timeline (object enumeration on 2025-08-12 22:14:09; COUNT() queries on 2025-08-14 00:17:47 to 00:18:00; detailed User table query on 2025-08-14 11:09:21).
**Lab emulation:**

- Salesforce: enumerate Account, Contact, User, Opportunity with progressively larger LIMIT clauses (10, 100, 1000) to mimic the testing-then-export pattern. Capture Connected App OAuth Usage call counts.
- M365 mirror: same pattern via Graph `/v1.0/users`, `/v1.0/groups`, `/v1.0/applications`. Capture `MicrosoftGraphActivityLogs`.
- Tune the request rate so the volume signature is visible but not absurd. R5 fires on >50 enumeration calls in 5 minutes from a single app.
- Lab folder: `../emulation/salesforce/`, `../emulation/m365/`.

**Detection rule:** R5.

### 8. T1213.006, Data from Information Repositories: Databases

**Plan:** Document.
**Tactic:** Collection.
**What happened:** Substantive SOQL pulls against User (with the full PII column set), Case (LIMIT 10000), `CaseTeamMemberHistory__c` (LIMIT 5000), and Organization (tenant fingerprint). GTIG documents the same pattern across Account, Opportunity, User, Case.
**Evidence:** Cloudflare timeline (queries on 2025-08-13 19:33:11, 2025-08-14 04:34:39, 2025-08-14 11:09:14, 2025-08-14 11:09:21); GTIG sample queries.
**Why not separately emulated:** Captured implicitly by T1087.004 (the discovery queries) and the bulk export covered by T1567.002. Adding a third lab variant would not produce a distinct rule.
**Detection coverage:** R5 (volume) and R6 (bulk-export-then-delete pattern).

### 9. T1567.002, Exfiltration to Cloud Storage

**Plan:** Document.
**Tactic:** Exfiltration.
**What happened:** Salesforce Bulk API 2.0 jobs created from 208.68.36.90 to exfiltrate the Cases object on 2025-08-17 11:11:56 to 11:15:18. Broader exfiltration phase 2025-08-17 to 08-20 with egress through Tor exit nodes.
**Evidence:** Cloudflare timeline (Bulk API job execution); GTIG advisory (broader exfiltration window and Tor IOCs).
**Why not emulated:** The Salesforce Developer Edition can issue Bulk API jobs but not against a populated, multi-tenant target representative of the real campaign. The detection logic is the value here, not the egress action.
**Detection rule:** R6.

### 10. T1070, Indicator Removal

**Plan:** Document.
**Tactic:** Defense Evasion.
**What happened:** The Bulk API 2.0 export job created at 2025-08-17 11:11:56 was deleted at 2025-08-17 11:15:42, roughly 24 seconds after completion. permiso.io flags the immediate-deletion behavior as the campaign's anti-forensic signature; the deletion does not impact Salesforce Event Monitoring records, which is what makes the pattern detectable.
**Evidence:** Cloudflare timeline (deletion event); permiso.io signal-detection section.
**Why not emulated:** The lab can emulate creation+deletion of a Bulk API job in Developer Edition, but Setup Audit Trail does not capture job-level CRUD without Event Monitoring. Marked Document and covered by the same rule (R6) as T1567.002.

---

## Detection Rule Cross-Reference

| Rule | ATT&CK | Hypothesis | Data Source |
|---|---|---|---|
| R1 | T1552.001 | An attacker is verifying credentials harvested from leaked source by issuing requests with `User-Agent: truffleHog` | SaaS API access logs (Salesforce Event Monitoring `ApiEvent`; Sentinel `MicrosoftGraphActivityLogs`) |
| R2 | T1528 (Salesforce) | A newly-created Connected App (within last N hours) requests `api` + `refresh_token` scopes | Salesforce `EventLogFile` (`LoginAs`, `ConnectedApplication`) + Setup Audit Trail |
| R3 | T1528 (M365 mirror) | Entra ID consent grant for an app requesting high-privilege scopes (`User.Read.All`, `Files.Read.All`, `Mail.Read`) | Entra ID `AuditLogs`, `OperationName == "Consent to application"` |
| R4 | T1550.001 / T1078.004 | Service-principal sign-in for an `AppId` with no preceding user-interactive sign-in in the prior 24 hours | `SigninLogs` (ServicePrincipal schema); Salesforce Login History `Application Type == OAuth` |
| R5 | T1087.004 / T1213.006 | Anomalous volume of cloud-account enumeration calls from a single app within a 5-minute window (>50 calls) | Graph `/users` enumeration via `MicrosoftGraphActivityLogs`; Connected App OAuth Usage SOQL counts |
| R6 | T1567.002 / T1070 | Bulk export job created and deleted by the same Connected App within 30 minutes | Salesforce Event Monitoring `BulkApi2`, `ApiTotalUsage:DELETE` |

KQL translations for R3, R4, R5 land in `../detections/kql/`. Sigma sources of truth land in `../detections/sigma/`. One file per rule, named by ATT&CK ID.

---

## Source Library

| Source | Title | Link |
|---|---|---|
| Google Threat Intelligence Group (Google Cloud Blog) | Widespread Data Theft Targets Salesforce Instances via Salesloft Drift | https://cloud.google.com/blog/topics/threat-intelligence/data-theft-salesforce-instances-via-salesloft-drift |
| Cloudflare Blog | The impact of the Salesloft Drift breach on Cloudflare and our customers | https://blog.cloudflare.com/response-to-salesloft-drift-incident/ |
| Permiso Security | Anatomy of the Salesloft Breach: Detection, Response, and Lessons Learned | https://permiso.io/blog/anatomy-of-the-salesloft-breach |
| Project | Threat Profile (this repo) | [[Lab Setup/profile/README]] |
