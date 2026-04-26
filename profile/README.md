# Threat Profile: UNC6395 / GRUB1 / ShinyHunters

**Case Study:** Salesloft Drift OAuth Compromise and Salesforce Mass Exfiltration (August 2025)

> Hybrid actor + campaign profile. Actor-centric framing with the Salesloft Drift incident as the primary documented operation.
> Sources: [[GTIG Advisory]], [[CloudFlare Victim-Side Blog]], [[permiso.io Anatomy Writeup]]
> Sections marked **[Inferred]** are drafted from analyst inference, not direct quotes from the three source files. Review before publishing.

---

## 1. Executive Summary

Between March and August 2025, a financially motivated actor tracked as UNC6395 (Mandiant), GRUB1 (Cloudflare), and publicly claimed by ShinyHunters, compromised the Salesloft Drift application and used its OAuth integration to mass-exfiltrate Salesforce data from downstream customers including Cloudflare. Initial access was obtained against Salesloft's GitHub repositories between March and June 2025, allowing the actor to extract OAuth tokens for the Drift application from Salesloft's AWS environment. The actor then operated against victim Salesforce tenants from August 8 to August 20, 2025, executing reconnaissance SOQL queries and using the Salesforce Bulk API 2.0 to exfiltrate Case, Account, Contact, and User objects. Stolen records were mined for embedded secrets (AWS access keys, Snowflake credentials, passwords, SSO and VPN URLs) to enable downstream compromise. Salesloft revoked Drift OAuth and refresh tokens and removed Drift from the Salesforce AppExchange on August 20, 2025, containing the campaign.

---

## 2. Actor Identification

| Field | Value |
|---|---|
| Primary designation | UNC6395 |
| Aliases | GRUB1 (Cloudflare), ShinyHunters (self-claimed) |
| First observed (this campaign) | 2025-03 (Salesloft GitHub access) |
| Last observed (this campaign) | 2025-08-20 |
| Attribution confidence | Medium |
| Attributing vendors | Mandiant (UNC6395), Cloudflare (GRUB1), Salesloft, Google Threat Intelligence Group |
| Suspected origin | Unattributed |

### Attribution Notes

ShinyHunters publicly claimed responsibility for the campaign but did not share private indicators that would confirm operational overlap with prior ShinyHunters activity. Mandiant tracks the cluster under the uncategorized designation UNC6395, which signals the group has not yet been linked with confidence to a known named actor. Cloudflare uses its own internal designation GRUB1 for activity observed against its tenant. Treat all three names as referring to the same activity cluster for this campaign, while preserving distinction in case future reporting separates them.

---

## 3. Motivation and Objectives

The actor's behavior is consistent with financial motivation rather than espionage or disruption. Operational goals observed across the three reports:

- Harvest long-lived secrets embedded in customer support records (AWS AKIA keys, Snowflake tokens, passwords, SSO/VPN URLs) to pivot into downstream environments.
- Aggregate large volumes of customer contact and case data across many Salesforce tenants in a single supply-chain operation.
- Possible resale, extortion, or public leak of stolen data, that would be consistent with ShinyHunters' historical monetization pattern.

---

## 4. Victimology and Targeting

### Sectors Targeted

Cross-sector. Any organization running Salesforce with the Salesloft Drift integration enabled was in scope. Confirmed and reported victims sit primarily in technology and SaaS (Cloudflare named publicly).

### Geography

Global, driven by Salesforce + Drift install base rather than geographic targeting.

### Targeting Logic

Targeting was opportunistic, scoped by the Salesloft Drift install base. Per permiso.io, the per-user OAuth token architecture meant that any Salesforce admin who had connected the Salesloft integration provided the actor with admin-level access on connection, multiplying the attack surface across hundreds of tenants from one upstream compromise.

### Notable Victims

| Victim | Date | Source | Notes |
|---|---|---|---|
| Cloudflare | 2025-08-09 to 2025-08-17 | Cloudflare blog | Salesforce tenant accessed, Cases object exfiltrated via Bulk API |
| Salesloft (upstream) | 2025-03 to 2025-06 | permiso.io | GitHub repository access; OAuth tokens extracted from AWS environment |

GTIG noted that customers not integrated with Salesforce were not impacted by this campaign.

---

## 5. Campaign Timeline

### Phases

1. **Pre-staging (2025-03 to 2025-06):** Access to Salesloft's GitHub repositories. Persistence established by adding a guest user to the GitHub organization.
2. **Token extraction:** OAuth tokens for the Drift application extracted from the Drift AWS environment, likely from Secrets Manager or Systems Manager Parameter Store.
3. **Reconnaissance and testing (2025-08-08 to 2025-08-16):** Tenant logins, schema enumeration, count queries, sample record pulls.
4. **Exfiltration (2025-08-17 to 2025-08-20):** Bulk API 2.0 jobs against Cases and other objects, egress through Tor.
5. **Anti-forensics:** Bulk API jobs deleted immediately after completion (logs retained on Salesforce side).
6. **Containment (2025-08-20):** Salesloft revoked all active Drift access and refresh tokens; Drift removed from Salesforce AppExchange.

### Event Table

Drawn from the Cloudflare timeline; representative of activity against any single victim tenant.

| Date / Time (UTC) | Phase | Event | Source |
|---|---|---|---|
| 2025-03 to 2025-06 | Pre-staging | Salesloft GitHub repositories accessed; guest user added for persistence | permiso.io |
| 2025-08-09 11:51:13 | Reconnaissance | TruffleHog observed verifying a token against Cloudflare Customer Tenant `client/v4/user/tokens/verify`, received 404 from 44.215.108.109 | Cloudflare |
| 2025-08-12 22:14:08 | Reconnaissance | Login to Cloudflare's Salesforce tenant from 44.215.108.109 | Cloudflare |
| 2025-08-12 22:14:09 | Reconnaissance | GET `/services/data/v58.0/sobjects/` (object enumeration) | Cloudflare |
| 2025-08-13 19:33:02 | Reconnaissance | Login from 44.215.108.109 | Cloudflare |
| 2025-08-13 19:33:03 | Reconnaissance | GET `/services/data/v58.0/sobjects/` | Cloudflare |
| 2025-08-13 19:33:07 / 19:33:09 | Reconnaissance | GET `/services/data/v58.0/sobjects/Case/describe/` (Case metadata) | Cloudflare |
| 2025-08-13 19:33:11 | Reconnaissance | First observed broad SOQL query against Case object from 44.215.108.109 | Cloudflare |
| 2025-08-14 00:17:40 | Reconnaissance | Lists available objects, counts Account, Contact, User | Cloudflare |
| 2025-08-14 00:17:47 | Reconnaissance | `SELECT COUNT() FROM Account` | Cloudflare |
| 2025-08-14 00:17:51 | Reconnaissance | `SELECT COUNT() FROM Contact` | Cloudflare |
| 2025-08-14 00:18:00 | Reconnaissance | `SELECT COUNT() FROM User` | Cloudflare |
| 2025-08-14 04:34:39 | Reconnaissance | Query against `CaseTeamMemberHistory__c` (LIMIT 5000) | Cloudflare |
| 2025-08-14 11:09:14 | Reconnaissance | Query against Organization table | Cloudflare |
| 2025-08-14 11:09:21 | Reconnaissance | Detailed User table query (LIMIT 20, ordered by LastLoginDate) | Cloudflare |
| 2025-08-14 11:09:22 | Reconnaissance | GET `/services/data/v58.0/limits/` | Cloudflare |
| 2025-08-16 19:26:37 | Reconnaissance | Login from 44.215.108.109 | Cloudflare |
| 2025-08-16 19:28:08 | Reconnaissance | `SELECT COUNT() FROM Case` | Cloudflare |
| 2025-08-17 11:11:23 | Exfiltration | Login from 208.68.36.90 (DigitalOcean) | Cloudflare |
| 2025-08-17 11:11:55 | Exfiltration | `SELECT COUNT() FROM Case` | Cloudflare |
| 2025-08-17 11:11:56 to 11:15:18 | Exfiltration | Salesforce Bulk API 2.0 job executed from 208.68.36.90 to exfiltrate Cases object | Cloudflare |
| 2025-08-17 11:15:42 | Anti-forensics | Bulk API 2.0 job deleted from 208.68.36.90 | Cloudflare |
| 2025-08-17 to 2025-08-20 | Exfiltration | Broader exfiltration phase across tenants, egress via Tor | permiso.io / GTIG |
| 2025-08-20 | Containment | Salesloft revoked all Drift access and refresh tokens; removed Drift from Salesforce AppExchange | GTIG |

---

## 6. Initial Access Vector

The initial access vector was the upstream compromise of the Salesloft Drift application:

- The actor obtained access to Salesloft's GitHub repositories between March and June 2025.
- Inside Salesloft's environment the actor extracted OAuth tokens for the Drift Salesforce integration, likely from AWS Secrets Manager or SSM Parameter Store.
- Drift uses a per-user OAuth token architecture: each user who connects the integration grants a token with the privileges of that user. Where a Salesforce admin had connected Drift, the actor obtained admin-equivalent access. This produced hundreds of valid downstream tokens from a single upstream compromise.

Standard victim-side controls (MFA, IP allowlists on user logins, session timeouts) did not catch the initial access because OAuth-token-based access bypasses interactive authentication paths.

---

## 7. Tactics, Techniques, and Procedures (TTPs)

### MITRE ATT&CK Mapping

| ATT&CK ID | Tactic | Technique | Observed Behavior |
|---|---|---|---|
| T1195.001 | Initial Access | Supply Chain Compromise: Compromise Software Dependencies and Development Tools | Compromise of Salesloft Drift, used as a trusted third-party integration into victim Salesforce tenants |
| T1199 | Initial Access | Trusted Relationship | Use of Salesloft Drift's pre-existing OAuth trust into customer Salesforce orgs |
| T1528 | Credential Access | Steal Application Access Token | Extraction of Drift OAuth tokens from Salesloft's AWS environment |
| T1098.001 | Persistence | Account Manipulation: Additional Cloud Credentials | Added guest user to Salesloft's GitHub organization for persistence |
| T1078.004 | Defense Evasion / Persistence | Valid Accounts: Cloud Accounts | OAuth token reuse against victim Salesforce tenants |
| T1538 | Discovery | Cloud Service Dashboard | GET against `/services/data/v58.0/sobjects/` and `/limits/` |
| T1580 | Discovery | Cloud Infrastructure Discovery | Object enumeration, COUNT() probes against Account, Contact, User, Case |
| T1213.006 | Collection | Data from Information Repositories: Databases | SOQL queries against User, Case, CaseTeamMemberHistory, Organization |
| T1567 | Exfiltration | Exfiltration Over Web Service | Bulk API 2.0 jobs over HTTPS to actor-controlled infrastructure |
| T1090.003 | Command and Control | Proxy: Multi-hop Proxy | Use of Tor exit nodes during the exfiltration phase |
| T1070 | Defense Evasion | Indicator Removal | Immediate deletion of Bulk API jobs after completion |
| T1552.001 | Credential Access | Unsecured Credentials: Credentials in Files | Mining exfiltrated case data for AWS AKIA keys, Snowflake tokens, passwords |

### Notable Tradecraft

- **Per-user OAuth token abuse:** The actor weaponized Drift's per-user OAuth model so that a single upstream compromise produced admin-equivalent reach across many downstream tenants.
- **Schema-then-bulk pattern:** Recon consistently followed a "describe + COUNT() + sample LIMIT 20" pattern before pivoting to Bulk API 2.0 for full extraction.
- **Bulk API 2.0 job hygiene:** Export jobs were deleted within seconds of completion to suppress evidence in the Bulk API job listing, though Salesforce Event Monitoring records persisted.
- **Infrastructure tiering:** AWS infrastructure (44.215.108.109) used for reconnaissance and testing; DigitalOcean (208.68.36.90) and Tor exit nodes used for exfiltration.
- **Secret mining workflow:** Exfiltrated data was scraped offline with TruffleHog and string searches for AKIA prefixes, `snowflakecomputing.com`, and credential keywords.

---

## 8. Tooling

| Tool | Purpose | Open Source / Custom | Notes |
|---|---|---|---|
| TruffleHog | Secret scanning across exfiltrated records and live token verification | OSS | Observed verifying a Cloudflare token on 2025-08-09 |
| Salesforce Bulk API 2.0 | Mass record export | Native Salesforce | Primary exfiltration channel |
| Salesforce-Multi-Org-Fetcher/1.0 | Custom multi-tenant query / fetch tool | Custom | Distinctive User-Agent string |
| Salesforce CLI (Salesforce-CLI/1.0) | Recon and query | Native | Observed User-Agent |
| python-requests/2.32.4 | Custom scripting | OSS library | Observed User-Agent |
| Python/3.11 aiohttp/3.12.15 | Parallel async API client | OSS library | Suggests parallelized API calls |
| Tor | Anonymized egress during exfiltration | OSS | Multiple exit nodes observed (see IOCs) |
| GitHub Actions | **[Inferred]** Possible pivot path from Salesloft's GitHub into AWS | Native | permiso.io flags as a likely pathway |

---

## 9. Infrastructure

### Source Infrastructure

| IP / Host | ASN / Provider | Role | First Seen | Last Seen |
|---|---|---|---|---|
| 44.215.108.109 | AWS | Reconnaissance and testing against Cloudflare tenant | 2025-08-09 | 2025-08-16 |
| 208.68.36.90 | DigitalOcean | Primary exfiltration source (Bulk API 2.0) | 2025-08-17 | 2025-08-20 |
| Multiple Tor exit nodes | Various | Anonymized exfiltration egress | 2025-08-17 | 2025-08-20 |

### Infrastructure Patterns

- The legitimate Salesloft OAuth connection baseline originates from AWS IP ranges. The actor's testing phase from AWS (44.215.108.109) blended with that baseline; the pivot to DigitalOcean and Tor for exfiltration broke the baseline and is the highest-signal infrastructure indicator.
- No evidence of bulletproof hosting; the actor preferred hyperscaler and reputable VPS providers for testing, then switched to anonymizing infrastructure for the exfiltration phase.

---

## 10. Sample Queries and Commands

Representative SOQL observed during recon and exfiltration:

```sql
-- Object inventory
SELECT COUNT() FROM Account;
SELECT COUNT() FROM Contact;
SELECT COUNT() FROM User;
SELECT COUNT() FROM Case;
SELECT COUNT() FROM Opportunity;
```

```sql
-- Active user enumeration
SELECT Id, Username, Email, FirstName, LastName, Name, Title, CompanyName,
       Department, Division, Phone, MobilePhone, IsActive, LastLoginDate,
       CreatedDate, LastModifiedDate, TimeZoneSidKey, LocaleSidKey,
       LanguageLocaleKey, EmailEncodingKey
FROM User
WHERE IsActive = true
ORDER BY LastLoginDate DESC NULLS LAST
LIMIT 20
```

```sql
-- Case bulk pull
SELECT Id, Username, Email, FirstName, LastName, Name, Title, CompanyName,
       Department, Division, Phone, MobilePhone, IsActive, LastLoginDate,
       CreatedDate, LastModifiedDate, TimeZoneSidKey, LocaleSidKey,
       LanguageLocaleKey, EmailEncodingKey
FROM Case
LIMIT 10000
```

```sql
-- Tenant fingerprinting
SELECT Id, Name, OrganizationType, InstanceName, IsSandbox
FROM Organization
LIMIT 1
```

```sql
-- Custom object discovery (observed against Cloudflare)
SELECT Id, IsDeleted, Name, CreatedDate, CreatedById, LastModifiedDate,
       LastModifiedById, SystemModstamp, LastViewedDate, LastReferencedDate,
       Case__c
FROM CaseTeamMemberHistory__c
LIMIT 5000
```

REST endpoints observed:

```
GET  /services/data/v58.0/sobjects/
GET  /services/data/v58.0/sobjects/Case/describe/
GET  /services/data/v58.0/limits/
POST /services/data/v58.0/jobs/...      (Bulk API 2.0 job creation)
DELETE /services/data/v58.0/jobs/...    (Bulk API 2.0 job deletion)
```

---

## 11. Indicators of Compromise (IOCs)

### Network

| Indicator | Type | Description | Source |
|---|---|---|---|
| 208.68.36.90 | IPv4 | DigitalOcean, primary exfiltration source | Cloudflare, GTIG, permiso.io |
| 44.215.108.109 | IPv4 | AWS, reconnaissance and testing | Cloudflare, GTIG, permiso.io |
| 154.41.95.2 | IPv4 | Tor exit node | GTIG |
| 176.65.149.100 | IPv4 | Tor exit node | GTIG |
| 179.43.159.198 | IPv4 | Tor exit node | GTIG |
| 185.130.47.58 | IPv4 | Tor exit node | GTIG |
| 185.207.107.130 | IPv4 | Tor exit node | GTIG |
| 185.220.101.33 | IPv4 | Tor exit node | GTIG |
| 185.220.101.133 | IPv4 | Tor exit node | GTIG |
| 185.220.101.143 | IPv4 | Tor exit node | GTIG |
| 185.220.101.164 | IPv4 | Tor exit node | GTIG |
| 185.220.101.167 | IPv4 | Tor exit node | GTIG |
| 185.220.101.169 | IPv4 | Tor exit node | GTIG |
| 185.220.101.180 | IPv4 | Tor exit node | GTIG |
| 185.220.101.185 | IPv4 | Tor exit node | GTIG |
| 192.42.116.20 | IPv4 | Tor exit node | GTIG |
| 192.42.116.179 | IPv4 | Tor exit node | GTIG |
| 194.15.36.117 | IPv4 | Tor exit node | GTIG |
| 195.47.238.83 | IPv4 | Tor exit node | GTIG |
| 195.47.238.178 | IPv4 | Tor exit node | GTIG |

### Application / Identity

| Indicator | Type | Description | Source |
|---|---|---|---|
| Salesforce-Multi-Org-Fetcher/1.0 | User-Agent | Custom multi-tenant fetcher tool | Cloudflare, GTIG |
| Salesforce-CLI/1.0 | User-Agent | Salesforce CLI usage | Cloudflare, GTIG |
| python-requests/2.32.4 | User-Agent | Custom Python scripting | Cloudflare, GTIG |
| Python/3.11 aiohttp/3.12.15 | User-Agent | Parallel async API usage | Cloudflare, GTIG |
| TruffleHog | User-Agent | Secret scanning tool | Cloudflare |

### Behavioral

| Indicator | Type | Description |
|---|---|---|
| Bulk API 2.0 job creation followed by deletion within seconds | Behavioral | Anti-forensic pattern |
| OAuth refresh-token activity from non-AWS ASN for Drift Connected App | Behavioral | Baseline deviation |

---

## 12. Detection Opportunities

### High-Signal Detections

- Salesloft Drift OAuth Connected App authenticating from any ASN other than its established AWS baseline (especially DigitalOcean or Tor).
- Bulk API 2.0 job creation by a user or service account with no prior Bulk API history.
- Bulk API 2.0 job deletion within a short window (e.g. less than 5 minutes) after job completion.
- OAuth refresh-token events from new geographic regions for service-account-style identities.
- Salesforce REST API access patterns matching the recon sequence: `/sobjects/` listing, then `/sobjects/<Object>/describe/`, then `SELECT COUNT()`, then bulk export.
- Inbound API requests with the User-Agent strings listed in IOCs.

### Salesforce Event Names to Monitor

```
UniqueQuery
BulkApi2
RestApi:/services/data/sobjects
RestApi:/services/data/query
RestApi:/services/data/limits
RestApi:/services/data/jobs
ApiTotalUsage:GET
ApiTotalUsage:POST
ApiTotalUsage:DELETE
Login:oauthrefreshtoken
```

### Suggested Detection Rules

| Rule Name | Logic | Data Source | Severity |
|---|---|---|---|
| Drift OAuth ASN deviation | Drift Connected App login where source ASN is not in established baseline (AWS) | Salesforce Event Monitoring (Login, Login:oauthrefreshtoken) | High |
| Bulk API job rapid deletion | BulkApi2 job DELETE within 5 minutes of job COMPLETE | Salesforce Event Monitoring (BulkApi2, ApiTotalUsage:DELETE) | High |
| Recon-then-bulk sequence | Same identity executes `/sobjects/` list, then `/describe/`, then `SELECT COUNT()`, then bulk export within 24h | Salesforce Event Monitoring (RestApi, UniqueQuery, BulkApi2) | High |
| Suspicious User-Agent against Salesforce | API request with User-Agent matching `Salesforce-Multi-Org-Fetcher/1.0`, `python-requests/2.32.4`, `aiohttp/3.12.15`, or `Salesforce-CLI/1.0` from non-sanctioned source | Salesforce Event Monitoring (RestApi, ApiTotalUsage) | High |
| Tor egress to Salesforce | Salesforce login from a known Tor exit node | Salesforce Event Monitoring + Tor exit list | Critical |
| Secret pattern in case body | New or modified Case body matches `AKIA[0-9A-Z]{16}`, `snowflakecomputing.com`, or password keyword density | Salesforce DLP / case scanning | Medium |

---

## 13. Mitigations

### Containment

1. Disable the Salesloft Drift integration and any Salesloft connected apps in Salesforce.
2. Revoke all OAuth and refresh tokens granted to the Drift application and Drift Email application.
3. Disconnect Drift from Google Workspace and notify Google Workspace administrators.
4. Conduct forensic analysis of Salesforce Event Monitoring logs to scope the intrusion.

### Eradication and Recovery

- Rotate credentials across all third-party services that integrate with Salesforce.
- Reset passwords for impacted user accounts.
- Re-issue API keys, AWS access keys, Snowflake credentials, and any other secrets that may have appeared in case data.
- Review all integrations associated with the Drift instance for residual access.
- Open a Salesforce support case to obtain the full set of SOQL queries executed by the actor against your tenant.

### Hardening (Long Term)

- Restrict Connected App scopes to the minimum required; avoid `full` access.
- Set the IP Relaxation policy on Connected Apps to "Enforce IP restrictions."
- Define Login IP Ranges on user profiles to restrict access to trusted networks.
- Remove the "API Enabled" permission from default profiles and grant it via a Permission Set only to authorized users.
- Configure session timeouts on integrations to limit the lifespan of compromised sessions.
- Implement a recurring (weekly) credential rotation process for third-party service secrets.
- Establish baseline ASN fingerprints for vendor OAuth connections and alert on deviation.
- Run secret scanning (TruffleHog or equivalent) against case data and prevent storage of credentials in support records.
- Architectural review of how third-party SaaS integrations store and rotate OAuth tokens upstream.

---

## 14. Impact Assessment

### Data Affected

- Salesforce Case objects: customer support tickets and associated metadata.
- Customer contact information: names, emails, phone numbers, account associations.
- Embedded credentials within case bodies and attachments:
  - AWS access keys (AKIA prefix)
  - Snowflake tokens and credentials
  - Passwords
  - SSO and VPN login URLs
  - Generic API tokens
- OAuth tokens for Google Workspace integrations connected through Drift.
- Tokens and credentials for dozens of other applications integrated through Drift.

### Downstream Risk

The greater risk is second-order: stolen secrets enable lateral movement into AWS accounts, Snowflake data warehouses, and Google Workspace tenants of every organization whose support records contained credential material. Even organizations that fully rotated Drift OAuth tokens remain exposed if embedded secrets in their Salesforce case data were not also rotated.

### Scope Boundary

Per GTIG, customers without Salesforce integration to Salesloft Drift are not impacted by this campaign.

---

## 15. Lessons Learned

- **NHI compromise as a attack surface multiplier:** The chain ran from a human identity at Salesloft into machine identities (OAuth tokens) that were then trusted across hundreds of customer environments. Service-to-service trust now warrants the same scrutiny applied to human SSO.
- **Vendor secrets storage is a frontline target:** OAuth tokens stored in AWS Secrets Manager and SSM Parameter Store became the lever for the entire campaign. Robust monitoring and tight access control on secrets stores is essential.
- **Per-user OAuth designs concentrate admin risk:** When admins connect integrations under their own identity, the integration inherits admin reach. Service-account integrations with scoped permissions reduce this.
- **Vendor-connection baselines are high-signal:** The Salesloft to AWS baseline was tight; deviation to DigitalOcean was the cleanest detection signal in the campaign.
- **Anti-forensic API behavior is itself a signal:** Bulk API job deletion within seconds of completion is rare in legitimate use and worth alerting on.
- **Attribution remains soft:** Public claim by ShinyHunters with no shared private IOCs leaves Mandiant's UNC6395 designation as the most defensible label.

---

## 16. Open Questions

- How did the actor first gain access to Salesloft's GitHub repositories in March 2025?
- Were any other Salesloft applications beyond Drift compromised during the GitHub access window?
- What is the full count of victim Salesforce tenants?
- Have any of the harvested AWS or Snowflake credentials been operationalized in observed downstream intrusions?
- Is the data being held for extortion, sold on a forum, or staged for public leak?
- Does activity overlap meaningfully with prior ShinyHunters campaigns, or is the public claim opportunistic?

---

## 17. References

| Source | Title | Date | Link |
|---|---|---|---|
| Google Threat Intelligence Group (Google Cloud Blog) | Widespread Data Theft Targets Salesforce Instances via Salesloft Drift | 2025-08 | [cloud.google.com](https://cloud.google.com/blog/topics/threat-intelligence/data-theft-salesforce-instances-via-salesloft-drift) |
| Cloudflare Blog | The impact of the Salesloft Drift breach on Cloudflare and our customers | 2025-08 | [blog.cloudflare.com](https://blog.cloudflare.com/response-to-salesloft-drift-incident/#detailed-event-timeline) |
| Permiso Security | Anatomy of the Salesloft Breach: Detection, Response, and Lessons Learned | 2025 | [permiso.io](https://permiso.io/blog/anatomy-of-the-salesloft-breach) |