# KQL Translations, UNC6395 / Salesloft Drift Package

One file. R2 is the only rule here whose correlation cannot be expressed in Sigma.

| File | Sigma source | Sentinel tables |
|---|---|---|
| `R2_T1550.001_serviceprincipal_no_human.kql` | `R2_T1550.001_oauth_signin_no_human_precursor.yml` | `AADServicePrincipalSignInLogs` joined to `SigninLogs` |

## Why This One Exists

Sigma has no correlation type for the absence of an event.
Its four types cover counting and co-occurrence, not "nothing matching happened in the prior window".

So the Sigma file for R2 is only the trigger half.
On its own it matches every successful service-principal sign-in in the tenant.
The `leftanti` join in this `.kql` is what isolates the sign-ins with no human counterpart in 24 hours.

This file is the rule. The YAML is not.

## Why It Is Hand-Written

| Reason | Detail |
|---|---|
| Table coverage | The Kusto backend for pySigma maps Defender XDR, ASIM and Azure Monitor. Not Entra ID `SigninLogs` |
| Correlations | The backend does not implement them at all |

`sigma convert -t kusto` on this rule yields an unsupported-feature error.
The Sigma file and this one are maintained side by side, neither derived from the other.
Change one, change the other.

## Status

Not run against data.
The lab has no Entra ID tenant, so the Microsoft side of R2 is untested.
The Salesforce side ran against real Login History and correctly stayed silent.
See [`../../validation/Validation.md`](../../validation/Validation.md).
