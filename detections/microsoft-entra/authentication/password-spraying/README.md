# Password Spraying Detection

Detect a source IP producing failed interactive Microsoft Entra ID sign-ins against multiple distinct accounts within a one-hour window.

## Files

- [Detection.kql](Detection.kql)
- [metadata.yaml](metadata.yaml)
- [test-cases.md](test-cases.md)
- [references.md](references.md)

## Detection summary

**Data source:** EntraIdSignInEvents  
**Window:** 1 hour  
**Threshold:** 5 distinct users and 10 total failures  
**Technique:** T1110.003 — Password Spraying  
**Default severity:** Medium; raise based on corroborating evidence

## Detection logic

The query identifies one source IP failing authentication against multiple accounts. That behavioral pattern is more consistent with password spraying than single-account password guessing.

## Investigation

Review all targeted users, successful authentications from the source, privileged accounts among the targets, Conditional Access/MFA results, source reputation, and related endpoint/email activity.

Treat the result as a suspicious pattern requiring analyst validation.
