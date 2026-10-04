# Password Guessing / Brute Force Detection

Detect repeated failed interactive Microsoft Entra ID sign-ins against the same account from the same source IP within a short time window.

## Files

- [Detection.kql](Detection.kql)
- [metadata.yaml](metadata.yaml)
- [test-cases.md](test-cases.md)
- [references.md](references.md)

## Detection summary

**Data source:** EntraIdSignInEvents  
**Window:** 15 minutes  
**Threshold:** 8 failed sign-ins  
**Technique:** T1110.001 — Password Guessing  
**Default severity:** Medium

## Why it is separate from password spraying

Password guessing repeatedly targets an account. Password spraying targets many different accounts from the same source. This query is designed specifically for the first pattern.

## Investigation

Review the targeted account, source IP, applications, user agent, Conditional Access/MFA outcome, and any successful sign-in that follows the failed attempts.

Treat the detection as a suspicious authentication pattern, not proof of compromise.
