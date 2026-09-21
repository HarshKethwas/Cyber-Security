# Detection Engineering Library

This repository uses a single canonical detection structure.

Each detection should be treated as a deployable SOC artifact rather than only a KQL snippet.

## Detection standard

Every production-shaped detection should document:

- **Objective** — the attacker behavior or security problem
- **Threat scenario** — why the behavior matters
- **Data source / telemetry** — required tables and fields
- **Detection logic** — exact KQL or other query
- **MITRE ATT&CK** — only techniques supported by the observed behavior
- **Severity** — operational impact and escalation conditions
- **Confidence** — how strongly the logic indicates malicious activity
- **False positives** — known legitimate causes
- **Tuning** — environment-specific exclusions and thresholds
- **Validation** — expected positive and negative test cases
- **Investigation pivots** — what the analyst checks next
- **Response** — recommended containment and remediation actions

## Current canonical projects

| Detection | Platform | Primary telemetry | Focus |
|---|---|---|---|
| [Entra Password Spray](../KQL%20Queeries/Brute-Force-and-Password-Spray-Detection/) | Microsoft Defender XDR | `EntraIdSignInEvents` | Identity / Credential Access |
| [Office Child Process](../KQL%20Queeries/Office-Application-Child-Process-Hunting/) | Microsoft Defender XDR | `DeviceProcessEvents` | Initial Access / Execution |
| [Scheduled Task Persistence](../KQL%20Queeries/Suspicious-Scheduled-Task-Persistence/) | Microsoft Defender XDR | `DeviceProcessEvents` | Persistence |
| [Suspicious PowerShell](../KQL%20Queeries/Suspicious_PowerShell-Execution/) | Microsoft Defender XDR | `DeviceProcessEvents` | Execution / Defense Evasion |

The existing legacy query folders remain available for compatibility while they are migrated into the canonical structure.

## Quality bar

A query is not considered complete because it returns suspicious rows. A portfolio-quality detection should show how the result becomes an analyst decision: why it fired, how to validate it, how to reduce noise, and what to do next.
