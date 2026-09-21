# Detection Standard

Use this template for every new detection added to the repository.

## Metadata

| Field | Example |
|---|---|
| Name | Entra Password Spray |
| Status | Active / Experimental / Deprecated |
| Platform | Microsoft Defender XDR |
| Data source | EntraIdSignInEvents |
| Severity | Low / Medium / High / Critical |
| Confidence | Low / Medium / High |
| ATT&CK | T1110.003 |
| Owner | Harsh Kethwas |
| Version | 1.0 |

## 1. Objective

What attacker behavior or security problem does the detection address?

## 2. Threat scenario

Describe a realistic attack path and why the behavior is security-relevant.

## 3. Telemetry requirements

List the tables, fields, retention assumptions, and any prerequisites.

## 4. Detection logic

Provide the exact query and make threshold values easy to tune.

## 5. Why it works

Explain the behavioral signal. Avoid relying only on indicator lists.

## 6. MITRE ATT&CK

Map only techniques supported by observed behavior. Use sub-techniques when evidence supports them.

## 7. Severity and confidence

Keep these separate:

- **Severity** describes potential operational impact.
- **Confidence** describes how strongly the detection indicates malicious activity.

## 8. False positives

Document expected legitimate activity and common environmental noise.

## 9. Tuning

Document:

- exclusions,
- thresholds,
- baselines,
- allowlists,
- environment-specific assumptions.

## 10. Validation

Include at least:

- one positive test,
- one negative test,
- one realistic benign edge case.

Record the expected query result.

## 11. Investigation pivots

Show what an analyst should query next.

Examples:

- user,
- device,
- IP,
- parent process,
- child process,
- network destination,
- file hash,
- successful authentication.

## 12. Response

Describe containment, eradication, credential actions, blocking, or escalation appropriate to the use case.

## 13. Known limitations

State what the detection cannot determine by itself.

A detection should make its limitations visible rather than implying more certainty than the telemetry supports.
