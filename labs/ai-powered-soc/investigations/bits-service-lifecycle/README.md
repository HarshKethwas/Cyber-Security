# BITS Service Lifecycle Investigation

Evidence-led Windows service lifecycle investigation from the AI-Powered SOC lab.

**Disposition:** The repeated Demand Start ↔ Automatic transitions are consistent with Microsoft's documented BITS lifecycle. The supplied evidence did not establish malicious BITS persistence or endpoint compromise. Historical attribution remains incomplete.

## Contents
- [Detailed investigation](./investigation.md)
- [Wazuh custom rules](./wazuh/windows_bits_rules.xml)
- [Synthetic logtest fixtures](./wazuh/logtest-samples.jsonl)
- [Test cases](./tests/test-cases.md)
- [Evidence timeline](./evidence/timeline.csv)
- [Collector usage](./README-collector.md)
- [References](./references/sources.md)

## Key findings
- Windows Event ID 7040 (Wazuh rule 61104) recorded repeated BITS startup-type changes.
- Microsoft documents delayed automatic startup when BITS jobs are active and Demand Start when no jobs are active. A transition alone is not proof of abuse.
- The active Sysmon configuration excluded the BITS service Start registry value, suppressing Event ID 13 until the targeted exclusion was removed.
- A controlled test confirmed Event ID 13 visibility and showed `sc.exe` as the requesting tool and `services.exe` as the registry writer.
- OneDrive task execution and a C# compiler launch were time-correlated with separate changes; causation was not demonstrated.

## Wazuh rule design

Local IDs use **100520–100524** to avoid a collision with existing repository rule 100510.

| Rule | Level | Purpose |
|---|---:|---|
| 100520 | 3 | BITS Event ID 7040 lifecycle context |
| 100521 | 3 | Sysmon 13 write to BITS Start |
| 100522 | 12 | BITS Start set to Disabled |
| 100523 | 7 | Explicit `sc.exe config BITS` execution |
| 100524 | 6 | `bitsadmin.exe` execution; dual-use hunting pivot |

**Validation status:** XML is well-formed and synthetic JSONL fixtures parse. Runtime testing against the Wazuh 4.13.1 manager and actual decoded EventChannel records remains outstanding. Verify parent IDs and decoded fields before deployment; run `wazuh-analysisd -t` and `wazuh-logtest`.

## Evidence handling
The public write-up generalizes the local profile name. Raw endpoint data can contain usernames, paths, command lines, job identifiers and URLs; sanitize before sharing.

## Limitations
The Sysmon exclusion prevented historical registry-write attribution before the fix. The final BITS state after the last supplied transition was not provided. No endpoint-wide compromise assessment or complete binary verification was performed. This is an educational lab case, not a confirmed malware incident.

## Primary reference
[Microsoft Learn — BITS Startup Type](https://learn.microsoft.com/en-us/windows/win32/bits/bits-startup-type)