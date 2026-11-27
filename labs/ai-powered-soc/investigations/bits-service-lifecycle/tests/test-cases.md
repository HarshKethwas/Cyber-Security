# Wazuh test cases

These fixtures validate intended rule behavior only. They are synthetic examples, not endpoint evidence.

| Test | Input | Expected custom rule | Handling |
|---|---|---:|---|
| T1 | System Event ID 7040 for service BITS, Demand Start → Automatic | 100520 | Level 3 lifecycle context |
| T2 | Sysmon Event ID 13 write to BITS\Start, value 0x00000003 | 100521 | Level 3 registry-change context |
| T3 | Same registry path, value 0x00000004 | 100521 + 100522 | Level 12 disabled-state validation |
| T4 | Sysmon Event ID 1 command line sc.exe config BITS start= auto | 100523 | Review user, parent, integrity and authorization |
| T5 | Sysmon Event ID 1 execution of bitsadmin.exe | 100524 | Inspect job details; dual-use utility |

## Validation steps

1. Confirm built-in parent IDs (61104, 61615) and process group (sysmon_event1) against installed Wazuh 4.13.1.
2. Run `wazuh-analysisd -t` after installing the custom XML.
3. Paste each newline-delimited JSON fixture separately into `wazuh-logtest`.
4. Confirm decoded fields and custom ID. Adjust rules and fixtures together if field names differ.
5. Test positive and negative cases. Normal BITS lifecycle transitions must not generate high-severity incidents.
6. Record manager version, ruleset revision, timestamp, output and analyst interpretation.

## Important

A successful synthetic `wazuh-logtest` fixture is not end-to-end endpoint validation. Runtime testing with real EventChannel records remains required.
