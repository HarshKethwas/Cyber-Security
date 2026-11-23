# D001 — Ruleset Test Evidence

**Test date:** 2026-11-23  
**Detection:** D001 — Suspicious PowerShell execution  
**Custom rule:** 100500  
**Test type:** Positive synthetic JSON event in Wazuh Dashboard Ruleset Test  
**Result:** Pass

## Input event

A compact, single-line JSON event was supplied to Ruleset Test. It represented Sysmon Event ID 1 from `Microsoft-Windows-Sysmon/Operational`, with:

- Image: Windows PowerShell executable
- Command line: PowerShell launched with `-ExecutionPolicy Bypass`
- Parent image: Windows PowerShell executable
- Host field: lab endpoint (value omitted here)

The command payload was a harmless marker-writing command. The event was synthetic JSON for Ruleset Test; it was not a captured live event.

## Observed test output

### Phase 1 — Pre-decoding

Completed successfully. The full event was received as one JSON line.

### Phase 2 — Decoding

Decoder: `json`

The following fields were extracted:

- `win.eventdata.commandLine`
- `win.eventdata.image`
- `win.eventdata.parentImage`
- `win.system.channel`
- `win.system.computer`
- `win.system.eventID`
- `win.system.providerName`
- `win.system.severityValue`

### Phase 3 — Rule filtering

Matched:

| Output | Value |
|---|---|
| Rule ID | `100500` |
| Level | `8` |
| Description | `SOC D001: Suspicious PowerShell execution pattern on [lab host]` |
| ATT&CK technique | `T1059.001` |
| ATT&CK tactic | Execution |
| Result | Alert to be generated |

## Conclusion

D001 passed its positive **synthetic Ruleset Test**. Wazuh's JSON decoder extracted the expected event fields, and custom rule 100500 matched the execution-policy-bypass command-line indicator.

This does not yet prove that the live Windows event was ingested and generated an alert in `wazuh-alerts-*`. A negative Ruleset Test and a live endpoint test remain pending.

## Next tests

1. Negative synthetic test: ordinary PowerShell command without any D001 indicators; expected result is no match for rule 100500.
2. Live positive test: execute a harmless PowerShell command with `-ExecutionPolicy Bypass` on the lab endpoint and search Wazuh alerts for rule 100500.
3. Live negative test: execute ordinary PowerShell and confirm rule 100500 does not trigger.

