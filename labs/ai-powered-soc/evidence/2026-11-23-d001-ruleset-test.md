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

## Negative synthetic test

A second compact JSON event represented ordinary PowerShell execution without any of the D001 command-line indicators:

```powershell
powershell.exe -NoLogo -NoProfile -Command "Write-Output 'SOC_LAB_D001_BENIGN'"
```

Observed output:

- Phase 1: Completed pre-decoding.
- Phase 2: JSON decoder extracted the image, command line, parent image, Sysmon channel, and Event ID.
- No Phase 3 rule match was reported.

**Result:** Negative synthetic test passed. The benign command did not match custom rule 100500.

## Test summary

| Test | Result |
|---|---|
| Positive synthetic event with `-ExecutionPolicy Bypass` | Pass — rule 100500, level 8 |
| Negative synthetic ordinary PowerShell event | Pass — no rule 100500 match |
| Live positive endpoint test | Pending |
| Live negative endpoint test | Pending |

## Next tests

Wazuh documentation states that saving custom-rule changes is sufficient for Ruleset Test, but the Wazuh manager must be restarted before the updated rules generate live alerts. After a successful Ruleset Test:

1. Restart the Wazuh manager container and confirm it returns to a healthy running state.
2. Execute a harmless PowerShell command with `-ExecutionPolicy Bypass` on the lab endpoint and search Wazuh alerts for rule 100500.
3. Execute ordinary PowerShell and confirm rule 100500 does not trigger in live telemetry.


## Live endpoint test — Sysmon capture confirmed (2026-11-24)

A fresh benign live test was executed on the Windows 11 endpoint using PowerShell with `-ExecutionPolicy Bypass` and a unique output marker:

```text
SOC_LAB_D001_LIVE_20261124_011505
```

The elevated PowerShell query returned a Sysmon Event ID 1 record with:

| Field | Observation |
|---|---|
| Event ID | 1 — Process Create |
| UTC time | `2026-11-23 19:45:05.510` |
| Image | Windows PowerShell 5.1 executable |
| Parent image | Windows PowerShell 5.1 executable |
| Command line | Contains `-ExecutionPolicy Bypass` and the unique test marker |

**Conclusion:** Live Windows process generation and local Sysmon capture are confirmed. This evidence does not yet confirm Wazuh agent forwarding, manager rule processing, or a live alert from rule 100500.

### Next diagnostic

Search Wazuh alerts for the unique marker and inspect any matching built-in alert. Then submit an equivalent single-line JSON event to the manager's `/var/ossec/bin/wazuh-logtest` to determine whether the manager has loaded custom rule 100500. Compare the logtest result with the Dashboard Ruleset Test result.


## Manager-side wazuh-logtest validation — passed (2026-11-24)

The same compact synthetic Sysmon Event ID 1 JSON was piped into the running Wazuh Manager 4.13.1 container:

```powershell
$json | docker exec -i single-node-wazuh.manager-1 /var/ossec/bin/wazuh-logtest
```

Observed result:

- Phase 1: pre-decoding completed.
- Phase 2: JSON decoder extracted `win.eventdata.image`, `commandLine`, `parentImage`, `win.system.channel`, and `win.system.eventID`.
- Phase 3: custom rule **100500**, level **8**, matched.
- Description: `SOC D001: Suspicious PowerShell execution pattern on predator`.
- ATT&CK: T1059.001 (Execution / PowerShell).

**Conclusion:** The running manager's `wazuh-logtest` engine has loaded and can match rule 100500 against this synthetic JSON representation. This still does not prove that the live Windows EventChannel record was forwarded, processed by the manager, and indexed as a live alert. The next task is to search Wazuh for the unique live marker and inspect the matching raw event if found.



## Interpretation correction — synthetic JSON versus EventChannel

The positive and negative tests documented earlier used the `json` decoder. They validated the initial field conditions but did not reproduce the real Windows EventChannel decoder hierarchy. For native Sysmon Event ID 1, Wazuh applies built-in parent rule **61603**, which is level 0 and adds the `sysmon_event1` group. The custom rules have now been corrected to use `<if_sid>61603</if_sid>`.

Therefore, the earlier synthetic test results are retained as historical JSON-condition tests, not as proof that the corrected D001 child rule matches native EventChannel events. The next required evidence is a live Wazuh alert with rule ID 100500 from the endpoint marker event.

