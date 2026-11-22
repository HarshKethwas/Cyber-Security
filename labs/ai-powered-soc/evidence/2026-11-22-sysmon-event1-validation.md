# Evidence Record — Sysmon Process Creation Baseline

**Date:** 2026-11-22  
**Endpoint:** Windows 11 lab endpoint (hostname and account intentionally omitted)  
**Source:** Local Windows Event Log — `Microsoft-Windows-Sysmon/Operational`  
**Event:** Sysmon Event ID 1 — Process Create  
**Validation type:** Local telemetry generation

## Observed: account and user discovery

A controlled command was executed:

```powershell
whoami.exe /all
```

The captured Sysmon Event ID 1 record included:

| Field | Sanitized observation |
|---|---|
| Event ID | 1 |
| Image | `C:\Windows\System32\whoami.exe` |
| Command line | `"C:\WINDOWS\system32\whoami.exe" /all` |
| Parent image | `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe` |
| Sysmon RuleName | `technique_id=T1033, technique_name=System Owner/User Discovery` |
| Process GUID | Present in source event |
| Parent Process GUID | Present in source event |
| Hashes | Present in source event; values intentionally not copied here |

This confirms that Sysmon recorded the process and its parent relationship. The Sysmon RuleName metadata labels this activity as T1033 (System Owner/User Discovery).

## Observed: encoded PowerShell test execution

A benign encoded PowerShell command was created from this harmless payload:

```powershell
Write-Output 'SOC_LAB_ENCODED_BASELINE'
```

It was launched with the `-EncodedCommand` argument. The console displayed:

```text
SOC_LAB_ENCODED_BASELINE
```

This confirms that the controlled test process executed successfully. The screenshot evidence captured the command and console output, but did not include the complete corresponding Sysmon Event ID 1 record with its full command line. That event still needs to be isolated for rule validation.

## Validation status

| Check | Result |
|---|---|
| Sysmon Event ID 1 generation | Observed |
| `whoami.exe /all` captured | Observed |
| Parent process captured | Observed |
| Sysmon T1033 RuleName metadata | Observed |
| Benign encoded PowerShell execution | Observed |
| Full encoded PowerShell Sysmon record | Pending |
| Wazuh receipt of these exact events | Not yet evidenced in this record |
| Wazuh decoded field names | Pending |
| Custom rule positive / negative tests | Pending |

## Next validation step

Find these same events in Wazuh and inspect the full alert/event JSON. Confirm the decoded field paths for:

- `win.system.eventID`
- `win.system.channel`
- `win.eventdata.image`
- `win.eventdata.commandLine`
- `win.eventdata.parentImage`
- `win.eventdata.parentCommandLine`

Do not infer Wazuh ingestion from the local Windows Event Log alone. Use the Wazuh event record to prove the end-to-end path.

**Privacy:** Usernames, host identifiers, SIDs, hashes, and other endpoint-specific values are intentionally omitted from this public evidence note.
