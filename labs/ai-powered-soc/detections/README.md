# Detection Engineering — Baseline v0.2

This directory tracks custom detections for the AI-Powered SOC Lab, built around Windows Sysmon process-creation telemetry.

> **Status:** Initial telemetry confirmed; first custom rules drafted, not yet deployed  
> **Data source:** Windows Sysmon — Event ID 1 (Process Create)  
> **Custom rule IDs:** 100500–100510  
> **Rule file:** [soc_windows_baseline.xml](./wazuh/rules/soc_windows_baseline.xml)

## Detection catalogue

| Detection ID | Name | Custom rule ID | ATT&CK mapping | Status |
|---|---|---:|---|---|
| D001 | Suspicious PowerShell execution | 100500 | T1059.001 | Drafted; testing pending |
| D002 | Encoded PowerShell from non-PowerShell parent | 100501 | T1059.001, T1027 | Drafted; testing pending |
| D003 | `whoami.exe /all` identity discovery | 100510 | T1033 | Drafted; testing pending |
| D004 | Suspicious LOLBin usage | 100520 | To be implemented | Planned |
| D005 | Suspicious parent-child process relationships | 100530 | To be implemented | Planned |

## Confirmed lab telemetry

### Encoded PowerShell — Wazuh alert observed

The lab's benign `-EncodedCommand` test reached Wazuh and generated **rule 92057, level 12**, mapped to ATT&CK T1059.001. The event was decoded by `windows_eventchannel` and included Sysmon Event ID 1, the PowerShell image and command line, and its parent image.

Rule 92057 is existing Wazuh coverage for an encoded PowerShell child process launched by a PowerShell parent. Our custom D002 rule is deliberately narrower in a different dimension: it looks for encoded PowerShell launched by a **non-PowerShell parent**, extending coverage without intentionally duplicating the observed rule 92057 condition.

### Account discovery — local Sysmon event observed

The local Sysmon Event ID 1 record for `whoami.exe /all` was captured with `powershell.exe` as its parent and RuleName metadata identifying T1033. No corresponding Wazuh alert JSON has been supplied yet.

The absence of this event from `wazuh-alerts-*` does not by itself prove an ingestion failure. Wazuh's base Sysmon Event ID 1 rule is a level-0 grouping rule; ordinary process events that do not match an alerting child rule do not appear in the alerts index. To inspect all received events, configure JSON archives and enable their indexing, or use a custom rule such as D003 to create an alert for the behavior.

See the [sanitized evidence record](../evidence/2026-11-22-sysmon-event1-validation.md).

## Telemetry fields confirmed in the Wazuh event

The supplied Wazuh JSON confirms these decoded field names for Sysmon Event ID 1:

| Rule-engine field | Evidence |
|---|---|
| `win.system.eventID` | `1` |
| `win.system.channel` | `Microsoft-Windows-Sysmon/Operational` |
| `win.eventdata.image` | PowerShell executable path |
| `win.eventdata.commandLine` | Full command line containing `-EncodedCommand` |
| `win.eventdata.parentImage` | Parent executable path |
| `win.eventdata.parentCommandLine` | Parent command line |
| `win.eventdata.processGuid` | Present |
| `win.eventdata.parentProcessGuid` | Present |
| `win.eventdata.user` | Present |

In the indexed alert JSON, these are nested under `data.win...`. In Wazuh rule XML, the field names are referenced as `win.eventdata.image`, `win.eventdata.commandLine`, and so on (without the JSON wrapper `data.` prefix). This field naming is also demonstrated by Wazuh rule 92057, which matched the submitted event.

## False-positive case study — Rule 92213

A Wazuh rule 92213 alert (level 15) was inspected on 2026-11-22. It was caused by Windows PowerShell creating:

`%LOCALAPPDATA%\Temp\__PSScriptPolicyTest_[random].ps1`

The supplied Sysmon Event ID 11 event identifies `powershell.exe` as the creator. This filename pattern is associated with PowerShell script execution-policy test behavior, so the specific lab event is assessed as likely benign. Rule 92213 matches broad Temp-path plus script/executable-extension conditions; it does not establish that a file was transferred from an external source. Its T1105 mapping should therefore not be treated as proof of ingress transfer in this event.

- [Full sanitized analysis and proposed tuning](../evidence/2026-11-22-rule-92213-false-positive.md)
- [Draft narrow level-3 severity tuning](./wazuh/rules/noise_reduction_draft.xml)

The tuning is **draft only**. It retains a low-priority alert rather than silently suppressing the event. Validate the parent/child match with `wazuh-logtest` before deployment. Do not suppress all PowerShell files in Temp or disable rule 92213 globally.

## D001 — first positive Ruleset Test passed (2026-11-23)

The Dashboard Ruleset Test was supplied with compact, single-line synthetic JSON Sysmon Event ID 1 records. The positive event decoded the expected fields and matched custom rule **100500**, level **8**, mapped to T1059.001 (Execution). A negative event representing ordinary PowerShell execution decoded successfully but produced no Phase 3 rule match.

Both **synthetic positive and negative tests passed**. Live Windows-to-Wazuh positive and negative validation remain pending. See the [D001 test evidence](../evidence/2026-11-23-d001-ruleset-test.md).

## Rule implementation

The initial custom XML is committed at:

`wazuh/rules/soc_windows_baseline.xml`

It contains three draft rules:

- **100500 / D001:** PowerShell execution with selected suspicious command-line indicators such as execution-policy bypass, hidden window, download, or dynamic execution patterns.
- **100501 / D002:** Encoded PowerShell launched by a parent other than PowerShell or PowerShell 7. This complements the observed existing rule 92057.
- **100510 / D003:** `whoami.exe /all` identity and privilege discovery.

The file is a draft. These rules have **not yet been deployed, parsed by this Wazuh manager, or positively and negatively validated**. Do not treat them as active protections until the steps below pass.

## Detection hypotheses and tuning

### D001 — Suspicious PowerShell execution

**Behavior:** PowerShell or PowerShell 7 starts with selected execution options or command patterns that warrant investigation.

Initial indicators include execution-policy bypass, hidden window, `DownloadString`, `Invoke-WebRequest`, `Start-BitsTransfer`, `FromBase64String`, and `IEX`.

**Tuning:** These are context signals, not proof of malicious activity. Administrative scripts and software deployment tools may use some of these features. Validate parent, user, path, and command-line context; add exceptions only when justified by evidence.

### D002 — Encoded PowerShell commands

**Behavior:** PowerShell is launched with an encoded-command parameter.

The currently observed Wazuh rule 92057 detects the specific pattern where a PowerShell parent starts an encoded PowerShell child. Custom rule 100501 is intended to detect encoded PowerShell launched by a non-PowerShell parent.

**Tuning:** Encoded commands are not automatically malicious. Decode Base64 as text for inspection; never execute the decoded content as part of triage.

### D003 — Account and domain discovery

**Behavior:** A process enumerates local/domain users, groups, or identity context.

The first custom rule, 100510, targets the observed `whoami.exe /all` behavior. Future related rules will cover `net.exe user`, `net.exe localgroup`, `net.exe group`, `nltest.exe /domain_trusts`, and relevant PowerShell discovery cmdlets.

**Tuning:** Inventory tools and administrative scripts may legitimately perform discovery. Add separate rules with accurate ATT&CK mappings rather than assigning every discovery technique to one broad rule.

### D004 — Suspicious LOLBin usage

**Behavior:** A legitimate Windows utility is used with arguments associated with proxy execution, script execution, download, or file decoding.

Initial binaries to evaluate: `certutil.exe`, `mshta.exe`, `rundll32.exe`, `regsvr32.exe`, `bitsadmin.exe`, `wscript.exe`, and `cscript.exe`.

**Tuning:** Binary execution alone is insufficient. Require suspicious arguments, paths, parent process, or corroborating telemetry.

### D005 — Suspicious parent-child process relationships

**Behavior:** An application such as Office launches a scripting engine, command shell, or proxy-execution utility.

Initial parent processes: `WINWORD.EXE`, `EXCEL.EXE`, `POWERPNT.EXE`, `OUTLOOK.EXE`, and `ONENOTE.EXE`.

Initial child processes: `powershell.exe`, `pwsh.exe`, `cmd.exe`, `wscript.exe`, `cscript.exe`, `mshta.exe`, `rundll32.exe`, and `regsvr32.exe`.

**Tuning:** Parent-child combinations need business-context validation. Process GUIDs can support correlation across related Sysmon events.

## Validation methodology

Every custom detection must pass:

1. **Telemetry:** Expected Sysmon event is generated.
2. **Decoder:** Wazuh extracts the expected event ID and fields.
3. **Positive test:** Controlled behavior matches the intended custom rule.
4. **Negative test:** Benign or unrelated behavior does not produce an unintended alert.
5. **False-positive review:** Legitimate administrative behavior is documented.
6. **Live validation:** The custom rule ID appears in Wazuh alerts after deployment.
7. **Evidence:** Sanitized event, logtest output, alert JSON, and test notes are retained.

Use `/var/ossec/bin/wazuh-logtest` to test the rules before relying on them. Save rule files under `/var/ossec/etc/rules/`; after successful testing, restart the Wazuh manager to apply the rules to live events.

## Safe positive tests planned

### D001 — execution-policy bypass indicator with harmless command

```powershell
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -Command "Write-Output 'SOC_LAB_D001_BYPASS_TEST'"
```

This does not download or execute external code; it tests whether the command-line indicator matches.

### D002 — encoded PowerShell from cmd.exe

Generate the Base64 string from a harmless payload and launch the child PowerShell process via `cmd.exe` so its parent image is not PowerShell. This is designed to test custom rule 100501 rather than the previously observed rule 92057.

```powershell
$payload = "Write-Output 'SOC_LAB_D002_CMD_PARENT'"
$encoded = [Convert]::ToBase64String(
    [Text.Encoding]::Unicode.GetBytes($payload)
)
$ps = "$env:WINDIR\System32\WindowsPowerShell\v1.0\powershell.exe"
$cmd = "`"$ps`" -NoLogo -NoProfile -EncodedCommand $encoded"

Start-Process -FilePath "$env:WINDIR\System32\cmd.exe" -ArgumentList "/c $cmd" -Wait -NoNewWindow
```

### D003 — identity discovery

```powershell
whoami.exe /all
```

This was already observed locally in Sysmon. Repeat it after deployment to confirm custom rule 100510 generates a Wazuh alert.

## Test record

| Test | Expected result | Actual result |
|---|---|---|
| Existing D002 encoded PowerShell test | Existing rule 92057 triggers when PowerShell is the parent | Confirmed: rule 92057, level 12 |
| Custom D001 positive test | Rule 100500 triggers | Pending |
| Custom D001 benign test | No alert from rule 100500 | Pending |
| Custom D002 with cmd.exe parent | Rule 100501 triggers | Pending |
| Custom D003 `whoami.exe /all` | Rule 100510 triggers | Pending |

## References

- [Wazuh custom rules](https://documentation.wazuh.com/current/user-manual/ruleset/rules/custom.html)
- [Wazuh rules XML syntax](https://documentation.wazuh.com/current/user-manual/ruleset/ruleset-xml-syntax/rules.html)
- [Wazuh testing decoders and rules](https://documentation.wazuh.com/current/user-manual/ruleset/testing.html)
- [Wazuh Sysmon ruleset](https://github.com/wazuh/wazuh-ruleset/blob/master/rules/0595-win-sysmon_rules.xml)
- [Wazuh rule 92057 — encoded PowerShell child process](https://detections.org/detections/wazuh/wazuh/92057/)
- [Wazuh event archiving](https://documentation.wazuh.com/current/user-manual/manager/event-logging.html)
- [Microsoft Sysmon events](https://learn.microsoft.com/en-us/windows/security/operating-system-security/sysmon/sysmon-events)
- [MITRE ATT&CK](https://attack.mitre.org/)

---

*The initial custom XML is draft code. Only mark a rule implemented after Wazuh accepts it, and only mark it validated after live positive and negative tests.*
