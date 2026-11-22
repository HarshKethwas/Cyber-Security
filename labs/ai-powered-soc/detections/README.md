# Detection Engineering — Baseline v0.1

This directory tracks the first five custom detections planned for the AI-Powered SOC Lab. The detections are designed for Wazuh using Windows Sysmon process-creation telemetry.

> **Status:** Baseline defined; implementation and validation pending  
> **Data source:** Windows Sysmon — Event ID 1 (Process Create)  
> **Rule IDs:** Reserved in the 100500–100530 range

## Detection catalogue

| Detection ID | Name | Planned Wazuh rule ID | ATT&CK mapping | Initial status |
|---|---|---:|---|---|
| D001 | Suspicious PowerShell execution | 100500 | T1059.001 | Planned |
| D002 | Encoded PowerShell commands | 100501 | T1059.001, T1027 | Planned |
| D003 | Account and domain discovery | 100510 | T1087, T1069 | Planned |
| D004 | Suspicious LOLBin usage | 100520 | T1218, T1105, T1140 | Planned |
| D005 | Suspicious parent-child process relationships | 100530 | T1059.001, T1204.002 | Planned |

ATT&CK mappings are starting hypotheses and will be refined to the observed behavior and exact sub-technique during implementation.

## Telemetry fields to validate

The initial rules are expected to use these decoded Sysmon fields. Confirm their exact names and values against a real event from this Wazuh deployment before writing production rules.

| Field | Purpose |
|---|---|
| `win.system.eventID` | Identify Sysmon Event ID 1 |
| `win.eventdata.image` | Executable path |
| `win.eventdata.commandLine` | Full process command line |
| `win.eventdata.parentImage` | Parent executable path |
| `win.eventdata.parentCommandLine` | Parent process command line |
| `win.eventdata.user` | Account running the process |
| `win.eventdata.processGuid` | Process correlation identifier |
| `win.eventdata.parentProcessGuid` | Parent process correlation identifier |
| `win.eventdata.hashes` | Available process hashes |

Field availability can differ with collection and decoding configuration. Do not assume a missing field is populated.

## Lab evidence received — 2026-11-22

A local Windows Sysmon Event ID 1 sample was captured for `whoami.exe /all`. It records `powershell.exe` as the parent image and includes Sysmon RuleName metadata identifying T1033 (System Owner/User Discovery). A benign PowerShell `-EncodedCommand` test also executed and printed its expected marker.

This validates local Sysmon process telemetry and gives us a concrete parent-child and discovery test case. It does **not yet prove** that the same events reached Wazuh or identify the exact Wazuh-decoded field paths. The full encoded-process Sysmon event and Wazuh event JSON are still required before final rule tuning.

See [the sanitized evidence record](../evidence/2026-11-22-sysmon-event1-validation.md).

## Detection hypotheses and logic

### D001 — Suspicious PowerShell execution

**Behavior:** PowerShell or PowerShell 7 starts with suspicious execution options or script content.

Initial command-line indicators to evaluate:

- Hidden window options such as `-WindowStyle Hidden`
- Execution policy bypass options
- Non-interactive execution combined with other suspicious behavior
- Download-and-execute patterns such as `DownloadString`, `Invoke-WebRequest`, or `IEX`
- Base64 decoding or dynamically executed content

**Tuning:** Do not alert on every PowerShell process. Evaluate combinations of executable, arguments, parent process, user context, and environment baselines.

### D002 — Encoded PowerShell commands

**Behavior:** PowerShell is launched with `-EncodedCommand` or its accepted abbreviated form.

**Tuning:** Encoded commands are not automatically malicious. Capture the full command line, decode the Base64 content safely during analysis, and inspect the resulting script. Do not execute decoded content during triage.

### D003 — Account and domain discovery

**Behavior:** A process enumerates local/domain users, groups, or domain trust information.

Initial commands to evaluate:

- `net.exe user`
- `net.exe localgroup`
- `net.exe group`
- `whoami.exe /all`
- `nltest.exe /domain_trusts`
- PowerShell commands such as `Get-LocalUser`, `Get-LocalGroup`, `Get-ADUser`, or `Get-ADGroup`

**Tuning:** Administrative scripts and inventory tools may perform these operations. Capture command arguments and user/parent context.

### D004 — Suspicious LOLBin usage

**Behavior:** A legitimate Windows utility is used with arguments associated with proxy execution, script execution, download, or file decoding.

Initial binaries and command-line patterns to evaluate:

| Binary | Context to investigate |
|---|---|
| `certutil.exe` | URL retrieval, cache operations, or file decoding |
| `mshta.exe` | Remote HTA, JavaScript, or VBScript execution |
| `rundll32.exe` | Unusual DLL paths or script/URL invocation |
| `regsvr32.exe` | Suspicious scriptlet or remote registration patterns |
| `bitsadmin.exe` | Unexpected transfer jobs |
| `wscript.exe` / `cscript.exe` | Scripts launched from unusual locations or parents |

**Tuning:** Binary execution alone is insufficient. Require suspicious arguments, paths, parent process, or corroborating telemetry. The first implementation will prioritize a small, explainable set of behaviors over a broad noisy rule.

### D005 — Suspicious parent-child process relationships

**Behavior:** Office applications launch scripting engines, command shells, or proxy execution utilities.

Initial parent processes:

- `WINWORD.EXE`
- `EXCEL.EXE`
- `POWERPNT.EXE`
- `OUTLOOK.EXE`
- `ONENOTE.EXE`

Initial child processes:

- `powershell.exe` / `pwsh.exe`
- `cmd.exe`
- `wscript.exe` / `cscript.exe`
- `mshta.exe`
- `rundll32.exe`
- `regsvr32.exe`

**Tuning:** Validate the actual `parentImage` and `image` fields. Add known legitimate software exceptions only when supported by observed evidence. Consider parent command line and process GUID correlation for deeper investigation.

## Validation methodology

Every detection must pass all of the following before being marked complete:

1. **Telemetry check:** Verify that the endpoint generated the expected Sysmon event.
2. **Decoder check:** Confirm Wazuh exposes the expected event ID and fields.
3. **Positive test:** A controlled test event matches the intended rule.
4. **Negative test:** A benign or unrelated event does not match the rule.
5. **False-positive review:** Document legitimate software and administrative behavior that may trigger it.
6. **Live validation:** Confirm the alert appears in Wazuh after the custom rule is deployed.
7. **Evidence:** Retain sanitized raw event, logtest output, alert JSON, and test notes.

Use `/var/ossec/bin/wazuh-logtest` on the Wazuh server to inspect decoding and rule matches before live deployment. Wazuh documents that the logtest tool evaluates the same rules as its analysis engine; restart the manager after saving custom rules before expecting live alerts to use the new rules.

## Test record template

| Test | Input / activity | Expected result | Actual result | Evidence |
|---|---|---|---|---|
| Positive | Controlled behavior for the detection | Custom rule matches | Pending | Pending |
| Negative | Benign PowerShell / administrative activity | No high-confidence alert | Pending | Pending |
| Live | Repeat controlled behavior on endpoint | Alert visible in Wazuh | Pending | Pending |

## Rule implementation layout

Custom rules will be version-controlled here and deployed to the Wazuh manager's custom rules directory only after validation:

```text
detections/
├── README.md
└── wazuh/
    ├── README.md
    └── rules/
        └── soc_windows_baseline.xml
```

Use the reserved custom IDs above. Do not overwrite built-in Wazuh rule files.

## Current next action

Revalidate the running Docker services, Wazuh agent status, Sysmon service, and one real Sysmon Event ID 1 event. Inspect the event in Wazuh and record the actual decoded fields. Then implement D001 and D002 first, test them with `wazuh-logtest`, and proceed through D003–D005.

## References

- [Wazuh custom rules](https://documentation.wazuh.com/current/user-manual/ruleset/rules/custom.html)
- [Wazuh testing decoders and rules](https://documentation.wazuh.com/current/user-manual/ruleset/testing.html)
- [Wazuh Sysmon ruleset](https://github.com/wazuh/wazuh-ruleset/blob/master/rules/0595-win-sysmon_rules.xml)
- [Microsoft Sysmon events](https://learn.microsoft.com/en-us/windows/security/operating-system-security/sysmon/sysmon-events)
- [MITRE ATT&CK](https://attack.mitre.org/)

---

*This catalogue records the initial detection design. A detection must not be marked implemented or validated until its rule, positive test, negative test, and live result are documented.*
