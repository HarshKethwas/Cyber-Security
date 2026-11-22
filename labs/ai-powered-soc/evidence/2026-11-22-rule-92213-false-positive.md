# False-Positive Analysis — Wazuh Rule 92213

**Date:** 2026-11-22  
**Alert rule:** 92213  
**Severity configured by rule:** Level 15  
**Source event:** Sysmon Event ID 11 — FileCreate  
**Assessment:** Likely benign PowerShell execution-policy test artifact; validate before suppressing

## Observed event

The supplied Wazuh alert JSON contains the following relevant fields:

| Field | Observed value |
|---|---|
| `data.win.system.eventID` | `11` |
| `data.win.system.channel` | `Microsoft-Windows-Sysmon/Operational` |
| `data.win.eventdata.image` | `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe` |
| `data.win.eventdata.targetFilename` | `C:\Users\[redacted]\AppData\Local\Temp\__PSScriptPolicyTest_[random].ps1` |
| `data.win.eventdata.ruleName` | `technique_id=T1059.001,technique_name=PowerShell` |
| Wazuh rule | `92213` |
| Wazuh alert level | `15` |
| ATT&CK mapping | `T1105` — Ingress Tool Transfer |

The event records PowerShell creating a temporary file whose name begins with `__PSScriptPolicyTest_` and ends with `.ps1`.

## Why this is likely a false positive

The filename pattern `__PSScriptPolicyTest_*.ps1` is associated with PowerShell's script execution-policy test behavior. The observed creating process is the Windows PowerShell executable, and the target is in the user's Local Temp directory.

The supplied event does not show evidence of an external transfer, such as a download URL, network connection, or a suspicious parent/command line. It only records file creation. Therefore, the T1105 mapping in this alert is not established by this event alone.

This assessment is **likely benign**, not a definitive proof that the file was harmless. Validate the context if the alert occurs on another host, with another process, or alongside suspicious network/process activity.

## Why Wazuh raised a level-15 alert

The built-in rule 92213 matches Sysmon Event ID 11 events where `win.eventdata.targetFilename` is under a user's `AppData\Local\Temp` directory and has one of a list of script/executable extensions, including `.ps1`.

The rule does not inspect the file contents, signer, process command line, network source, or whether the file was downloaded. This broad path-and-extension condition explains why a legitimate PowerShell temporary script triggers it.

A level of 15 represents the severity assigned by the rule. It is not a calibrated probability that the event is malicious.

The `firedtimes: 17` value in the submitted alert is a rule firing counter, not proof that this one event represents 17 separate malicious files.

## Proposed narrow exception

A possible child rule can suppress only the known PowerShell policy-test filename pattern while allowing other suspicious file creations in Temp to remain visible:

```xml
<group name="windows,sysmon,noise_reduction,">
  <rule id="100599" level="0">
    <if_sid>92213</if_sid>
    <field name="win.eventdata.targetFilename" type="pcre2">(?i)\\AppData\\Local\\Temp\\__PSScriptPolicyTest_[^\\]+\.ps1$</field>
    <description>Suppress known PowerShell execution-policy test file creation</description>
  </rule>
</group>
```

**Do not deploy this exception until it passes validation.** First use `wazuh-logtest` with the exact sanitized event to confirm that rule 92213 is the parent match and rule 100599 is the final level-0 match. Then test both:

- Positive exception test: a `__PSScriptPolicyTest_*.ps1` file under the user's Local Temp directory is suppressed.
- Negative control: a differently named `.ps1` file, and an executable such as `.exe` in Temp, still trigger the intended detection.

If your Wazuh version or rule hierarchy does not permit the child rule to override this parent as expected, do not force an untested workaround. Revisit the logtest phases and custom ruleset configuration.

## Analyst disposition

**Disposition for this lab event:** Likely benign / false positive from a broad built-in rule.

**Recommended action:** Consider a narrow, test-backed child rule that reduces this specific PowerShell policy-test pattern to low severity while retaining an alert. Do not disable rule 92213 globally or suppress all `.ps1` files under Temp.

## References

- [Wazuh rule 92213 — matching condition and source XML](https://detections.org/detections/wazuh/wazuh/92213/)
- [Wazuh malware detection use case](https://documentation.wazuh.com/current/getting-started/use-cases/malware-detection.html)
- [Wazuh issue #39227 — Rule 92213 ATT&CK mapping concerns](https://github.com/wazuh/wazuh/issues/39227)
- [Wazuh issue #18465 — Rule 92213 regex tuning discussion](https://github.com/wazuh/wazuh/issues/18465)
- [Microsoft PowerShell execution policies](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_execution_policies)

---

*This record documents one lab alert. It does not establish that every alert matching rule 92213 is benign.*
