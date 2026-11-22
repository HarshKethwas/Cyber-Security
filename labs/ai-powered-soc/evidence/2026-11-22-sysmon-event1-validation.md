# Evidence Record — Sysmon and Wazuh Process-Creation Baseline

**Date:** 2026-11-22  
**Endpoint:** Windows 11 lab endpoint (host and account identifiers omitted)  
**Source:** Sysmon Operational channel and Wazuh alert index  
**Primary event:** Sysmon Event ID 1 — Process Create

## 1. Local Sysmon: account and user discovery

A controlled command was executed:

```powershell
whoami.exe /all
```

The local Sysmon Event ID 1 record included:

| Field | Sanitized observation |
|---|---|
| Event ID | 1 |
| Image | `C:\Windows\System32\whoami.exe` |
| Command line | `whoami.exe /all` |
| Parent image | `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe` |
| Sysmon RuleName | `technique_id=T1033, technique_name=System Owner/User Discovery` |
| Process GUID | Present |
| Parent Process GUID | Present |

This confirms local Sysmon telemetry for `whoami.exe /all` and its parent process.

## 2. Wazuh: encoded PowerShell event received and alerted

A benign encoded PowerShell test was created from:

```powershell
Write-Output 'SOC_LAB_ENCODED_BASELINE'
```

The command was launched using PowerShell `-EncodedCommand`. The Wazuh event JSON supplied for this test confirms:

| Field | Observed value |
|---|---|
| Index | `wazuh-alerts-4.x-2026.11.22` |
| Sysmon event ID | `1` |
| Channel | `Microsoft-Windows-Sysmon/Operational` |
| Decoder | `windows_eventchannel` |
| Location | `EventChannel` |
| Process image | `powershell.exe` |
| Command line | Contains `-EncodedCommand` and the benign test payload |
| Parent image | `powershell.exe` |
| Wazuh rule ID | `92057` |
| Wazuh rule level | `12` |
| Rule description | PowerShell spawned PowerShell with a Base64-encoded command |
| ATT&CK | `T1059.001` |

This proves the encoded PowerShell Sysmon event reached Wazuh and generated an indexed alert.

Rule 92057 is an existing Wazuh ruleset detection. Its condition looks for a PowerShell parent and a PowerShell command line containing an encoded-command parameter. The lab's observed test matched that behavior. The custom D002 rule is therefore designed as complementary coverage for encoded PowerShell launched by a **non-PowerShell parent**, rather than duplicating the exact rule 92057 condition.

## 3. Why the whoami event was not found in wazuh-alerts

The `whoami.exe /all` event was visible in the local Sysmon channel, but no corresponding Wazuh alert JSON has been provided yet.

This does not prove that Wazuh failed to receive it. The normal Sysmon Event ID 1 base rule is a level-0 grouping rule; level-0 events are not displayed as alerts. The `wazuh-alerts-*` index stores events that trigger alert rules with a sufficiently high level.

To search unalerted events, configure Wazuh event archiving (`logall_json`) and enable Filebeat archive forwarding, then query the `wazuh-archives-*` index. This consumes additional disk space, so enable it deliberately and monitor storage. Alternatively, deploy and validate the custom D003 rule for `whoami.exe /all`; a matching custom alert should then appear in the alerts index.

## 4. Validation status

| Check | Result |
|---|---|
| Local Sysmon Event ID 1 generation | Observed |
| Local `whoami.exe /all` event | Observed |
| Parent-process metadata in Sysmon | Observed |
| Benign encoded PowerShell execution | Observed |
| Encoded PowerShell event received by Wazuh | Confirmed |
| Wazuh alert for encoded PowerShell | Confirmed — rule 92057, level 12 |
| Wazuh decoded fields | Confirmed for image, commandLine, parentImage, eventID and channel |
| Wazuh alert for `whoami.exe /all` | Not yet observed |
| Custom rules 100500 / 100501 / 100510 | Drafted; not yet deployed or validated |
| Positive and negative custom-rule tests | Pending |

## 5. Next validation steps

1. Deploy the lab's custom XML rules to the Wazuh manager's `/var/ossec/etc/rules/` directory.
2. Validate the XML and rule matching with `wazuh-logtest`.
3. Restart the Wazuh manager only after the test succeeds.
4. Re-run harmless positive tests for D001, D002 (from a non-PowerShell parent), and D003 (`whoami.exe /all`).
5. Confirm the new rule IDs appear in Wazuh alerts.
6. Run benign negative tests and record any false positives.

**Privacy:** Usernames, host identifiers, SIDs, agent IP, process hashes and encoded payload strings are intentionally omitted from this public evidence record.
