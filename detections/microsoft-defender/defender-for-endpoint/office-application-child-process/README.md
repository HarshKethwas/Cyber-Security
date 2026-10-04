# Office Application Child Process Detection & Hunting

A Microsoft Defender for Endpoint project focused on detecting and hunting suspicious processes spawned by Microsoft Office applications.

## Why this project exists

Office applications are frequently involved in attack chains where a user opens a malicious or weaponized document and the Office process launches a command shell, scripting engine, LOLBin, or download utility.

This project uses two complementary approaches:

1. **High-confidence behavioral detection** — identifies Office applications spawning a curated set of high-risk child processes and adds command-line context.
2. **Rarity-based hunting** — identifies Office child-process relationships that are new or uncommon compared with a recent environment-specific baseline.

The two approaches are intentionally separate. The first is suitable for alerting; the second is better suited to analyst-led hunting and discovery.

---

## Data Source

**Microsoft Defender for Endpoint**

Primary table:

`DeviceProcessEvents`

Microsoft documents this table as containing process-creation events plus parent/initiating-process metadata such as command line, folder path, hashes, and process-unique identifiers.

---

## Project Structure

```text
office-application-child-process/
├── README.md
├── query-01-suspicious-office-child-process.kql
├── query-02-uncommon-office-child-process.kql
├── metadata.yaml
├── test-cases.md
└── references.md
```

---

# Detection 01 — Suspicious Office Child Process

### Objective

Detect Office applications launching processes commonly associated with command execution, script execution, LOLBin abuse, persistence, or payload transfer.

### Office parent processes

- winword.exe
- excel.exe
- powerpnt.exe
- outlook.exe
- onenote.exe
- msaccess.exe
- publisher.exe

### Monitored child processes

- cmd.exe
- powershell.exe
- pwsh.exe
- wscript.exe
- cscript.exe
- mshta.exe
- rundll32.exe
- regsvr32.exe
- certutil.exe
- bitsadmin.exe
- wmic.exe
- schtasks.exe
- msbuild.exe
- installutil.exe

### Detection improvements over the original query

The original implementation aggregated events with `summarize`. The portfolio version intentionally returns **one process event per row** so analysts retain investigation pivots such as:

- ProcessUniqueId
- InitiatingProcessUniqueId
- ProcessCommandLine
- InitiatingProcessCommandLine
- FolderPath
- Process and parent SHA1
- Account UPN
- Signature information
- ReportId

This makes the output more useful for triage and incident investigation.

### Detection reasoning

The query adds contextual reasons for common Office attack patterns:

- Encoded or decoded PowerShell
- PowerShell download/network activity
- Suspicious PowerShell execution parameters
- Signed binary proxy execution candidates
- File-transfer utility abuse
- Scheduled-task persistence activity

---

# Detection 02 — Uncommon Office Child Process

### Objective

Identify Office-to-child process relationships that are new or unusually rare in the local environment.

This is intentionally a **hunting query**, not a high-confidence alert.

### Method

A 13-day historical baseline is compared with activity from the most recent 24 hours.

The hunt evaluates:

- Whether the parent/child relationship was previously unseen
- How many devices observed the relationship
- Network/download indicators
- Obfuscation indicators
- Execution from user-writable locations
- High-risk LOLBins

### Hunt Priority

The resulting score is a triage aid:

| Score | Hunt Priority |
|---:|---|
| 70+ | High |
| 40–69 | Medium |
| <40 | Low |

The score is **not a malware verdict**. Analysts should validate the process, user intent, file reputation, command line, signatures, and surrounding activity.

---

# MITRE ATT&CK Coverage

Depending on the observed child process and command-line behavior, the detections can support investigation of:

| Technique | Relevance |
|---|---|
| T1059.001 | PowerShell |
| T1059.003 | Windows Command Shell |
| T1059.005 | Visual Basic / script interpreter activity |
| T1218 | System Binary Proxy Execution |
| T1105 | Ingress Tool Transfer |
| T1053.005 | Scheduled Task/Job: Scheduled Task |
| T1027 | Obfuscated Files or Information |
| T1140 | Deobfuscate/Decode Files or Information |

Technique mapping should be applied **conditionally to the evidence actually observed**, rather than assuming every Office child process represents every technique.

---

# Investigation Workflow

When the detection fires:

```text
Office Process
      ↓
Child Process
      ↓
Review Command Line
      ↓
Validate Parent Process
      ↓
Check User / Account
      ↓
Check File Path + Signature
      ↓
Check Network Activity
      ↓
Check File / Persistence Activity
      ↓
Determine User Intent
      ↓
Contain / Escalate
```

### Investigation pivots

Start with:

- DeviceName
- InitiatingProcessUniqueId
- ProcessUniqueId
- InitiatingProcessCommandLine
- ProcessCommandLine
- SHA1
- FolderPath
- InitiatingProcessFolderPath
- InitiatingProcessAccountUpn
- Timestamp

Then pivot into:

- DeviceNetworkEvents
- DeviceFileEvents
- DeviceEvents
- Microsoft Defender alerts
- User/account activity

---

# False Positive Considerations

Legitimate examples can include:

- Office add-ins
- Document-management software
- Enterprise automation
- Software deployment tools
- Security testing
- Remote support tooling
- Business workflows

Recommended tuning should be based on observed enterprise behavior rather than a permanent global allowlist.

---

# Validation

See [test-cases.md](test-cases.md) for expected positive and negative scenarios.

The detection should be validated in an authorized lab or test tenant before being used as a production alert.

---

# References

See [references.md](references.md).

---

## Author

**Harsh Kethwas**

SOC Analyst | Microsoft Security | KQL | Detection Engineering | Threat Hunting
