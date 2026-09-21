# Office Application Child Process Hunting

## Objective

Identify suspicious process execution originating from Microsoft Office applications, with separate logic for known high-risk child processes and uncommon child processes.

This project is designed as a **SOC hunting workflow**: the query identifies candidates, then process-tree, file, network, and user context are used to determine verdict.

## Data source

**Microsoft Defender XDR**

Table:

```text
DeviceProcessEvents
```

Useful fields:

- `Timestamp`
- `DeviceName`
- `AccountName`
- `InitiatingProcessFileName`
- `InitiatingProcessCommandLine`
- `FileName`
- `ProcessCommandLine`
- `ReportId`

## Detection 1 — Known suspicious child processes

### Logic

The first query looks for Office applications spawning known higher-risk executables such as:

- PowerShell
- Windows Script Host
- MSHTA
- Rundll32
- Regsvr32
- Certutil
- Bitsadmin
- Scheduled-task utilities

Command-line indicators add investigation context such as encoded payloads, download cradles, and hidden execution.

### Why this is useful

A direct Office → LOLBin/process relationship is generally more informative than a PowerShell command-line keyword alone because it preserves the process-chain context.

## Detection 2 — Uncommon child processes

The second query takes an anomaly-oriented approach:

1. identify Office parent processes,
2. exclude a baseline of commonly observed children,
3. score remaining events using multiple suspicious characteristics,
4. prioritize the highest-scoring events for analyst review.

### Risk model

| Signal | Weight |
|---|---:|
| Network/download indicator | +30 |
| Obfuscation/encoded execution | +30 |
| User-writable or temporary path | +20 |
| High-risk LOLBin | +20 |

The score is a **hunt prioritization score**, not an objective probability of maliciousness.

A score of 70 does not mean “70% malicious.” It means more independent suspicious characteristics are present.

## MITRE ATT&CK mapping

| Technique | Use in this project |
|---|---|
| **T1204.002 – Malicious File** | Applicable when a malicious document causes the execution chain |
| **T1059.001 – PowerShell** | When PowerShell is spawned |
| **T1059.003 – Windows Command Shell** | When cmd.exe is spawned |
| **T1218 – System Binary Proxy Execution** | When applicable LOLBins such as rundll32/regsvr32/mshta are observed |
| **T1105 – Ingress Tool Transfer** | Only when the command line indicates transfer/download behavior |

Avoid mapping every result to every listed technique. ATT&CK should reflect the behavior actually observed in the event.

## Investigation workflow

### 1. Start with the process tree

Identify:

```text
Office document/application
        ↓
Child process
        ↓
Grandchild process
        ↓
Network / file activity
```

Determine whether the child process is expected for the application and business workflow.

### 2. Review the Office parent

Check:

- user account,
- document/application context,
- parent command line,
- recent user activity,
- whether the application was launched from email, browser, or a known business workflow.

### 3. Review child command line

Look for:

- encoded PowerShell,
- download commands,
- script interpreters,
- hidden execution,
- unusual paths,
- LOLBin abuse.

### 4. Pivot to endpoint telemetry

Correlate:

- `DeviceNetworkEvents`,
- `DeviceFileEvents`,
- `DeviceRegistryEvents`,
- subsequent `DeviceProcessEvents`.

### 5. Scope the user and device

Determine whether the same:

- user,
- hash,
- parent process,
- command line,
- destination domain/IP

appeared elsewhere.

### 6. Validate legitimacy

Common benign causes include:

- Office add-ins,
- document-management integrations,
- enterprise automation,
- security testing,
- software deployment,
- line-of-business applications.

## Validation scenarios

### Positive

A Word process launches PowerShell with encoded-command or download behavior.

Expected result: **Detection 1 match** and elevated priority for investigation.

### Positive

An Office process launches a normally uncommon executable from a user-writable path and the command line contains download activity.

Expected result: **Detection 2 receives multiple risk signals**.

### Negative / tuning

An Office application launches a known enterprise integration process repeatedly from a trusted path.

Expected result: baseline the process or path only after validating that the activity is consistently legitimate.

## Response considerations

For confirmed malicious execution:

- isolate the endpoint when appropriate,
- collect process/file/network evidence,
- block confirmed malicious infrastructure,
- remove persistence,
- assess the originating document or email,
- investigate other users/devices exposed to the same artifact.

**Status:** Active detection/hunting project  
**Confidence:** Medium until correlated with additional endpoint or identity evidence.
