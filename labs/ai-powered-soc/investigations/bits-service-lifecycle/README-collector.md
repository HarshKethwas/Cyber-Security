# Read-only BITS evidence collector

The PowerShell collector is provided in the companion downloadable case package. It reads event logs and the current BITS service/registry state only.

## Usage

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\Collect-BITSInvestigation.ps1 -Hours 24
.\Collect-BITSInvestigation.ps1 -Hours 72 -CorrelationSeconds 90
```

## Collection scope

- System Event ID 7040 filtered for BITS.
- Sysmon Event ID 13 for the BITS service `Start` registry value.
- Sysmon Event ID 1 within a configurable time window around each 7040 event.
- Security Event ID 4688 where available.
- PowerShell Operational Event ID 4104 where available.
- Current BITS service state and registry values.
- Installed BITS-related event channel metadata.

## Safety and data handling

- Does not change services or registry values.
- Does not start, stop, disable, or reconfigure BITS.
- Does not complete, cancel, or delete BITS jobs.
- Does not call `Get-BitsTransfer`.
- Writes timestamped JSON and CSV exports plus a SHA-256 manifest beneath `C:\CyberLab\Evidence`.

Review and sanitize collected endpoint data before sharing. Event records may contain usernames, local paths, process command lines, job IDs, and URLs.
