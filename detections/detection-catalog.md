# Detection Catalog

A recruiter should be able to understand the security coverage of this repository without opening every folder.

| Project | Platform | Telemetry | ATT&CK | Validation status |
|---|---|---|---|---|
| Entra Password Spray | Microsoft Defender XDR | Entra sign-ins | T1110.003 | Query + documented scenarios |
| Office Application Child Process | Microsoft Defender XDR | Process creation | T1204, T1059, T1218 | Query + hunting workflow |
| Scheduled Task Persistence | Microsoft Defender XDR | Process creation | T1053.005 | Query + tuning guidance |
| Suspicious PowerShell | Microsoft Defender XDR | Process creation | T1059.001, T1027, T1105, T1140 | Query + investigation guide |

## Reading this repository

Start with the detections that combine:

1. behavior-based logic,
2. analyst investigation pivots,
3. false-positive handling,
4. MITRE mapping,
5. validation scenarios.

Those projects demonstrate the full detection-engineering lifecycle rather than query writing alone.
