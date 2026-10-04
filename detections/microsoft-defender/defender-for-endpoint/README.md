# Defender for Endpoint Detections

Microsoft Defender for Endpoint detection engineering projects built around endpoint telemetry and attacker behavior.

## Projects

### Office Application Child Process Detection & Hunting

Detects and hunts suspicious child processes launched by Microsoft Office applications.

- [Project README](office-application-child-process/README.md)
- [Suspicious Office Child Process](office-application-child-process/query-01-suspicious-office-child-process.kql)
- [Uncommon Office Child Process Hunt](office-application-child-process/query-02-uncommon-office-child-process.kql)
- [Metadata](office-application-child-process/metadata.yaml)

## Detection standard

Projects should document:

- Objective and threat scenario
- Data source and required telemetry
- Detection or hunt logic
- MITRE ATT&CK mapping
- Investigation pivots
- False-positive considerations
- Tuning guidance
- Validation test cases
- Response recommendations
