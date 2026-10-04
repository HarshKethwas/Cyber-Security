# Microsoft Entra Detection Engineering

Detection projects focused on Microsoft Entra identity telemetry and authentication behavior.

## Authentication

- [Password Guessing / Brute Force](authentication/password-guessing/)
- [Password Spraying](authentication/password-spraying/)

## Detection philosophy

Authentication detections should distinguish between different attacker behaviors rather than grouping all failed sign-ins into one broad query.

Each detection should document:

- Behavioral objective
- Required telemetry
- Thresholds and time windows
- KQL implementation
- MITRE ATT&CK mapping
- Investigation pivots
- False-positive considerations
- Tuning guidance
- Validation test cases
- Response considerations
