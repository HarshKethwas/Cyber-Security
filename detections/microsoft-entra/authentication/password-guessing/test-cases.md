# Test Cases — Password Guessing / Brute Force

Run only in an authorized test environment.

| ID | Scenario | Expected |
|---|---|---|
| BF-01 | Same account + same source IP produces 8+ failed interactive sign-ins within 15 minutes | Detection |
| BF-02 | Same account + same IP produces 5 failures within 15 minutes | No detection |
| BF-03 | Same account fails from different IPs without meeting the per-IP threshold | No detection |
| BF-04 | Multiple users targeted from one IP | Investigate with Password Spraying detection |

## Investigation validation

For each positive result, confirm:

- Account identity
- Account privilege level
- Source IP
- Application
- User agent
- MFA / Conditional Access result
- Any subsequent successful sign-in
