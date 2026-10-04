# Test Cases — Office Application Child Process

These cases are designed for an authorized lab or test tenant.

## Detection 01 — Expected Positive Cases

| Test | Parent | Child | Expected |
|---|---|---|---|
| P01 | WINWORD.EXE | powershell.exe | Alert |
| P02 | EXCEL.EXE | cmd.exe | Alert |
| P03 | POWERPNT.EXE | mshta.exe | Alert |
| P04 | OUTLOOK.EXE | rundll32.exe | Alert |
| P05 | WINWORD.EXE | certutil.exe | Alert |

### Command-line enrichment

For PowerShell cases, validate that command-line indicators produce a meaningful `DetectionReason`, such as:

- Encoded/decoded content
- Download activity
- Hidden or non-profile execution

## Detection 01 — Expected Negative / Review Cases

| Test | Parent | Child | Expected |
|---|---|---|---|
| N01 | WINWORD.EXE | msedge.exe | No alert |
| N02 | EXCEL.EXE | chrome.exe | No alert |
| N03 | OUTLOOK.EXE | teams.exe | No alert |

These negative cases help validate that the curated suspicious-child list is not excessively noisy.

---

# Detection 02 — Hunting Cases

| Test | Scenario | Expected |
|---|---|---|
| H01 | Office launches a child process never observed during the baseline window | High/Medium priority candidate |
| H02 | Rare Office child runs from a user-writable path | Higher priority |
| H03 | Rare Office child has download indicators | Higher priority |
| H04 | Rare Office child is a known LOLBin | Higher priority |
| H05 | Rare but legitimate enterprise process | Investigate and tune |

## Validation Checklist

For every positive result, verify:

- Was the Office document expected?
- Is the child process signed?
- Is the child process path legitimate?
- Is the account expected?
- Is the command line expected?
- Is there network activity?
- Was a new file created?
- Is there persistence?
- Are there related Defender alerts?

Do not treat the score alone as proof of malicious activity.
