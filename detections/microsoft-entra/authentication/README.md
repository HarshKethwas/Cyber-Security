# Entra ID Authentication Attack Detections

Two Microsoft Defender XDR KQL detections for suspicious failed interactive sign-in patterns in Microsoft Entra ID.

The detections intentionally separate two attacker behaviors:

| Detection | Behavioral pattern | Primary ATT&CK |
|---|---|---|
| Password Guessing / Brute Force | Repeated failures against one account from one source IP | T1110.001 |
| Password Spraying | One source IP targets multiple accounts | T1110.003 |

This separation makes the detections easier to tune, investigate, and explain during an SOC review.

## Data Source

**Microsoft Defender XDR**

Primary table: EntraIdSignInEvents

The table contains Microsoft Entra interactive and non-interactive sign-in activity and includes fields such as Timestamp, LogonType, ErrorCode, AccountUpn, IPAddress, Application, and UserAgent.

Microsoft documentation:
https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-entraidsigninevents-table

## Project Structure

    authentication/
    ├── password-guessing/
    │   ├── Detection.kql
    │   ├── README.md
    │   ├── metadata.yaml
    │   ├── test-cases.md
    │   └── references.md
    │
    └── password-spraying/
        ├── Detection.kql
        ├── README.md
        ├── metadata.yaml
        ├── test-cases.md
        └── references.md

---

# Detection 01 — Password Guessing / Brute Force

**Path:** password-guessing/

### Objective

Identify repeated failed interactive authentication attempts against the same user account from the same source IP within a short time window.

This is designed around a password-guessing/brute-force pattern. MITRE defines password guessing as repeated attempts to authenticate using guessed passwords.

### Logic

The query:

1. Looks back one day.
2. Restricts activity to interactive sign-ins.
3. Selects failed authentication events.
4. Requires an account and source IP.
5. Groups failures by account, source IP, and 15-minute window.
6. Triggers when at least 8 failures occur in the window.
7. Retains application and user-agent context for investigation.

### Thresholds

These values are **portfolio baseline values**, not universal production thresholds.

- Lookback: 1 day
- Window: 15 minutes
- Trigger: 8 or more failed sign-ins

Tune according to authentication volume, lockout policy, account type, VPN/proxy architecture, and observed false positives.

### Severity

**Medium by default**

Consider increasing severity when:

- A privileged account is targeted.
- The source IP is suspicious or unexpected.
- A successful authentication follows the failed attempts.
- MFA or Conditional Access behavior is abnormal.
- Related endpoint, mailbox, or identity alerts are present.

---

# Detection 02 — Password Spraying

**Path:** password-spraying/

### Objective

Identify one source IP producing failed interactive sign-ins against multiple distinct accounts within a one-hour window.

This matches the characteristic pattern of password spraying: a single or small set of passwords attempted against many accounts to reduce the risk of account lockout.

### Logic

The query:

1. Looks back one day.
2. Restricts activity to interactive authentication failures.
3. Requires account and source IP data.
4. Groups failures by source IP and one-hour window.
5. Counts total failures.
6. Counts distinct targeted accounts.
7. Triggers when at least 5 distinct users and 10 total failures are observed.

### Thresholds

These are **starting values for a portfolio/lab implementation**.

- Lookback: 1 day
- Window: 1 hour
- Minimum distinct users: 5
- Minimum failures: 10

Tune according to the environment.

### Severity

**Medium by default; High when corroborated**

Increase severity when:

- Privileged users are among the targets.
- One or more accounts authenticate successfully afterward.
- The source targets a large number of users.
- The source is suspicious or anomalous.
- Related endpoint, email, or identity telemetry supports compromise.

---

# Investigation Workflow

    Detection
       ↓
    Identify source IP
       ↓
    Identify affected account(s)
       ↓
    Review application / user agent
       ↓
    Review MFA / Conditional Access
       ↓
    Check for successful sign-in
       ↓
    Check endpoint / mailbox / identity activity
       ↓
    Determine scope and impact
       ↓
    Contain / escalate

## Investigation pivots

Start with:

- IPAddress
- AccountUpn
- FirstSeen
- LastSeen
- Application
- UserAgent

For correlated incidents, pivot into additional Defender XDR telemetry and incidents.

# Scope Limitations

These queries detect **failed-sign-in patterns**. They do not by themselves prove:

- Credential stuffing
- Account compromise
- Malicious IP reputation
- Successful use of valid credentials

T1078 Valid Accounts should be applied only when the investigation establishes use of legitimate credentials.

Credential stuffing is a separate ATT&CK sub-technique, T1110.004, and is not claimed by this project.

# Tuning Philosophy

Microsoft recommends applying time filters early, selecting only useful fields, and using summarize where aggregation is meaningful.

Recommended tuning process:

    Observe normal failures
            ↓
    Identify expected noisy sources
            ↓
    Tune windows and thresholds
            ↓
    Add scoped environment exceptions
            ↓
    Validate true positives
            ↓
    Measure alert volume

Avoid broad permanent allowlists whenever possible.

## References

- Microsoft Defender XDR — EntraIdSignInEvents: https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-entraidsigninevents-table
- Microsoft Defender XDR — Advanced hunting query language: https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-query-language
- Microsoft Defender XDR — Advanced hunting best practices: https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-best-practices
- MITRE ATT&CK — T1110 Brute Force: https://attack.mitre.org/techniques/T1110/
- MITRE ATT&CK — T1110.001 Password Guessing: https://attack.mitre.org/techniques/T1110/001/
- MITRE ATT&CK — T1110.003 Password Spraying: https://attack.mitre.org/techniques/T1110/003/

## Author

**Harsh Kethwas**

SOC Analyst | Microsoft Security | KQL | Detection Engineering | Threat Hunting