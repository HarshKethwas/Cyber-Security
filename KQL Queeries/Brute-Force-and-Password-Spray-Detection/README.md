# Entra ID Password Spray Detection

## Objective

Detect password-spray-like authentication activity where a single source IP produces failed interactive sign-ins against multiple user accounts.

The key behavioral signal is **breadth across accounts**, not simply a large number of failed logins.

## Threat scenario

Password spraying attempts a small number of candidate passwords across many accounts to avoid the lockout thresholds associated with repeatedly attacking one user.

This query therefore looks for:

- repeated authentication failures,
- one source IP,
- multiple distinct user accounts,
- a bounded average number of attempts per user.

It is intended for triage and analytics, not as proof of compromise by itself.

## Data source

**Microsoft Defender XDR**

Table:

```text
EntraIdSignInEvents
```

Required fields:

- `Timestamp`
- `LogonType`
- `ErrorCode`
- `IPAddress`
- `AccountUpn`

## Detection logic

Default parameters:

| Parameter | Default | Purpose |
|---|---:|---|
| Lookback | 24h | Analysis window |
| Failed attempts | 10/hour/IP | Minimum authentication failures |
| Distinct users | 5/hour/IP | Minimum account breadth |
| Attempts/user | <= 5 | Prevent single-account brute force from dominating the signal |

The query calculates:

```text
AttemptsPerUser = FailedAttempts / DistinctUsers
```

A result is therefore more consistent with spraying when an IP has meaningful breadth across accounts while the average attack volume against each account remains relatively low.

## KQL

```kql
// Purpose:
// Identify password-spray-like activity by looking for one source IP
// generating failures across multiple distinct user accounts.
// Tune thresholds for the target tenant and authentication population.

let Lookback = 24h;
let MinFailedAttempts = 10;
let MinDistinctUsers = 5;
let MaxAttemptsPerUser = 5;

EntraIdSignInEvents
| where Timestamp >= ago(Lookback)
| where LogonType == "interactive"
| where ErrorCode != 0
| where isnotempty(IPAddress)
| where isnotempty(AccountUpn)
| summarize
    FailedAttempts = count(),
    DistinctUsers = dcount(AccountUpn),
    Users = make_set(AccountUpn, 50)
    by IPAddress, bin(Timestamp, 1h)
| extend AttemptsPerUser = todouble(FailedAttempts) / DistinctUsers
| where FailedAttempts >= MinFailedAttempts
| where DistinctUsers >= MinDistinctUsers
| where AttemptsPerUser <= MaxAttemptsPerUser
| project
    Timestamp,
    IPAddress,
    FailedAttempts,
    DistinctUsers,
    AttemptsPerUser,
    Users
| order by DistinctUsers desc, FailedAttempts desc
```

## MITRE ATT&CK

| Technique | Relevance |
|---|---|
| **T1110.003 – Password Spraying** | Primary behavior detected |
| **T1110 – Brute Force** | Parent technique |

Do not automatically label every result as **T1078 Valid Accounts**. That technique requires evidence of successful use of valid credentials, which this query does not itself establish.

## Investigation workflow

### 1. Validate source context

Check:

- IP reputation and ASN
- VPN / proxy / hosting-provider ownership
- geographic consistency
- whether the IP is an approved corporate egress point

### 2. Scope affected identities

Review:

- number of targeted users,
- privileged accounts,
- service accounts,
- repeated targeting of the same users,
- whether the users share a business group or application.

### 3. Correlate successful authentication

Search for successful sign-ins from the same source IP after or during the failures.

A successful authentication should be investigated as a separate escalation signal.

### 4. Review authentication controls

Check:

- MFA result,
- Conditional Access result,
- authentication method,
- device information,
- risk detections where available.

### 5. Scope follow-on activity

For a suspicious successful sign-in, pivot into:

- endpoint activity,
- mailbox access,
- file access,
- privilege changes,
- suspicious application consent,
- additional authentication from unusual locations.

## False-positive considerations

Common sources of noise include:

- users repeatedly entering bad passwords,
- stale credentials,
- application authentication retries,
- shared outbound NAT,
- enterprise VPN gateways,
- automated identity-management processes.

A broad corporate egress IP can legitimately touch many users, so IP reputation alone should not determine verdict.

## Tuning

Tune in this order:

1. confirm the telemetry and authentication population,
2. establish normal failure volumes,
3. exclude known trusted egress sources where justified,
4. adjust `MinDistinctUsers` before dramatically increasing the failure threshold,
5. validate against historical benign and malicious examples.

Avoid extremely high thresholds that make low-and-slow spraying invisible.

## Severity guidance

**Default: Medium**

Escalate the investigation when one or more of these are present:

- privileged identities targeted,
- suspicious source infrastructure,
- successful authentication after failures,
- MFA or Conditional Access anomalies,
- repeated campaigns from the same infrastructure.

Severity is an operational decision and should be configured for the environment.

## Validation scenarios

### Positive

An external IP generates:

- 20 failed attempts,
- against 8 distinct users,
- within one hour,
- with no more than 5 failures per user on average.

Expected result: **match**.

### Negative

One user generates:

- 20 failed attempts,
- from one IP,
- with no other users targeted.

Expected result: **no password-spray match**; investigate separately as possible brute force or user error.

### Negative

A known enterprise NAT gateway produces a small volume of failures across multiple users with normal business context.

Expected result: **review/tune**, not automatic compromise verdict.

## Response considerations

If the activity is confirmed malicious, response may include:

- blocking or restricting the source where operationally appropriate,
- resetting affected credentials,
- enforcing MFA or stronger authentication,
- investigating successful authentications,
- scoping the source IP across other identities and tenants,
- reviewing conditional-access gaps.

## Detection quality notes

This is intentionally a **behavioral detector**, not a reputation-based IOC rule. Its value comes from account breadth plus controlled per-user attempt volume.

**Status:** Active research detection  
**Confidence:** Medium by default; increases when correlated with successful authentication or additional suspicious activity.
