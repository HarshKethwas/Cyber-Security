# Test Cases — Password Spraying

Run only in an authorized test environment.

| ID | Scenario | Expected |
|---|---|---|
| PS-01 | One IP produces 10+ failures against 5+ distinct accounts within 1 hour | Detection |
| PS-02 | One IP targets 4 accounts with 10 failures | No detection |
| PS-03 | One IP produces 10 failures against only one account | Investigate with Password Guessing detection |
| PS-04 | Expected shared VPN/proxy egress generates broad failures | Tune after investigation |

## Investigation validation

For each positive result, determine:

- Number of targeted users
- Privileged accounts among targets
- Whether any authentication succeeded
- MFA / Conditional Access outcomes
- Whether the source IP is expected infrastructure
- Whether related endpoint or mailbox activity exists
