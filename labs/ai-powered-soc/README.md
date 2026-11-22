# AI-Powered SOC Lab

A hands-on Security Operations Center lab designed to explore the complete defensive workflow: endpoint telemetry collection, SIEM ingestion, detection engineering, threat hunting, threat intelligence enrichment, incident investigation, and carefully controlled automation.

> **Project status:** In progress  
> **Current milestone:** Milestone 1 — endpoint telemetry pipeline  
> **Last documentation update:** 2026-11-22

## Project objectives

The lab is intended to provide practical experience with:

- Collecting Windows endpoint telemetry and understanding the underlying event sources.
- Ingesting and analyzing endpoint events in a SIEM.
- Developing and validating behavior-focused detections.
- Mapping relevant activity to MITRE ATT&CK.
- Simulating controlled attack behaviors to test defensive visibility.
- Enriching alerts with threat-intelligence context.
- Building Python-based investigation and automation workflows.
- Exploring an AI-assisted SOC analyst that explains evidence and recommends next steps, with human approval for disruptive response actions.

## Current implementation

### Milestone 1 — Wazuh and Sysmon telemetry pipeline

<badge>Completed as reported</badge>

The initial lab setup was completed with the following components:

| Component | Implementation |
|---|---|
| SIEM / security monitoring | Wazuh v4.13.1 |
| Deployment method | Docker |
| Endpoint | Windows 11 |
| Endpoint collection | Wazuh Agent |
| Endpoint telemetry | Microsoft Sysmon |
| Sysmon event source | Microsoft-Windows-Sysmon/Operational |
| Integration | Sysmon events configured for collection by Wazuh |

### Work completed

1. Deployed Wazuh SIEM/XDR v4.13.1 using Docker.
2. Connected a Windows 11 endpoint using the Wazuh Agent.
3. Installed and configured Microsoft Sysmon on the Windows endpoint.
4. Configured Wazuh to collect Sysmon operational events.
5. Verified that endpoint events reached Wazuh and that alerts were generated.

### Initial event categories observed

The following activity categories were observed during the initial validation:

| Activity | Observation |
|---|---|
| Process creation | Process execution telemetry observed |
| File creation | File activity telemetry observed |
| Discovery activity | Discovery-related activity observed |
| Account discovery | Activity involving `net.exe` observed |
| MITRE ATT&CK mapping | ATT&CK-mapped detections observed in Wazuh |

These are initial validation observations, not a claim of complete ATT&CK coverage or a production-grade detection program.

### Data flow

```text
┌──────────────────────────────┐
│       Windows 11 Endpoint    │
│                              │
│  User / Process / File Events│
│              │               │
│              ▼               │
│           Sysmon             │
│              │               │
│              ▼               │
│         Wazuh Agent          │
└──────────────┬───────────────┘
               │
               │ Endpoint event forwarding
               ▼
┌──────────────────────────────┐
│       Wazuh Docker Stack     │
│                              │
│        Wazuh Manager         │
│              │               │
│              ▼               │
│          Indexer             │
│              │               │
│              ▼               │
│          Dashboard           │
│                              │
│  Event analysis and alerts   │
└──────────────────────────────┘
```

The diagram represents the logical telemetry flow. The exact Docker services, network configuration, ports, resource allocation, and persistent-volume settings should be added from the actual Compose configuration before this documentation is treated as a reproducible deployment guide.

## Validation record

The first milestone focused on confirming the telemetry pipeline, not on claiming advanced custom detection engineering.

| Validation area | Reported outcome | Evidence to retain |
|---|---|---|
| Wazuh deployment | Deployed with Docker | Compose file, service status |
| Windows endpoint | Agent connected | Agent status screenshot |
| Sysmon | Installed and configured | Sysmon configuration and service status |
| Event forwarding | Sysmon events reached Wazuh | Raw event / Wazuh event screenshot |
| Alert generation | Alerts observed | Wazuh alert screenshot |
| Event categories | Process, file, discovery, account discovery | Sanitized event examples |

**Evidence note:** Screenshots, raw event samples, Sysmon configuration, Docker Compose files, and agent configuration have not yet been added to this repository. Add sanitized evidence as it is recaptured and verified. Never commit API keys, credentials, private IP information that should not be disclosed, or sensitive endpoint data.

## Planned milestones

The following items are planned and are not represented as completed work.

### Milestone 2 — Detection engineering

- Create custom Wazuh rules for suspicious PowerShell execution.
- Add detections for encoded PowerShell command lines.
- Investigate LOLBin activity such as `certutil.exe`, `mshta.exe`, and `rundll32.exe`.
- Detect account and domain discovery behavior.
- Analyze suspicious parent-child process relationships.
- Document rule logic, event fields, severity, ATT&CK mapping, false positives, and validation cases.
- Test rules with Wazuh `wazuh-logtest` and controlled endpoint activity.

**Exit criteria:** A version-controlled set of custom detections with reproducible positive and benign test cases.

### Milestone 3 — Attack simulation and threat hunting

- Use controlled, isolated simulations to generate relevant endpoint telemetry.
- Evaluate detection coverage against selected ATT&CK techniques.
- Record expected telemetry, observed events, alerts, and detection gaps.
- Document hunting hypotheses and investigation pivots.

**Exit criteria:** Repeatable test cases with evidence of which behaviors were and were not detected.

### Milestone 4 — Threat intelligence and Python automation

- Integrate the Wazuh alert workflow with Python.
- Enrich indicators using VirusTotal and AbuseIPDB.
- Normalize alert fields and retain source references.
- Add error handling, API rate-limit handling, caching, and secrets management.
- Create an incident record from enriched alerts.

**Exit criteria:** A tested enrichment service with clear handling of unavailable or inconclusive intelligence.

### Milestone 5 — AI-assisted SOC investigation

- Build an investigation workflow using Python and LangGraph.
- Summarize alerts using the underlying evidence.
- Correlate process, user, host, and indicator context where available.
- Provide ATT&CK context and recommended investigation pivots.
- Generate structured investigation findings and reports.
- Require analyst approval before disruptive response actions.

**Exit criteria:** An AI-assisted investigation that cites its input evidence, identifies uncertainty, and does not independently execute containment.

### Milestone 6 — Phishing analysis lab

- Build a contained email test environment.
- Generate benign test messages and controlled phishing simulations.
- Extract URLs, domains, sender information, and attachment hashes.
- Analyze indicators and connect results to the investigation workflow.

**Exit criteria:** A repeatable email-analysis scenario with documented evidence and outcomes.

### Milestone 7 — Response automation

- Implement controlled response playbooks.
- Add analyst approval and audit logging.
- Simulate endpoint isolation, indicator blocking, and account response before considering live actions.
- Record action inputs, outputs, failures, and rollback considerations.

**Exit criteria:** Auditable response workflows with human authorization for high-impact actions.

### Milestone 8 — Portfolio release

- Publish architecture and deployment documentation.
- Add sanitized screenshots and sample event data.
- Add detection test cases and investigation reports.
- Document configuration, limitations, and troubleshooting.
- Record a complete attack-to-investigation demonstration.

**Exit criteria:** Another practitioner can understand the architecture, reproduce the documented parts, and follow the evidence from endpoint activity to investigation.

## Planned technology stack

| Area | Planned technology |
|---|---|
| SIEM | Wazuh |
| Endpoint telemetry | Sysmon, Windows Event Logs |
| Endpoint agent | Wazuh Agent |
| Deployment | Docker / Docker Compose |
| Attack simulation | Atomic Red Team and controlled scripts |
| Detection engineering | Wazuh XML rules |
| Automation | Python |
| API service | FastAPI (planned) |
| Threat intelligence | VirusTotal, AbuseIPDB |
| AI orchestration | LangGraph |
| ATT&CK mapping | MITRE ATT&CK |
| Version control | Git and GitHub |

Tools in this table are planned components unless explicitly listed in the completed Milestone 1 section.

## Security and operational principles

- Run simulations only on systems and networks that are owned or explicitly authorized.
- Keep attack simulation isolated from production systems.
- Use test indicators and benign samples wherever possible.
- Store credentials in environment variables or a secret manager; never commit secrets.
- Treat external threat-intelligence results as enrichment, not definitive proof of maliciousness.
- Preserve raw evidence and distinguish observed facts from analytical conclusions.
- Require human approval before host isolation, account disablement, blocking, or other disruptive actions.
- Log automated decisions and actions so investigations remain auditable.

## Project notes and next action

The initial Wazuh–Sysmon pipeline is documented as the first completed milestone based on the implementation and validation reported during the project.

**Next action:** Revalidate the existing Docker services, Wazuh agent connectivity, Sysmon event generation, and end-to-end event ingestion. Capture sanitized evidence and configuration before beginning custom detection development.

## References

- [Wazuh documentation](https://documentation.wazuh.com/current/)
- [Wazuh ruleset](https://documentation.wazuh.com/current/user-manual/ruleset/)
- [Microsoft Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
- [MITRE ATT&CK](https://attack.mitre.org/)
- [Atomic Red Team](https://atomicredteam.io/)
- [LangGraph documentation](https://docs.langchain.com/oss/python/langgraph/overview)

---

*This is an evolving educational and defensive-security lab. Its current milestone demonstrates initial telemetry collection and alert generation; it is not yet a complete or production-ready SOC platform.*
