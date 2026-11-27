# AI-Powered SOC Lab

A hands-on Security Operations Center lab designed to explore endpoint telemetry collection, SIEM ingestion, detection engineering, threat hunting, incident investigation, and carefully controlled automation.

> **Project status:** In progress  
> **Current milestone:** Milestone 1 — endpoint telemetry pipeline  
> **Last documentation update:** 2026-11-25

## Project objectives

- Collect Windows endpoint telemetry and understand its event sources.
- Ingest and analyze endpoint events in a SIEM.
- Develop and validate behavior-focused detections.
- Map relevant activity to MITRE ATT&CK.
- Simulate controlled attack behaviors to test defensive visibility.
- Enrich alerts with threat-intelligence context.
- Build Python-based investigation and automation workflows.
- Explore AI-assisted investigations with human approval for disruptive response actions.

## Current implementation

### Milestone 1 — Wazuh and Sysmon telemetry pipeline

The initial lab setup is documented with Wazuh v4.13.1, Docker, a Windows 11 endpoint, Wazuh Agent, Microsoft Sysmon, and event collection through the Sysmon Operational channel.

### BITS service lifecycle investigation

An evidence-led investigation examined repeated Background Intelligent Transfer Service (BITS) startup-type changes, corrected a Sysmon filtering gap that suppressed Event ID 13 for the BITS Start registry value, and developed a Wazuh detection-tuning approach.

**Disposition:** The repeated Demand Start ↔ Automatic transitions are consistent with Microsoft's documented BITS lifecycle. The supplied evidence did not establish malicious activity or endpoint compromise. Historical attribution remains incomplete.

[**Read the BITS investigation and detection pack →**](./investigations/bits-service-lifecycle/README.md)

The BITS case includes:
- Detailed investigation timeline and limitations
- Sysmon telemetry-gap analysis
- Custom Wazuh rules 100520–100524
- Synthetic validation fixtures and test cases
- Read-only PowerShell evidence collector
- Primary references

**Validation caveat:** The custom Wazuh XML is well-formed and synthetic JSONL fixtures parse, but runtime validation against the lab's Wazuh 4.13.1 manager remains outstanding. Confirm parent rule IDs and decoded fields before deployment.

## Data flow

```text
Windows 11 Endpoint
  ├─ Windows Event Logs
  ├─ Sysmon
  └─ Wazuh Agent
        |
        v
Wazuh Docker Stack
  ├─ Manager
  ├─ Indexer
  └─ Dashboard
```

The diagram represents logical flow. Add the actual Docker Compose configuration and sanitized deployment evidence before treating it as a reproducible deployment guide.

## Planned milestones

### Detection engineering
- Suspicious PowerShell and encoded commands
- LOLBin activity
- Account and domain discovery
- Suspicious parent-child process relationships
- Positive and benign validation cases

### Attack simulation and threat hunting
- Controlled isolated simulations
- ATT&CK coverage evaluation
- Evidence-based hunting hypotheses and pivots

### Threat intelligence and Python automation
- VirusTotal and AbuseIPDB enrichment
- Structured investigation records
- Rate-limit handling, caching, and secrets management

### AI-assisted SOC investigation
- Python and LangGraph orchestration
- Evidence-grounded summaries and ATT&CK context
- Human approval before disruptive response

### Phishing analysis and response automation
- Contained email test environment
- Indicator extraction and enrichment
- Auditable analyst-approved response playbooks

### Portfolio release
- Architecture and deployment documentation
- Sanitized screenshots and sample events
- Reproducible detection test cases
- End-to-end attack-to-investigation demonstration

## Security and operational principles

- Run simulations only on owned or explicitly authorized systems.
- Isolate attack simulation from production environments.
- Use test indicators and benign samples wherever possible.
- Never commit credentials or sensitive endpoint data.
- Treat threat intelligence as enrichment, not definitive proof.
- Preserve raw evidence and distinguish facts from hypotheses.
- Require human approval for host isolation, account disablement, and other disruptive actions.
- Log automated decisions and actions.

## References

- [Wazuh documentation](https://documentation.wazuh.com/current/)
- [Microsoft Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
- [MITRE ATT&CK](https://attack.mitre.org/)
- [Atomic Red Team](https://atomicredteam.io/)
- [LangGraph documentation](https://docs.langchain.com/oss/python/langgraph/overview)

---

*This is an evolving educational and defensive-security lab, not a production-ready SOC platform.*


### BITS service lifecycle case study

A documented Windows investigation examined repeated BITS startup-type transitions, corrected a Sysmon filtering gap affecting Event ID 13 visibility, and developed candidate Wazuh detections. The evidence supported expected BITS lifecycle behaviour; compromise was not substantiated. The custom rules and collector remain subject to lab runtime validation.

[**Open the BITS case study →**](./investigations/bits-service-lifecycle/README.md)
