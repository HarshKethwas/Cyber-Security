# 🛡️ Cyber Security Portfolio

### Harsh Kethwas

**SOC Analyst | Detection Engineering | Threat Hunting | Incident Response**

[![GitHub](https://img.shields.io/badge/GitHub-HarshKethwas-black?logo=github)](https://github.com/HarshKethwas)
[![KQL](https://img.shields.io/badge/KQL-Microsoft%20Security-blue)](https://learn.microsoft.com/en-us/kusto/query/)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK-red)](https://attack.mitre.org/)
[![Microsoft Defender](https://img.shields.io/badge/Microsoft-Defender%20XDR-0078D4?logo=microsoft)](https://www.microsoft.com/en-us/security/business/endpoint-security/microsoft-defender-endpoint)
[![Wazuh](https://img.shields.io/badge/Wazuh-SIEM-4A90E2)](https://wazuh.com/)

---

## 👨‍💻 About Me

I am a cybersecurity professional focused on **Security Operations, Detection Engineering, Threat Hunting, and Incident Response**.

This repository documents my practical security work, including:

- Detection engineering using **KQL**
- Microsoft Defender XDR investigations
- Microsoft Entra ID security monitoring
- Threat hunting and behavioral analysis
- MITRE ATT&CK mapping
- Incident investigation and response
- Windows endpoint telemetry and Sysmon
- SIEM monitoring with Wazuh
- Malware analysis and security research

My goal is to build detections that are not only technically correct, but also **investigable, tunable, and useful to a SOC analyst**.

---

## 🎯 What This Repository Contains

This repository is my hands-on cybersecurity portfolio. Projects are documented through a practical workflow:

```text
Threat
  ↓
Detection
  ↓
Investigation
  ↓
Evidence
  ↓
MITRE ATT&CK Mapping
  ↓
Response
  ↓
Tuning / Lessons Learned
```

Each project is designed to demonstrate how a security analyst approaches a security problem.

---

## 🔎 Detection Engineering

The detection engineering section contains security detections built primarily with **Kusto Query Language (KQL)** and Microsoft security telemetry.

### Current Detection Areas

| Category | Examples |
|---|---|
| Identity Security | Password Spray, Brute Force, Account Abuse |
| Endpoint Security | Suspicious PowerShell, Office Child Processes |
| Persistence | Scheduled Task Abuse |
| Defense Evasion | Encoded Commands, LOLBins |
| Network / Download Activity | Download Cradles, Suspicious Network Activity |
| Cloud / Identity | Entra ID authentication monitoring |

Explore the [detection engineering documentation](./detections/README.md).

---

## 🕵️ Threat Hunting

Threat hunting projects focus on identifying suspicious behavior that may not immediately generate a high-confidence alert.

Hunting areas include PowerShell abuse, Office application abuse, persistence, credential access, living-off-the-land techniques, suspicious authentication, and endpoint anomalies.

Explore the [threat hunting documentation](./threat-hunting/README.md).

---

## 🚨 Incident Response

Security alerts are only the beginning of a SOC investigation. The repository documents triage, scoping, timeline reconstruction, root cause analysis, containment, eradication, recovery, and lessons learned.

Explore the [incident response documentation](./incident-response/README.md).

---

## 🧪 Security Labs

### AI-Powered SOC Lab

An evolving hands-on lab to build and document an end-to-end defensive workflow, starting with Windows endpoint telemetry and Wazuh.

**Milestone 1 — reported complete:**
- Deployed Wazuh v4.13.1 with Docker.
- Connected a Windows 11 endpoint using Wazuh Agent.
- Installed and configured Microsoft Sysmon.
- Integrated Sysmon operational events into Wazuh.
- Observed process creation, file creation, discovery, and account-discovery activity.
- Verified initial event collection and alert generation.

**Planned next:** custom Wazuh detections, controlled attack simulations, Python threat-intelligence enrichment, LangGraph-based AI investigations, and analyst-approved response automation.

[**Read the AI-Powered SOC Lab documentation →**](./labs/ai-powered-soc/README.md)

See the [Security Labs index](./labs/README.md) for other lab areas.

---

## 🦠 Malware Analysis

The malware-analysis section focuses on static and dynamic analysis, including file metadata, hashes, strings, PE characteristics, process activity, file and registry modifications, network connections, and persistence mechanisms.

---

## 🧠 MITRE ATT&CK

Detections and investigations are mapped to the **MITRE ATT&CK framework** whenever applicable.

| Technique | Description |
|---|---|
| T1059.001 | PowerShell |
| T1110 | Brute Force |
| T1110.003 | Password Spraying |
| T1078 | Valid Accounts |
| T1218 | System Binary Proxy Execution |
| T1105 | Ingress Tool Transfer |
| T1027 | Obfuscated Files or Information |

MITRE mapping helps connect individual detections to broader attacker behavior and attack chains.

---

## 🛠️ Technology Stack

**Security platforms:** Microsoft Defender XDR, Microsoft Entra ID, Microsoft Sentinel, Wazuh.

**Detection and query:** KQL, Windows Event Logs, Sysmon.

**Frameworks:** MITRE ATT&CK.

**Engineering and analysis:** Python, PowerShell, Docker, Git, GitHub, malware analysis, threat hunting, incident response, IOC analysis.

---

## 📈 Current Focus

- Microsoft Security
- KQL and detection engineering
- Threat hunting and incident response
- Endpoint telemetry and SIEM investigations
- Building reproducible security labs and validation evidence

---

## 📚 Documentation Standard

For major detections and investigations, I aim to document:

1. Objective and threat scenario
2. Data source and required telemetry
3. Detection logic and evidence
4. MITRE ATT&CK mapping
5. Severity and rationale
6. Investigation steps
7. False positives and tuning
8. Validation test cases
9. Response guidance

This ensures that projects demonstrate both **technical implementation and SOC analyst methodology**.

---

## 👨‍💻 About the Author

**Harsh Kethwas**

Cybersecurity professional focused on:

**SOC Operations • Detection Engineering • Threat Hunting • Microsoft Security • Incident Response**

GitHub: [@HarshKethwas](https://github.com/HarshKethwas)

---

> ⚠️ **Disclaimer**
>
> All security research, detections, simulations, and laboratory activities in this repository are performed for educational, defensive security, and authorized testing purposes only.

---

⭐ **If you find this repository useful, consider giving it a star.**
