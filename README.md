# 🛡️ Cyber Security Portfolio

### Harsh Kethwas

**SOC Analyst | Detection Engineering | Threat Hunting | Incident Response**

[![GitHub](https://img.shields.io/badge/GitHub-HarshKethwas-black?logo=github)](https://github.com/HarshKethwas)
[![KQL](https://img.shields.io/badge/KQL-Microsoft%20Security-blue)](https://learn.microsoft.com/en-us/kusto/query/)
[![MITRE ATT\&CK](https://img.shields.io/badge/MITRE-ATT%26CK-red)](https://attack.mitre.org/)
[![Microsoft Defender](https://img.shields.io/badge/Microsoft-Defender%20XDR-0078D4?logo=microsoft)](https://www.microsoft.com/en-us/security/business/endpoint-security/microsoft-defender-endpoint)
[![Wazuh](https://img.shields.io/badge/Wazuh-SIEM-4A90E2)](https://wazuh.com/)

---

## 👨‍💻 About Me

I am a cybersecurity professional focused on **Security Operations, Detection Engineering, Threat Hunting, and Incident Response**.

This repository documents my practical security work, including:

* Detection engineering using **KQL**
* Microsoft Defender XDR investigations
* Microsoft Entra ID security monitoring
* Threat hunting and behavioral analysis
* MITRE ATT&CK mapping
* Incident investigation and response
* Windows endpoint telemetry and Sysmon
* SIEM monitoring with Wazuh
* Malware analysis and security research

My goal is to build detections that are not only technically correct, but also **investigable, tunable, and useful to a SOC analyst**.

---

# 🎯 What This Repository Contains

This repository is my hands-on cybersecurity portfolio.

Instead of focusing only on theoretical concepts, I document security work through:

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

Each project is designed to demonstrate how a security analyst approaches a real-world security problem.

---

# 🔎 Detection Engineering

The detection engineering section contains security detections built primarily with **Kusto Query Language (KQL)** and Microsoft security telemetry.

### Current Detection Areas

| Category                       | Examples                                      |
| ------------------------------ | --------------------------------------------- |
| 🔐 Identity Security           | Password Spray, Brute Force, Account Abuse    |
| 🖥️ Endpoint Security          | Suspicious PowerShell, Office Child Processes |
| ⚙️ Persistence                 | Scheduled Task Abuse                          |
| 🧩 Defense Evasion             | Encoded Commands, LOLBins                     |
| 🌐 Network / Download Activity | Download Cradles, Suspicious Network Activity |
| ☁️ Cloud / Identity            | Entra ID authentication monitoring            |

### Featured Detections

#### 🔥 Office Application → Suspicious Child Process

Detects potentially malicious processes spawned by Microsoft Office applications such as:

```text
WINWORD.EXE
EXCEL.EXE
POWERPNT.EXE
OUTLOOK.EXE
ONENOTE.EXE
```

The detection looks for suspicious child processes including:

```text
powershell.exe
cmd.exe
mshta.exe
rundll32.exe
regsvr32.exe
certutil.exe
bitsadmin.exe
schtasks.exe
```

It also analyzes command-line activity for indicators such as:

* Encoded PowerShell
* Download cradles
* Script execution
* Obfuscation
* Suspicious execution parameters

---

#### 🔐 Entra ID Brute Force / Password Spray Detection

Detects repeated failed authentication attempts in Microsoft Entra ID and helps identify:

* Brute-force attacks
* Password spraying
* Credential stuffing
* Suspicious authentication sources
* Potential account compromise

The investigation workflow includes source IP analysis, affected-user analysis, successful authentication checks, MFA/Conditional Access review, and follow-on activity.

---

# 🕵️ Threat Hunting

Threat hunting projects focus on identifying suspicious behavior that may not immediately generate a high-confidence alert.

Hunting areas include:

```text
PowerShell Abuse
Office Application Abuse
Persistence
Credential Access
Living-off-the-Land Techniques
Suspicious Authentication
Endpoint Anomalies
```

The objective is to move from simple indicator matching toward **behavior-based detection and investigation**.

---

# 🚨 Incident Response

Security alerts are only the beginning of a SOC investigation.

This repository documents investigation workflows that follow the lifecycle:

```text
Alert
 ↓
Triage
 ↓
Scoping
 ↓
Timeline Reconstruction
 ↓
Root Cause Analysis
 ↓
Containment
 ↓
Eradication
 ↓
Recovery
 ↓
Lessons Learned
```

Example investigations include:

* Password Spray Investigation
* Phishing Investigation
* Suspicious PowerShell Activity
* Persistence Investigation
* Potential Account Compromise

Each investigation is designed to answer:

> **What happened? How did it happen? What was affected? What evidence supports the conclusion? What should be done next?**

---

# 🧪 Security Labs

## Wazuh + Sysmon Lab

A Windows security monitoring lab built to generate and investigate endpoint telemetry.

### Architecture

```text
┌────────────────────┐
│   Windows Endpoint │
│                    │
│      Sysmon        │
└─────────┬──────────┘
          │
          ▼
┌────────────────────┐
│    Wazuh Agent     │
└─────────┬──────────┘
          │
          ▼
┌────────────────────┐
│   Wazuh Manager    │
└─────────┬──────────┘
          │
          ▼
┌────────────────────┐
│      Indexer       │
└─────────┬──────────┘
          │
          ▼
┌────────────────────┐
│     Dashboard      │
└────────────────────┘
```

The lab is used to simulate endpoint activity, collect telemetry, create detections, and investigate security events.

---

# 🦠 Malware Analysis

The malware-analysis section focuses on understanding malicious files and behavior through:

### Static Analysis

* File metadata
* Hash analysis
* Strings
* PE characteristics
* Imported functions
* Suspicious indicators

### Dynamic Analysis

* Process creation
* File activity
* Registry modifications
* Network connections
* Persistence mechanisms
* Behavioral indicators

The purpose is to connect malware behavior with **observable detection opportunities**.

---

# 🧠 MITRE ATT&CK

Detections and investigations are mapped to the **MITRE ATT&CK framework** whenever applicable.

Examples include:

| Technique | Description                     |
| --------- | ------------------------------- |
| T1059.001 | PowerShell                      |
| T1110     | Brute Force                     |
| T1110.003 | Password Spraying               |
| T1078     | Valid Accounts                  |
| T1218     | System Binary Proxy Execution   |
| T1105     | Ingress Tool Transfer           |
| T1027     | Obfuscated Files or Information |

MITRE mapping helps connect individual detections to broader attacker behavior and attack chains.

---

# 🛠️ Technology Stack

### Security Platforms

* Microsoft Defender XDR
* Microsoft Entra ID
* Microsoft Sentinel
* Wazuh

### Detection & Query

* Kusto Query Language (KQL)
* Windows Event Logs
* Sysmon

### Security Frameworks

* MITRE ATT&CK

### Analysis

* Malware Analysis
* Threat Hunting
* Incident Response
* IOC Analysis
* Behavioral Analysis

### Tools

* Git / GitHub
* Docker
* Windows
* PowerShell
* WSL

---

# 📁 Repository Structure

```text
Cyber-Security/
│
├── detections/
│   ├── identity/
│   ├── endpoint/
│   ├── persistence/
│   ├── defense-evasion/
│   └── cloud/
│
├── threat-hunting/
│   ├── powershell/
│   ├── credential-access/
│   ├── persistence/
│   └── lateral-movement/
│
├── incident-response/
│   ├── password-spray/
│   ├── phishing/
│   └── persistence/
│
├── malware-analysis/
│   ├── static-analysis/
│   └── dynamic-analysis/
│
├── labs/
│   ├── wazuh/
│   ├── sysmon/
│   └── microsoft-security/
│
├── documentation/
│
└── assets/
```

> Repository structure is continuously evolving as new projects and investigations are added.

---

# 📊 Detection Philosophy

A detection should answer more than:

> "Is this command suspicious?"

The goal is to build detections that answer:

### What happened?

Identify the behavior.

### Why is it suspicious?

Explain the detection logic.

### What should the analyst investigate?

Provide investigation pivots.

### What could be a false positive?

Document legitimate behavior.

### What should happen next?

Provide response guidance.

This approach helps transform raw telemetry into **actionable security detections**.

---

# 📈 Current Focus

My current learning and project focus is:

```text
Microsoft Security
      +
KQL
      +
Detection Engineering
      +
Threat Hunting
      +
Incident Response
      +
MITRE ATT&CK
```

I am continuously expanding this repository with practical labs, detections, investigations, and security research.

---

# 🚀 Roadmap

### Phase 1 — Detection Engineering

* [x] PowerShell detection
* [x] Office child-process hunting
* [x] Entra ID brute-force detection
* [x] Scheduled task persistence detection
* [ ] Break-glass account monitoring
* [ ] Suspicious service creation
* [ ] LOLBin detection library
* [ ] Advanced PowerShell hunting

### Phase 2 — Threat Hunting

* [ ] Credential access hunting
* [ ] Lateral movement hunting
* [ ] Persistence hunting
* [ ] Living-off-the-Land hunting
* [ ] Cloud identity hunting

### Phase 3 — Incident Response

* [ ] Password spray investigation
* [ ] Phishing investigation
* [ ] Account compromise investigation
* [ ] PowerShell attack investigation
* [ ] Persistence investigation

### Phase 4 — Security Labs

* [x] Wazuh deployment
* [x] Sysmon telemetry
* [ ] Windows attack simulation
* [ ] Detection validation
* [ ] End-to-end SOC lab

---

# 📚 Documentation Standard

For major detections and investigations, I aim to document:

```text
Objective
    ↓
Threat Scenario
    ↓
Data Source
    ↓
Detection Logic
    ↓
KQL / Evidence
    ↓
MITRE ATT&CK
    ↓
Severity
    ↓
Investigation Steps
    ↓
False Positives
    ↓
Tuning
    ↓
Response
```

This ensures that projects demonstrate both **technical implementation and SOC analyst methodology**.

---

# 👨‍💻 About the Author

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
