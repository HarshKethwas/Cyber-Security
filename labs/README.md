# Security Labs

Hands-on security lab documentation covering endpoint telemetry, SIEM monitoring, identity administration, detection validation, and Microsoft security tooling.

## Labs

| Lab | Status | Description |
|---|---|---|
| [AI-Powered SOC Lab](./ai-powered-soc/README.md) | In progress — Milestone 1 reported complete | Wazuh, Docker, Windows 11, Sysmon telemetry pipeline and planned AI-assisted SOC workflow |
| [Windows Server Identity Lab](./windows-server-identity/README.md) | In progress — Phase 1 | Isolated Windows Server 2025 VM for AD DS, DNS, identity lifecycle, Group Policy, and security auditing |
| Microsoft Security | Planned | Defender XDR, Entra ID, Sentinel, and investigation workflows |

## Windows Server Identity Lab

The lab currently has a Windows Server 2025 Standard Evaluation VM installed and a VirtualBox Host-only network identified at `192.168.56.1/24`. The Host-only DHCP server has been disabled. NAT-to-Host-only cutover, static guest IP configuration, connectivity validation, and AD DS deployment remain pending.

See the [Windows Server Identity Lab documentation](./windows-server-identity/README.md) for the topology, progress checklist, planned phases, safety boundaries, and evidence standard.

## AI-Powered SOC Lab — current scope

The first milestone established a reported end-to-end telemetry path:

- Wazuh v4.13.1 deployed using Docker.
- Windows 11 endpoint connected with Wazuh Agent.
- Sysmon installed and configured on the endpoint.
- Sysmon operational events integrated into Wazuh.
- Initial process, file, discovery, and account-discovery events observed.
- Wazuh alert generation verified during initial testing.

See the [project documentation](./ai-powered-soc/README.md) for architecture, validation notes, planned milestones, and the next action.

> Custom detection development, attack simulation coverage, threat-intelligence integration, AI investigation, and response automation are planned work. They should only be marked complete after implementation and validation.
