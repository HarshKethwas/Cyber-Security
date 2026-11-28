# Windows Server Identity Lab

> **Status:** In progress — Phase 1 installation completed; isolated-network cutover and validation pending  
> **Platform:** Oracle VirtualBox on Windows 11 host  
> **Guest OS:** Windows Server 2025 Standard Evaluation (Desktop Experience)  
> **Lab purpose:** Learn Windows Server administration, Active Directory Domain Services (AD DS), DNS, Group Policy, identity lifecycle, authentication, authorization, and security monitoring.

## 1. Lab objectives

- Build an isolated Windows Server environment for identity and directory-services practice.
- Understand local accounts versus domain accounts, users, groups, SIDs, OUs, domains, forests, and trusts.
- Deploy AD DS and DNS, then administer users, groups, computers, and Group Policy.
- Learn authentication flows including Kerberos, NTLM, LDAP, and DNS/DC Locator dependencies.
- Generate and investigate Windows security events for account management, authentication, privilege use, and directory changes.
- Later forward server and client telemetry to the existing Wazuh lab for detection engineering.

## 2. Architecture plan

Initial topology (target):

```text
Windows 11 Host
  ├─ VirtualBox
  ├─ Existing Wazuh Docker stack (host-side)
  └─ VirtualBox Host-only interface: 192.168.56.1/24
           |
           | Host-only network — isolated from physical LAN
           |
           └─ DC01 — Windows Server 2025
                Static IPv4 target: 192.168.56.10/24
                Default gateway: none
                DNS: 192.168.56.10 after DNS role deployment
                Planned role: AD DS + DNS
```

A separate Windows client VM will be added in a later phase. Do not join the physical Windows 11 host to the lab domain.

## 3. Host and VM configuration

### Host network interfaces observed

| Host interface | IPv4 | Purpose |
|---|---:|---|
| Ethernet (Realtek) | 192.168.1.5/24 | Physical/local network |
| Ethernet 3 (VirtualBox Host-Only Ethernet Adapter) | 192.168.56.1/24 | Lab host-only interface |
| vEthernet (WSL / Hyper-V firewall) | 172.26.96.1/20 | WSL virtual networking |

The proposed lab subnet `192.168.56.0/24` does not overlap with the host's reported physical or WSL subnets.

### VirtualBox VM

| Setting | Observed value |
|---|---|
| VM name | DC1 (Windows hostname still to be confirmed/renamed to DC01) |
| Guest OS profile | Windows Server 2025 (64-bit) |
| Installed OS | Windows Server 2025 Standard Evaluation |
| OS build | 26100.1 (as reported by `Get-ComputerInfo`) |
| RAM | Initially observed as 2 GB; increase to 4 GB before role installation |
| vCPU | Previously observed as 3; target 2 vCPU |
| Virtual disk | 50 GB |
| Network adapter | Intel PRO/1000 MT Desktop |
| Initial network mode | NAT |

### Host-only network

| Setting | Observed / target |
|---|---|
| Adapter | VirtualBox Host-Only Ethernet Adapter (host interface: Ethernet 3) |
| Host IPv4 | 192.168.56.1 |
| Prefix | 192.168.56.1/24 |
| DHCP server | Disabled (confirmed by operator) |
| VM network mode | **Pending cutover** — NAT is retained until initial updates/activation are complete |

## 4. Progress and evidence

### Phase 1 — Installation and safe network preparation

| Task | Status | Evidence / notes |
|---|---|---|
| Install VirtualBox | Completed | VirtualBox Manager screenshots reviewed |
| Create Windows Server VM | Completed | VM recreated after initial disk-selection issue |
| Install Windows Server 2025 Standard Evaluation | Completed | Successful interactive login and desktop observed |
| Verify guest OS identity | Completed | `Get-ComputerInfo` reported Windows Server 2025 Standard Evaluation, build 26100.1, AMD64 |
| Verify guest NIC | Completed | `Get-NetAdapter` reported Ethernet, Intel PRO/1000 MT Desktop Adapter, Status Up, 1 Gbps |
| Identify host-only adapter | Completed | Host `Get-NetAdapter` identified Ethernet 3 as VirtualBox Host-Only Ethernet Adapter |
| Check host subnet overlap | Completed | Host `ipconfig` showed physical LAN 192.168.1.0/24, WSL 172.26.96.0/20, host-only 192.168.56.0/24 |
| Disable VirtualBox host-only DHCP | Completed | Operator confirmed DHCP disabled |
| Increase guest RAM to 4 GB and set 2 vCPU | Pending verification | Earlier screenshot showed 2 GB RAM and 3 processors; adjust while VM is powered off |
| Complete Windows updates and evaluation activation | Pending | NAT retained for this initial connectivity step |
| Switch VM from NAT to Host-only | Pending | Do this only after initial update/activation work; disable any second adapter |
| Set server hostname to DC01 | Pending | VM display name is DC1; Windows hostname not yet verified |
| Configure guest static IP 192.168.56.10/24 with no gateway | Pending | Do not set final DNS until DNS role is installed |
| Verify host-to-guest connectivity and no direct internet route | Pending | Capture command outputs |
| Take clean VM snapshot | Pending | Take before AD DS installation/promotion |

### Commands used for verification

Guest OS:
```powershell
Get-ComputerInfo | Select-Object WindowsProductName, WindowsVersion, OsArchitecture
Get-NetAdapter
```

Host interfaces:
```powershell
ipconfig
Get-NetAdapter | Format-Table Name, InterfaceDescription, Status
```

## 5. Planned phases

### Phase 2 — Hostname, static networking, and baseline

- Verify VM resource allocation.
- Rename Windows Server to `DC01` (the VM's display name is not the same as the guest hostname).
- Switch to Host-only networking after initial updates/activation.
- Configure `192.168.56.10/24`, with no default gateway.
- Test connectivity to host `192.168.56.1`; verify there is no default route or unintended internet access.
- Record OS version, patch level, time synchronization, and firewall profile.
- Take a clean VirtualBox snapshot.

### Phase 3 — Active Directory Domain Services and DNS

Planned domain: `corp.test` (isolated training namespace; not a production domain).

- Install AD DS and DNS roles.
- Promote `DC01` as the first domain controller in a new forest.
- Understand forest/domain functional levels and DNS dependencies.
- Validate with `Get-ADDomain`, `Get-ADForest`, `Get-ADDomainController`, and `dcdiag`.

### Phase 4 — Identity and access administration

- Create organizational units for IT, HR, Finance, Workstations, Groups, and Service Accounts.
- Create test users and security groups.
- Practice account enable/disable, password reset, lockout/unlock, group membership, and delegated administration.
- Learn group scopes, SIDs, AGDLP, least privilege, and privileged account separation.
- Explore service accounts and Group Managed Service Accounts (gMSA).

### Phase 5 — Client onboarding and Group Policy

- Build a separate Windows client VM on the same host-only network.
- Join it to `corp.test`; do not join the physical host.
- Create and link test Group Policy Objects.
- Validate policy application, DNS registration, domain logon, and computer/user scope.

### Phase 6 — Security auditing and Wazuh integration

- Enable appropriate Advanced Audit Policy settings.
- Generate controlled identity and authentication activity.
- Review Security log events including 4624/4625, 4720–4726, 4728/4732, 4740, 4767, 4768/4769, and 5136 where applicable.
- Onboard the server and client to Wazuh after verifying network reachability and published manager ports.
- Develop detections for account lifecycle, privileged group changes, lockouts, and suspicious authentication.

## 6. Safety boundaries

- Keep the domain controller on Host-only networking; do not use Bridged networking.
- Do not expose AD DS, DNS, LDAP, Kerberos, SMB, or RDP services to the home LAN or internet.
- Keep the physical Windows host outside the test domain.
- Use synthetic test identities and passwords, never production credentials.
- Take snapshots before AD DS promotion and significant Group Policy changes.
- Do not claim a phase is complete until configuration and validation evidence have been recorded.
- Host-only networking permits communication between the host and guest; it is isolation from the physical LAN, not a security boundary between the guest and host.

## 7. Change log

| Date | Change |
|---|---|
| 2026-11-28 | Created Windows Server 2025 Standard Evaluation VM and reached the desktop. |
| 2026-11-28 | Verified guest OS identity and Intel PRO/1000 virtual NIC. |
| 2026-11-28 | Identified VirtualBox host-only interface at 192.168.56.1/24. |
| 2026-11-28 | Disabled VirtualBox host-only DHCP server. |
| 2026-11-28 | Recorded remaining Phase 1 tasks; NAT-to-Host-only cutover and guest static IP are not yet verified. |

## 8. Evidence collection standard

For each phase, keep sanitized evidence in `evidence/` with:
- Date and objective
- Environment and configuration
- Commands run
- Actual output or sanitized screenshot
- Expected versus observed result
- Troubleshooting and corrective action
- Security implications and lessons learned
- Status: passed, failed, or pending

Do not commit passwords, activation keys, personal IP/MAC details beyond what is necessary, domain user secrets, or unredacted production logs.
