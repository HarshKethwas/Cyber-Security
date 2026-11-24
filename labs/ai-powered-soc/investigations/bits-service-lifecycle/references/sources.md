# References

1. Microsoft Learn — [BITS Startup Type](https://learn.microsoft.com/en-us/windows/win32/bits/bits-startup-type). Documents delayed automatic startup when jobs are active and Demand Start when no jobs are active.
2. Microsoft Learn — [Sysmon configuration files](https://learn.microsoft.com/en-us/windows/security/operating-system-security/sysmon/sysmon-configuration-files). Describes filtering configuration and include/exclude behavior.
3. Microsoft Sysinternals — [Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon).
4. Wazuh — [Configuring log collection](https://documentation.wazuh.com/current/user-manual/capabilities/log-data-collection/configuration.html).
5. Wazuh — [localfile configuration](https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/localfile.html).
6. Wazuh ruleset — [Windows System rules](https://github.com/wazuh/wazuh-ruleset/blob/master/rules/0590-win-system_rules.xml). Parent rule reference for 61104; validate against installed version.
7. Wazuh ruleset — [Windows Sysmon rules](https://github.com/wazuh/wazuh-ruleset/blob/master/rules/0595-win-sysmon_rules.xml). Parent rule references for 61603 and 61615; validate against installed version.
8. Wazuh — [Rules XML syntax](https://documentation.wazuh.com/current/user-manual/ruleset/ruleset-xml-syntax/rules.html).

## Evidence provenance

Based on user-supplied Wazuh alert JSON, Windows Event ID 7040, PowerShell Event ID 4104 and command history, Sysmon Event IDs 1/13/16, the active Sysmon configuration display, Task Scheduler metadata, BITS job output, and controlled test commands. No independent disk image, malware sample, complete binary verification, or endpoint-wide compromise assessment was performed.
