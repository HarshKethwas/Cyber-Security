# Docker Persistence Map — Wazuh Manager

**Date:** 2026-11-22  
**Container:** `single-node-wazuh.manager-1`  
**Image:** `wazuh/wazuh-manager:4.13.1`

## Verified manager mounts

The output of `docker inspect` confirms that the manager's configuration directory is backed by a writable Docker named volume:

| Host-side source (sanitized) | Container destination | Type | Writable |
|---|---|---|---|
| `single-node_wazuh_etc/_data` | `/var/ossec/etc` | Docker volume | Yes |
| `single-node_wazuh_logs/_data` | `/var/ossec/logs` | Docker volume | Yes |
| `single-node_wazuh_queue/_data` | `/var/ossec/queue` | Docker volume | Yes |
| `single-node_wazuh_integrations/_data` | `/var/ossec/integrations` | Docker volume | Yes |
| `single-node_wazuh_agentless/_data` | `/var/ossec/agentless` | Docker volume | Yes |
| `single-node_wazuh_active_response/_data` | `/var/ossec/active-response/bin` | Docker volume | Yes |
| `single-node_wazuh_api_configuration/_data` | `/var/ossec/api/configuration` | Docker volume | Yes |
| `single-node_wazuh_wodles/_data` | `/var/ossec/wodles` | Docker volume | Yes |

The manager's `ossec.conf` is supplied separately through a host bind mount at `/wazuh-config-mount/etc/ossec.conf`. This should not be modified as part of the initial custom-rule deployment unless inspection shows a configuration change is required.

## Deployment implication

Custom Wazuh rules can be stored under:

```text
/var/ossec/etc/rules/
```

Because `/var/ossec/etc` is a writable named volume, files placed under this path should persist across a normal container restart and container recreation that reuses the same volume. They will not be preserved if the volume itself is deleted.

## Pending verification

Before copying any custom XML:

1. Inspect the current contents of `/var/ossec/etc/rules/`.
2. Check whether `/var/ossec/etc/ossec.conf` includes `etc/rules` in its `<ruleset>` configuration.
3. Inspect existing `local_rules.xml` without overwriting it.
4. Validate the new rules with `/var/ossec/bin/wazuh-logtest`.
5. Restart the manager only after successful parsing and rule-match validation.

**Status:** Persistent destination identified. Rule directory and rule-loading configuration have not yet been inspected.
