# Integrations

Where the secure edition's security events can go. All three tools speak the same two formats, so a
SIEM rule or a Home Assistant automation written once covers the audit, the auto-close and the watchdog.

| Folder | For | Transport |
|---|---|---|
| [`wazuh/`](wazuh/) | Wazuh, or any SIEM that reads syslog with a JSON message | syslog (UDP, TCP, TLS) |
| [`home-assistant/`](home-assistant/) | Home Assistant, Node-RED, anything on MQTT | MQTT 3.1.1 (plain or TLS), with discovery |

| Sender | Sends | How to point it |
|---|---|---|
| [`tools/security_audit.py`](../tools/security_audit.py) | One summary and one event per finding, each run | `--syslog`, `--mqtt`, or `CLEANYOURTV_SYSLOG` / `CLEANYOURTV_MQTT` |
| [`tools/adb_autoclose.py`](../tools/adb_autoclose.py) | Whether debugging was closed and the port refuses | the same |
| [`addons/security-watchdog/`](../addons/security-watchdog/) | Every change it sees on the TV, live | `syslog` and `mqtt` in its config.json |
| [`tools/integrations.py`](../tools/integrations.py) | A saved audit report, or a test event | `integrations.py audit report.json --syslog ...`, `integrations.py test ...` |

The sending code is in [`tools/integrations.py`](../tools/integrations.py) (Python standard library only)
and in the watchdog's `SyslogSender` and `MqttLink` (Java, no libraries). TLS always checks the
certificate and the host name; give your own CA (`?ca=` for the tools, `ca_pem` for the watchdog)
rather than switching the check off, which neither side allows.
