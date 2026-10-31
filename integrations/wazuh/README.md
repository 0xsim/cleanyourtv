# Wazuh

Turns the TV's security events into Wazuh alerts: findings from
[`tools/security_audit.py`](../../tools/security_audit.py), results from
[`tools/adb_autoclose.py`](../../tools/adb_autoclose.py), and live events from the
[security-watchdog](../../addons/security-watchdog/) add-on. Any SIEM that reads syslog with a JSON
message works the same way; these files are the Wazuh version.

## What arrives

Every event is one syslog line (RFC 3164, facility local0) from the program `cleanyourtv`, with the TV's
name as the host and one JSON object as the message:

```
Oct 30 12:00:05 living-room-tv cleanyourtv: {"detail":"It can read the screen and the keys pressed. (com.evil.spy/com.evil.spy.Svc)","device":"Living Room TV","event":"accessibility","origin":"watchdog","package":"com.evil.spy","severity":"high","source":"cleanyourtv","time":"2026-10-30T12:00:05Z","title":"com.evil.spy has accessibility access"}
```

| Field | Values |
|---|---|
| `event` | `audit_summary`, `audit_finding`, `adb_close`, and from the watchdog `adb_usb`, `adb_wireless`, `adb_network`, `adb_persistent`, `adb_port_stuck`, `adb_closed`, `accessibility`, `notification_access`, `device_admin`, `keyboard`, `proxy`, `private_dns`, `app_installed`, `app_removed`, `verifier_off`, … |
| `severity` | `high`, `medium`, `low`, `info` |
| `device` | The name given with `--device-name` or `device_name` (default: the TV's model) |
| `id`, `finding` | Audit findings only: `ADB-001`, `PRM-001`, … (the full list is in `tools/security_audit.py`). Rules match `finding`, as Wazuh keeps `id` as a static field |
| `package` | The app concerned, when there is one |
| `origin` | `watchdog` for the add-on's events |

## Install

On the Wazuh manager:

1. Copy [`cleanyourtv_decoders.xml`](cleanyourtv_decoders.xml) to `/var/ossec/etc/decoders/` and
   [`cleanyourtv_rules.xml`](cleanyourtv_rules.xml) to `/var/ossec/etc/rules/`.
2. Add the `<remote>` block from [`ossec-remote.xml`](ossec-remote.xml) to `/var/ossec/etc/ossec.conf`,
   with `allowed-ips` narrowed to your TVs and the computer that runs the audit.
3. Restart: `systemctl restart wazuh-manager`.
4. Test before pointing anything at it: run `/var/ossec/bin/wazuh-logtest` and paste the sample line
   above. Phase 2 should name the `cleanyourtv` decoder and list the JSON fields; phase 3 should fire
   rule 100711 at level 12.

Then send real events:

```bash
TV_HOST=<tv ip> tools/venv/bin/python -I tools/security_audit.py --syslog syslog+udp://<wazuh ip>:514 --device-name "Living Room TV"
tools/venv/bin/python -I tools/integrations.py test --syslog syslog+udp://<wazuh ip>:514
```

and give the watchdog `"syslog": ["syslog+udp://<wazuh ip>:514"]` in its config.

## Rules

| Rule | Level | Fires on |
|---|---|---|
| 100700 | 0 | Every Clean Your TV event (the parent) |
| 100701 to 100704 | 3, 5, 8, 10 | `severity` info, low, medium, high |
| 100710 | 12 | Network ADB open, set to reopen at boot, or still answering after being closed |
| 100711 | 12 | An app given accessibility, notification access or device admin (high only: your own apps are info) |
| 100712 | 12 | Web traffic sent through a proxy |
| 100713 | 12 | `adb_autoclose.py` switched debugging off but the port still answers |
| 100714 | 12 | A high audit finding of the same kinds: no ADB prompt, persistent ADB port, debug build, SELinux off, proxy, accessibility, notification access, device admin |
| 100720 | 3 | An audit ran (one summary per run; alert on its absence if you schedule audits) |
| 100730 | 10 | Three sideloaded installs on one TV within 10 minutes |

The IDs 100700 to 100739 are in Wazuh's range for local rules; move the block if your own rules use them.

## Notes

- UDP syslog is fire-and-forget. The watchdog keeps an outbox and resends what a TCP or TLS target did
  not take; over UDP it cannot know. Use `syslog+tcp://` where the network allows it.
- The watchdog's events carry the time the TV saw the change in `time`; the syslog header carries the
  time it was sent, which can be later after an outage.
- Other SIEMs: Graylog, Elastic (Filebeat syslog input) and Splunk all parse the JSON message once the
  `cleanyourtv:` header is split off. `?format=rfc5424` on the URL switches to RFC 5424 headers.
