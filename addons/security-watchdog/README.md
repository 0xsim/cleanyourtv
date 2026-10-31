# Security Watchdog

Watches the TV's security around the clock and tells you when something changes: debugging switched
on, a new app installed from outside a store, an app given accessibility or notification access, a
proxy or Private DNS change. It keeps its own log on the TV, can send every event to a SIEM over
syslog and to Home Assistant over MQTT, and can switch debugging off by itself when it has been left on.

For the [Clean Your TV](../../README.md) launcher it declares a [module card](../../docs/modules.md):
once you answer **Show card**, its tile reads "Watchdog" with a red glow. On any other Android TV home
it is an ordinary app.

It is the on-TV half of the security tools in this fork. The other half runs on your computer:
[`tools/security_audit.py`](../../tools/security_audit.py) (a full check, on demand) and
[`tools/adb_autoclose.py`](../../tools/adb_autoclose.py) (close debugging when a session ends).

> No screenshot yet: this add-on has not been run on a real TV. Treat the first install as a test, and
> check the event list after you switch debugging on and off once.

## What it watches

| Change | Severity | Why it matters |
|---|---|---|
| Network ADB starts listening on port 5555 | high | Plaintext; on some firmware anyone on your network gets a shell |
| Network ADB set to reopen at every boot (`persist.adb.tcp.port`) | high | The port comes back after each restart |
| An app other than yours gets accessibility access | high | It can read the screen and every key pressed |
| An app other than yours gets notification access | high | It reads the text of every notification |
| An app becomes a device administrator | high | It can lock or wipe the TV and resist removal |
| A proxy is set for all web traffic | high | The classic way to watch or change what the TV sends |
| USB or Wireless debugging switched on | medium | A way in while it stays on |
| An app is installed from outside an app store | medium | Sideloaded APKs skip the store's checks |
| The keyboard changes to an app you installed | medium | A keyboard sees every password typed |
| Private DNS changes, Play Protect app checks switched off | medium | Who sees your lookups; whether APKs are checked |
| An app installed from a store, developer options on | low | Worth a look, rarely a problem |
| Things switched back off, apps removed | info | Kept in the log |

Your own apps never count against you: the watchdog itself, the Clean Your TV launcher, and anything
you list in `trusted_packages` are always reported as info.

It checks settings the moment they change (Android tells it), apps as they are installed or removed,
and everything else once a minute, with a full re-check every `sweep_minutes`. The first look after
installing reports only what is already risky, not every app on the TV.

## Debugging auto-close

Debugging left on is the usual way a TV stays open. With `WRITE_SECURE_SETTINGS` (which `install.sh`
grants), the watchdog switches USB debugging and Wireless debugging off once any form of debugging has
been on for `adb_autoclose_minutes` (default 30). Switching USB debugging off stops adbd, which closes
the network port too.

- The clock starts when debugging comes on, including the session you install the watchdog with.
- On the TV, **Keep it on longer** restarts the clock, and **Close debugging now** closes it at once.
- From Home Assistant, the **Close ADB** button does the same.
- `adb_autoclose_minutes: 0` turns auto-close off; the watchdog then only reports.

Unlike `tools/adb_autoclose.py` on your computer, this keeps working when the computer is gone: a
laptop that went to sleep mid-session cannot leave the TV open. It cannot revoke the computers the TV
already trusts; do that once in Developer options.

## Install

```bash
TV_HOST=<tv ip> addons/security-watchdog/install.sh                 # watch and keep a local log
TV_HOST=<tv ip> addons/security-watchdog/install.sh ~/tv-watchdog.json   # and report to your servers
```

It builds the app, installs it, grants `WRITE_SECURE_SETTINGS` (skip that with `NO_AUTOCLOSE=1`) and
`POST_NOTIFICATIONS`, pushes the config and checks that the TV accepted it. A config with a mistake is
refused and the previous one stays in use, so a typo never switches reporting off.

The config can hold an MQTT password. Keep the file outside the repository, and push it over USB or
Wireless debugging where the TV offers them: network ADB on port 5555 is plaintext.

## Config

All keys are optional. [`config.example.json`](config.example.json):

| Key | Default | What it does |
|---|---|---|
| `device_name` | the TV's model | Its name in syslog and Home Assistant. Use the same `--device-name` with the host tools so everything lands on one device |
| `syslog` | none | One URL or a list: `syslog+udp://host:514`, `syslog+tcp://host:514`, `syslog+tls://host:6514`; add `?format=rfc5424` for RFC 5424 |
| `mqtt` | none | `mqtt://user:pass@host:1883` or `mqtts://user:pass@host:8883` |
| `mqtt_base` | `cleanyourtv` | Topic prefix |
| `ha_discovery` | `homeassistant` | Home Assistant's discovery prefix, or `off` |
| `ca_pem` | system CAs | Your own CA certificate (PEM), for `mqtts` and `syslog+tls` with a home CA |
| `adb_autoclose_minutes` | 30 | 0 to 1440; 0 turns auto-close off |
| `trusted_packages` | none | Your own apps: always info |
| `sweep_minutes` | 15 | Full re-check interval |
| `on_screen_alerts` | `high` | Show a toast and a notification for events this bad: `high`, `medium` or `off` |

TLS certificates and host names are always checked; there is no switch to turn that off. Give your own
CA in `ca_pem` instead.

## Reporting

**Syslog / SIEM.** Each event is one RFC 3164 line tagged `cleanyourtv`, whose message is a JSON object
(`event`, `severity`, `title`, `detail`, `package`, `device`, `time`, `origin: watchdog`), the same format the
audit's `--syslog` option sends. Events that could not be sent wait in an outbox on the TV (up
to 1000 per target) and go out when the server answers again. A ready Wazuh decoder and rules are in
[`integrations/wazuh/`](../../integrations/wazuh/).

**MQTT / Home Assistant.** The watchdog stays connected and publishes:

| Topic | Retained | Content |
|---|---|---|
| `<base>/<device>/watchdog/state` | yes | Debugging, auto-close minutes left, proxy, Private DNS, keyboard, accessibility and notification holders, device admins, app count, last event |
| `<base>/<device>/watchdog/availability` | yes | `online`, or `offline` (the broker publishes it when the TV goes away) |
| `<base>/<device>/event` | no | One JSON object per event, shared with the host tools |
| `<base>/<device>/watchdog/command` | (listens) | `close_adb` or `sweep`; anything else is ignored |

With discovery on, Home Assistant gets binary sensors (USB debugging, Wireless debugging, Network ADB
listening, HTTP proxy set), sensors (ADB auto-close, Last security event, Private DNS, Installed apps)
and two buttons (Close ADB, Re-check security), on the same device as the host audit's sensors.
Example automations are in [`integrations/home-assistant/`](../../integrations/home-assistant/).

The command topic only accepts the two commands that make the TV safer or re-check it, so a broker
account that can publish there can never open anything. Still, give the TV its own MQTT user that can
only use its own topics.

**From your computer.** The shell can read the newest events and the config result:

```bash
TV_HOST=<tv ip> tools/venv/bin/python -I tools/tv.py 'content query --uri content://io.github.securetv.watchdog.config/events'
```

## Permissions

| Permission | Why |
|---|---|
| `INTERNET` | Sends events to the syslog and MQTT servers named in your config, and checks whether port 5555 answers on 127.0.0.1. Nothing goes anywhere unless the config names a server. |
| `QUERY_ALL_PACKAGES` | Sees every installed app, so it can report new ones (Android 11+ hides them otherwise). |
| `RECEIVE_BOOT_COMPLETED` | Starts watching after a reboot. |
| `FOREGROUND_SERVICE`, `FOREGROUND_SERVICE_SPECIAL_USE` | Keeps watching in the background, with an ongoing notification as Android requires. |
| `POST_NOTIFICATIONS` | Shows high-severity alerts in the notification shade on Android 13+. `install.sh` grants it. |
| `WRITE_SECURE_SETTINGS` | Only to switch debugging off (auto-close, the Close button, the Home Assistant button). Android lets only ADB grant it; `install.sh` does unless `NO_AUTOCLOSE=1`. |

It reads settings, the app list, device admins and two system properties, and changes nothing but
the two debugging switches. Its log, outboxes and config stay in its private storage; backups are off.
The config provider answers only callers holding `WRITE_SECURE_SETTINGS`, which on a TV means ADB.
No accounts, no telemetry, no ads, no libraries.

## Uninstall

Settings → Apps → Security Watchdog → Uninstall, or
`tools/venv/bin/python -I tools/tv.py 'pm uninstall io.github.securetv.watchdog'`. Its retained MQTT
topics stay on your broker until you clear them.
