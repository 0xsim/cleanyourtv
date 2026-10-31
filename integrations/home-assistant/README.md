# Home Assistant

The TV's security as Home Assistant entities, over MQTT: the
[security-watchdog](../../addons/security-watchdog/) add-on reports live, and
[`tools/security_audit.py`](../../tools/security_audit.py) adds the full audit's results to the same
device. Both use MQTT discovery, so the entities appear by themselves once the
[MQTT integration](https://www.home-assistant.io/integrations/mqtt/) is set up.

## Set up

1. Give each TV its own MQTT user, limited to its own topics: [`mosquitto-acl.conf`](mosquitto-acl.conf)
   is an example for the Mosquitto add-on. The command topic only accepts "close ADB" and "re-check",
   but a user that can only touch its own topics is still the right default.
2. Put the TV's MQTT URL in the watchdog's config (`"mqtt": "mqtt://tv-living-room:<password>@<broker>:1883"`)
   and run `addons/security-watchdog/install.sh` with it.
3. Run the audit with the same device name, so its sensors join the watchdog's device:

   ```bash
   export CLEANYOURTV_MQTT='mqtt://cleanyourtv-tools:<password>@<broker>:1883'
   TV_HOST=<tv ip> tools/venv/bin/python -I tools/security_audit.py --device-name "Living Room TV"
   ```

   The environment variable keeps the password out of your shell history; `--mqtt` works too.

4. Copy what you want from [`automations.yaml`](automations.yaml) into your automations, with your own
   entity IDs and notify service.

## Entities

One device per TV, named after `device_name` / `--device-name` (the TV's model by default).

| Entity | From | What it shows |
|---|---|---|
| USB debugging, Wireless debugging, Network ADB listening, HTTP proxy set | watchdog | `on` is a problem |
| ADB auto-close | watchdog | Minutes until debugging is switched off, or `off` |
| Last security event | watchdog | Its title; the whole state (accessibility holders, device admins, keyboard, …) as attributes |
| Private DNS, Installed apps | watchdog | As named |
| Close ADB, Re-check security | watchdog | Buttons |
| Security audit, High findings, Medium findings, Network ADB open (audit), Last audit, Security patch | audit | The newest audit's results, the worst finding's title as the state's attributes |
| Last ADB close | `adb_autoclose.py` | `closed`, `still_open` or `unknown` |

The watchdog's entities go `unavailable` when the TV is off or the app is stopped (its MQTT will). The
audit's entities keep the last result until the next run.

## Topics

| Topic | Retained | Published by |
|---|---|---|
| `cleanyourtv/<device>/watchdog/state` | yes | watchdog |
| `cleanyourtv/<device>/watchdog/availability` | yes | watchdog (`online`), broker (`offline`) |
| `cleanyourtv/<device>/watchdog/command` | no | Home Assistant's buttons: `close_adb`, `sweep` |
| `cleanyourtv/<device>/audit` | yes | `security_audit.py` |
| `cleanyourtv/<device>/adb_close` | yes | `adb_autoclose.py` |
| `cleanyourtv/<device>/event` | no | all three: one JSON object per event, with `severity` and `title` |

`?base=` on the URL (`mqtt_base` in the watchdog's config) changes the `cleanyourtv` prefix, and
`?discovery=off` (`ha_discovery: "off"`) skips discovery for brokers without Home Assistant.

## Running the audit on a schedule

The audit needs ADB, so it can only run while debugging is on. A weekly reminder that runs it from the
computer you set up with is the practical form; the watchdog covers the days in between. On a Linux box
with the repo and its venv:

```bash
# crontab -e: Sundays at 10:00, closing debugging again afterwards
0 10 * * 0  cd ~/cleanyourtv && TV_HOST=<tv ip> CLEANYOURTV_MQTT='mqtt://...' tools/venv/bin/python -I tools/adb_autoclose.py run -- tools/venv/bin/python -I tools/security_audit.py --device-name "Living Room TV"
```

That only works while debugging is on at that time, which the watchdog's auto-close usually prevents:
turn debugging on, run it, and let `adb_autoclose.py` close it again.
