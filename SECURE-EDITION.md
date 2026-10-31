# Secure edition

This fork of [Gathin23/cleanyourtv](https://github.com/Gathin23/cleanyourtv) keeps everything the
original does and adds security tooling around it: a way to check how exposed a TV is, a way to make
sure debugging does not stay open, a watchdog that lives on the TV, and reporting to the systems you
already use (a SIEM over syslog, Home Assistant over MQTT).

The launcher is unchanged and stays offline: no internet permission, as upstream. Everything that
talks to the network is a separate tool or a separate add-on that you choose to install.

## What it adds

| Piece | Runs on | What it does |
|---|---|---|
| [`tools/security_audit.py`](tools/security_audit.py) | your computer | A read-only check of the TV, with a severity and a fix for each finding |
| [`tools/adb_autoclose.py`](tools/adb_autoclose.py) | your computer | Switches debugging off when you are done, and proves port 5555 is closed |
| [`addons/security-watchdog/`](addons/security-watchdog/) | the TV | Watches for changes all the time, reports them, closes debugging left on |
| [`tools/integrations.py`](tools/integrations.py), [`integrations/`](integrations/) | both | Syslog to a SIEM (Wazuh decoder and rules included) and MQTT to Home Assistant |

## Why these

Cleaning a TV means turning on ADB, and ADB is the weak point:

- **Network ADB is plaintext.** On firmware without the "Allow USB debugging?" prompt
  (`ro.adb.secure` unset or 0), anyone on your network gets a shell. The audit tells you whether your TV
  is one of those; auto-close makes sure the window is short either way.
- **Debugging is easy to forget.** A session that ends with a laptop going to sleep leaves the port
  open for days. `adb_autoclose.py run -- ...` closes it when the command ends, fails, or is stopped
  (Ctrl-C, the terminal closing); a laptop that sleeps or loses power cannot run anything, which is
  what the watchdog is for: it closes debugging from the TV itself after a timeout.
- **What spyware needs is visible.** Accessibility, notification access, device admin, a third-party
  keyboard, a proxy: an app that wants to watch you asks for one of these. The audit lists who holds
  them now; the watchdog tells you the moment it changes.

## Quick start

```bash
git clone https://github.com/<you>/cleanyourtv && cd cleanyourtv
python3 -m venv tools/venv && tools/venv/bin/pip install -r tools/requirements.txt
export TV_HOST=192.168.1.50                       # your TV, with debugging on

# 1. How exposed is it?
tools/venv/bin/python -I tools/security_audit.py

# 2. Clean it as upstream describes, but with debugging closed at the end whatever happens:
tools/venv/bin/python -I tools/adb_autoclose.py run -- tools/disable.sh examples/<your tv>/debloat.txt

# 3. Optional: leave a watchdog on the TV (needs a JDK and the Android SDK, as the launcher does)
addons/security-watchdog/install.sh ~/tv-watchdog.json
```

Reporting is opt-in everywhere. Nothing is sent until you name a server: `--syslog` / `--mqtt` (or the
`CLEANYOURTV_SYSLOG` / `CLEANYOURTV_MQTT` environment variables) for the tools, `syslog` / `mqtt` in the
watchdog's config.

## Design rules

These hold for everything this fork adds, and the tests check the ones that can be checked:

- **The audit only reads.** Every command it sends is a `getprop`, `settings get`, `pm list`, `appops
  query-op`, `cat /proc/net/...` or `dumpsys device_policy`; `tests/test_security_audit.py` fails if one
  that writes is added.
- **Closed means refused.** `adb_autoclose.py` reports success only when the TV refuses a new
  connection on the port (the check is upstream's `tools/adb-closed.py`), never because a switch was sent.
- **No new dependencies.** The host tools use Python's standard library (plus upstream's `adb-shell`);
  the watchdog uses no libraries at all. Less code from elsewhere is less to trust.
- **TLS is never weakened.** Certificates and host names are always checked. For a home CA, give the
  CA (`?ca=` / `ca_pem`); there is no "insecure" switch.
- **Passwords stay out of sight.** URLs are printed with the password masked; the audit report is
  written with mode 0600; the watchdog keeps its config in private storage with backups off.
- **Commands from outside can only make the TV safer.** The watchdog's MQTT command topic accepts
  "close ADB" and "re-check" and nothing else, and ignores retained messages; its config provider checks
  that the caller is the shell (ADB) or root, and a config change is first reported to the old targets.
- **A name is not proof.** Apps you name with `--trust` / `trusted_packages`, and (on the TV) apps
  signed with the same key as the watchdog, are reported as info. An app that only carries the name of
  something this repository builds stays visible, at low, with a note to trust it once you have checked.

## Limits

Read these before you rely on it.

- **Not yet run on a real TV.** The Python tools are tested against simulated TVs and real sockets,
  and the watchdog's logic has unit tests and builds cleanly, but none of it has met real firmware yet.
  Run the audit on your TV first and compare it with what you know; install the watchdog as a test.
- **Firmware wins.** If the firmware keeps network ADB open (`persist.adb.tcp.port`), neither tool can
  close it for good; both tell you so. Nothing here can change `ro.adb.secure`.
- **Authorised computers stay authorised.** Revoking the keys the TV trusts can only be done on the TV
  (Developer options > Revoke USB debugging authorisations).
- **The watchdog is an app.** Anyone with ADB or root can stop it, and its silence is the signal: Home
  Assistant shows it unavailable, and `integrations/home-assistant/automations.yaml` has an alert for that.
  A compromise of the firmware itself is out of its reach.
- **UDP syslog can lose events.** Use `syslog+tcp://` or `syslog+tls://` where you can; the watchdog
  resends what a TCP target missed.
- **Pushing a config over network ADB sends its password in clear.** Use USB or Wireless debugging for
  that step, and a dedicated MQTT user per TV (`integrations/home-assistant/mosquitto-acl.conf`).

## Relationship to upstream

Upstream is MIT-licensed, and so is everything added here ([LICENSE](LICENSE)). The launcher, the
debloat tools, the lists and the other add-ons are upstream's, unchanged. Upstream's rules keep
network features and new permissions out of its own repository and send them to forks, which is what
this is; to pull upstream's new TV lists and fixes, merge its `main` into this fork from time to time.
