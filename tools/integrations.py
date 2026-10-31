#!/usr/bin/env python3
"""Send security results to a SIEM over syslog, and to Home Assistant over MQTT. Standard library only.

Used by tools/security_audit.py and tools/adb_autoclose.py (--syslog, --mqtt). It can also send a
saved audit by itself:

    integrations.py audit report.json --syslog syslog+udp://192.168.1.20:514
    integrations.py audit report.json --mqtt mqtt://user:pass@192.168.1.10:1883
    integrations.py test --syslog syslog+tcp://192.168.1.20:514      send one test event

Targets
  syslog+udp://host[:514]     plain UDP, the default for most collectors (Wazuh, rsyslog, Graylog)
  syslog+tcp://host[:514]     TCP, one message per line
  syslog+tls://host[:6514]    TCP over TLS, the certificate checked against the system's CAs or ?ca=
  options: ?format=rfc3164 (default, what Wazuh pre-decodes) or rfc5424, ?facility=local0, ?ca=FILE
  mqtt://user:pass@host[:1883]    MQTT 3.1.1; mqtts://...:8883 over TLS (?ca=FILE for your own CA)
  options: ?base=cleanyourtv (topic prefix), ?discovery=homeassistant (prefix; "off" to skip)

Percent-encode / ? # @ and : in a user name or password (%2F %3F %23 %40 %3A).
A password on the command line ends up in your shell history and the process list, so the same URLs
can come from the environment instead: CLEANYOURTV_SYSLOG (comma-separated) and CLEANYOURTV_MQTT.

Every syslog message is one JSON object after the header, tagged `cleanyourtv`, so a SIEM can decode
it with its JSON decoder; integrations/wazuh/ has a ready decoder and rules. Over MQTT, the audit is a
retained state on <base>/<device>/audit, events go to <base>/<device>/event, and Home Assistant
discovery creates the sensors (integrations/home-assistant/ has example automations). The device name
is the same one the security-watchdog add-on uses, so its sensors land on the same device.

There is no option to skip TLS certificate checks: give your own CA with ?ca= instead.
"""
import argparse
import datetime as dt
import json
import os
import re
import secrets
import socket
import ssl
import struct
import sys
from urllib.parse import parse_qs, unquote, urlsplit

TAG = "cleanyourtv"
FACILITIES = {"kern": 0, "user": 1, "daemon": 3, "auth": 4, "syslog": 5, "authpriv": 10,
              **{f"local{i}": 16 + i for i in range(8)}}
SYSLOG_SEVERITY = {"high": 3, "medium": 4, "low": 5, "info": 6}
TIMEOUT_S = 10.0


def redact(url):
    """Hides everything between the user name and the last '@', so a password holding '/', '?', '#' or
    '@' is still hidden whole. Used for every URL that reaches a message."""
    return re.sub(r"://([^:/@]*):.*@(?=[^@]*$)", r"://\1:***@", url or "")


def slug(name):
    """A topic- and hostname-safe form of the TV's name: living-room-tv -> living_room_tv."""
    text = re.sub(r"[^a-z0-9]+", "_", (name or "").lower()).strip("_")
    return text[:48] or "tv"


# ---------------------------------------------------------------------------------------------------
# Targets

class Target:
    def __init__(self, url):
        parts = urlsplit(url)
        self.url = url
        self.scheme = parts.scheme.lower()
        self.host = parts.hostname
        self.query = {k: v[-1] for k, v in parse_qs(parts.query).items()}
        self.user = unquote(parts.username) if parts.username else None
        self.password = unquote(parts.password) if parts.password else None
        defaults = {"syslog+udp": 514, "syslog+tcp": 514, "syslog+tls": 6514, "mqtt": 1883, "mqtts": 8883}
        if self.scheme not in defaults:
            raise ValueError(f"unknown target {self.scheme or redact(url)!r}: use syslog+udp, syslog+tcp, "
                             "syslog+tls, mqtt or mqtts")
        if not self.host:
            raise ValueError(f"no host in {self.redacted()} (percent-encode / ? # @ in a password)")
        try:
            self.port = parts.port or defaults[self.scheme]
        except ValueError:
            raise ValueError(f"bad port in {self.redacted()} (percent-encode / ? # @ in a password)")

    def redacted(self):
        """The URL with the password hidden, for messages and logs."""
        return redact(self.url)

    def tls_context(self):
        context = ssl.create_default_context(cafile=self.query.get("ca"))
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        return context


def targets_from(syslog_urls, mqtt_url):
    """The command line's targets, or the environment's when the command line gives none."""
    syslog_urls = list(syslog_urls or [])
    if not syslog_urls and os.environ.get("CLEANYOURTV_SYSLOG"):
        syslog_urls = [u.strip() for u in os.environ["CLEANYOURTV_SYSLOG"].split(",") if u.strip()]
    mqtt_url = mqtt_url or os.environ.get("CLEANYOURTV_MQTT") or None
    return syslog_urls, mqtt_url


# ---------------------------------------------------------------------------------------------------
# Syslog

def syslog_message(event, severity, hostname, fmt="rfc3164", facility="local0", now=None):
    """One syslog line: header, then the event as compact JSON."""
    now = now or dt.datetime.now(dt.timezone.utc)
    if facility not in FACILITIES:
        raise ValueError(f"unknown syslog facility {facility!r}")
    if fmt not in ("rfc3164", "rfc5424"):
        raise ValueError(f"format must be rfc3164 or rfc5424, not {fmt!r}")
    pri = FACILITIES[facility] * 8 + SYSLOG_SEVERITY.get(severity, 6)
    body = json.dumps(event, separators=(",", ":"), sort_keys=True, default=str)
    host = slug(hostname).replace("_", "-")
    if fmt == "rfc5424":
        stamp = now.astimezone(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
        return f"<{pri}>1 {stamp} {host} {TAG} - - - {body}"
    local = now.astimezone()
    stamp = f"{local.strftime('%b')} {local.day:>2} {local.strftime('%H:%M:%S')}"
    return f"<{pri}>{stamp} {host} {TAG}: {body}"


def send_syslog(target, messages, connector=socket.create_connection):
    fmt = target.query.get("format", "rfc3164")
    if fmt not in ("rfc3164", "rfc5424"):
        raise ValueError(f"format must be rfc3164 or rfc5424, not {fmt!r}")
    if target.scheme == "syslog+udp":
        family = socket.AF_INET6 if ":" in target.host else socket.AF_INET
        with socket.socket(family, socket.SOCK_DGRAM) as sock:
            sock.settimeout(TIMEOUT_S)
            for message in messages:
                sock.sendto(message.encode("utf-8"), (target.host, target.port))
        return
    with connector((target.host, target.port), timeout=TIMEOUT_S) as raw:
        sock = target.tls_context().wrap_socket(raw, server_hostname=target.host) \
            if target.scheme == "syslog+tls" else raw
        try:
            for message in messages:
                sock.sendall(message.encode("utf-8") + b"\n")
        finally:
            if sock is not raw:
                sock.close()


# ---------------------------------------------------------------------------------------------------
# MQTT 3.1.1, publish only

def _remaining_length(n):
    out = bytearray()
    while True:
        byte, n = n % 128, n // 128
        out.append(byte | (0x80 if n else 0))
        if not n:
            return bytes(out)


def _string(text):
    data = text.encode("utf-8")
    return struct.pack("!H", len(data)) + data


def connect_packet(client_id, user=None, password=None, keepalive=30):
    flags = 0x02                                   # clean session
    payload = _string(client_id)
    if user is not None:
        flags |= 0x80
        payload += _string(user)
        if password is not None:
            flags |= 0x40
            payload += _string(password)
    body = _string("MQTT") + bytes([4, flags]) + struct.pack("!H", keepalive) + payload
    return bytes([0x10]) + _remaining_length(len(body)) + body


def publish_packet(topic, payload, packet_id, retain=False):
    body = _string(topic) + struct.pack("!H", packet_id) + payload
    header = 0x30 | 0x02 | (0x01 if retain else 0)   # QoS 1
    return bytes([header]) + _remaining_length(len(body)) + body


def _read_exact(sock, n):
    data = b""
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            raise ConnectionError("the broker closed the connection")
        data += chunk
    return data


def _read_packet(sock):
    first = _read_exact(sock, 1)[0]
    length, shift = 0, 0
    while True:
        byte = _read_exact(sock, 1)[0]
        length |= (byte & 0x7F) << shift
        if not byte & 0x80:
            break
        shift += 7
        if shift > 21:
            raise ConnectionError("malformed packet from the broker")
    return first, _read_exact(sock, length)


CONNACK_ERRORS = {1: "protocol version refused", 2: "client id refused", 3: "broker unavailable",
                  4: "bad user name or password", 5: "not authorised"}


def mqtt_publish(target, messages, connector=socket.create_connection):
    """Publish [(topic, payload dict or str, retain)] with QoS 1, waiting for each PUBACK."""
    with connector((target.host, target.port), timeout=TIMEOUT_S) as raw:
        sock = target.tls_context().wrap_socket(raw, server_hostname=target.host) \
            if target.scheme == "mqtts" else raw
        try:
            client_id = f"{TAG}-{secrets.token_hex(4)}"
            sock.sendall(connect_packet(client_id, target.user, target.password))
            kind, body = _read_packet(sock)
            if kind != 0x20 or len(body) != 2:
                raise ConnectionError("the broker did not answer CONNECT")
            if body[1]:
                raise ConnectionError(f"the broker refused: {CONNACK_ERRORS.get(body[1], body[1])}")
            for packet_id, (topic, payload, retain) in enumerate(messages, start=1):
                data = payload if isinstance(payload, bytes) else (
                    payload if isinstance(payload, str) else json.dumps(payload, separators=(",", ":"))
                ).encode("utf-8")
                sock.sendall(publish_packet(topic, data, packet_id, retain))
                while True:
                    kind, body = _read_packet(sock)
                    if kind == 0x40 and body == struct.pack("!H", packet_id):
                        break
            sock.sendall(b"\xe0\x00")                # DISCONNECT
        finally:
            if sock is not raw:
                sock.close()


# ---------------------------------------------------------------------------------------------------
# Home Assistant

def ha_device(device_name, model=None, manufacturer=None):
    device = {"identifiers": [f"{TAG}_{slug(device_name)}"], "name": device_name}
    if model:
        device["model"] = model
    if manufacturer:
        device["manufacturer"] = manufacturer
    return device


def discovery_messages(prefix, base, device, sensors):
    """Retained discovery configs. sensors: (component, object_id, name, state topic, extra config)."""
    node = device["identifiers"][0]
    messages = []
    for component, object_id, name, topic, extra in sensors:
        config = {"name": name, "unique_id": f"{node}_{object_id}", "state_topic": topic,
                  "device": device, **extra}
        messages.append((f"{prefix}/{component}/{node}/{object_id}/config", config, True))
    return messages


def audit_state(report):
    findings = report.get("findings", [])
    worst = next((f for f in findings if f["severity"] != "info"), None)
    return {
        **report["summary"],
        "result": worst["severity"] if worst else "ok",
        "top": worst["title"] if worst else "",
        "adb_network_open": bool(report.get("adb_network_open")),
        "security_patch": report["device"].get("security_patch"),
        "time": report["time"],
    }


def audit_mqtt_messages(report, target):
    base = target.query.get("base", TAG).strip("/")
    prefix = target.query.get("discovery", "homeassistant").strip("/")
    name = report["device_name"]
    node = slug(name)
    state_topic = f"{base}/{node}/audit"
    event_topic = f"{base}/{node}/event"
    messages = []
    if prefix != "off":
        device = ha_device(name, report["device"].get("model"), report["device"].get("manufacturer"))
        js = "{{ value_json.%s }}"
        messages += discovery_messages(prefix, base, device, [
            ("sensor", "audit_result", "Security audit", state_topic,
             {"value_template": js % "result", "icon": "mdi:shield-search",
              "json_attributes_topic": state_topic}),
            ("sensor", "high_findings", "High findings", state_topic,
             {"value_template": js % "high", "state_class": "measurement", "icon": "mdi:shield-alert"}),
            ("sensor", "medium_findings", "Medium findings", state_topic,
             {"value_template": js % "medium", "state_class": "measurement", "icon": "mdi:shield-half-full"}),
            ("binary_sensor", "adb_network_open", "Network ADB open (audit)", state_topic,
             {"value_template": "{{ 'ON' if value_json.adb_network_open else 'OFF' }}",
              "device_class": "problem"}),
            ("sensor", "last_audit", "Last audit", state_topic,
             {"value_template": js % "time", "device_class": "timestamp"}),
            ("sensor", "security_patch", "Security patch", state_topic,
             {"value_template": js % "security_patch", "icon": "mdi:calendar-lock"}),
        ])
    messages.append((state_topic, audit_state(report), True))
    for finding in report["findings"]:
        if finding["severity"] != "info":
            messages.append((event_topic, {"event": "audit_finding", "device": name, **finding}, False))
    return messages


# ---------------------------------------------------------------------------------------------------
# What the tools call

def audit_syslog_messages(report, target, now=None):
    fmt = target.query.get("format", "rfc3164")
    facility = target.query.get("facility", "local0")
    if facility not in FACILITIES:
        raise ValueError(f"unknown facility {facility!r}")
    name = report["device_name"]
    common = {"source": TAG, "device": name, "model": report["device"].get("model"),
              "audit_time": report["time"]}
    counts = report["summary"]
    lines = [syslog_message({**common, "event": "audit_summary", **counts, "severity": "info",
                             "title": f"Security audit: {counts['high']} high, {counts['medium']} medium",
                             "adb_network_open": report.get("adb_network_open")},
                            "info", name, fmt, facility, now)]
    for finding in report["findings"]:
        # "finding" repeats the id under a name no SIEM reserves (Wazuh keeps "id" as a static field).
        lines.append(syslog_message({**common, "event": "audit_finding", **finding, "finding": finding["id"]},
                                    finding["severity"], name, fmt, facility, now))
    return lines


def export_audit(report, syslog_urls, mqtt_url):
    """Send an audit report. Returns the problems, one line each; an empty list when all went out."""
    syslog_urls, mqtt_url = targets_from(syslog_urls, mqtt_url)
    problems = []
    for url in syslog_urls:
        try:
            target = Target(url)
            if not target.scheme.startswith("syslog"):
                raise ValueError(f"{target.redacted()} is not a syslog URL")
            send_syslog(target, audit_syslog_messages(report, target))
        except (OSError, ValueError, KeyError, ssl.SSLError) as e:
            problems.append(f"syslog {url_for_message(url)}: {e}")
    if mqtt_url:
        try:
            target = Target(mqtt_url)
            if not target.scheme.startswith("mqtt"):
                raise ValueError(f"{target.redacted()} is not an MQTT URL")
            mqtt_publish(target, audit_mqtt_messages(report, target))
        except (OSError, ValueError, ssl.SSLError, ConnectionError) as e:
            problems.append(f"mqtt {url_for_message(mqtt_url)}: {e}")
    return problems


def export_event(event, syslog_urls, mqtt_url, device_name=None, severity=None):
    """Send one event (adb_autoclose's result, say) to every target."""
    syslog_urls, mqtt_url = targets_from(syslog_urls, mqtt_url)
    name = device_name or event.get("device") or "tv"
    now = dt.datetime.now(dt.timezone.utc)
    payload = {"source": TAG, "device": name, "time": now.isoformat(timespec="seconds"), **event}
    severity = severity or {"closed": "info", "unknown": "low", "still_open": "high"}.get(
        event.get("result"), "info")
    payload.setdefault("severity", severity)
    problems = []
    for url in syslog_urls:
        try:
            target = Target(url)
            line = syslog_message(payload, severity, name, target.query.get("format", "rfc3164"),
                                  target.query.get("facility", "local0"), now)
            send_syslog(target, [line])
        except (OSError, ValueError, KeyError, ssl.SSLError) as e:
            problems.append(f"syslog {url_for_message(url)}: {e}")
    if mqtt_url:
        try:
            target = Target(mqtt_url)
            base = target.query.get("base", TAG).strip("/")
            node = slug(name)
            messages = [(f"{base}/{node}/event", payload, False)]
            if event.get("event") == "adb_close":
                state_topic = f"{base}/{node}/adb_close"
                prefix = target.query.get("discovery", "homeassistant").strip("/")
                if prefix != "off":
                    messages += discovery_messages(prefix, base, ha_device(name), [
                        ("sensor", "last_adb_close", "Last ADB close", state_topic,
                         {"value_template": "{{ value_json.result }}", "icon": "mdi:lan-disconnect",
                          "json_attributes_topic": state_topic})])
                messages.append((state_topic, {"result": event.get("result"), "time": payload["time"],
                                               "ports": event.get("ports", {})}, True))
            mqtt_publish(target, messages)
        except (OSError, ValueError, ssl.SSLError, ConnectionError) as e:
            problems.append(f"mqtt {url_for_message(mqtt_url)}: {e}")
    return problems


def url_for_message(url):
    return redact(url)


def main(argv=None):
    p = argparse.ArgumentParser(description="Send a saved audit, or a test event, to syslog and MQTT.")
    p.add_argument("what", choices=("audit", "test"))
    p.add_argument("report", nargs="?", help="audit: the JSON file security_audit.py --out wrote")
    p.add_argument("--syslog", action="append", default=[], metavar="URL")
    p.add_argument("--mqtt", metavar="URL")
    p.add_argument("--device-name", default="tv")
    args = p.parse_args(argv)
    if args.what == "audit":
        if not args.report:
            p.error("audit needs the report file")
        with open(args.report, encoding="utf-8") as f:
            report = json.load(f)
        problems = export_audit(report, args.syslog, args.mqtt)
    else:
        problems = export_event({"event": "test", "message": "integration test from cleanyourtv"},
                                args.syslog, args.mqtt, args.device_name, "info")
    for problem in problems:
        print(problem, file=sys.stderr)
    syslog_urls, mqtt_url = targets_from(args.syslog, args.mqtt)
    if not syslog_urls and not mqtt_url:
        print("nothing to send to: give --syslog or --mqtt (or set CLEANYOURTV_SYSLOG / CLEANYOURTV_MQTT)",
              file=sys.stderr)
        return 2
    print("sent" if not problems else "some targets failed")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
