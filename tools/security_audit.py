#!/usr/bin/env python3
"""A read-only security check of the connected TV: what an attacker on your network, or an app on the
TV, could use against you.

    security_audit.py                         audit the TV at TV_HOST and print the report
    security_audit.py --json                  the same report as JSON, for scripts and a SIEM
    security_audit.py --out report.json       also write the JSON report to a file (mode 0600)
    security_audit.py --trust com.example.app the app is yours: report what it holds as info only
    security_audit.py --fail-on medium        exit 1 when a finding is medium or worse (default: high)
    security_audit.py --syslog syslog+udp://192.168.1.20:514
                                              send every finding to a syslog server or SIEM (Wazuh)
    security_audit.py --mqtt mqtt://user:pass@192.168.1.10:1883
                                              publish the result to MQTT, with Home Assistant discovery
    security_audit.py --device-name living-room-tv
                                              the name the TV gets in syslog and Home Assistant

Exit codes: 0 nothing at or above --fail-on, 1 at least one such finding, 2 the audit could not run.

What it looks at, and why each one matters:
  * ADB: whether it asks "Allow USB debugging?" at all (ro.adb.secure), whether it listens on the
    network now, and whether it reopens after every reboot (persist.adb.tcp.port). Network ADB is
    plaintext, and on a set without the prompt anyone on the LAN gets a shell.
  * The build: a debuggable build, SELinux off, an unlocked bootloader, an old security patch.
  * Apps holding the powers spyware wants: accessibility (reads the screen and keys), notification
    access, device admin, the keyboard (sees every password typed), draw-over-apps, usage access, and
    the right to install other apps.
  * Apps installed from outside an app store, Play Protect's app check switched off.
  * The network: a proxy that every web request goes through, Private DNS, and the ports the TV
    listens on.

It changes nothing on the TV: every command it sends reads a property, a setting or a list, and
tests/test_security_audit.py holds the command list to that. Package names read from the TV are
only printed, never put into another command.
"""
import argparse
import datetime as dt
import json
import os
import re
import secrets
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent

PACKAGE_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z0-9_]+)+")
COMPONENT_RE = re.compile(r"([A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z0-9_]+)+)/([A-Za-z0-9_.$]+)")

SEVERITIES = ("high", "medium", "low", "info")
RANK = {name: i for i, name in enumerate(SEVERITIES)}

# One shell call per key, all sent as one batch. Every command only reads; the test suite checks
# each one against READ_ONLY below, so a command that writes cannot slip into this table.
COMMANDS = {
    "model": "getprop ro.product.model",
    "manufacturer": "getprop ro.product.manufacturer",
    "android": "getprop ro.build.version.release",
    "sdk": "getprop ro.build.version.sdk",
    "patch": "getprop ro.build.version.security_patch",
    "adb_secure": "getprop ro.adb.secure",
    "debuggable": "getprop ro.debuggable",
    "build_type": "getprop ro.build.type",
    "verified_boot": "getprop ro.boot.verifiedbootstate",
    "flash_locked": "getprop ro.boot.flash.locked",
    "tcp_port": "getprop service.adb.tcp.port",
    "persist_tcp_port": "getprop persist.adb.tcp.port",
    "selinux": "getenforce",
    "adb_enabled": "settings get global adb_enabled",
    "adb_wifi_enabled": "settings get global adb_wifi_enabled",
    "developer_options": "settings get global development_settings_enabled",
    "verifier": "settings get global package_verifier_enable",
    "non_market": "settings get secure install_non_market_apps",
    "accessibility_services": "settings get secure enabled_accessibility_services",
    "notification_listeners": "settings get secure enabled_notification_listeners",
    "default_ime": "settings get secure default_input_method",
    "enabled_imes": "settings get secure enabled_input_methods",
    "private_dns_mode": "settings get global private_dns_mode",
    "private_dns_host": "settings get global private_dns_specifier",
    "http_proxy": "settings get global http_proxy",
    "proxy_host": "settings get global global_http_proxy_host",
    "proxy_port": "settings get global global_http_proxy_port",
    "third_party": "pm list packages -3 -i --user 0 || pm list packages -3 -i",
    "install_ops": "appops query-op REQUEST_INSTALL_PACKAGES allow",
    "overlay_ops": "appops query-op SYSTEM_ALERT_WINDOW allow",
    "usage_ops": "appops query-op GET_USAGE_STATS allow",
    "listening": "cat /proc/net/tcp /proc/net/tcp6",
    "device_policy": "dumpsys device_policy",
}
READ_ONLY = ("getprop ", "getenforce", "settings get ", "pm list packages ", "appops query-op ",
             "cat /proc/net/", "dumpsys device_policy")

# Installers that mean "a person or a script put this APK here", rather than an app store.
SIDELOAD_INSTALLERS = {"", "null", "com.android.shell", "com.android.packageinstaller",
                       "com.google.android.packageinstaller"}

# Ports TV firmware commonly opens for features the owner uses; anything else gets a closer look.
KNOWN_PORTS = {
    5555: "network ADB",
    8008: "Chromecast (Cast HTTP)",
    8009: "Chromecast (Cast)",
    8443: "Chromecast (Cast setup)",
    9080: "DIAL / second screen",
    7000: "AirPlay receiver",
    7100: "AirPlay receiver",
    6466: "Android TV Remote",
    6467: "Android TV Remote pairing",
    1900: "UPnP / DLNA",
    8060: "DIAL",
    56789: "DIAL / second screen",
}


@dataclass
class Finding:
    id: str
    severity: str
    title: str
    detail: str
    fix: str = ""
    packages: list = field(default_factory=list)


# ---------------------------------------------------------------------------------------------------
# Collecting

def batch_command(commands, nonce):
    """One shell line that runs every command and marks where each answer starts. The nonce is new
    each run, so nothing the TV prints can pass for a marker and overwrite another answer."""
    parts = []
    for key, command in commands.items():
        parts.append(f"echo '@@{nonce}:{key}@@'; ({command}) 2>/dev/null")
    return "; ".join(parts)


def split_batch(output, keys, nonce):
    """The batch's output, cut back into one answer per key. A key with no marker reads as ''."""
    answers = {key: "" for key in keys}
    current = None
    lines = []
    for raw in output.replace("\r", "").split("\n"):
        marker = re.fullmatch(rf"@@{re.escape(nonce)}:([a-z_]+)@@", raw.strip())
        if marker and marker.group(1) in answers:
            if current is not None:
                answers[current] = "\n".join(lines).strip()
            current, lines = marker.group(1), []
        elif current is not None:
            lines.append(raw)
    if current is not None:
        answers[current] = "\n".join(lines).strip()
    return answers


def collect(shell, nonce=None):
    """Every answer the audit needs, from one round trip. `shell` runs one command on the TV."""
    nonce = nonce or secrets.token_hex(8)
    return split_batch(shell(batch_command(COMMANDS, nonce)), COMMANDS, nonce)


# ---------------------------------------------------------------------------------------------------
# Reading the answers

def value(facts, key):
    """A setting or property, with Android's "null" and empty both read as None."""
    text = (facts.get(key) or "").strip()
    return None if text in ("", "null") else text


def components(setting):
    """pkg/class entries of a colon-separated setting, as (package, component) pairs."""
    found = []
    for match in COMPONENT_RE.finditer(setting or ""):
        pair = (match.group(1), f"{match.group(1)}/{match.group(2)}")
        if pair not in found:
            found.append(pair)
    return found


def packages_in(text):
    """Package names in an appops or pm answer, one per line, with or without a 'package:' prefix."""
    names = []
    for line in (text or "").splitlines():
        line = line.strip()
        if line.startswith("package:"):
            line = line[len("package:"):]
        token = line.split()[0] if line.split() else ""
        if PACKAGE_RE.fullmatch(token) and token not in names:
            names.append(token)
    return names


def third_party(facts):
    """package -> installer for every app the owner (or a script) installed, from `pm list -3 -i`."""
    apps = {}
    for line in (facts.get("third_party") or "").splitlines():
        match = re.match(r"\s*package:(\S+)(?:\s+installer=(\S*))?", line)
        if match and PACKAGE_RE.fullmatch(match.group(1)):
            apps[match.group(1)] = (match.group(2) or "").strip()
    return apps


def device_admins(text):
    """(enabled admin packages, device or profile owner packages) from `dumpsys device_policy`."""
    admins, owners = [], []
    owner_re = re.compile(r"admin=ComponentInfo\{([A-Za-z_][\w.]*)/")
    section, base = None, 0
    for line in (text or "").splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        indent = len(line) - len(line.lstrip())
        if section and indent <= base:
            section = None          # a line no deeper than the heading starts the next section
        if stripped.startswith("Enabled Device Admins"):
            section, base = "admins", indent
            continue
        if stripped.startswith(("Device Owner", "Profile Owner")):
            section, base = "owner", indent
            # Some builds print the admin on the heading line itself.
        if section == "admins":
            match = re.fullmatch(r"([A-Za-z_][\w.]*)/[\w.$]+:", stripped)
            if match and match.group(1) not in admins:
                admins.append(match.group(1))
        elif section == "owner":
            match = owner_re.search(stripped)
            if match and match.group(1) not in owners:
                owners.append(match.group(1))
    return admins, owners


def _ipv4(word):
    return bytes.fromhex(word)[::-1]


def _ipv6(hexstr):
    # /proc/net/tcp6 writes the address as four 32-bit words, each in host (little-endian) order.
    return b"".join(bytes.fromhex(hexstr[i:i + 8])[::-1] for i in range(0, 32, 8))


def listening_ports(text):
    """{port: True when something listens beyond loopback} from /proc/net/tcp and tcp6."""
    ports = {}
    for line in (text or "").splitlines():
        parts = line.split()
        if len(parts) < 4 or parts[3] != "0A" or ":" not in parts[1]:
            continue
        address, port_hex = parts[1].split(":", 1)
        try:
            port = int(port_hex, 16)
            if len(address) == 8:
                ip = _ipv4(address)
                loopback = ip[0] == 127
            elif len(address) == 32:
                ip = _ipv6(address)
                mapped = ip[:12] == b"\x00" * 10 + b"\xff\xff"
                loopback = ip == b"\x00" * 15 + b"\x01" or (mapped and ip[12] == 127)
            else:
                continue
        except ValueError:
            continue
        ports[port] = ports.get(port, False) or not loopback
    return ports


def patch_age_months(patch, today):
    try:
        date = dt.date.fromisoformat(patch)
    except (TypeError, ValueError):
        return None
    return (today.year - date.year) * 12 + (today.month - date.month)


def project_packages(root=ROOT):
    """The launcher and add-on package names this repository builds. A name is not proof of who built
    the app, so evaluate() only softens what these hold to low; --trust is what makes them info."""
    names = set()
    pattern = re.compile(r"applicationId\b[^\n]*?['\"]([A-Za-z_][\w.]*\.[\w.]+)['\"]")
    for gradle in list(root.glob("launcher/app/build.gradle*")) + list(root.glob("addons/*/app/build.gradle*")):
        try:
            names.update(pattern.findall(gradle.read_text(encoding="utf-8")))
        except OSError:
            continue
    return names


# ---------------------------------------------------------------------------------------------------
# Judging

def evaluate(facts, today=None, trusted=(), known=()):
    """The findings, worst first.

    `trusted` packages are the owner's own (--trust) and only ever info. `known` packages carry the name
    of an app this repository builds: a name proves nothing (spyware can take any name that is not
    installed), so their powers stay visible, at low, with a note to --trust them once checked.
    """
    today = today or dt.date.today()
    trusted = set(trusted)
    known = set(known) - trusted
    apps = third_party(facts)
    findings = []

    def add(*args, **kwargs):
        findings.append(Finding(*args, **kwargs))

    def holder_severity(package, third_party_severity):
        if package in trusted:
            return "info"
        if package not in apps:
            return "info"
        if package in known:
            return "low" if RANK[third_party_severity] < RANK["low"] else third_party_severity
        return third_party_severity

    def known_note(package):
        return (" It has the name of an app from this repository; if you installed it, pass --trust "
                f"{package}.") if package in known else ""

    # ADB ---------------------------------------------------------------------------------------
    secure = value(facts, "adb_secure")
    if secure != "1":
        add("ADB-001", "high", "ADB does not ask before giving a computer a shell",
            f"ro.adb.secure is {secure or 'not set'}; adbd reads a missing value as 0. Any device that "
            "reaches the ADB port gets a shell without the 'Allow USB debugging?' prompt.",
            "Keep debugging off whenever you are not using it, and check with "
            "tools/adb_autoclose.py that the port stays closed. The firmware cannot be changed from here.")
    persist = value(facts, "persist_tcp_port")
    if persist and persist not in ("-1", "0"):
        add("ADB-002", "high", f"Network ADB reopens on port {persist} after every reboot",
            "persist.adb.tcp.port is set, so the plaintext ADB port comes back at each start.",
            "Turn USB debugging off in Developer options; ask the vendor if it stays.")
    tcp = value(facts, "tcp_port")
    ports = listening_ports(facts.get("listening"))
    adb_ports = sorted({int(tcp)} if tcp and tcp.isdigit() and tcp not in ("0",) else set())
    adb_ports = sorted(set(adb_ports) | ({5555} if ports.get(5555) else set()))
    if adb_ports:
        listed = ", ".join(str(p) for p in adb_ports)
        add("ADB-003", "medium", f"Network ADB is open on port {listed}",
            "Expected while a tool is connected over the network. The port is plaintext: close it as "
            "soon as you are done.",
            "tools/venv/bin/python -I tools/adb_autoclose.py now")
    if value(facts, "adb_wifi_enabled") == "1":
        add("ADB-004", "low", "Wireless debugging is on",
            "It is paired and encrypted, but it is still a way in while it stays on.",
            "Developer options > Wireless debugging > off when you are done.")
    if value(facts, "adb_enabled") == "1":
        add("ADB-005", "info", "USB debugging is on", "Needed for this audit; switch it off afterwards.")
    if value(facts, "developer_options") == "1":
        add("DEV-001", "low", "Developer options are on",
            "Not a hole by itself, but every debugging switch lives there.",
            "Settings > Developer options > off, once you no longer need it.")

    # The build ---------------------------------------------------------------------------------
    build_type = value(facts, "build_type")
    if value(facts, "debuggable") == "1" or build_type in ("userdebug", "eng"):
        add("BLD-001", "high", "This is a debug build of Android",
            f"ro.debuggable={value(facts, 'debuggable') or '?'}, ro.build.type={build_type or '?'}: on such "
            "builds ADB can become root.",
            "Ask the vendor for a production (user) build.")
    selinux = value(facts, "selinux")
    if selinux and selinux.lower().startswith("permissive"):
        add("BLD-002", "high", "SELinux is off (permissive)",
            "Android's sandbox between apps is not enforced.", "Ask the vendor for a firmware update.")
    boot = value(facts, "verified_boot")
    if (boot and boot not in ("green",)) or value(facts, "flash_locked") == "0":
        add("BLD-003", "medium", "Verified boot is not fully on",
            f"verifiedbootstate={boot or '?'}, flash.locked={value(facts, 'flash_locked') or '?'}: the "
            "system partition could have been modified without the TV noticing.",
            "Unless you unlocked it yourself, ask the vendor.")
    patch = value(facts, "patch")
    age = patch_age_months(patch, today)
    if age is None:
        add("BLD-004", "low", "The security patch level is unknown",
            "ro.build.version.security_patch is empty on this firmware.")
    else:
        severity = "high" if age > 24 else "medium" if age > 12 else "low" if age > 6 else "info"
        add("BLD-004", severity, f"Security patch from {patch} ({age} months old)",
            "Known Android vulnerabilities published since then are not fixed on this TV.",
            "Install firmware updates; keep the TV off untrusted networks if none come.")

    # Installing apps ---------------------------------------------------------------------------
    installers = [p for p in packages_in(facts.get("install_ops")) if p in apps]
    for package in installers:
        add("APP-001", holder_severity(package, "medium"), f"{package} may install other apps",
            "It holds 'Install unknown apps'. A compromised or malicious app with this right can drop "
            "more apps onto the TV.",
            "Settings > Apps > Special app access > Install unknown apps > off for it.", [package])
    if value(facts, "non_market") == "1":
        add("APP-002", "medium", "Apps from unknown sources are allowed (legacy switch)",
            "install_non_market_apps is 1: any app may sideload others.",
            "Settings > Security > Unknown sources > off.")
    if value(facts, "verifier") == "0":
        add("APP-003", "medium", "Play Protect app checks are off",
            "package_verifier_enable is 0: installed APKs are not checked for known malware.",
            "Play Store > Play Protect > Scan apps > on.")
    sideloaded = sorted(p for p, installer in apps.items() if installer in SIDELOAD_INSTALLERS)
    own = [p for p in sideloaded if p in trusted or p in known]
    others = [p for p in sideloaded if p not in trusted and p not in known]
    if others:
        add("APP-004", "low", f"{len(others)} app(s) installed from outside an app store",
            "Sideloaded apps skip the store's checks. Make sure you know each one: " + ", ".join(others),
            "Remove the ones you do not recognise in Settings > Apps.", others)
    if own:
        add("APP-005", "info", f"{len(own)} app(s) from this repository or --trust, installed by ADB",
            ", ".join(own) + ". Names only: check they are the ones you built.", packages=own)

    # Powers that spyware wants -----------------------------------------------------------------
    for package, component in components(facts.get("accessibility_services")):
        add("PRM-001", holder_severity(package, "high"), f"{package} has accessibility access",
            f"{component} can read what is on screen and every key pressed, and act for you."
            + known_note(package),
            "Settings > Accessibility > turn it off unless you set it up yourself.", [package])
    for package, component in components(facts.get("notification_listeners")):
        add("PRM-002", holder_severity(package, "high"), f"{package} reads your notifications",
            f"{component} sees the text of every notification on the TV." + known_note(package),
            "Settings > Apps > Special app access > Notification access > off.", [package])
    admins, owners = device_admins(facts.get("device_policy"))
    for package in admins:
        add("PRM-003", holder_severity(package, "high"), f"{package} is a device administrator",
            "A device admin can lock the TV, wipe it, or refuse to be uninstalled." + known_note(package),
            "Settings > Security > Device admin apps > deactivate it.", [package])
    for package in owners:
        add("PRM-004", holder_severity(package, "medium"), f"{package} manages this TV (device owner)",
            "Normal on a TV a company or hotel manages; on a home TV, find out why.", "", [package])
    ime = value(facts, "default_ime")
    ime_pairs = components(ime)
    if ime_pairs:
        package, component = ime_pairs[0]
        add("PRM-005", holder_severity(package, "medium"), f"The keyboard is {package}",
            f"{component} sees everything typed on the TV, passwords included." + known_note(package),
            "Use the TV's own keyboard unless you trust this one.", [package])
    default_package = ime_pairs[0][0] if ime_pairs else None
    for package, component in components(facts.get("enabled_imes")):
        if package != default_package and package in apps and package not in trusted:
            add("PRM-006", "low", f"Another keyboard is enabled: {package}",
                f"{component} can be switched to at any time.",
                "Settings > Keyboard > disable keyboards you do not use.", [package])
    for op, pid, label, why in (
            ("overlay_ops", "PRM-007", "may draw over other apps",
             "An overlay can cover a login screen with a fake one."),
            ("usage_ops", "PRM-008", "can see which apps you use and when",
             "Usage access is a full viewing history of the TV.")):
        holders = [p for p in packages_in(facts.get(op)) if p in apps and p not in trusted]
        if holders:
            add(pid, "low", f"{len(holders)} app(s) {label}", f"{why} Holders: {', '.join(holders)}",
                "Settings > Apps > Special app access: switch off what you do not need.", holders)

    # Network -----------------------------------------------------------------------------------
    proxy = value(facts, "http_proxy")
    proxy_host = value(facts, "proxy_host")
    if (proxy and proxy not in (":0",)) or proxy_host:
        shown = proxy or f"{proxy_host}:{value(facts, 'proxy_port') or '?'}"
        add("NET-001", "high", f"Web traffic goes through a proxy: {shown}",
            "A proxy you did not set is a classic way to watch or change what the TV sends.",
            "If you did not set it: settings put global http_proxy :0 (and check your network).")
    mode = value(facts, "private_dns_mode")
    host = value(facts, "private_dns_host")
    if mode == "hostname" and host:
        add("NET-002", "info", f"Private DNS: {host}", "DNS lookups are encrypted to this resolver.")
    elif mode == "off":
        add("NET-002", "info", "Private DNS is off",
            "DNS lookups go unencrypted to your router; fine if your router filters them.")
    exposed = sorted(p for p, network in ports.items() if network and p not in adb_ports)
    if facts.get("listening"):
        known = [p for p in exposed if p in KNOWN_PORTS]
        unknown = [p for p in exposed if p not in KNOWN_PORTS]
        if known:
            add("NET-003", "info", f"{len(known)} known service port(s) open to the network",
                ", ".join(f"{p} ({KNOWN_PORTS[p]})" for p in known))
        if unknown:
            add("NET-004", "low", f"{len(unknown)} other port(s) open to the network",
                "Something on the TV accepts connections on: " + ", ".join(str(p) for p in unknown)
                + ". Find out which app it is if you do not know.",
                "tools/venv/bin/python -I tools/tv.py 'netstat -ltnp' (where the TV allows it)")
    else:
        add("NET-005", "info", "Listening ports were not checked",
            "This firmware does not let the shell read /proc/net/tcp.")

    findings.sort(key=lambda f: (RANK[f.severity], f.id))
    return findings


def device_info(facts):
    return {
        "manufacturer": value(facts, "manufacturer"),
        "model": value(facts, "model"),
        "android": value(facts, "android"),
        "sdk": value(facts, "sdk"),
        "security_patch": value(facts, "patch"),
    }


def summarize(findings):
    counts = {name: 0 for name in SEVERITIES}
    for finding in findings:
        counts[finding.severity] += 1
    return counts


def build_report(facts, findings, now=None, device_name=None):
    now = now or dt.datetime.now(dt.timezone.utc)
    info = device_info(facts)
    return {
        "tool": "cleanyourtv-security-audit",
        "version": 1,
        "time": now.isoformat(timespec="seconds"),
        "device_name": device_name or info.get("model") or "tv",
        "device": info,
        "summary": summarize(findings),
        "adb_network_open": any(f.id == "ADB-003" for f in findings),
        "findings": [asdict(f) for f in findings],
    }


def text_report(report):
    device = report["device"]
    name = " ".join(x for x in (device.get("manufacturer"), device.get("model")) if x) or "TV"
    head = f"TV security audit - {name}, Android {device.get('android') or '?'}"
    counts = report["summary"]
    lines = [head, " · ".join(f"{counts[s]} {s}" for s in SEVERITIES), ""]
    for finding in report["findings"]:
        if finding["severity"] == "info":
            continue
        lines.append(f"{finding['severity'].upper():<7} {finding['id']}  {finding['title']}")
        lines.append(f"        {finding['detail']}")
        if finding["fix"]:
            lines.append(f"        Fix: {finding['fix']}")
        lines.append("")
    info = [f for f in report["findings"] if f["severity"] == "info"]
    if info:
        lines.append("Info")
        lines.extend(f"  {f['id']}  {f['title']}" for f in info)
    return "\n".join(lines).rstrip() + "\n"


# ---------------------------------------------------------------------------------------------------
# Command line

def connect():
    sys.path.insert(0, str(HERE))
    try:
        import tv
    except ImportError as e:
        print(f"cannot load tools/tv.py ({e}).\nrun: python3 -m venv tools/venv && "
              "tools/venv/bin/pip install -r tools/requirements.txt", file=sys.stderr)
        raise SystemExit(2)
    except SystemExit as e:          # tv.py exits with a message when TV_HOST is missing or bad
        if e.code not in (None, 0):
            print(e.code, file=sys.stderr)
        raise SystemExit(2)
    try:
        return tv.connect()
    except Exception as e:
        print(f"cannot reach the TV at {os.environ.get('TV_HOST', 'TV_HOST')}: {e}\n"
              "Check TV_HOST and that debugging is on (tools/tv.py --probe).", file=sys.stderr)
        raise SystemExit(2)


def write_private(path, text):
    """Write a report readable by this account only: it lists what is installed on the TV."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0), 0o600)
    if hasattr(os, "fchmod"):
        os.fchmod(fd, 0o600)         # O_CREAT's mode only applies to a new file
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(text)


def parse_args(argv):
    p = argparse.ArgumentParser(description="Read-only security audit of the connected TV.")
    p.add_argument("--json", action="store_true", help="print the JSON report instead of text")
    p.add_argument("--out", help="also write the JSON report to this file")
    p.add_argument("--trust", action="append", default=[], metavar="PACKAGE",
                   help="an app you installed on purpose; may be given several times")
    p.add_argument("--fail-on", choices=SEVERITIES[:3], default="high",
                   help="exit 1 when a finding is this severe or worse (default: high)")
    p.add_argument("--device-name", help="the TV's name in syslog and Home Assistant (default: model)")
    p.add_argument("--syslog", action="append", default=[], metavar="URL",
                   help="syslog+udp://host:514, syslog+tcp://host:514 or syslog+tls://host:6514")
    p.add_argument("--mqtt", metavar="URL", help="mqtt://user:pass@host:1883 or mqtts://...:8883")
    args = p.parse_args(argv)
    for package in args.trust:
        if not PACKAGE_RE.fullmatch(package):
            p.error(f"not a package name: {package!r}")
    return args


def main(argv=None):
    args = parse_args(sys.argv[1:] if argv is None else argv)
    dev = connect()
    try:
        facts = collect(lambda command: dev.shell(command, read_timeout_s=120.0) or "")
    finally:
        try:
            dev.close()
        except Exception:
            pass
    if not value(facts, "sdk"):
        print("the TV answered nothing the audit could read; check the connection", file=sys.stderr)
        return 2
    findings = evaluate(facts, trusted=set(args.trust), known=project_packages())
    report = build_report(facts, findings, device_name=args.device_name)
    as_json = json.dumps(report, indent=2)
    print(as_json if args.json else text_report(report), end="" if not args.json else "\n")
    if args.out:
        try:
            write_private(args.out, as_json + "\n")
        except OSError as e:
            print(f"cannot write {args.out}: {e.strerror or e}", file=sys.stderr)
            return 2
    sys.path.insert(0, str(HERE))
    import integrations
    syslog_urls, mqtt_url = integrations.targets_from(args.syslog, args.mqtt)
    if syslog_urls or mqtt_url:
        for problem in integrations.export_audit(report, syslog_urls, mqtt_url):
            print(f"export: {problem}", file=sys.stderr)
    worst = RANK[args.fail_on]
    return 1 if any(RANK[f.severity] <= worst for f in findings) else 0


if __name__ == "__main__":
    sys.exit(main())
