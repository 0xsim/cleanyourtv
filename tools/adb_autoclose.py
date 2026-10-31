#!/usr/bin/env python3
"""Close the TV's debugging when you are done, and prove the network port is shut.

    adb_autoclose.py now                     switch debugging off now, then check port 5555 refuses
    adb_autoclose.py after 30m               wait 30 minutes (or 90s, 2h, 45 = minutes), then close
    adb_autoclose.py run -- <command> ...    run a command, then close, whatever way it ends

    --keep-usb              keep USB debugging: switch Wireless debugging off and reboot the TV, which
                            drops the plaintext TCP port (adb tcpip) without touching the USB switch
    --wireless-port N       also check Wireless debugging's own port (adb mdns services shows it)
    --check-host IP         the TV's own address, when TV_HOST points at tools/relay.py (127.0.0.1)
    --syslog URL / --mqtt URL / --device-name NAME
                            report the result to a SIEM or Home Assistant (see tools/integrations.py)

Exit codes: 0 debugging is off and the port refuses connections; 1 the port still answers; 2 the
result could not be checked (the TV is off or out of reach). In `run` mode a clean close returns the
command's own exit code.

Why a tool for one switch: network ADB is plaintext, and on firmware without the "Allow USB debugging?"
prompt any device on the LAN gets a shell, so a session left open is the usual way a TV stays exposed.
Switching debugging off also ends the session that sends the command, so the switch is the last thing
sent, and only the TV refusing a new connection counts as closed (the check is tools/adb-closed.py).

What it cannot do: revoke the computers the TV already trusts. Do that once on the TV (Developer
options > Revoke USB debugging authorisations). The security-watchdog add-on can also close debugging
from the TV itself after a timeout, which keeps working if this computer goes away.
"""
import argparse
import os
import re
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
ADB_CLOSED = HERE / "adb-closed.py"

CLOSE_ALL = "settings put global adb_wifi_enabled 0; settings put global adb_enabled 0"
CLOSE_KEEP_USB = "settings put global adb_wifi_enabled 0; sync; svc power reboot || reboot"
STATE = ("echo adb=$(settings get global adb_enabled) wifi=$(settings get global adb_wifi_enabled) "
         "tcp=$(getprop service.adb.tcp.port)")
LOOPBACK = ("127.0.0.1", "localhost", "::1")


def parse_duration(text):
    """Seconds from '30m', '90s', '2h' or a bare number of minutes."""
    match = re.fullmatch(r"\s*(\d+(?:\.\d+)?)\s*([smh]?)\s*", text or "")
    if not match:
        raise ValueError(f"not a duration: {text!r} (try 30m, 90s or 2h)")
    number, unit = float(match.group(1)), match.group(2) or "m"
    seconds = number * {"s": 1, "m": 60, "h": 3600}[unit]
    if seconds <= 0:
        raise ValueError("the duration must be more than zero")
    return seconds


def tv_endpoint():
    """(host, port) from TV_HOST and TV_PORT, the way tools/tv.py reads them."""
    sys.path.insert(0, str(HERE))
    import tv
    return tv.HOST, tv.PORT


def connect():
    sys.path.insert(0, str(HERE))
    import tv
    return tv.connect(timeout=20)


def read_state(dev):
    answer = (dev.shell(STATE, read_timeout_s=20.0) or "").strip()
    return dict(re.findall(r"(\w+)=(\S*)", answer))


def send_close(dev, keep_usb):
    """Send the switch. The session ends while it runs, so a dropped connection is the normal answer."""
    try:
        dev.shell(CLOSE_KEEP_USB if keep_usb else CLOSE_ALL, read_timeout_s=10.0)
    except Exception:
        pass
    try:
        dev.close()
    except Exception:
        pass


def port_state(host, port, python=sys.executable):
    """0 closed (the TV refused), 1 open, 2 unknown: tools/adb-closed.py's own answer."""
    result = subprocess.run([python, "-I", str(ADB_CLOSED), host, str(port)],
                            capture_output=True, text=True, timeout=30)
    return result.returncode, (result.stdout + result.stderr).strip()


def verify(host, ports, wait_s=20.0, step_s=2.0, check=port_state, sleep=time.sleep):
    """Poll each port until the TV refuses it or wait_s runs out. {port: (code, message)}."""
    results = {}
    deadline = time.monotonic() + wait_s
    for port in ports:
        while True:
            code, message = check(host, port)
            if code == 0 or time.monotonic() >= deadline:
                break
            sleep(step_s)
        results[port] = (code, message)
    return results


def close_and_verify(args, host, port, connect_fn=connect, check=port_state):
    """Close debugging on the TV and check the ports. Returns (exit code, event for the exports)."""
    event = {"event": "adb_close", "mode": args.mode, "keep_usb": args.keep_usb}
    try:
        dev = connect_fn()
    except Exception as e:
        # Nothing to send the switch to. The port may already be closed: let the check decide.
        event["connect_error"] = str(e)
        dev = None
    if dev is not None:
        try:
            event["before"] = read_state(dev)
            # The model names the TV in Home Assistant when --device-name is not given, as the audit does.
            event["model"] = (dev.shell("getprop ro.product.model", read_timeout_s=20.0) or "").strip()
        except Exception:
            event.setdefault("before", {})
        send_close(dev, args.keep_usb)
        print("debugging switched off" + (" (rebooting to drop the TCP port)" if args.keep_usb else ""))
    ports = [port] + ([args.wireless_port] if args.wireless_port else [])
    wait = 120.0 if args.keep_usb else 20.0
    results = verify(host, ports, wait_s=wait, check=check)
    event["ports"] = {str(p): {0: "closed", 1: "open", 2: "unknown"}[code] for p, (code, _) in results.items()}
    codes = [code for code, _ in results.values()]
    for p, (code, message) in results.items():
        print(f"port {p}: {message}" if message else f"port {p}: {event['ports'][str(p)]}")
    if 1 in codes:
        event["result"] = "still_open"
        event["title"] = "Debugging was switched off but the ADB port still answers"
        print("The TV still accepts ADB. On this TV another switch keeps it open: turn USB debugging, "
              "Network/ADB debugging and Wireless debugging off in Developer options, then run "
              "this again.", file=sys.stderr)
        return 1, event
    if 2 in codes:
        event["result"] = "unknown"
        event["title"] = "Debugging switched off; the port could not be checked"
        print("Could not confirm the port is closed (the TV did not answer). Check again once it is on.",
              file=sys.stderr)
        return 2, event
    event["result"] = "closed"
    event["title"] = "Debugging switched off and the ADB port is closed"
    print("Closed. Also revoke the trusted computers once: Developer options > Revoke USB debugging "
          "authorisations.")
    return 0, event


def report(args, event):
    sys.path.insert(0, str(HERE))
    import integrations
    syslog_urls, mqtt_url = integrations.targets_from(args.syslog, args.mqtt)
    if not (syslog_urls or mqtt_url):
        return
    name = args.device_name or event.get("model") or "tv"
    for problem in integrations.export_event(event, syslog_urls, mqtt_url, name):
        print(f"export: {problem}", file=sys.stderr)


def parse_args(argv):
    argv = list(argv)
    command = []
    if "--" in argv:                      # run -- <command>: everything after -- is the command
        cut = argv.index("--")
        argv, command = argv[:cut], argv[cut + 1:]
    p = argparse.ArgumentParser(description="Close the TV's debugging and check the port is shut.")
    p.add_argument("mode", choices=("now", "after", "run"))
    p.add_argument("duration", nargs="?", help="after: how long to wait (30m, 90s, 2h)")
    p.add_argument("--keep-usb", action="store_true", help="keep USB debugging; reboot to drop TCP")
    p.add_argument("--wireless-port", type=int, help="Wireless debugging's port, to check as well")
    p.add_argument("--check-host", help="the TV's own IP when TV_HOST is a relay on 127.0.0.1")
    p.add_argument("--device-name", help="the TV's name in syslog and Home Assistant")
    p.add_argument("--syslog", action="append", default=[], metavar="URL")
    p.add_argument("--mqtt", metavar="URL")
    args = p.parse_intermixed_args(argv)
    args.command = command
    if args.mode == "after":
        if not args.duration:
            p.error("after needs a duration, e.g. after 30m")
        try:
            args.seconds = parse_duration(args.duration)
        except ValueError as e:
            p.error(str(e))
    elif args.duration:
        p.error(f"{args.mode} takes no duration")
    if args.mode == "run" and not command:
        p.error("run needs a command after --, e.g. run -- tools/disable.sh my-list.txt")
    if args.mode != "run" and command:
        p.error("only run takes a command after --")
    return args


def check_host(args, host):
    if args.check_host:
        return args.check_host
    if host in LOOPBACK:
        raise SystemExit("TV_HOST is a relay on this computer, so the TV's own port cannot be checked "
                         "there: add --check-host <tv ip>.")
    return host


def main(argv=None, connect_fn=connect, check=port_state, sleep=time.sleep):
    args = parse_args(sys.argv[1:] if argv is None else argv)
    host, port = tv_endpoint()
    target = check_host(args, host)
    if args.mode == "now":
        code, event = close_and_verify(args, target, port, connect_fn, check)
        report(args, event)
        return code
    if args.mode == "after":
        minutes = args.seconds / 60
        print(f"Debugging will be switched off in {minutes:g} minute(s). Ctrl-C cancels "
              "(and leaves it on).", flush=True)
        try:
            sleep(args.seconds)
        except KeyboardInterrupt:
            print("\nCancelled: debugging is still on. Close it with: "
                  "tools/venv/bin/python -I tools/adb_autoclose.py now", file=sys.stderr)
            return 130
        code, event = close_and_verify(args, target, port, connect_fn, check)
        report(args, event)
        return code
    # run: the command gets the same environment (TV_HOST, TV_PORT), and closing happens even when it
    # fails or is interrupted with Ctrl-C (which reaches the child too, as it shares the terminal).
    child = 1
    try:
        child = subprocess.call(args.command)
    except KeyboardInterrupt:
        child = 130
    except OSError as e:
        print(f"could not run {args.command[0]}: {e}", file=sys.stderr)
        child = 127
    finally:
        print(f"command finished ({child}); closing debugging", flush=True)
        code, event = close_and_verify(args, target, port, connect_fn, check)
        event["command_exit"] = child
        report(args, event)
    return child if code == 0 else code


if __name__ == "__main__":
    sys.exit(main())
