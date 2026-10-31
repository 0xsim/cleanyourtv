"""tools/adb_autoclose.py: debugging is switched off last, and only a refused port counts as closed.

The TV is a fake that records the commands it is sent and drops the session on the switch, the way
a real adbd does; the port check is a fake too, so no network is touched.

Run from the repository root: python3 -m unittest discover -s tests -v
"""
import io
import sys
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest import mock

from tools import adb_autoclose as ac


class FakeDev:
    def __init__(self):
        self.sent = []
        self.closed = False

    def shell(self, command, read_timeout_s=None):
        self.sent.append(command)
        if command.startswith("echo adb="):
            return "adb=1 wifi=0 tcp=5555\n"
        if command == "getprop ro.product.model":
            return "Example 55X\n"
        raise ConnectionResetError("adbd went away")   # the switch ends the session

    def close(self):
        self.closed = True


def checker(*codes):
    """A port check that answers the given codes in turn, then repeats the last one."""
    answers = list(codes)

    def check(host, port):
        code = answers.pop(0) if len(answers) > 1 else answers[0]
        return code, {0: "closed", 1: "open", 2: "no answer"}[code]
    return check


def quiet(fn, *args, **kwargs):
    with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
        return fn(*args, **kwargs)


class DurationTest(unittest.TestCase):
    def test_units(self):
        self.assertEqual(ac.parse_duration("30m"), 1800)
        self.assertEqual(ac.parse_duration("90s"), 90)
        self.assertEqual(ac.parse_duration("2h"), 7200)
        self.assertEqual(ac.parse_duration("45"), 2700)

    def test_refusals(self):
        for bad in ("", "soon", "-5m", "0", "10d"):
            with self.assertRaises(ValueError, msg=bad):
                ac.parse_duration(bad)


class ArgsTest(unittest.TestCase):
    def test_after_with_options_on_either_side(self):
        args = ac.parse_args(["after", "30m", "--keep-usb"])
        self.assertEqual(args.seconds, 1800)
        self.assertTrue(args.keep_usb)
        args = ac.parse_args(["--wireless-port", "37000", "after", "2h"])
        self.assertEqual((args.seconds, args.wireless_port), (7200, 37000))

    def test_run_takes_everything_after_the_separator(self):
        args = ac.parse_args(["run", "--keep-usb", "--", "tools/disable.sh", "--force", "x.txt"])
        self.assertEqual(args.command, ["tools/disable.sh", "--force", "x.txt"])
        self.assertTrue(args.keep_usb)

    def test_refusals(self):
        for argv in (["after"], ["now", "5m"], ["run"], ["now", "--", "ls"], ["after", "soon"]):
            with self.assertRaises(SystemExit, msg=argv):
                quiet(ac.parse_args, argv)


class CloseTest(unittest.TestCase):
    def args(self, *argv):
        return ac.parse_args(list(argv) or ["now"])

    def test_switch_is_sent_and_the_session_drop_is_expected(self):
        dev = FakeDev()
        code, event = quiet(ac.close_and_verify, self.args(), "192.168.1.50", 5555,
                            lambda: dev, checker(0))
        self.assertEqual(code, 0)
        self.assertEqual(dev.sent[-1], ac.CLOSE_ALL)
        self.assertTrue(dev.sent[-1].endswith("adb_enabled 0"), "the USB switch must be sent last")
        self.assertEqual(event["result"], "closed")
        self.assertEqual(event["before"], {"adb": "1", "wifi": "0", "tcp": "5555"})

    def test_keep_usb_reboots_instead(self):
        dev = FakeDev()
        quiet(ac.close_and_verify, self.args("now", "--keep-usb"), "h", 5555, lambda: dev, checker(0),
              lambda s: None)
        self.assertEqual(dev.sent[-1], ac.CLOSE_KEEP_USB)
        self.assertNotIn("adb_enabled 0", dev.sent[-1])

    def test_still_open_is_exit_1(self):
        with mock.patch.object(ac, "verify", return_value={5555: (1, "open")}):
            code, event = quiet(ac.close_and_verify, self.args(), "h", 5555, FakeDev, checker(1))
        self.assertEqual((code, event["result"]), (1, "still_open"))

    def test_no_answer_is_exit_2(self):
        with mock.patch.object(ac, "verify", return_value={5555: (2, "no answer")}):
            code, _ = quiet(ac.close_and_verify, self.args(), "h", 5555, FakeDev, checker(2))
        self.assertEqual(code, 2)

    def test_unreachable_tv_lets_the_check_decide(self):
        def refuse():
            raise ConnectionRefusedError("refused")
        code, event = quiet(ac.close_and_verify, self.args(), "h", 5555, refuse, checker(0))
        self.assertEqual((code, event["result"]), (0, "closed"))
        self.assertIn("refused", event["connect_error"])

    def test_wireless_port_is_checked_too(self):
        seen = []

        def check(host, port):
            seen.append(port)
            return 0, "closed"
        quiet(ac.close_and_verify, self.args("now", "--wireless-port", "37001"), "h", 5555, FakeDev, check)
        self.assertEqual(seen, [5555, 37001])


class VerifyTest(unittest.TestCase):
    def test_polls_until_refused(self):
        slept = []
        results = ac.verify("h", [5555], wait_s=60, step_s=1, check=checker(1, 1, 0), sleep=slept.append)
        self.assertEqual(results[5555][0], 0)
        self.assertEqual(len(slept), 2)


class MainTest(unittest.TestCase):
    def run_main(self, argv, check=None, sleep=None):
        with mock.patch.object(ac, "tv_endpoint", return_value=("192.168.1.50", 5555)):
            return quiet(ac.main, argv, connect_fn=FakeDev, check=check or checker(0),
                         sleep=sleep or (lambda s: None))

    def test_run_returns_the_commands_exit_code_after_closing(self):
        code = self.run_main(["run", "--", sys.executable, "-c", "raise SystemExit(3)"])
        self.assertEqual(code, 3)

    def test_run_reports_a_port_left_open(self):
        with mock.patch.object(ac, "verify", return_value={5555: (1, "open")}):
            code = self.run_main(["run", "--", sys.executable, "-c", "pass"])
        self.assertEqual(code, 1)

    def test_after_waits_then_closes(self):
        waited = []
        self.assertEqual(self.run_main(["after", "90s"], sleep=waited.append), 0)
        self.assertEqual(waited, [90.0])

    def test_after_ctrl_c_leaves_it_on(self):
        def interrupted(seconds):
            raise KeyboardInterrupt
        self.assertEqual(self.run_main(["after", "1m"], sleep=interrupted), 130)

    def test_a_relay_checks_the_tvs_own_port(self):
        seen = []

        def check(host, port):
            seen.append((host, port))
            return 0, "closed"
        with mock.patch.object(ac, "tv_endpoint", return_value=("127.0.0.1", 15555)):
            quiet(ac.main, ["now", "--check-host", "192.168.1.50"], connect_fn=FakeDev, check=check,
                  sleep=lambda s: None)
            quiet(ac.main, ["now", "--check-host", "192.168.1.50", "--check-port", "5577"], connect_fn=FakeDev,
                  check=check, sleep=lambda s: None)
        self.assertEqual(seen, [("192.168.1.50", 5555), ("192.168.1.50", 5577)])

    def test_keep_usb_waits_for_the_restart_before_checking(self):
        events = []

        def check(host, port):
            events.append("check")
            return 0, "closed"
        quiet(ac.close_and_verify, ac.parse_args(["now", "--keep-usb"]), "h", 5555, FakeDev, check,
              lambda s: events.append(f"sleep {s:g}"))
        self.assertEqual(events[:2], [f"sleep {ac.REBOOT_WAIT_S:g}", "check"])

    def test_sigterm_during_run_still_closes(self):
        dev = FakeDev()
        with mock.patch.object(ac, "tv_endpoint", return_value=("192.168.1.50", 5555)), \
                mock.patch.object(ac.subprocess, "call", side_effect=ac._Stop(15)):
            code = quiet(ac.main, ["run", "--", "x"], connect_fn=lambda: dev, check=checker(0),
                         sleep=lambda s: None)
        self.assertEqual(code, 130)
        self.assertEqual(dev.sent[-1], ac.CLOSE_ALL)

    def test_missing_tv_host_is_exit_2(self):
        with mock.patch.dict(ac.os.environ, {}, clear=True), mock.patch.dict(ac.sys.modules):
            ac.sys.modules.pop("tv", None)              # import it fresh, with no TV_HOST
            with self.assertRaises(SystemExit) as cm:
                quiet(ac.tv_endpoint)
        self.assertEqual(cm.exception.code, 2)

    def test_a_relay_needs_the_real_address(self):
        args = ac.parse_args(["now"])
        with self.assertRaises(SystemExit):
            ac.check_host(args, "127.0.0.1")
        args = ac.parse_args(["now", "--check-host", "192.168.1.50"])
        self.assertEqual(ac.check_host(args, "127.0.0.1"), "192.168.1.50")


if __name__ == "__main__":
    unittest.main()
