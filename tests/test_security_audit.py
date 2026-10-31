"""tools/security_audit.py against simulated TVs.

The audit's promise is that it changes nothing and claims nothing the TV did not say, so the tests
hold the command table to read-only verbs and check each finding against a hand-built answer set:
one TV with every problem the audit knows, one clean TV, and the parsers on their own.

Run from the repository root: python3 -m unittest discover -s tests -v
"""
import datetime as dt
import io
import json
import os
import re
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import mock

from tools import security_audit as sa

TODAY = dt.date(2026, 10, 30)

PROC_TCP = """\
  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000:15B3 00000000:0000 0A 00000000:00000000 00:00000000 00000000  2000        0 1 1
   1: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 2 1
   2: 6401A8C0:15B3 3201A8C0:C350 01 00000000:00000000 00:00000000 00000000  2000        0 3 1
  sl  local_address                         remote_address                        st tx_queue
   0: 00000000000000000000000000000000:1F49 00000000000000000000000000000000:0000 0A 00000000:00000000
   1: 0000000000000000FFFF00000100007F:22B8 00000000000000000000000000000000:0000 0A 00000000:00000000
   2: 00000000000000000000000001000000:1A0A 00000000000000000000000000000000:0000 0A 00000000:00000000
   3: 00000000000000000000000000000000:D431 00000000000000000000000000000000:0000 0A 00000000:00000000
"""

DEVICE_POLICY = """\
Current Device Policy Manager state:
  Immutable state:
    mHasFeature=true
  Device Owner:
    admin=ComponentInfo{com.evil.mdm/com.evil.mdm.Receiver}
    name=
    package=com.evil.mdm
  Enabled Device Admins (User 0, provisioningState: 0):
    com.evil.mdm/.Receiver:
      uid=10140
      testOnlyAdmin=false
    com.vendor.remote/.AdminReceiver:
      uid=1000
  Other section:
    com.not.an.admin/.Thing:
"""

BAD_TV = {
    "model": "Example 55X", "manufacturer": "Example", "android": "10", "sdk": "29",
    "patch": "2023-01-05", "adb_secure": "0", "debuggable": "1", "build_type": "userdebug",
    "verified_boot": "orange", "flash_locked": "0", "tcp_port": "5555", "persist_tcp_port": "5555",
    "selinux": "Permissive", "adb_enabled": "1", "adb_wifi_enabled": "1", "developer_options": "1",
    "verifier": "0", "non_market": "1",
    "accessibility_services": "com.evil.spy/com.evil.spy.Svc:com.gathin.tvhome/com.gathin.tvhome.HomeKeyService:"
                              "com.android.talkback/.TalkBackService",
    "notification_listeners": "com.evil.spy/com.evil.spy.Listener",
    "default_ime": "com.evil.keys/.Ime", "enabled_imes": "com.evil.keys/.Ime:com.other.kb/.K",
    "private_dns_mode": "off", "private_dns_host": "null",
    "http_proxy": "10.0.0.66:8888", "proxy_host": "null", "proxy_port": "null",
    "third_party": "package:com.evil.spy  installer=null\n"
                   "package:com.evil.keys  installer=com.android.packageinstaller\n"
                   "package:com.other.kb  installer=com.android.vending\n"
                   "package:com.evil.mdm  installer=null\n"
                   "package:com.files.app  installer=com.android.vending\n"
                   "package:com.gathin.tvhome  installer=null",
    "install_ops": "com.files.app\ncom.android.vending\n",
    "overlay_ops": "package:com.evil.spy\ncom.android.systemui\n",
    "usage_ops": "com.evil.spy\n",
    "listening": PROC_TCP,
    "device_policy": DEVICE_POLICY,
}

CLEAN_TV = {
    "model": "Clean 43", "manufacturer": "Clean", "android": "14", "sdk": "34", "patch": "2026-09-01",
    "adb_secure": "1", "debuggable": "0", "build_type": "user", "verified_boot": "green",
    "flash_locked": "1", "tcp_port": "", "persist_tcp_port": "", "selinux": "Enforcing",
    "adb_enabled": "1", "adb_wifi_enabled": "0", "developer_options": "1", "verifier": "1",
    "non_market": "null", "accessibility_services": "null", "notification_listeners": "null",
    "default_ime": "com.google.android.leanback.ime/.LeanbackImeService",
    "enabled_imes": "com.google.android.leanback.ime/.LeanbackImeService",
    "private_dns_mode": "hostname", "private_dns_host": "dns.adguard-dns.com",
    "http_proxy": "null", "proxy_host": "null", "proxy_port": "null",
    "third_party": "package:com.netflix.ninja  installer=com.android.vending",
    "install_ops": "", "overlay_ops": "", "usage_ops": "",
    "listening": "  sl  local_address rem_address   st\n   0: 00000000:1F49 00000000:0000 0A 0\n",
    "device_policy": "Current Device Policy Manager state:\n  Immutable state:\n    mHasFeature=true\n",
}


def batch_output(answers):
    return "\n".join(f"@@{key}@@\n{answers.get(key, '')}" for key in sa.COMMANDS) + "\n"


def by_id(findings):
    out = {}
    for finding in findings:
        out.setdefault(finding.id, []).append(finding)
    return out


class CommandTableTest(unittest.TestCase):
    def test_every_command_only_reads(self):
        for key, command in sa.COMMANDS.items():
            for part in command.split("||"):
                self.assertTrue(part.strip().startswith(sa.READ_ONLY),
                                f"{key}: {part.strip()!r} is not a read-only command")

    def test_no_command_writes_or_chains_anything_else(self):
        verbs = re.compile(r"\b(put|set|setprop|grant|revoke|enable|disable|install|uninstall|clear|"
                           r"reboot|rm|delete|write|kill|start|stop)\b")
        for key, command in sa.COMMANDS.items():
            for bad in (";", "&&", ">", "`", "$("):
                self.assertNotIn(bad, command, f"{key}: {command!r}")
            self.assertIsNone(verbs.search(command), f"{key}: {command!r}")

    def test_batch_round_trips(self):
        answers = {"model": "A", "sdk": "34", "listening": "line one\nline two"}
        got = sa.split_batch(batch_output(answers), sa.COMMANDS)
        self.assertEqual(got["model"], "A")
        self.assertEqual(got["listening"], "line one\nline two")
        self.assertEqual(got["patch"], "")

    def test_batch_marks_each_command(self):
        line = sa.batch_command({"a": "getprop x", "b": "settings get global y"})
        self.assertEqual(line, "echo '@@a@@'; (getprop x) 2>/dev/null; echo '@@b@@'; "
                               "(settings get global y) 2>/dev/null")


class ParserTest(unittest.TestCase):
    def test_listening_ports(self):
        ports = sa.listening_ports(PROC_TCP)
        self.assertEqual(ports, {5555: True, 8080: False, 8009: True, 8888: False, 6666: False, 54321: True})

    def test_established_connections_are_not_listening(self):
        self.assertNotIn(50000, sa.listening_ports(PROC_TCP))

    def test_device_admins_and_owner(self):
        admins, owners = sa.device_admins(DEVICE_POLICY)
        self.assertEqual(admins, ["com.evil.mdm", "com.vendor.remote"])
        self.assertEqual(owners, ["com.evil.mdm"])

    def test_owner_on_the_heading_line(self):
        _, owners = sa.device_admins("  Device Owner: admin=ComponentInfo{com.a.b/com.a.b.R}\n")
        self.assertEqual(owners, ["com.a.b"])

    def test_components_and_packages(self):
        self.assertEqual(sa.components("a.b/.C:x.y/x.y.Z"), [("a.b", "a.b/.C"), ("x.y", "x.y/x.y.Z")])
        self.assertEqual(sa.packages_in("package:a.b\nc.d uid=1\nnot a package\n"), ["a.b", "c.d"])

    def test_names_with_shell_syntax_are_dropped(self):
        self.assertEqual(sa.packages_in("a.b;reboot\n$(x).y\n"), [])
        self.assertEqual(sa.third_party({"third_party": "package:a.b;rm  installer=null"}), {})

    def test_patch_age(self):
        self.assertEqual(sa.patch_age_months("2025-10-01", TODAY), 12)
        self.assertIsNone(sa.patch_age_months("soon", TODAY))

    def test_project_packages_include_the_launcher(self):
        names = sa.project_packages()
        self.assertIn("com.gathin.tvhome", names)
        self.assertIn("io.github.maxhayim.remoteaccess", names)


class BadTvTest(unittest.TestCase):
    def setUp(self):
        self.findings = sa.evaluate(BAD_TV, today=TODAY, trusted={"com.gathin.tvhome"})
        self.ids = by_id(self.findings)

    def severity(self, fid, package=None):
        for finding in self.ids[fid]:
            if package is None or package in finding.packages:
                return finding.severity
        raise AssertionError(f"{fid} for {package} not reported")

    def test_adb_findings(self):
        self.assertEqual(self.severity("ADB-001"), "high")
        self.assertEqual(self.severity("ADB-002"), "high")
        self.assertEqual(self.severity("ADB-003"), "medium")
        self.assertIn("5555", self.ids["ADB-003"][0].title)
        self.assertEqual(self.severity("ADB-004"), "low")

    def test_build_findings(self):
        self.assertEqual(self.severity("BLD-001"), "high")
        self.assertEqual(self.severity("BLD-002"), "high")
        self.assertEqual(self.severity("BLD-003"), "medium")
        self.assertEqual(self.severity("BLD-004"), "high")   # 45 months old

    def test_spyware_powers(self):
        self.assertEqual(self.severity("PRM-001", "com.evil.spy"), "high")
        self.assertEqual(self.severity("PRM-001", "com.gathin.tvhome"), "info")     # trusted
        self.assertEqual(self.severity("PRM-001", "com.android.talkback"), "info")  # system app
        self.assertEqual(self.severity("PRM-002", "com.evil.spy"), "high")
        self.assertEqual(self.severity("PRM-003", "com.evil.mdm"), "high")
        self.assertEqual(self.severity("PRM-003", "com.vendor.remote"), "info")
        self.assertEqual(self.severity("PRM-004", "com.evil.mdm"), "medium")
        self.assertEqual(self.severity("PRM-005", "com.evil.keys"), "medium")
        self.assertEqual(self.severity("PRM-006", "com.other.kb"), "low")
        self.assertEqual(self.ids["PRM-007"][0].packages, ["com.evil.spy"])
        self.assertEqual(self.ids["PRM-008"][0].packages, ["com.evil.spy"])

    def test_install_findings(self):
        self.assertEqual(self.severity("APP-001", "com.files.app"), "medium")
        self.assertNotIn("com.android.vending", [p for f in self.ids["APP-001"] for p in f.packages])
        self.assertEqual(self.severity("APP-002"), "medium")
        self.assertEqual(self.severity("APP-003"), "medium")
        self.assertEqual(self.ids["APP-004"][0].packages, ["com.evil.keys", "com.evil.mdm", "com.evil.spy"])
        self.assertEqual(self.ids["APP-005"][0].packages, ["com.gathin.tvhome"])

    def test_network_findings(self):
        self.assertEqual(self.severity("NET-001"), "high")
        self.assertIn("10.0.0.66:8888", self.ids["NET-001"][0].title)
        self.assertIn("8009", self.ids["NET-003"][0].detail)
        self.assertIn("54321", self.ids["NET-004"][0].detail)
        self.assertNotIn("8080", self.ids["NET-004"][0].detail)   # loopback only

    def test_worst_first(self):
        ranks = [sa.RANK[f.severity] for f in self.findings]
        self.assertEqual(ranks, sorted(ranks))


class CleanTvTest(unittest.TestCase):
    def test_only_low_and_info(self):
        findings = sa.evaluate(CLEAN_TV, today=TODAY)
        self.assertEqual([f for f in findings if f.severity in ("high", "medium")], [])
        ids = {f.id for f in findings}
        self.assertIn("DEV-001", ids)
        self.assertIn("ADB-005", ids)
        self.assertNotIn("ADB-003", ids)
        self.assertIn("NET-002", ids)


class ReportTest(unittest.TestCase):
    def test_json_report_shape(self):
        findings = sa.evaluate(BAD_TV, today=TODAY)
        now = dt.datetime(2026, 10, 30, 12, 0, tzinfo=dt.timezone.utc)
        report = sa.build_report(BAD_TV, findings, now=now, device_name="living-room")
        self.assertEqual(report["device_name"], "living-room")
        self.assertEqual(report["time"], "2026-10-30T12:00:00+00:00")
        self.assertTrue(report["adb_network_open"])
        self.assertEqual(sum(report["summary"].values()), len(report["findings"]))
        json.dumps(report)
        text = sa.text_report(report)
        self.assertIn("HIGH    ADB-001", text)
        self.assertIn("Example 55X", text)


class MainTest(unittest.TestCase):
    class Dev:
        def __init__(self, answers):
            self.answers = answers

        def shell(self, command, read_timeout_s=None):
            return batch_output(self.answers)

        def close(self):
            pass

    def run_main(self, answers, *argv):
        out, err = io.StringIO(), io.StringIO()
        with mock.patch.object(sa, "connect", return_value=self.Dev(answers)), \
                redirect_stdout(out), redirect_stderr(err):
            code = sa.main(list(argv))
        return code, out.getvalue(), err.getvalue()

    def test_exit_codes(self):
        self.assertEqual(self.run_main(BAD_TV)[0], 1)
        self.assertEqual(self.run_main(CLEAN_TV)[0], 0)
        self.assertEqual(self.run_main(CLEAN_TV, "--fail-on", "low")[0], 1)

    def test_nothing_readable_is_exit_2(self):
        self.assertEqual(self.run_main({})[0], 2)

    def test_json_and_private_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "report.json")
            code, out, _ = self.run_main(BAD_TV, "--json", "--out", path)
            self.assertEqual(json.loads(out)["tool"], "cleanyourtv-security-audit")
            self.assertEqual(json.loads(Path(path).read_text())["device"]["model"], "Example 55X")
            if os.name == "posix":
                self.assertEqual(os.stat(path).st_mode & 0o777, 0o600)

    def test_trust_refuses_shell_syntax(self):
        with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            sa.parse_args(["--trust", "a.b;reboot"])


if __name__ == "__main__":
    unittest.main()
