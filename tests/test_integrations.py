"""tools/integrations.py against real sockets on 127.0.0.1: a syslog listener and a small MQTT broker.

The broker speaks just enough MQTT 3.1.1 to check what the client sends: CONNECT with the user and
password, QoS 1 PUBLISH with retain where the state is meant to stay, a wait for each PUBACK, and a
DISCONNECT at the end.

Run from the repository root: python3 -m unittest discover -s tests -v
"""
import datetime as dt
import json
import os
import socket
import struct
import threading
import unittest
from unittest import mock

from tools import integrations as ig
from tools import security_audit as sa
from tests.test_security_audit import BAD_TV, TODAY

NOW = dt.datetime(2026, 10, 30, 12, 0, 5, tzinfo=dt.timezone.utc)


def report():
    findings = sa.evaluate(BAD_TV, today=TODAY, trusted={"com.gathin.tvhome"})
    return sa.build_report(BAD_TV, findings, now=NOW, device_name="Living Room TV")


class FakeBroker(threading.Thread):
    """Accepts one client, answers CONNECT and every QoS 1 PUBLISH, records what it got."""

    def __init__(self, connack_code=0):
        super().__init__(daemon=True)
        self.server = socket.socket()
        self.server.bind(("127.0.0.1", 0))
        self.server.listen(1)
        self.port = self.server.getsockname()[1]
        self.connack_code = connack_code
        self.connect = None
        self.published = []
        self.disconnected = False

    @staticmethod
    def read_packet(conn):
        first = conn.recv(1)
        if not first:
            return None, b""
        length, shift = 0, 0
        while True:
            byte = conn.recv(1)[0]
            length |= (byte & 0x7F) << shift
            if not byte & 0x80:
                break
            shift += 7
        body = b""
        while len(body) < length:
            body += conn.recv(length - len(body))
        return first[0], body

    def run(self):
        try:
            self.serve()
        finally:
            self.server.close()

    def serve(self):
        conn, _ = self.server.accept()
        with conn:
            kind, body = self.read_packet(conn)
            self.connect = body
            conn.sendall(bytes([0x20, 0x02, 0x00, self.connack_code]))
            if self.connack_code:
                return
            while True:
                kind, body = self.read_packet(conn)
                if kind is None:
                    return
                if kind >> 4 == 3:
                    n = struct.unpack("!H", body[:2])[0]
                    topic = body[2:2 + n].decode()
                    packet_id = body[2 + n:4 + n]
                    payload = body[4 + n:].decode()
                    self.published.append((topic, payload, bool(kind & 1), (kind >> 1) & 3))
                    conn.sendall(bytes([0x40, 0x02]) + packet_id)
                elif kind == 0xE0:
                    self.disconnected = True
                    return


class UdpListener:
    def __init__(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.settimeout(5)
        self.port = self.sock.getsockname()[1]

    def receive(self, n):
        got = [self.sock.recv(65535).decode() for _ in range(n)]
        self.sock.close()
        return got


class EncodingTest(unittest.TestCase):
    def test_remaining_length(self):
        self.assertEqual(ig._remaining_length(0), b"\x00")
        self.assertEqual(ig._remaining_length(127), b"\x7f")
        self.assertEqual(ig._remaining_length(128), b"\x80\x01")
        self.assertEqual(ig._remaining_length(16383), b"\xff\x7f")
        self.assertEqual(ig._remaining_length(2097152), b"\x80\x80\x80\x01")

    def test_connect_packet_flags(self):
        packet = ig.connect_packet("c", "u", "p")
        self.assertEqual(packet[0], 0x10)
        self.assertEqual(packet[2:10], b"\x00\x04MQTT\x04\xc2")   # user + password + clean session
        self.assertEqual(ig.connect_packet("c")[9], 0x02)

    def test_slug_and_redaction(self):
        self.assertEqual(ig.slug("Living Room TV!"), "living_room_tv")
        self.assertEqual(ig.slug(""), "tv")
        target = ig.Target("mqtt://me:s3cret@10.0.0.2")
        self.assertNotIn("s3cret", target.redacted())
        self.assertEqual((target.user, target.password, target.port), ("me", "s3cret", 1883))

    def test_target_refusals(self):
        for url in ("http://x", "syslog+udp://", "mqtt://h:99999", "nonsense"):
            with self.assertRaises(ValueError, msg=url):
                ig.Target(url)

    def test_environment_fills_in(self):
        env = {"CLEANYOURTV_SYSLOG": "syslog+udp://a, syslog+tcp://b", "CLEANYOURTV_MQTT": "mqtt://c"}
        with mock.patch.dict(os.environ, env):
            self.assertEqual(ig.targets_from([], None), (["syslog+udp://a", "syslog+tcp://b"], "mqtt://c"))
            self.assertEqual(ig.targets_from(["syslog+udp://x"], "mqtt://y"), (["syslog+udp://x"], "mqtt://y"))


class SyslogTest(unittest.TestCase):
    def test_rfc3164_line(self):
        line = ig.syslog_message({"a": 1}, "high", "Living Room TV", now=NOW)
        self.assertTrue(line.startswith("<131>"))        # local0 (16) * 8 + err (3)
        self.assertRegex(line, r"^<131>\w{3} [ \d]\d \d\d:\d\d:\d\d living-room-tv cleanyourtv: \{\"a\":1\}$")

    def test_rfc5424_line(self):
        line = ig.syslog_message({"a": 1}, "info", "tv", fmt="rfc5424", facility="user", now=NOW)
        self.assertEqual(line, '<14>1 2026-10-30T12:00:05.000Z tv cleanyourtv - - - {"a":1}')

    def test_audit_over_udp(self):
        listener = UdpListener()
        rep = report()
        problems = ig.export_audit(rep, [f"syslog+udp://127.0.0.1:{listener.port}"], None)
        self.assertEqual(problems, [])
        lines = listener.receive(1 + len(rep["findings"]))
        bodies = [json.loads(line.split(": ", 1)[1]) for line in lines]
        self.assertEqual(bodies[0]["event"], "audit_summary")
        self.assertEqual(bodies[0]["device"], "Living Room TV")
        ids = {b["id"] for b in bodies[1:]}
        self.assertIn("ADB-001", ids)
        self.assertTrue(all(b["source"] == "cleanyourtv" for b in bodies))

    def test_tcp_lines_are_newline_framed(self):
        server = socket.socket()
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        received = []

        def serve():
            conn, _ = server.accept()
            with conn:
                data = b""
                while True:
                    chunk = conn.recv(65535)
                    if not chunk:
                        break
                    data += chunk
                received.append(data)
        thread = threading.Thread(target=serve, daemon=True)
        thread.start()
        target = ig.Target(f"syslog+tcp://127.0.0.1:{server.getsockname()[1]}")
        ig.send_syslog(target, ["one", "two"])
        thread.join(5)
        server.close()
        self.assertEqual(received, [b"one\ntwo\n"])

    def test_unreachable_target_is_a_problem_not_a_crash(self):
        problems = ig.export_audit(report(), ["syslog+tcp://127.0.0.1:1"], None)
        self.assertEqual(len(problems), 1)


class MqttTest(unittest.TestCase):
    def test_audit_with_discovery(self):
        broker = FakeBroker()
        broker.start()
        problems = ig.export_audit(report(), [], f"mqtt://user:pw@127.0.0.1:{broker.port}")
        broker.join(5)
        self.assertEqual(problems, [])
        self.assertIn(b"user", broker.connect)
        self.assertIn(b"pw", broker.connect)
        self.assertTrue(broker.disconnected)
        topics = {t: (json.loads(p), retain, qos) for t, p, retain, qos in broker.published}
        state, retain, qos = topics["cleanyourtv/living_room_tv/audit"]
        self.assertTrue(retain)
        self.assertEqual(qos, 1)
        self.assertEqual(state["result"], "high")
        self.assertTrue(state["adb_network_open"])
        config, retain, _ = topics["homeassistant/binary_sensor/cleanyourtv_living_room_tv/adb_network_open/config"]
        self.assertTrue(retain)
        self.assertEqual(config["device"]["identifiers"], ["cleanyourtv_living_room_tv"])
        self.assertEqual(config["state_topic"], "cleanyourtv/living_room_tv/audit")
        events = [p for t, p, r, q in broker.published if t.endswith("/event")]
        self.assertTrue(events)
        self.assertTrue(all(not r for t, p, r, q in broker.published if t.endswith("/event")))

    def test_discovery_off_and_custom_base(self):
        broker = FakeBroker()
        broker.start()
        ig.export_audit(report(), [], f"mqtt://127.0.0.1:{broker.port}?base=home/tv&discovery=off")
        broker.join(5)
        topics = [t for t, *_ in broker.published]
        self.assertIn("home/tv/living_room_tv/audit", topics)
        self.assertFalse(any(t.startswith("homeassistant/") for t in topics))

    def test_refused_login_is_reported(self):
        broker = FakeBroker(connack_code=4)
        broker.start()
        problems = ig.export_audit(report(), [], f"mqtt://u:wrong@127.0.0.1:{broker.port}")
        broker.join(5)
        self.assertEqual(len(problems), 1)
        self.assertIn("bad user name or password", problems[0])
        self.assertNotIn("wrong", problems[0])

    def test_adb_close_event(self):
        broker = FakeBroker()
        broker.start()
        event = {"event": "adb_close", "result": "closed", "ports": {"5555": "closed"}}
        problems = ig.export_event(event, [], f"mqtt://127.0.0.1:{broker.port}", "Living Room TV")
        broker.join(5)
        self.assertEqual(problems, [])
        topics = {t: (json.loads(p), r) for t, p, r, q in broker.published}
        self.assertEqual(topics["cleanyourtv/living_room_tv/adb_close"][0]["result"], "closed")
        self.assertTrue(topics["cleanyourtv/living_room_tv/adb_close"][1])
        self.assertEqual(topics["cleanyourtv/living_room_tv/event"][0]["severity"], "info")


if __name__ == "__main__":
    unittest.main()
