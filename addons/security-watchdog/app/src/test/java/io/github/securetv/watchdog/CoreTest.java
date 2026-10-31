package io.github.securetv.watchdog;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.time.ZoneOffset;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.json.JSONObject;
import org.junit.Test;

public class CoreTest {
    private static final long T = 1_793_361_605_000L;   // 2026-10-30T12:00:05Z

    // Config --------------------------------------------------------------------------------------

    @Test
    public void configDefaultsWhenEmpty() {
        Config c = Config.parse("{}", "BRAVIA 4K VH2");
        assertEquals("BRAVIA 4K VH2", c.deviceName);
        assertEquals("bravia_4k_vh2", c.slug());
        assertEquals(30, c.adbAutocloseMinutes);
        assertTrue(c.syslog.isEmpty());
        assertNull(c.mqtt);
    }

    @Test
    public void configFull() {
        Config c = Config.parse("{\"device_name\":\"Living Room TV\",\"syslog\":[\"syslog+udp://10.0.0.2\","
                + "\"syslog+tls://siem.lan:6514\"],\"mqtt\":\"mqtt://tv:p%40ss@10.0.0.3\",\"adb_autoclose_minutes\":0,"
                + "\"trusted_packages\":[\"com.mine.app\"],\"on_screen_alerts\":\"medium\"}", "x");
        assertEquals("living_room_tv", c.slug());
        assertEquals(2, c.syslog.size());
        assertEquals(6514, Config.port(c.syslog.get(1)));
        assertEquals(514, Config.port(c.syslog.get(0)));
        assertEquals(1883, Config.port(c.mqtt));
        assertEquals(0, c.adbAutocloseMinutes);
        assertTrue(c.trusts("com.mine.app"));
        assertArrayEquals(new String[]{"tv", "p@ss"}, MqttLink.userInfo(c.mqtt));
    }

    @Test
    public void configRefusals() {
        String[] bad = {"not json", "{\"syslog\":\"http://x\"}", "{\"mqtt\":\"syslog+udp://x\"}",
                "{\"adb_autoclose_minutes\":-1}", "{\"trusted_packages\":[\"a;b\"]}", "{\"device_name\":\"\"}",
                "{\"mqtt_base\":\"a/#\"}", "{\"ca_pem\":\"nope\"}", "{\"on_screen_alerts\":\"loud\"}",
                "{\"syslog\":\"syslog+udp://\"}"};
        for (String json : bad) {
            try {
                Config.parse(json, "m");
                fail("accepted " + json);
            } catch (IllegalArgumentException expected) {
                assertFalse(expected.getMessage(), expected.getMessage().contains("p@ss"));
            }
        }
    }

    @Test
    public void passwordsAreRedacted() {
        assertEquals("mqtt://tv:***@10.0.0.3", Config.redact("mqtt://tv:secret@10.0.0.3"));
        try {
            Config.parse("{\"mqtt\":\"ftp://tv:secret@h\"}", "m");
            fail();
        } catch (IllegalArgumentException e) {
            assertFalse(e.getMessage().contains("secret"));
        }
    }

    @Test
    public void slugMatchesThePythonTools() {
        assertEquals("living_room_tv", Config.slug("Living Room TV!"));
        assertEquals("tv", Config.slug("!!!"));
    }

    // Syslog --------------------------------------------------------------------------------------

    @Test
    public void syslogLines() throws Exception {
        JSONObject event = new SecurityEvent("proxy", "high", "Web traffic now goes through x", "d", null, T)
                .toJson("Living Room TV");
        String line = SyslogSender.format(event, "high", "Living Room TV", T, ZoneOffset.UTC, false);
        assertTrue(line, line.startsWith("<131>Oct 30 12:00:05 living-room-tv cleanyourtv: {"));
        JSONObject body = new JSONObject(line.substring(line.indexOf(": ") + 2));
        assertEquals("proxy", body.getString("event"));
        assertEquals("watchdog", body.getString("origin"));
        String five = SyslogSender.format(event, "info", "tv", T, ZoneOffset.UTC, true);
        assertTrue(five, five.startsWith("<134>1 2026-10-30T12:00:05Z tv cleanyourtv - - - {"));
        String early = SyslogSender.format(event, "low", "tv", T - 29L * 86_400_000L, ZoneOffset.UTC, false);
        assertTrue(early, early.startsWith("<133>Oct  1 12:00:05 tv"));
        assertTrue(SyslogSender.rfc5424(URI.create("syslog+udp://h?format=rfc5424")));
    }

    // MQTT ----------------------------------------------------------------------------------------

    @Test
    public void remainingLength() {
        assertArrayEquals(new byte[]{0}, MqttLink.remainingLength(0));
        assertArrayEquals(new byte[]{(byte) 0x80, 1}, MqttLink.remainingLength(128));
        assertArrayEquals(new byte[]{(byte) 0xFF, 0x7F}, MqttLink.remainingLength(16383));
    }

    @Test
    public void connectCarriesWillAndLogin() throws Exception {
        byte[] p = MqttLink.connectPacket("id", "u", "pw", "base/tv/watchdog/availability", "offline", 60);
        MqttLink.Packet parsed = MqttLink.readPacket(new ByteArrayInputStream(p));
        assertEquals(1, parsed.type);
        assertEquals(4, parsed.body[6]);                              // protocol level
        assertEquals((byte) (0x80 | 0x40 | 0x20 | 0x04 | 0x02), parsed.body[7]);
        String body = new String(parsed.body, StandardCharsets.UTF_8);
        assertTrue(body.contains("base/tv/watchdog/availability"));
        assertTrue(body.contains("offline"));
        assertTrue(body.endsWith("pw"));
    }

    @Test
    public void publishAndParseRoundTrip() throws Exception {
        byte[] p = MqttLink.publishPacket("a/b", "hello".getBytes(StandardCharsets.UTF_8), 7, true);
        assertEquals(0x33, p[0] & 0xFF);                               // PUBLISH, QoS 1, retain
        MqttLink.Packet parsed = MqttLink.readPacket(new ByteArrayInputStream(p));
        assertArrayEquals(new String[]{"a/b", "hello"}, MqttLink.parsePublish(parsed));
    }

    @Test
    public void subscribeIsQos0() throws Exception {
        byte[] p = MqttLink.subscribePacket(3, "x/command");
        assertEquals(0x82, p[0] & 0xFF);
        assertEquals(0, p[p.length - 1]);
    }

    @Test
    public void backoffGrowsAndCaps() {
        assertEquals(2_000L, MqttLink.backoffMs(0));
        assertEquals(4_000L, MqttLink.backoffMs(2));
        assertEquals(300_000L, MqttLink.backoffMs(30));
    }

    // Home Assistant ------------------------------------------------------------------------------

    @Test
    public void discoveryUsesTheSharedDevice() throws Exception {
        Config c = Config.parse("{\"device_name\":\"Living Room TV\"}", "m");
        HomeAssistant ha = new HomeAssistant(c);
        List<String[]> msgs = ha.discoveryMessages("Model", "1.0");
        assertEquals(10, msgs.size());
        JSONObject usb = null;
        for (String[] m : msgs) {
            JSONObject cfg = new JSONObject(m[1]);
            assertEquals("cleanyourtv_living_room_tv", cfg.getJSONObject("device").getJSONArray("identifiers").getString(0));
            assertEquals("cleanyourtv/living_room_tv/watchdog/availability", cfg.getString("availability_topic"));
            if (m[0].equals("homeassistant/binary_sensor/cleanyourtv_living_room_tv/usb_debugging/config")) usb = cfg;
        }
        assertEquals("problem", usb.getString("device_class"));
        assertEquals("cleanyourtv/living_room_tv/event", ha.eventTopic());
        assertTrue(new HomeAssistant(Config.parse("{\"ha_discovery\":\"off\"}", "m")).discoveryMessages("m", "1").isEmpty());
    }

    @Test
    public void stateJson() throws Exception {
        Map<String, String> s = new HashMap<>();
        s.put(Snapshot.ADB, "1");
        s.put(Snapshot.PROXY, "10.0.0.66:8888");
        Snapshot snap = new Snapshot(s, Map.of("a.b", ""), Set.of(), true);
        JSONObject o = HomeAssistant.state(snap, 12L, null, T);
        assertTrue(o.getBoolean("adb_usb"));
        assertTrue(o.getBoolean("adb_network"));
        assertEquals(12, o.getInt("adb_autoclose_min"));
        assertEquals("10.0.0.66:8888", o.getString("proxy"));
        assertEquals("none", o.getJSONObject("last_event").getString("title"));
        assertTrue(HomeAssistant.state(snap, null, null, T).isNull("adb_autoclose_min"));
    }

    // Auto-close ----------------------------------------------------------------------------------

    @Test
    public void autoCloseClock() {
        Snapshot on = new Snapshot(Map.of(Snapshot.ADB, "1"), Map.of(), Set.of(), false);
        Snapshot off = new Snapshot(Map.of(Snapshot.ADB, "0"), Map.of(), Set.of(), false);
        long since = AutoClose.onSince(on, 0L, T);
        assertEquals(T, since);
        assertEquals(T, AutoClose.onSince(on, T, T + 5_000));          // the clock keeps running
        assertEquals(0L, AutoClose.onSince(off, T, T + 5_000));        // and stops when off
        assertEquals(30 * 60_000L, AutoClose.remainingMs(on, since, T, 30));
        assertEquals(0L, AutoClose.remainingMs(on, since, T + 31 * 60_000L, 30));
        assertEquals(-1L, AutoClose.remainingMs(on, since, T, 0));     // disabled
        assertEquals(-1L, AutoClose.remainingMs(off, since, T, 30));
        assertEquals(Long.valueOf(1L), AutoClose.minutesLeft(on, since, T + 29 * 60_000L + 1, 30));
        assertNull(AutoClose.minutesLeft(off, since, T, 30));
        Snapshot portOnly = new Snapshot(Map.of(), Map.of(), Set.of(), true);
        assertTrue(AutoClose.debuggingOn(portOnly));
    }

    // Store ---------------------------------------------------------------------------------------

    @Test
    public void storeKeepsTheNewestEventsAndOutboxes() throws Exception {
        File dir = Files.createTempDirectory("watchdog").toFile();
        Store store = new Store(dir);
        assertNull(store.snapshot());
        SecurityEvent[] many = new SecurityEvent[Store.LOG_LIMIT + 10];
        for (int i = 0; i < many.length; i++) many[i] = new SecurityEvent("t", "info", "e" + i, "", null, T + i * 1000L);
        store.log(Arrays.asList(many), "tv");
        List<SecurityEvent> recent = store.recent(3);
        assertEquals("e" + (many.length - 1), recent.get(0).title);
        assertEquals(Store.LOG_LIMIT, store.recent(10_000).size());

        store.queue("syslog+udp://a", Arrays.asList("one", "two", "three"));
        assertEquals(3, store.pending("syslog+udp://a").size());
        store.sent("syslog+udp://a", 2);
        assertEquals(Collections.singletonList("three"), store.pending("syslog+udp://a"));
        store.sent("syslog+udp://a", 1);
        assertTrue(store.pending("syslog+udp://a").isEmpty());

        store.setNumber("k", 42L);
        assertEquals(42L, new Store(dir).number("k", 0L));
        Snapshot s = new Snapshot(Map.of(Snapshot.ADB, "1"), Map.of("a.b", ""), Set.of(), true);
        store.saveSnapshot(s);
        assertEquals(s, new Store(dir).snapshot());
    }

    @Test
    public void eventJsonRoundTrip() throws Exception {
        SecurityEvent e = new SecurityEvent("app_installed", "medium", "App installed", "d", "a.b", T);
        JSONObject o = e.toJson("Living Room TV");
        assertEquals("cleanyourtv", o.getString("source"));
        assertEquals("2026-10-30T12:00:05Z", o.getString("time"));
        SecurityEvent back = SecurityEvent.fromJson(o);
        assertEquals("a.b", back.packageName);
        assertEquals(T, back.timeMs);
        assertTrue(back.atLeast("medium"));
        assertFalse(back.atLeast("high"));
    }
}
