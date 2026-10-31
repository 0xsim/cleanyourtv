package io.github.securetv.watchdog;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.junit.Test;

public class SnapshotTest {
    private static final long T = 1_800_000_000_000L;
    private static final Set<String> TRUSTED = Set.of("io.github.securetv.watchdog", "com.gathin.tvhome");

    private static Map<String, String> settings(String... pairs) {
        Map<String, String> m = new HashMap<>();
        for (int i = 0; i < pairs.length; i += 2) m.put(pairs[i], pairs[i + 1]);
        return m;
    }

    private static Map<String, String> apps(String... pairs) {
        Map<String, String> m = new LinkedHashMap<>();
        for (int i = 0; i < pairs.length; i += 2) m.put(pairs[i], pairs[i + 1]);
        return m;
    }

    private static Snapshot snap(Map<String, String> settings, Map<String, String> apps, Set<String> admins, boolean port) {
        return new Snapshot(settings, apps, admins, port);
    }

    private static SecurityEvent find(List<SecurityEvent> events, String type, String pkg) {
        for (SecurityEvent e : events) {
            if (e.type.equals(type) && (pkg == null || pkg.equals(e.packageName))) return e;
        }
        return null;
    }

    private final Snapshot quiet = snap(settings(Snapshot.ADB, "0", Snapshot.DNS_MODE, "opportunistic"),
            apps("com.netflix.ninja", "com.android.vending"), Set.of(), false);

    @Test
    public void nothingChangedMeansNoEvents() {
        assertTrue(quiet.diffFrom(quiet, TRUSTED, T).isEmpty());
    }

    @Test
    public void debuggingOnIsReportedAndOffIsInfo() {
        Snapshot on = snap(settings(Snapshot.ADB, "1", Snapshot.DNS_MODE, "opportunistic"), quiet.apps, Set.of(), true);
        List<SecurityEvent> events = on.diffFrom(quiet, TRUSTED, T);
        assertEquals(SecurityEvent.MEDIUM, find(events, "adb_usb", null).severity);
        assertEquals(SecurityEvent.HIGH, find(events, "adb_network", null).severity);
        List<SecurityEvent> back = quiet.diffFrom(on, TRUSTED, T);
        assertEquals(SecurityEvent.INFO, find(back, "adb_usb", null).severity);
        assertEquals(SecurityEvent.INFO, find(back, "adb_network", null).severity);
    }

    @Test
    public void persistentPortIsHigh() {
        Snapshot p = snap(settings(Snapshot.ADB, "0", Snapshot.DNS_MODE, "opportunistic", Snapshot.PERSIST_PORT, "5555"),
                quiet.apps, Set.of(), false);
        assertEquals(SecurityEvent.HIGH, find(p.diffFrom(quiet, TRUSTED, T), "adb_persistent", null).severity);
        Snapshot cleared = snap(settings(Snapshot.ADB, "0", Snapshot.DNS_MODE, "opportunistic", Snapshot.PERSIST_PORT, "-1"),
                quiet.apps, Set.of(), false);
        assertEquals("", cleared.persistentPort());
    }

    @Test
    public void proxyAndPrivateDns() {
        Snapshot proxied = snap(settings(Snapshot.ADB, "0", Snapshot.DNS_MODE, "hostname", Snapshot.DNS_HOST,
                "evil.example", Snapshot.PROXY, "10.0.0.66:8888"), quiet.apps, Set.of(), false);
        List<SecurityEvent> events = proxied.diffFrom(quiet, TRUSTED, T);
        assertEquals(SecurityEvent.HIGH, find(events, "proxy", null).severity);
        assertTrue(find(events, "proxy", null).title.contains("10.0.0.66:8888"));
        assertEquals("Private DNS changed to evil.example", find(events, "private_dns", null).title);
        assertEquals(SecurityEvent.INFO, find(quiet.diffFrom(proxied, TRUSTED, T), "proxy", null).severity);
    }

    @Test
    public void emptyProxyMarkerIsNoProxy() {
        Snapshot s = snap(settings(Snapshot.PROXY, ":0"), Map.of(), Set.of(), false);
        assertEquals("", s.proxy());
        Snapshot global = snap(settings(Snapshot.PROXY_HOST, "p.example", Snapshot.PROXY_PORT, "3128"), Map.of(), Set.of(), false);
        assertEquals("p.example:3128", global.proxy());
    }

    @Test
    public void accessibilityHoldersBySource() {
        Snapshot s = snap(settings(Snapshot.ADB, "0", Snapshot.DNS_MODE, "opportunistic", Snapshot.A11Y,
                "com.evil.spy/com.evil.spy.Svc:com.gathin.tvhome/.HomeKeyService:com.android.talkback/.TalkBack"),
                apps("com.netflix.ninja", "com.android.vending", "com.evil.spy", ""), Set.of(), false);
        List<SecurityEvent> events = s.diffFrom(quiet, TRUSTED, T);
        assertEquals(SecurityEvent.HIGH, find(events, "accessibility", "com.evil.spy").severity);
        assertEquals(SecurityEvent.INFO, find(events, "accessibility", "com.gathin.tvhome").severity);
        assertEquals(SecurityEvent.LOW, find(events, "accessibility", "com.android.talkback").severity);
        SecurityEvent lost = find(quiet.diffFrom(s, TRUSTED, T), "accessibility_removed", "com.evil.spy");
        assertEquals("com.evil.spy lost accessibility access", lost.title);
    }

    @Test
    public void notificationListenersAndAdmins() {
        Snapshot s = snap(settings(Snapshot.ADB, "0", Snapshot.DNS_MODE, "opportunistic",
                Snapshot.LISTENERS, "com.evil.spy/.Listener"),
                apps("com.netflix.ninja", "com.android.vending", "com.evil.spy", "com.android.packageinstaller"),
                Set.of("com.evil.spy/com.evil.spy.Admin"), false);
        List<SecurityEvent> events = s.diffFrom(quiet, TRUSTED, T);
        assertEquals(SecurityEvent.HIGH, find(events, "notification_access", "com.evil.spy").severity);
        assertEquals(SecurityEvent.HIGH, find(events, "device_admin", "com.evil.spy").severity);
        assertEquals("com.evil.spy is no longer a device administrator",
                find(quiet.diffFrom(s, TRUSTED, T), "device_admin_removed", "com.evil.spy").title);
    }

    @Test
    public void installsBySource() {
        Snapshot s = snap(quiet.settings, apps("com.netflix.ninja", "com.android.vending",
                "com.side.loaded", "com.android.packageinstaller", "com.from.store", "com.android.vending",
                "io.github.securetv.watchdog", "com.android.shell"), Set.of(), false);
        List<SecurityEvent> events = s.diffFrom(quiet, TRUSTED, T);
        assertEquals(SecurityEvent.MEDIUM, find(events, "app_installed", "com.side.loaded").severity);
        assertEquals(SecurityEvent.LOW, find(events, "app_installed", "com.from.store").severity);
        assertEquals(SecurityEvent.INFO, find(events, "app_installed", "io.github.securetv.watchdog").severity);
        assertEquals(SecurityEvent.INFO, find(quiet.diffFrom(s, TRUSTED, T), "app_removed", "com.side.loaded").severity);
    }

    @Test
    public void keyboardChange() {
        Snapshot s = snap(settings(Snapshot.ADB, "0", Snapshot.DNS_MODE, "opportunistic", Snapshot.IME, "com.keys.log/.Ime"),
                apps("com.netflix.ninja", "com.android.vending", "com.keys.log", "com.android.vending"), Set.of(), false);
        assertEquals(SecurityEvent.MEDIUM, find(s.diffFrom(quiet, TRUSTED, T), "keyboard", "com.keys.log").severity);
    }

    @Test
    public void namesWithShellSyntaxNeverGetIn() {
        Snapshot s = snap(settings(Snapshot.A11Y, "a.b;reboot/.X:ok.pkg/.Y"), apps("a.b;rm", "", "ok.app", ""),
                Set.of("x.y/$(id)", "good.admin/.R"), false);
        assertEquals(Set.of("ok.pkg/.Y"), s.components(Snapshot.A11Y));
        assertEquals(Set.of("ok.app"), s.apps.keySet());
        assertEquals(Set.of("good.admin/.R"), s.admins);
    }

    @Test
    public void baselineReportsRiskNotEveryApp() {
        Snapshot s = snap(settings(Snapshot.ADB, "1", Snapshot.DNS_MODE, "hostname", Snapshot.DNS_HOST, "dns.example",
                Snapshot.PROXY, "10.0.0.1:80"), apps("a.b", "", "c.d", "com.android.vending"), Set.of(), true);
        List<SecurityEvent> events = s.baseline(TRUSTED, T);
        assertEquals("watchdog_baseline", events.get(0).type);
        assertTrue(find(events, "proxy", null) != null);
        assertTrue(find(events, "adb_network", null) != null);
        assertNull(find(events, "app_installed", null));
        assertNull(find(events, "private_dns", null));
    }

    @Test
    public void jsonRoundTrip() {
        Snapshot s = snap(settings(Snapshot.ADB, "1", Snapshot.A11Y, "a.b/.C"), apps("a.b", "x.y"),
                new LinkedHashSet<>(List.of("a.b/a.b.Admin")), true);
        Snapshot back = Snapshot.fromJson(s.toJson());
        assertEquals(s, back);
        assertTrue(back.adbListening);
        assertFalse(Snapshot.fromJson(quiet.toJson()).adbListening);
    }
}
