package io.github.securetv.watchdog;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.regex.Pattern;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

/**
 * What the TV's security looked like at one moment, and what changed between two moments.
 * Plain Java with no Android calls (Probe fills it in), so every rule below is unit tested.
 */
public final class Snapshot {
    public static final String ADB = "global/adb_enabled";
    public static final String ADB_WIFI = "global/adb_wifi_enabled";
    public static final String DEV = "global/development_settings_enabled";
    public static final String VERIFIER = "global/package_verifier_enable";
    public static final String DNS_MODE = "global/private_dns_mode";
    public static final String DNS_HOST = "global/private_dns_specifier";
    public static final String PROXY = "global/http_proxy";
    public static final String PROXY_HOST = "global/global_http_proxy_host";
    public static final String PROXY_PORT = "global/global_http_proxy_port";
    public static final String A11Y = "secure/enabled_accessibility_services";
    public static final String LISTENERS = "secure/enabled_notification_listeners";
    public static final String IME = "secure/default_input_method";
    public static final String TCP_PORT = "prop/service.adb.tcp.port";
    public static final String PERSIST_PORT = "prop/persist.adb.tcp.port";
    public static final int ADB_PORT = 5555;

    /** Every setting and property the watchdog reads, in the order Probe reads them. */
    public static final String[] KEYS = {ADB, ADB_WIFI, DEV, VERIFIER, DNS_MODE, DNS_HOST, PROXY, PROXY_HOST,
            PROXY_PORT, A11Y, LISTENERS, IME, TCP_PORT, PERSIST_PORT};

    static final Pattern PACKAGE = Pattern.compile("[A-Za-z_][A-Za-z0-9_]*(\\.[A-Za-z0-9_]+)+");
    static final Pattern COMPONENT = Pattern.compile("([A-Za-z_][A-Za-z0-9_]*(?:\\.[A-Za-z0-9_]+)+)/[A-Za-z0-9_.$]+");

    /** Installers that mean "a person or a script put this APK here", not an app store. */
    static final Set<String> SIDELOAD = Set.of("", "null", "com.android.shell", "com.android.packageinstaller",
            "com.google.android.packageinstaller");

    public final Map<String, String> settings;
    /** Apps the owner or a script installed (not part of the firmware): package -> installer. */
    public final Map<String, String> apps;
    /** Active device admins, as package/class. */
    public final Set<String> admins;
    /** Whether something accepts connections on the network ADB port. */
    public final boolean adbListening;

    public Snapshot(Map<String, String> settings, Map<String, String> apps, Set<String> admins, boolean adbListening) {
        Map<String, String> clean = new TreeMap<>();
        for (Map.Entry<String, String> e : settings.entrySet()) clean.put(e.getKey(), norm(e.getValue()));
        this.settings = Collections.unmodifiableMap(clean);
        Map<String, String> validApps = new TreeMap<>();
        for (Map.Entry<String, String> e : apps.entrySet()) {
            if (isPackage(e.getKey())) validApps.put(e.getKey(), norm(e.getValue()));
        }
        this.apps = Collections.unmodifiableMap(validApps);
        Set<String> validAdmins = new TreeSet<>();
        for (String a : admins) if (a != null && COMPONENT.matcher(a).matches()) validAdmins.add(a);
        this.admins = Collections.unmodifiableSet(validAdmins);
        this.adbListening = adbListening;
    }

    static String norm(String value) {
        if (value == null) return "";
        String v = value.trim();
        return v.equals("null") ? "" : v;
    }

    public static boolean isPackage(String name) {
        return name != null && PACKAGE.matcher(name).matches();
    }

    public String get(String key) {
        String v = settings.get(key);
        return v == null ? "" : v;
    }

    public boolean adbUsbOn() {
        return "1".equals(get(ADB));
    }

    public boolean adbWifiOn() {
        return "1".equals(get(ADB_WIFI));
    }

    /** host:port of the HTTP proxy every app uses, or "" when there is none. */
    public String proxy() {
        String p = get(PROXY);
        if (!p.isEmpty() && !p.equals(":0")) return p;
        String host = get(PROXY_HOST);
        if (host.isEmpty()) return "";
        String port = get(PROXY_PORT);
        return port.isEmpty() ? host : host + ":" + port;
    }

    public String privateDns() {
        String mode = get(DNS_MODE);
        if ("hostname".equals(mode)) return get(DNS_HOST).isEmpty() ? "hostname" : get(DNS_HOST);
        return mode.isEmpty() ? "default" : mode;
    }

    /** The network ADB port that stays set across reboots, or "" when there is none. */
    public String persistentPort() {
        String p = get(PERSIST_PORT);
        return p.isEmpty() || p.equals("-1") || p.equals("0") ? "" : p;
    }

    /** package/class entries of a colon-separated setting, validated. */
    public Set<String> components(String key) {
        Set<String> out = new LinkedHashSet<>();
        for (String part : get(key).split(":")) {
            String entry = part.trim();
            if (COMPONENT.matcher(entry).matches()) out.add(entry);
        }
        return out;
    }

    static String packageOf(String component) {
        int slash = component.indexOf('/');
        return slash < 0 ? component : component.substring(0, slash);
    }

    public boolean sideloaded(String pkg) {
        String installer = apps.get(pkg);
        return installer != null && SIDELOAD.contains(installer);
    }

    // ---------------------------------------------------------------------------------------------
    // Events

    /** What is worth reporting the first time the watchdog looks: risky states, not every app. */
    public List<SecurityEvent> baseline(Set<String> trusted, long now) {
        List<SecurityEvent> out = new ArrayList<>();
        out.add(new SecurityEvent("watchdog_baseline", SecurityEvent.INFO, "Watchdog started watching this TV",
                apps.size() + " installed app(s), " + components(A11Y).size() + " accessibility service(s)",
                null, now));
        Snapshot empty = new Snapshot(Collections.emptyMap(), apps, Collections.emptySet(), false);
        for (SecurityEvent e : empty.diff(this, trusted, now)) {
            // A Private DNS "change" from nothing is just the current setting, not news.
            if (!e.type.equals("app_installed") && !e.type.equals("private_dns") && e.atLeast(SecurityEvent.MEDIUM)) {
                out.add(e);
            }
        }
        return out;
    }

    /** Everything that changed from {@code before} to this snapshot, in a stable order. */
    public List<SecurityEvent> diffFrom(Snapshot before, Set<String> trusted, long now) {
        return before.diff(this, trusted, now);
    }

    List<SecurityEvent> diff(Snapshot now, Set<String> trusted, long time) {
        List<SecurityEvent> out = new ArrayList<>();
        Snapshot was = this;

        switched(out, was.adbUsbOn(), now.adbUsbOn(), "adb_usb", SecurityEvent.MEDIUM,
                "USB debugging was switched on", "USB debugging was switched off",
                "Anyone with a cable, or the network port, can now ask for a shell.", time);
        switched(out, was.adbWifiOn(), now.adbWifiOn(), "adb_wireless", SecurityEvent.MEDIUM,
                "Wireless debugging was switched on", "Wireless debugging was switched off",
                "The TV accepts paired debugging over Wi-Fi.", time);
        switched(out, was.adbListening, now.adbListening, "adb_network", SecurityEvent.HIGH,
                "Network ADB is listening on port " + ADB_PORT, "Network ADB stopped listening",
                "The port is plaintext; on some firmware anyone on the network gets a shell.", time);
        if (!now.persistentPort().isEmpty() && !now.persistentPort().equals(was.persistentPort())) {
            out.add(new SecurityEvent("adb_persistent", SecurityEvent.HIGH,
                    "Network ADB set to reopen at every boot (port " + now.persistentPort() + ")",
                    "persist.adb.tcp.port is set.", null, time));
        }
        switched(out, "1".equals(was.get(DEV)), "1".equals(now.get(DEV)), "developer_options", SecurityEvent.LOW,
                "Developer options were switched on", "Developer options were switched off", "", time);
        if ("0".equals(now.get(VERIFIER)) && !"0".equals(was.get(VERIFIER))) {
            out.add(new SecurityEvent("verifier_off", SecurityEvent.MEDIUM, "Play Protect app checks switched off",
                    "Installed APKs are no longer checked for known malware.", null, time));
        }
        if (!now.proxy().equals(was.proxy())) {
            if (now.proxy().isEmpty()) {
                out.add(new SecurityEvent("proxy", SecurityEvent.INFO, "The HTTP proxy was removed",
                        "Was " + was.proxy(), null, time));
            } else {
                out.add(new SecurityEvent("proxy", SecurityEvent.HIGH, "Web traffic now goes through " + now.proxy(),
                        "A proxy you did not set is a classic way to watch what the TV sends.", null, time));
            }
        }
        if (!now.privateDns().equals(was.privateDns())) {
            out.add(new SecurityEvent("private_dns", SecurityEvent.MEDIUM, "Private DNS changed to " + now.privateDns(),
                    "Was " + was.privateDns() + ". The DNS resolver sees every name the TV looks up.", null, time));
        }

        holders(out, was.components(A11Y), now.components(A11Y), now, trusted, "accessibility",
                "has accessibility access", "lost accessibility access",
                "It can read the screen and the keys pressed.", SecurityEvent.HIGH, time);
        holders(out, was.components(LISTENERS), now.components(LISTENERS), now, trusted, "notification_access",
                "reads notifications", "lost notification access",
                "It sees the text of every notification.", SecurityEvent.HIGH, time);
        holders(out, was.admins, now.admins, now, trusted, "device_admin",
                "is a device administrator", "is no longer a device administrator",
                "It can lock or wipe the TV and resist removal.", SecurityEvent.HIGH, time);

        String imeBefore = was.get(IME), imeNow = now.get(IME);
        if (!imeNow.equals(imeBefore) && COMPONENT.matcher(imeNow).matches()) {
            String pkg = packageOf(imeNow);
            String sev = trusted.contains(pkg) || !now.apps.containsKey(pkg) ? SecurityEvent.INFO : SecurityEvent.MEDIUM;
            out.add(new SecurityEvent("keyboard", sev, "The keyboard is now " + pkg,
                    "A keyboard sees everything typed, passwords included.", pkg, time));
        }

        for (Map.Entry<String, String> app : now.apps.entrySet()) {
            String pkg = app.getKey();
            if (was.apps.containsKey(pkg)) continue;
            String sev;
            String title;
            if (trusted.contains(pkg)) {
                sev = SecurityEvent.INFO;
                title = "App installed: " + pkg;
            } else if (now.sideloaded(pkg)) {
                sev = SecurityEvent.MEDIUM;
                title = "App installed from outside a store: " + pkg;
            } else {
                sev = SecurityEvent.LOW;
                title = "App installed: " + pkg;
            }
            String installer = app.getValue().isEmpty() ? "unknown" : app.getValue();
            out.add(new SecurityEvent("app_installed", sev, title, "Installer: " + installer, pkg, time));
        }
        for (String pkg : was.apps.keySet()) {
            if (!now.apps.containsKey(pkg)) {
                out.add(new SecurityEvent("app_removed", SecurityEvent.INFO, "App removed: " + pkg, "", pkg, time));
            }
        }
        return out;
    }

    private static void switched(List<SecurityEvent> out, boolean was, boolean now, String type, String severity,
                                 String onTitle, String offTitle, String detail, long time) {
        if (was == now) return;
        out.add(now ? new SecurityEvent(type, severity, onTitle, detail, null, time)
                : new SecurityEvent(type, SecurityEvent.INFO, offTitle, "", null, time));
    }

    private static void holders(List<SecurityEvent> out, Set<String> was, Set<String> now, Snapshot state,
                                Set<String> trusted, String type, String verb, String lostVerb, String why,
                                String worst, long time) {
        for (String component : now) {
            if (was.contains(component)) continue;
            String pkg = packageOf(component);
            String sev = trusted.contains(pkg) ? SecurityEvent.INFO
                    : state.apps.containsKey(pkg) ? worst : SecurityEvent.LOW;
            out.add(new SecurityEvent(type, sev, pkg + " " + verb, why + " (" + component + ")", pkg, time));
        }
        for (String component : was) {
            if (now.contains(component)) continue;
            String pkg = packageOf(component);
            out.add(new SecurityEvent(type + "_removed", SecurityEvent.INFO, pkg + " " + lostVerb, component, pkg, time));
        }
    }

    // ---------------------------------------------------------------------------------------------
    // Storage

    public JSONObject toJson() {
        JSONObject o = new JSONObject();
        try {
            o.put("settings", new JSONObject(settings));
            o.put("apps", new JSONObject(apps));
            o.put("admins", new JSONArray(admins));
            o.put("adb_listening", adbListening);
        } catch (JSONException impossible) {
            throw new IllegalStateException(impossible);
        }
        return o;
    }

    public static Snapshot fromJson(JSONObject o) {
        Map<String, String> settings = new LinkedHashMap<>();
        JSONObject s = o.optJSONObject("settings");
        if (s != null) for (String key : keys(s)) settings.put(key, s.optString(key));
        Map<String, String> apps = new LinkedHashMap<>();
        JSONObject a = o.optJSONObject("apps");
        if (a != null) for (String key : keys(a)) apps.put(key, a.optString(key));
        Set<String> admins = new LinkedHashSet<>();
        JSONArray d = o.optJSONArray("admins");
        if (d != null) for (int i = 0; i < d.length(); i++) admins.add(d.optString(i));
        return new Snapshot(settings, apps, admins, o.optBoolean("adb_listening"));
    }

    private static List<String> keys(JSONObject o) {
        List<String> out = new ArrayList<>();
        java.util.Iterator<String> it = o.keys();
        while (it.hasNext()) out.add(it.next());
        return out;
    }

    @Override
    public boolean equals(Object other) {
        if (!(other instanceof Snapshot)) return false;
        Snapshot s = (Snapshot) other;
        return adbListening == s.adbListening && settings.equals(s.settings) && apps.equals(s.apps)
                && admins.equals(s.admins);
    }

    @Override
    public int hashCode() {
        return Objects.hash(settings, apps, admins, adbListening);
    }
}
