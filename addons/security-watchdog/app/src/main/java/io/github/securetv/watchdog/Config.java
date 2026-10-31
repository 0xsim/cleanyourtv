package io.github.securetv.watchdog;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

/**
 * The owner's settings, pushed as config.json by install.sh. Every key is optional: with none, the
 * watchdog still watches and keeps its own log, it just sends nothing anywhere.
 *
 * <pre>
 * {
 *   "device_name": "Living Room TV",                  name in syslog and Home Assistant (default: model)
 *   "syslog": ["syslog+udp://192.168.1.20:514"],       one or more SIEM targets
 *   "mqtt": "mqtt://user:pass@192.168.1.10:1883",      or mqtts://...:8883
 *   "mqtt_base": "cleanyourtv",                        topic prefix
 *   "ha_discovery": "homeassistant",                   discovery prefix, or "off"
 *   "ca_pem": "-----BEGIN CERTIFICATE-----...",        your own CA, for mqtts and syslog+tls
 *   "adb_autoclose_minutes": 30,                       switch debugging off after this long; 0 = never
 *   "trusted_packages": ["com.example.mine"],          your own apps: their events are info only
 *   "sweep_minutes": 15,                               full re-check interval
 *   "on_screen_alerts": "high"                         show a toast for events this bad: high, medium, off
 * }
 * </pre>
 */
public final class Config {
    public static final int DEFAULT_AUTOCLOSE_MINUTES = 30;

    public final String deviceName;
    public final List<URI> syslog;
    public final URI mqtt;
    public final String mqttBase;
    public final String haDiscovery;
    public final String caPem;
    public final int adbAutocloseMinutes;
    public final Set<String> trusted;
    public final int sweepMinutes;
    public final String onScreenAlerts;

    private Config(String deviceName, List<URI> syslog, URI mqtt, String mqttBase, String haDiscovery, String caPem,
                   int adbAutocloseMinutes, Set<String> trusted, int sweepMinutes, String onScreenAlerts) {
        this.deviceName = deviceName;
        this.syslog = Collections.unmodifiableList(syslog);
        this.mqtt = mqtt;
        this.mqttBase = mqttBase;
        this.haDiscovery = haDiscovery;
        this.caPem = caPem;
        this.adbAutocloseMinutes = adbAutocloseMinutes;
        this.trusted = Collections.unmodifiableSet(trusted);
        this.sweepMinutes = sweepMinutes;
        this.onScreenAlerts = onScreenAlerts;
    }

    public static Config defaults(String model) {
        return new Config(model, new ArrayList<>(), null, "cleanyourtv", "homeassistant", null,
                DEFAULT_AUTOCLOSE_MINUTES, new LinkedHashSet<>(), 15, SecurityEvent.HIGH);
    }

    /** Parses and checks a config file. The message of the exception names the first bad key. */
    public static Config parse(String json, String model) throws IllegalArgumentException {
        JSONObject o;
        try {
            o = new JSONObject(json);
        } catch (JSONException e) {
            // Not e.getMessage(): Android's org.json quotes the whole input there, passwords included.
            throw new IllegalArgumentException("config.json is not valid JSON");
        }
        Config d = defaults(model);
        String name = o.optString("device_name", d.deviceName).trim();
        if (name.isEmpty() || name.length() > 64) throw new IllegalArgumentException("device_name must be 1 to 64 characters");

        List<URI> syslog = new ArrayList<>();
        Object s = o.opt("syslog");
        if (s instanceof String) {
            syslog.add(target((String) s, "syslog"));
        } else if (s instanceof JSONArray) {
            JSONArray a = (JSONArray) s;
            for (int i = 0; i < a.length(); i++) syslog.add(target(a.optString(i), "syslog"));
        } else if (s != null && s != JSONObject.NULL) {
            throw new IllegalArgumentException("syslog must be a URL or a list of URLs");
        }
        URI mqtt = o.has("mqtt") && !o.isNull("mqtt") ? target(o.optString("mqtt"), "mqtt") : null;

        String base = o.optString("mqtt_base", d.mqttBase).replaceAll("^/+|/+$", "");
        if (base.isEmpty() || base.contains("+") || base.contains("#")) {
            throw new IllegalArgumentException("mqtt_base must be a plain topic prefix");
        }
        String discovery = o.optString("ha_discovery", d.haDiscovery).replaceAll("^/+|/+$", "");
        String ca = o.has("ca_pem") && !o.isNull("ca_pem") ? o.optString("ca_pem") : null;
        if (ca != null && !ca.contains("-----BEGIN CERTIFICATE-----")) {
            throw new IllegalArgumentException("ca_pem must hold a PEM certificate");
        }
        int minutes = o.optInt("adb_autoclose_minutes", d.adbAutocloseMinutes);
        if (minutes < 0 || minutes > 24 * 60) throw new IllegalArgumentException("adb_autoclose_minutes must be 0 to 1440");

        Set<String> trusted = new LinkedHashSet<>();
        JSONArray t = o.optJSONArray("trusted_packages");
        if (t != null) {
            for (int i = 0; i < t.length(); i++) {
                String pkg = t.optString(i);
                if (!Snapshot.isPackage(pkg)) throw new IllegalArgumentException("not a package name: " + pkg);
                trusted.add(pkg);
            }
        }
        int sweep = o.optInt("sweep_minutes", d.sweepMinutes);
        if (sweep < 1 || sweep > 24 * 60) throw new IllegalArgumentException("sweep_minutes must be 1 to 1440");
        String alerts = o.optString("on_screen_alerts", d.onScreenAlerts).toLowerCase(Locale.ROOT);
        if (!alerts.equals(SecurityEvent.HIGH) && !alerts.equals(SecurityEvent.MEDIUM) && !alerts.equals("off")) {
            throw new IllegalArgumentException("on_screen_alerts must be high, medium or off");
        }
        return new Config(name, syslog, mqtt, base, discovery, ca, minutes, trusted, sweep, alerts);
    }

    static URI target(String url, String kind) {
        URI uri;
        try {
            uri = new URI(url.trim());
        } catch (URISyntaxException e) {
            throw new IllegalArgumentException(kind + ": not a URL: " + redact(url));
        }
        String scheme = uri.getScheme() == null ? "" : uri.getScheme().toLowerCase(Locale.ROOT);
        boolean ok = kind.equals("syslog")
                ? scheme.equals("syslog+udp") || scheme.equals("syslog+tcp") || scheme.equals("syslog+tls")
                : scheme.equals("mqtt") || scheme.equals("mqtts");
        if (!ok) throw new IllegalArgumentException(kind + ": unsupported scheme in " + redact(url));
        if (uri.getHost() == null) {
            throw new IllegalArgumentException(kind + ": no host in " + redact(url)
                    + " (percent-encode / ? # @ in a password)");
        }
        return uri;
    }

    public static int port(URI uri) {
        if (uri.getPort() > 0) return uri.getPort();
        switch (uri.getScheme().toLowerCase(Locale.ROOT)) {
            case "syslog+tls": return 6514;
            case "mqtt": return 1883;
            case "mqtts": return 8883;
            default: return 514;
        }
    }

    /** A URL with its password hidden, for the log and the screen. */
    public static String redact(String url) {
        // Everything from the user name's colon to the last '@', so a password holding / ? # @ stays hidden.
        return url == null ? "" : url.replaceAll("://([^:/@]*):.*@(?=[^@]*$)", "://$1:***@");
    }

    /** The topic- and host-safe form of the device name, the same as tools/integrations.py's slug(). */
    public String slug() {
        return slug(deviceName);
    }

    public static String slug(String name) {
        String s = (name == null ? "" : name.toLowerCase(Locale.ROOT)).replaceAll("[^a-z0-9]+", "_")
                .replaceAll("^_+|_+$", "");
        if (s.length() > 48) s = s.substring(0, 48);
        return s.isEmpty() ? "tv" : s;
    }

    public boolean trusts(String pkg) {
        return pkg != null && trusted.contains(pkg);
    }
}
