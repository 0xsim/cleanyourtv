package io.github.securetv.watchdog;

import java.util.ArrayList;
import java.util.List;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

/**
 * The MQTT topics and Home Assistant discovery configs. The device identifier is cleanyourtv_<slug>,
 * the same one tools/integrations.py gives the audit, so the watchdog's and the audit's sensors show
 * up on one device. Plain Java, unit tested.
 */
final class HomeAssistant {
    static final String CLOSE_ADB = "close_adb";
    static final String SWEEP = "sweep";

    final String base;
    final String slug;
    final String deviceName;
    final String discovery;

    HomeAssistant(Config config) {
        this.base = config.mqttBase;
        this.slug = config.slug();
        this.deviceName = config.deviceName;
        this.discovery = config.haDiscovery;
    }

    String availabilityTopic() {
        return base + "/" + slug + "/watchdog/availability";
    }

    String stateTopic() {
        return base + "/" + slug + "/watchdog/state";
    }

    String commandTopic() {
        return base + "/" + slug + "/watchdog/command";
    }

    String eventTopic() {
        return base + "/" + slug + "/event";
    }

    String node() {
        return "cleanyourtv_" + slug;
    }

    /** {topic, payload} pairs, all retained. Empty when discovery is "off". */
    List<String[]> discoveryMessages(String model, String version) {
        List<String[]> out = new ArrayList<>();
        if ("off".equals(discovery) || discovery.isEmpty()) return out;
        JSONObject device = new JSONObject();
        put(device, "identifiers", new JSONArray().put(node()));
        put(device, "name", deviceName);
        if (model != null) put(device, "model", model);
        put(device, "sw_version", "security-watchdog " + version);

        problem(out, device, "usb_debugging", "USB debugging", "value_json.adb_usb");
        problem(out, device, "wireless_debugging", "Wireless debugging", "value_json.adb_wifi");
        problem(out, device, "network_adb", "Network ADB listening", "value_json.adb_network");
        problem(out, device, "proxy_set", "HTTP proxy set", "value_json.proxy != ''");
        sensor(out, device, "adb_autoclose", "ADB auto-close",
                "{{ (value_json.adb_autoclose_min | string) ~ ' min' if value_json.adb_autoclose_min is not none else 'off' }}",
                "mdi:timer-lock-outline", false);
        sensor(out, device, "last_security_event", "Last security event", "{{ value_json.last_event.title }}",
                "mdi:shield-alert-outline", true);
        sensor(out, device, "private_dns", "Private DNS", "{{ value_json.private_dns }}", "mdi:dns", false);
        sensor(out, device, "installed_apps", "Installed apps", "{{ value_json.apps }}", "mdi:apps", false);
        button(out, device, "close_adb", "Close ADB", CLOSE_ADB, "mdi:lan-disconnect");
        button(out, device, "recheck", "Re-check security", SWEEP, "mdi:shield-refresh");
        return out;
    }

    private JSONObject common(JSONObject device, String objectId, String name) {
        JSONObject c = new JSONObject();
        put(c, "name", name);
        put(c, "unique_id", node() + "_" + objectId);
        put(c, "device", device);
        put(c, "availability_topic", availabilityTopic());
        return c;
    }

    private void problem(List<String[]> out, JSONObject device, String id, String name, String expression) {
        JSONObject c = common(device, id, name);
        put(c, "state_topic", stateTopic());
        put(c, "value_template", "{{ 'ON' if " + expression + " else 'OFF' }}");
        put(c, "device_class", "problem");
        out.add(new String[]{discovery + "/binary_sensor/" + node() + "/" + id + "/config", c.toString()});
    }

    private void sensor(List<String[]> out, JSONObject device, String id, String name, String template, String icon,
                        boolean attributes) {
        JSONObject c = common(device, id, name);
        put(c, "state_topic", stateTopic());
        put(c, "value_template", template);
        put(c, "icon", icon);
        if (attributes) put(c, "json_attributes_topic", stateTopic());
        out.add(new String[]{discovery + "/sensor/" + node() + "/" + id + "/config", c.toString()});
    }

    private void button(List<String[]> out, JSONObject device, String id, String name, String payload, String icon) {
        JSONObject c = common(device, id, name);
        put(c, "command_topic", commandTopic());
        put(c, "payload_press", payload);
        put(c, "icon", icon);
        out.add(new String[]{discovery + "/button/" + node() + "/" + id + "/config", c.toString()});
    }

    /** The retained state: what the sensors read. */
    static JSONObject state(Snapshot s, Long autocloseMinutes, SecurityEvent last, long now) {
        JSONObject o = new JSONObject();
        put(o, "adb_usb", s.adbUsbOn());
        put(o, "adb_wifi", s.adbWifiOn());
        put(o, "adb_network", s.adbListening);
        put(o, "adb_persistent_port", s.persistentPort());
        put(o, "adb_autoclose_min", autocloseMinutes == null ? JSONObject.NULL : autocloseMinutes);
        put(o, "developer_options", "1".equals(s.get(Snapshot.DEV)));
        put(o, "proxy", s.proxy());
        put(o, "private_dns", s.privateDns());
        put(o, "keyboard", Snapshot.packageOf(s.get(Snapshot.IME)));
        put(o, "accessibility", new JSONArray(s.components(Snapshot.A11Y)));
        put(o, "notification_listeners", new JSONArray(s.components(Snapshot.LISTENERS)));
        put(o, "device_admins", new JSONArray(s.admins));
        put(o, "apps", s.apps.size());
        JSONObject event = new JSONObject();
        put(event, "title", last == null ? "none" : last.title);
        put(event, "severity", last == null ? SecurityEvent.INFO : last.severity);
        put(event, "time", last == null ? JSONObject.NULL : Iso.format(last.timeMs));
        put(o, "last_event", event);
        put(o, "time", Iso.format(now));
        return o;
    }

    private static void put(JSONObject o, String key, Object value) {
        try {
            o.put(key, value);
        } catch (JSONException impossible) {
            throw new IllegalStateException(impossible);
        }
    }
}
