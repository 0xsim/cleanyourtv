package io.github.securetv.watchdog;

import org.json.JSONException;
import org.json.JSONObject;

/** One thing that changed on the TV, worth telling the owner about. Plain Java, so it is unit tested. */
public final class SecurityEvent {
    public static final String HIGH = "high";
    public static final String MEDIUM = "medium";
    public static final String LOW = "low";
    public static final String INFO = "info";

    public final String type;
    public final String severity;
    public final String title;
    public final String detail;
    /** The app the event is about, or null. Only ever a validated package name. */
    public final String packageName;
    public final long timeMs;

    public SecurityEvent(String type, String severity, String title, String detail, String packageName, long timeMs) {
        this.type = type;
        this.severity = severity;
        this.title = title;
        this.detail = detail == null ? "" : detail;
        this.packageName = packageName;
        this.timeMs = timeMs;
    }

    /** 0 for high to 3 for info, so lists can sort worst first. */
    public static int rank(String severity) {
        switch (severity) {
            case HIGH: return 0;
            case MEDIUM: return 1;
            case LOW: return 2;
            default: return 3;
        }
    }

    public boolean atLeast(String threshold) {
        return rank(severity) <= rank(threshold);
    }

    public JSONObject toJson(String device) {
        JSONObject o = new JSONObject();
        try {
            o.put("source", "cleanyourtv");
            o.put("origin", "watchdog");
            o.put("device", device);
            o.put("event", type);
            o.put("severity", severity);
            o.put("title", title);
            o.put("detail", detail);
            if (packageName != null) o.put("package", packageName);
            o.put("time", Iso.format(timeMs));
        } catch (JSONException impossible) {
            throw new IllegalStateException(impossible);
        }
        return o;
    }

    public static SecurityEvent fromJson(JSONObject o) {
        return new SecurityEvent(o.optString("event"), o.optString("severity", INFO), o.optString("title"),
                o.optString("detail"), o.has("package") ? o.optString("package") : null, Iso.parse(o.optString("time")));
    }
}
