package io.github.securetv.watchdog;

/**
 * When to switch debugging off. The clock starts when any form of debugging is seen on (USB, wireless
 * or the network port) and stops when all are off again. Plain Java, unit tested.
 */
final class AutoClose {
    static final String KEY_ON_SINCE = "adb_on_since_ms";

    private AutoClose() {
    }

    static boolean debuggingOn(Snapshot s) {
        return s.adbUsbOn() || s.adbWifiOn() || s.adbListening;
    }

    /** The new start of the clock: kept while debugging stays on, set when it comes on, 0 when off. */
    static long onSince(Snapshot s, long previous, long now) {
        if (!debuggingOn(s)) return 0L;
        return previous > 0 ? previous : now;
    }

    /** Milliseconds until debugging is switched off, 0 when it is due, or -1 when nothing is scheduled. */
    static long remainingMs(Snapshot s, long onSince, long now, int minutes) {
        if (minutes <= 0 || onSince <= 0 || !debuggingOn(s)) return -1L;
        return Math.max(0L, onSince + minutes * 60_000L - now);
    }

    /** Minutes left, rounded up, for the screen and Home Assistant; null when nothing is scheduled. */
    static Long minutesLeft(Snapshot s, long onSince, long now, int minutes) {
        long ms = remainingMs(s, onSince, now, minutes);
        return ms < 0 ? null : (ms + 59_999L) / 60_000L;
    }
}
