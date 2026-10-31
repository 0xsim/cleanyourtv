package io.github.securetv.watchdog;

import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.time.temporal.ChronoUnit;

/** ISO 8601 times in UTC, the form the host tools write too. */
final class Iso {
    private Iso() {
    }

    static String format(long ms) {
        return Instant.ofEpochMilli(ms).truncatedTo(ChronoUnit.SECONDS).toString();
    }

    static long parse(String text) {
        try {
            return Instant.parse(text).toEpochMilli();
        } catch (DateTimeParseException | NullPointerException e) {
            return 0L;
        }
    }
}
