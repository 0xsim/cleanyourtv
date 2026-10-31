package io.github.securetv.watchdog;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import org.json.JSONException;
import org.json.JSONObject;

/**
 * Everything the watchdog keeps, as small files in its private folder: the last snapshot, the event
 * log (the newest 200), one outbox per syslog target for events that could not be sent yet, and a
 * few numbers. Plain Java file I/O, so it is unit tested; private storage keeps it from other apps.
 */
final class Store {
    static final int LOG_LIMIT = 200;
    static final int OUTBOX_LIMIT = 1000;

    private final File dir;

    Store(File dir) {
        this.dir = dir;
        //noinspection ResultOfMethodCallIgnored
        dir.mkdirs();
    }

    File file(String name) {
        return new File(dir, name);
    }

    // Snapshot ------------------------------------------------------------------------------------

    synchronized Snapshot snapshot() {
        String text = read("snapshot.json");
        if (text == null) return null;
        try {
            return Snapshot.fromJson(new JSONObject(text));
        } catch (JSONException e) {
            return null;
        }
    }

    synchronized void saveSnapshot(Snapshot s) {
        write("snapshot.json", s.toJson().toString());
    }

    // Event log -----------------------------------------------------------------------------------

    synchronized void log(List<SecurityEvent> events, String device) {
        if (events.isEmpty()) return;
        List<String> lines = lines("events.jsonl");
        for (SecurityEvent e : events) lines.add(e.toJson(device).toString());
        if (lines.size() > LOG_LIMIT) lines = lines.subList(lines.size() - LOG_LIMIT, lines.size());
        write("events.jsonl", String.join("\n", lines) + "\n");
    }

    /** The newest events first. */
    synchronized List<SecurityEvent> recent(int max) {
        List<SecurityEvent> out = new ArrayList<>();
        List<String> lines = lines("events.jsonl");
        Collections.reverse(lines);
        for (String line : lines) {
            if (out.size() >= max) break;
            try {
                out.add(SecurityEvent.fromJson(new JSONObject(line)));
            } catch (JSONException ignored) {
            }
        }
        return out;
    }

    // Outboxes ------------------------------------------------------------------------------------

    static String outboxName(String target) {
        return "outbox-" + Integer.toHexString(target.hashCode()) + ".txt";
    }

    synchronized void queue(String target, List<String> syslogLines) {
        List<String> lines = lines(outboxName(target));
        lines.addAll(syslogLines);
        if (lines.size() > OUTBOX_LIMIT) lines = lines.subList(lines.size() - OUTBOX_LIMIT, lines.size());
        write(outboxName(target), String.join("\n", lines) + "\n");
    }

    synchronized List<String> pending(String target) {
        return lines(outboxName(target));
    }

    /** Drops the first {@code count} lines, the ones that were just sent. */
    synchronized void sent(String target, int count) {
        List<String> lines = lines(outboxName(target));
        lines = lines.subList(Math.min(count, lines.size()), lines.size());
        if (lines.isEmpty()) {
            //noinspection ResultOfMethodCallIgnored
            file(outboxName(target)).delete();
        } else {
            write(outboxName(target), String.join("\n", lines) + "\n");
        }
    }

    // Numbers -------------------------------------------------------------------------------------

    synchronized long number(String key, long fallback) {
        JSONObject state = state();
        return state.optLong(key, fallback);
    }

    synchronized void setNumber(String key, long value) {
        JSONObject state = state();
        try {
            state.put(key, value);
        } catch (JSONException impossible) {
            throw new IllegalStateException(impossible);
        }
        write("state.json", state.toString());
    }

    private JSONObject state() {
        String text = read("state.json");
        try {
            return text == null ? new JSONObject() : new JSONObject(text);
        } catch (JSONException e) {
            return new JSONObject();
        }
    }

    // Files ---------------------------------------------------------------------------------------

    String read(String name) {
        File f = file(name);
        if (!f.isFile()) return null;
        try {
            return new String(Files.readAllBytes(f.toPath()), StandardCharsets.UTF_8);
        } catch (IOException e) {
            return null;
        }
    }

    private List<String> lines(String name) {
        String text = read(name);
        List<String> out = new ArrayList<>();
        if (text == null) return out;
        for (String line : text.split("\n")) if (!line.trim().isEmpty()) out.add(line);
        return out;
    }

    /** Writes through a temporary file and a rename, so a power cut never leaves half a file. */
    void write(String name, String text) {
        File target = file(name);
        File tmp = file(name + ".tmp");
        try (FileOutputStream out = new FileOutputStream(tmp)) {
            out.write(text.getBytes(StandardCharsets.UTF_8));
            out.getFD().sync();
        } catch (IOException e) {
            return;
        }
        if (!tmp.renameTo(target)) {
            //noinspection ResultOfMethodCallIgnored
            tmp.delete();
        }
    }
}
