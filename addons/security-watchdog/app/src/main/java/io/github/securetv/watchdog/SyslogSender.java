package io.github.securetv.watchdog;

import java.io.IOException;
import java.io.OutputStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.List;
import java.util.Locale;

import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

import org.json.JSONObject;

/**
 * Sends events to a syslog collector or SIEM, in the same format as tools/integrations.py: an RFC 3164
 * header (what Wazuh pre-decodes) tagged "cleanyourtv", then the event as one JSON object.
 */
final class SyslogSender {
    static final String TAG = "cleanyourtv";
    private static final int TIMEOUT_MS = 10_000;
    private static final DateTimeFormatter RFC3164 = DateTimeFormatter.ofPattern("MMM ppd HH:mm:ss", Locale.ENGLISH);

    private SyslogSender() {
    }

    static int severityCode(String severity) {
        switch (severity) {
            case SecurityEvent.HIGH: return 3;     // err
            case SecurityEvent.MEDIUM: return 4;   // warning
            case SecurityEvent.LOW: return 5;      // notice
            default: return 6;                     // informational
        }
    }

    /** One line, without the trailing newline. Facility local0 (16). */
    static String format(JSONObject event, String severity, String hostname, long timeMs, ZoneId zone, boolean rfc5424) {
        int pri = 16 * 8 + severityCode(severity);
        String host = Config.slug(hostname).replace('_', '-');
        String body = event.toString();
        if (rfc5424) {
            return "<" + pri + ">1 " + Instant.ofEpochMilli(timeMs) + " " + host + " " + TAG + " - - - " + body;
        }
        String stamp = RFC3164.format(ZonedDateTime.ofInstant(Instant.ofEpochMilli(timeMs), zone));
        return "<" + pri + ">" + stamp + " " + host + " " + TAG + ": " + body;
    }

    /** Sends the lines to one target. Throws on any failure, so the caller keeps them for a retry. */
    static void send(URI target, List<String> lines, SSLSocketFactory tls) throws IOException {
        String scheme = target.getScheme().toLowerCase(Locale.ROOT);
        int port = Config.port(target);
        if (scheme.equals("syslog+udp")) {
            InetAddress address = InetAddress.getByName(target.getHost());
            try (DatagramSocket socket = new DatagramSocket()) {
                socket.setSoTimeout(TIMEOUT_MS);
                for (String line : lines) {
                    byte[] data = line.getBytes(StandardCharsets.UTF_8);
                    socket.send(new DatagramPacket(data, data.length, address, port));
                }
            }
            return;
        }
        try (Socket raw = new Socket()) {
            raw.connect(new InetSocketAddress(target.getHost(), port), TIMEOUT_MS);
            raw.setSoTimeout(TIMEOUT_MS);
            Socket socket = raw;
            if (scheme.equals("syslog+tls")) {
                SSLSocket ssl = (SSLSocket) tls.createSocket(raw, target.getHost(), port, true);
                Tls.handshake(ssl, target.getHost());
                socket = ssl;
            }
            OutputStream out = socket.getOutputStream();
            for (String line : lines) out.write((line + "\n").getBytes(StandardCharsets.UTF_8));
            out.flush();
            if (socket != raw) socket.close();
        }
    }

    static boolean rfc5424(URI target) {
        String q = target.getQuery();
        return q != null && q.contains("format=rfc5424");
    }
}
