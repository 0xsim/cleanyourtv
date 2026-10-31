package io.github.securetv.watchdog;

import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.LinkedBlockingDeque;

import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

/**
 * A small MQTT 3.1.1 client that stays connected: it publishes with QoS 1 and waits for each PUBACK,
 * keeps the session alive with PINGREQ, leaves a retained "offline" will so Home Assistant shows the
 * TV as unavailable when it goes away, and listens on one command topic. Reconnects with back-off.
 * The packet encoding is static and plain Java, so it is unit tested.
 */
final class MqttLink implements Runnable {
    interface Listener {
        void onConnected(MqttLink link);

        void onCommand(String payload);

        void onDisconnected(Exception cause);
    }

    static final class Message {
        final String topic;
        final byte[] payload;
        final boolean retain;

        Message(String topic, String payload, boolean retain) {
            this.topic = topic;
            this.payload = payload.getBytes(StandardCharsets.UTF_8);
            this.retain = retain;
        }
    }

    static final int KEEPALIVE_S = 60;
    private static final int CONNECT_TIMEOUT_MS = 10_000;
    private static final int ACK_TIMEOUT_MS = 10_000;
    private static final int MAX_QUEUE = 500;

    private final URI target;
    private final String clientId;
    private final String availabilityTopic;
    private final String commandTopic;
    private final SSLSocketFactory tls;
    private final Listener listener;
    private final LinkedBlockingDeque<Message> queue = new LinkedBlockingDeque<>();
    private volatile boolean stopped;
    private volatile boolean connected;
    private volatile Socket socket;
    private int nextId = 1;

    MqttLink(URI target, String clientId, String availabilityTopic, String commandTopic, SSLSocketFactory tls,
             Listener listener) {
        this.target = target;
        this.clientId = clientId;
        this.availabilityTopic = availabilityTopic;
        this.commandTopic = commandTopic;
        this.tls = tls;
        this.listener = listener;
    }

    boolean isConnected() {
        return connected;
    }

    /** Queues a message; the oldest is dropped when the broker has been away for a long time. */
    void publish(String topic, String payload, boolean retain) {
        while (queue.size() >= MAX_QUEUE) queue.pollFirst();
        queue.offerLast(new Message(topic, payload, retain));
    }

    void stop() {
        stopped = true;
        Socket s = socket;
        if (s != null) {
            try {
                s.close();
            } catch (IOException ignored) {
            }
        }
    }

    @Override
    public void run() {
        int attempt = 0;
        while (!stopped) {
            try {
                session();
                attempt = 0;
            } catch (Exception e) {
                connected = false;
                if (stopped) break;
                listener.onDisconnected(e);
                attempt++;
            }
            if (stopped) break;
            try {
                Thread.sleep(backoffMs(attempt));
            } catch (InterruptedException e) {
                break;
            }
        }
        connected = false;
    }

    static long backoffMs(int attempt) {
        return Math.min(300_000L, 2_000L << Math.min(Math.max(attempt - 1, 0), 8));
    }

    private void session() throws IOException {
        String host = target.getHost();
        int port = Config.port(target);
        Socket raw = new Socket();
        raw.connect(new InetSocketAddress(host, port), CONNECT_TIMEOUT_MS);
        Socket s = raw;
        if ("mqtts".equals(target.getScheme().toLowerCase(Locale.ROOT))) {
            SSLSocket ssl = (SSLSocket) tls.createSocket(raw, host, port, true);
            Tls.handshake(ssl, host);
            s = ssl;
        }
        socket = s;
        try {
            OutputStream out = s.getOutputStream();
            DataInputStream in = new DataInputStream(s.getInputStream());
            String[] login = userInfo(target);
            s.setSoTimeout(CONNECT_TIMEOUT_MS);
            out.write(connectPacket(clientId, login[0], login[1], availabilityTopic, "offline", KEEPALIVE_S));
            out.flush();
            Packet ack = readPacket(in);
            if (ack.type != 2 || ack.body.length != 2) throw new IOException("the broker did not answer CONNECT");
            if (ack.body[1] != 0) throw new IOException("the broker refused: " + connackReason(ack.body[1]));
            connected = true;
            out.write(publishPacket(availabilityTopic, "online".getBytes(StandardCharsets.UTF_8), id(), true));
            out.write(subscribePacket(id(), commandTopic));
            out.flush();
            listener.onConnected(this);
            loop(s, in, out);
        } finally {
            connected = false;
            socket = null;
            try {
                s.close();
            } catch (IOException ignored) {
            }
        }
    }

    private void loop(Socket s, DataInputStream in, OutputStream out) throws IOException {
        Map<Integer, Message> unacked = new LinkedHashMap<>();
        long lastSent = System.currentTimeMillis();
        long waitingSince = 0;
        s.setSoTimeout(500);
        while (!stopped) {
            Message next = unacked.isEmpty() ? queue.pollFirst() : null;
            if (next != null) {
                int packetId = id();
                unacked.put(packetId, next);
                out.write(publishPacket(next.topic, next.payload, packetId, next.retain));
                out.flush();
                lastSent = System.currentTimeMillis();
                waitingSince = lastSent;
            }
            long now = System.currentTimeMillis();
            if (!unacked.isEmpty() && now - waitingSince > ACK_TIMEOUT_MS) {
                for (Message m : unacked.values()) queue.offerFirst(m);   // resend after reconnecting
                throw new IOException("no PUBACK from the broker");
            }
            if (now - lastSent > KEEPALIVE_S * 500L) {
                out.write(new byte[]{(byte) 0xC0, 0});            // PINGREQ
                out.flush();
                lastSent = now;
            }
            Packet p;
            try {
                p = readPacketWithin(s, in);
            } catch (SocketTimeoutException idle) {
                continue;
            }
            if (p.type == 4 && p.body.length == 2) {               // PUBACK
                unacked.remove(((p.body[0] & 0xFF) << 8) | (p.body[1] & 0xFF));
            } else if (p.type == 3) {                              // PUBLISH from our subscription
                String[] tp = parsePublish(p);
                if (tp != null && commandTopic.equals(tp[0])) listener.onCommand(tp[1]);
            }
        }
        out.write(new byte[]{(byte) 0xE0, 0});                     // DISCONNECT
        out.flush();
    }

    private int id() {
        int value = nextId;
        nextId = nextId >= 65535 ? 1 : nextId + 1;
        return value;
    }

    // ---------------------------------------------------------------------------------------------
    // Packets

    static final class Packet {
        final int type;
        final int flags;
        final byte[] body;

        Packet(int first, byte[] body) {
            this.type = (first >> 4) & 0x0F;
            this.flags = first & 0x0F;
            this.body = body;
        }
    }

    /** Reads the first byte with the short idle timeout, the rest with a long one, so a packet is never cut. */
    private static Packet readPacketWithin(Socket s, DataInputStream in) throws IOException {
        int first = in.read();
        if (first < 0) throw new IOException("the broker closed the connection");
        int old = s.getSoTimeout();
        s.setSoTimeout(ACK_TIMEOUT_MS);
        try {
            return new Packet(first, readBody(in));
        } finally {
            s.setSoTimeout(old);
        }
    }

    static Packet readPacket(InputStream stream) throws IOException {
        DataInputStream in = stream instanceof DataInputStream ? (DataInputStream) stream : new DataInputStream(stream);
        int first = in.read();
        if (first < 0) throw new IOException("the broker closed the connection");
        return new Packet(first, readBody(in));
    }

    private static byte[] readBody(DataInputStream in) throws IOException {
        int length = 0;
        for (int shift = 0; ; shift += 7) {
            if (shift > 21) throw new IOException("malformed packet length");
            int b = in.readUnsignedByte();
            length |= (b & 0x7F) << shift;
            if ((b & 0x80) == 0) break;
        }
        byte[] body = new byte[length];
        in.readFully(body);
        return body;
    }

    static byte[] remainingLength(int n) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        do {
            int b = n % 128;
            n /= 128;
            out.write(n > 0 ? b | 0x80 : b);
        } while (n > 0);
        return out.toByteArray();
    }

    private static void string(ByteArrayOutputStream out, String s) {
        byte[] data = s.getBytes(StandardCharsets.UTF_8);
        out.write(data.length >> 8);
        out.write(data.length & 0xFF);
        out.write(data, 0, data.length);
    }

    private static byte[] packet(int first, byte[] body) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(first);
        byte[] len = remainingLength(body.length);
        out.write(len, 0, len.length);
        out.write(body, 0, body.length);
        return out.toByteArray();
    }

    static byte[] connectPacket(String clientId, String user, String password, String willTopic, String willPayload,
                                int keepalive) {
        ByteArrayOutputStream body = new ByteArrayOutputStream();
        string(body, "MQTT");
        body.write(4);                                      // protocol level 3.1.1
        int flags = 0x02 | 0x04 | 0x20;                     // clean session, will, will retain (will QoS 0)
        if (user != null) flags |= 0x80;
        if (user != null && password != null) flags |= 0x40;
        body.write(flags);
        body.write(keepalive >> 8);
        body.write(keepalive & 0xFF);
        string(body, clientId);
        string(body, willTopic);
        string(body, willPayload);
        if (user != null) string(body, user);
        if (user != null && password != null) string(body, password);
        return packet(0x10, body.toByteArray());
    }

    static byte[] publishPacket(String topic, byte[] payload, int packetId, boolean retain) {
        ByteArrayOutputStream body = new ByteArrayOutputStream();
        string(body, topic);
        body.write(packetId >> 8);
        body.write(packetId & 0xFF);
        body.write(payload, 0, payload.length);
        return packet(0x30 | 0x02 | (retain ? 0x01 : 0), body.toByteArray());
    }

    static byte[] subscribePacket(int packetId, String topic) {
        ByteArrayOutputStream body = new ByteArrayOutputStream();
        body.write(packetId >> 8);
        body.write(packetId & 0xFF);
        string(body, topic);
        body.write(0);                                      // QoS 0: a command needs no acknowledgement
        return packet(0x82, body.toByteArray());
    }

    /** {topic, payload} of an incoming PUBLISH, or null when it is malformed. */
    static String[] parsePublish(Packet p) {
        if (p.body.length < 2) return null;
        int len = ((p.body[0] & 0xFF) << 8) | (p.body[1] & 0xFF);
        int offset = 2 + len + (((p.flags >> 1) & 3) > 0 ? 2 : 0);
        if (offset > p.body.length) return null;
        String topic = new String(p.body, 2, len, StandardCharsets.UTF_8);
        String payload = new String(p.body, offset, p.body.length - offset, StandardCharsets.UTF_8);
        return new String[]{topic, payload};
    }

    static String connackReason(int code) {
        switch (code) {
            case 1: return "protocol version refused";
            case 2: return "client id refused";
            case 3: return "broker unavailable";
            case 4: return "bad user name or password";
            case 5: return "not authorised";
            default: return "code " + code;
        }
    }

    /** {user, password} from the URL, percent-decoded; nulls when absent. */
    static String[] userInfo(URI uri) {
        String info = uri.getRawUserInfo();
        if (info == null || info.isEmpty()) return new String[]{null, null};
        int colon = info.indexOf(':');
        String user = colon < 0 ? info : info.substring(0, colon);
        String pass = colon < 0 ? null : info.substring(colon + 1);
        return new String[]{decode(user), pass == null ? null : decode(pass)};
    }

    private static String decode(String s) {
        try {
            return URLDecoder.decode(s.replace("+", "%2B"), "UTF-8");
        } catch (java.io.UnsupportedEncodingException impossible) {
            return s;
        }
    }
}
