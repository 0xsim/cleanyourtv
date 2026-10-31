package io.github.securetv.watchdog;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.Service;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.pm.PackageManager;
import android.content.pm.ServiceInfo;
import android.database.ContentObserver;
import android.net.Uri;
import android.os.Build;
import android.os.Handler;
import android.os.HandlerThread;
import android.os.IBinder;
import android.os.Looper;
import android.provider.Settings;
import android.util.Log;
import android.widget.Toast;

import java.io.IOException;
import java.net.URI;
import java.time.ZoneId;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import javax.net.ssl.SSLSocketFactory;

/**
 * Watches the TV's security settings, its apps and its debugging, and reports what changes: to its
 * own log, to syslog targets and to MQTT / Home Assistant. Switches debugging off when it has been on
 * longer than adb_autoclose_minutes, if install.sh granted WRITE_SECURE_SETTINGS.
 *
 * All work runs on one background thread, so the snapshot, the store and the outboxes are only ever
 * touched from there (the MQTT link has its own thread and only queues).
 */
public class WatchdogService extends Service implements MqttLink.Listener {
    static final String TAG = "SecurityWatchdog";
    static final String ACTION_SWEEP = "io.github.securetv.watchdog.SWEEP";
    static final String ACTION_CLOSE_ADB = "io.github.securetv.watchdog.CLOSE_ADB";
    static final String ACTION_EXTEND = "io.github.securetv.watchdog.EXTEND";
    static final String ACTION_RELOAD = "io.github.securetv.watchdog.RELOAD";
    static final String STATUS_CHANGED = "io.github.securetv.watchdog.STATUS";
    private static final String CHANNEL = "watchdog";
    private static final String ALERTS = "alerts";
    private static final long TICK_MS = 60_000L;
    private static final String KEY_UNAVAILABLE_FOR = "autoclose_unavailable_for";
    private static final String KEY_STUCK_FOR = "port_stuck_for";
    private static final String KEY_LAST_CLOSE = "last_close_ms";
    private static final String KEY_REOPENED_FOR = "reopened_for";

    private HandlerThread thread;
    private Handler worker;
    private final Handler main = new Handler(Looper.getMainLooper());
    private Store store;
    private Config config;
    private HomeAssistant ha;
    private MqttLink mqtt;
    private SSLSocketFactory tls;
    private Snapshot current;
    private SecurityEvent lastEvent;
    private String configText;
    private Set<String> sameSigner = new HashSet<>();
    private long lastFullSweep;
    private int alertId = 100;

    private ContentObserver observer;
    private final BroadcastReceiver packages = new BroadcastReceiver() {
        @Override
        public void onReceive(Context context, Intent intent) {
            worker.post(() -> sweep(true));
        }
    };
    private final Runnable tick = new Runnable() {
        @Override
        public void run() {
            boolean full = System.currentTimeMillis() - lastFullSweep >= config.sweepMinutes * 60_000L;
            sweep(full);
            flushSyslog();
            worker.postDelayed(this, TICK_MS);
        }
    };

    static void start(Context c) {
        send(c, null);
    }

    static void send(Context c, String action) {
        Intent i = new Intent(c, WatchdogService.class);
        if (action != null) i.setAction(action);
        try {
            c.startForegroundService(i);
        } catch (RuntimeException e) {
            // Android 12+ refuses a foreground start from the background; boot and the app's own screen start it.
            Log.w(TAG, "service not started: " + e.getMessage());
        }
    }

    @Override
    public void onCreate() {
        super.onCreate();
        NotificationManager nm = getSystemService(NotificationManager.class);
        nm.createNotificationChannel(new NotificationChannel(CHANNEL, getString(R.string.channel_name),
                NotificationManager.IMPORTANCE_MIN));
        nm.createNotificationChannel(new NotificationChannel(ALERTS, getString(R.string.alerts_channel_name),
                NotificationManager.IMPORTANCE_HIGH));
        Notification n = new Notification.Builder(this, CHANNEL)
                .setSmallIcon(R.drawable.ic_shield)
                .setContentTitle(getString(R.string.app_name))
                .setContentText(getString(R.string.notification_text))
                .setOngoing(true)
                .build();
        if (Build.VERSION.SDK_INT >= 34) startForeground(1, n, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE);
        else startForeground(1, n);

        store = new Store(getFilesDir());
        thread = new HandlerThread("watchdog");
        thread.start();
        worker = new Handler(thread.getLooper());
        worker.post(() -> {
            loadConfig();
            sweep(true);
            worker.postDelayed(tick, TICK_MS);
        });

        observer = new ContentObserver(worker) {
            @Override
            public void onChange(boolean selfChange, Uri uri) {
                sweep(false);
            }
        };
        for (String key : Snapshot.KEYS) {
            Uri uri = settingUri(key);
            if (uri != null) getContentResolver().registerContentObserver(uri, false, observer);
        }
        IntentFilter f = new IntentFilter();
        f.addAction(Intent.ACTION_PACKAGE_ADDED);
        f.addAction(Intent.ACTION_PACKAGE_REPLACED);
        f.addAction(Intent.ACTION_PACKAGE_FULLY_REMOVED);
        f.addDataScheme("package");
        // System broadcasts arrive whatever the flag; it is ignored before Android 13.
        registerReceiver(packages, f, Context.RECEIVER_NOT_EXPORTED);
    }

    private static Uri settingUri(String key) {
        String name = key.substring(key.indexOf('/') + 1);
        if (key.startsWith("global/")) return Settings.Global.getUriFor(name);
        if (key.startsWith("secure/")) return Settings.Secure.getUriFor(name);
        return null;   // properties have no observer; the minute tick reads them
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        String action = intent == null ? null : intent.getAction();
        if (action != null) {
            worker.post(() -> {
                switch (action) {
                    case ACTION_SWEEP: sweep(true); break;
                    case ACTION_CLOSE_ADB: closeAdb(getString(R.string.reason_button)); break;
                    case ACTION_EXTEND: extend(); break;
                    case ACTION_RELOAD: loadConfig(); sweep(true); break;
                    default: break;
                }
            });
        }
        return START_STICKY;
    }

    @Override
    public void onDestroy() {
        getContentResolver().unregisterContentObserver(observer);
        unregisterReceiver(packages);
        if (mqtt != null) mqtt.stop();
        thread.quitSafely();
        super.onDestroy();
    }

    @Override
    public IBinder onBind(Intent intent) {
        return null;
    }

    // ---------------------------------------------------------------------------------------------
    // Config and forwarders

    private void loadConfig() {
        String text = store.read(ConfigProvider.NAME);
        String problem = null;
        Config next = Config.defaults(Build.MODEL);
        if (text != null) {
            try {
                next = Config.parse(text, Build.MODEL);
            } catch (IllegalArgumentException e) {
                problem = e.getMessage();
            }
        }
        if (config != null && !java.util.Objects.equals(text, configText)) {
            // Tell the old targets before switching to new ones: whoever pushed this config (ADB only)
            // could be pointing the reports somewhere else, and the owner should hear about it.
            handle(Collections.singletonList(new SecurityEvent("config_changed", SecurityEvent.MEDIUM,
                    "The watchdog's config was changed", next.syslog.size() + " syslog target(s), MQTT "
                    + (next.mqtt == null ? "off" : "on") + ", auto-close " + next.adbAutocloseMinutes + " min",
                    null, System.currentTimeMillis())));
            if (mqtt != null) mqtt.drain(3_000L);
        }
        config = next;
        configText = text;
        ha = new HomeAssistant(config);
        try {
            tls = Tls.factory(config.caPem);
        } catch (IOException e) {
            tls = (SSLSocketFactory) SSLSocketFactory.getDefault();
            Log.w(TAG, "ca_pem not used: " + e.getMessage());
        }
        if (mqtt != null) mqtt.stop();
        mqtt = null;
        if (config.mqtt != null) {
            mqtt = new MqttLink(config.mqtt, "cleanyourtv-watchdog-" + config.slug(), ha.availabilityTopic(),
                    ha.commandTopic(), tls, this);
            new Thread(mqtt, "mqtt").start();
        }
        store.setNumber("mqtt_connected", 0L);
        if (problem != null) {
            handle(Collections.singletonList(new SecurityEvent("config_error", SecurityEvent.MEDIUM,
                    "config.json was not used", problem, null, System.currentTimeMillis())));
        }
    }

    private String version() {
        try {
            return getPackageManager().getPackageInfo(getPackageName(), 0).versionName;
        } catch (android.content.pm.PackageManager.NameNotFoundException e) {
            return "?";
        }
    }

    /**
     * The owner's apps: this one, the ones config.json names, and the ones signed with the same key as
     * this one (the launcher and add-ons built on the same computer). A package name alone is no proof:
     * any app may take a name that is not installed yet.
     */
    private Set<String> trusted() {
        Set<String> t = new HashSet<>(config.trusted);
        t.add(getPackageName());
        t.addAll(sameSigner);
        return t;
    }

    private Set<String> sameSigner(Snapshot s) {
        Set<String> out = new HashSet<>();
        android.content.pm.PackageManager pm = getPackageManager();
        for (String pkg : s.apps.keySet()) {
            try {
                if (pm.checkSignatures(getPackageName(), pkg) == android.content.pm.PackageManager.SIGNATURE_MATCH) {
                    out.add(pkg);
                }
            } catch (RuntimeException ignored) {
            }
        }
        return out;
    }

    @Override
    public void onConnected(MqttLink link) {
        for (String[] m : ha.discoveryMessages(Build.MODEL, version())) link.publish(m[0], m[1], true);
        worker.post(() -> {
            store.setNumber("mqtt_connected", 1L);
            publishState();
            broadcastStatus();
        });
    }

    @Override
    public void onCommand(String payload) {
        String command = payload.trim();
        if (HomeAssistant.CLOSE_ADB.equals(command)) {
            worker.post(() -> closeAdb(getString(R.string.reason_mqtt)));
        } else if (HomeAssistant.SWEEP.equals(command)) {
            worker.post(() -> sweep(true));
        }
        // Anything else is ignored: the command topic can only ever make the TV safer or re-check it.
    }

    @Override
    public void onDisconnected(Exception cause) {
        Log.i(TAG, "MQTT: " + cause.getMessage());
        worker.post(() -> {
            store.setNumber("mqtt_connected", 0L);
            broadcastStatus();
        });
    }

    // ---------------------------------------------------------------------------------------------
    // Watching

    private void sweep(boolean full) {
        if (config == null) return;
        long now = System.currentTimeMillis();
        Snapshot fresh = null;
        if (!full && current != null) {
            // Settings and the port only; the app list changes through the package broadcasts.
            java.util.Map<String, String> settings = new java.util.HashMap<>();
            for (String key : Snapshot.KEYS) settings.put(key, Probe.setting(getContentResolver(), key));
            fresh = new Snapshot(settings, current.apps, current.admins, Probe.adbListening());
            // A new holder of accessibility, notification access or the keyboard may be an app installed a
            // moment ago, before its install broadcast arrived: judge it against the real app list.
            if (holdersChanged(current, fresh)) fresh = null;
        }
        if (fresh == null) {
            fresh = Probe.read(this);
            sameSigner = sameSigner(fresh);
            lastFullSweep = now;
        }
        Snapshot before = current != null ? current : store.snapshot();
        List<SecurityEvent> events = before == null ? fresh.baseline(trusted(), now)
                : fresh.diffFrom(before, trusted(), now);
        current = fresh;
        store.saveSnapshot(fresh);
        handle(events);
        checkAutoClose(now);
        publishState();
        broadcastStatus();
    }

    private static boolean holdersChanged(Snapshot a, Snapshot b) {
        return !a.components(Snapshot.A11Y).equals(b.components(Snapshot.A11Y))
                || !a.components(Snapshot.LISTENERS).equals(b.components(Snapshot.LISTENERS))
                || !a.get(Snapshot.IME).equals(b.get(Snapshot.IME));
    }

    private void checkAutoClose(long now) {
        long since = AutoClose.onSince(current, store.number(AutoClose.KEY_ON_SINCE, 0L), now);
        store.setNumber(AutoClose.KEY_ON_SINCE, since);
        if (since == 0L) store.setNumber(KEY_UNAVAILABLE_FOR, 0L);
        long lastClose = store.number(KEY_LAST_CLOSE, 0L);
        if ((current.adbUsbOn() || current.adbWifiOn()) && lastClose > 0 && now - lastClose < 5 * 60_000L
                && now - lastClose > 2_000L && store.number(KEY_REOPENED_FOR, -1L) != lastClose) {
            store.setNumber(KEY_REOPENED_FOR, lastClose);
            handle(Collections.singletonList(new SecurityEvent("adb_reopened", SecurityEvent.HIGH,
                    "Debugging came back on right after the watchdog closed it",
                    "Something on the TV switches it back on: the firmware, or an app holding "
                    + "WRITE_SECURE_SETTINGS. The watchdog tries again after the full timeout, not sooner.",
                    null, now)));
        }
        if (AutoClose.remainingMs(current, since, now, config.adbAutocloseMinutes) != 0L) return;
        if (!current.adbUsbOn() && !current.adbWifiOn()) {
            // Both switches are off and the port still answers: nothing an app can switch. Say so once.
            if (store.number(KEY_STUCK_FOR, -1L) != since) {
                store.setNumber(KEY_STUCK_FOR, since);
                handle(Collections.singletonList(new SecurityEvent("adb_port_stuck", SecurityEvent.HIGH,
                        "Port " + Snapshot.ADB_PORT + " still answers with debugging off",
                        "Reboot the TV. If it stays open, the firmware keeps network ADB on "
                        + "(tools/security_audit.py shows persist.adb.tcp.port).", null, now)));
            }
            return;
        }
        closeAdb(getString(R.string.reason_timer, config.adbAutocloseMinutes));
    }

    /** Switches every form of debugging off. Only does anything with WRITE_SECURE_SETTINGS. */
    private void closeAdb(String reason) {
        long now = System.currentTimeMillis();
        if (!Probe.holdsWriteSecureSettings(this)) {
            long since = store.number(AutoClose.KEY_ON_SINCE, 0L);
            if (store.number(KEY_UNAVAILABLE_FOR, -1L) != since) {
                store.setNumber(KEY_UNAVAILABLE_FOR, since);
                handle(Collections.singletonList(new SecurityEvent("adb_close_unavailable", SecurityEvent.MEDIUM,
                        "Debugging could not be switched off", "The watchdog lacks WRITE_SECURE_SETTINGS: run "
                        + "addons/security-watchdog/install.sh again, or switch debugging off yourself.", null, now)));
            }
            return;
        }
        try {
            Settings.Global.putInt(getContentResolver(), "adb_wifi_enabled", 0);
            Settings.Global.putInt(getContentResolver(), Settings.Global.ADB_ENABLED, 0);
        } catch (SecurityException e) {
            handle(Collections.singletonList(new SecurityEvent("adb_close_failed", SecurityEvent.MEDIUM,
                    "Debugging could not be switched off", e.getMessage(), null, now)));
            return;
        }
        // Restart the clock, so a firmware that turns debugging straight back on gets one attempt per
        // timeout rather than one a minute.
        store.setNumber(AutoClose.KEY_ON_SINCE, now);
        store.setNumber(KEY_LAST_CLOSE, now);
        handle(Collections.singletonList(new SecurityEvent("adb_closed", SecurityEvent.INFO,
                "Debugging switched off by the watchdog", reason, null, now)));
        worker.postDelayed(() -> sweep(false), 3_000L);
    }

    private void extend() {
        long now = System.currentTimeMillis();
        store.setNumber(AutoClose.KEY_ON_SINCE, now);
        handle(Collections.singletonList(new SecurityEvent("adb_extended", SecurityEvent.INFO,
                getString(R.string.extended_title, config.adbAutocloseMinutes), "", null, now)));
        publishState();
        broadcastStatus();
    }

    // ---------------------------------------------------------------------------------------------
    // Reporting

    private void handle(List<SecurityEvent> events) {
        if (events.isEmpty() || config == null) return;
        store.log(events, config.deviceName);
        for (SecurityEvent e : events) {
            if (lastEvent == null || e.atLeast(lastEvent.severity) || e.timeMs - lastEvent.timeMs > 3_600_000L) {
                lastEvent = e;
            }
            if (mqtt != null) mqtt.publish(ha.eventTopic(), e.toJson(config.deviceName).toString(), false);
            if (!"off".equals(config.onScreenAlerts) && e.atLeast(config.onScreenAlerts)) alert(e);
        }
        for (URI target : config.syslog) {
            List<String> lines = new ArrayList<>();
            boolean rfc5424 = SyslogSender.rfc5424(target);
            for (SecurityEvent e : events) {
                lines.add(SyslogSender.format(e.toJson(config.deviceName), e.severity, config.deviceName, e.timeMs,
                        ZoneId.systemDefault(), rfc5424));
            }
            store.queue(target.toString(), lines);
        }
        flushSyslog();
    }

    private void flushSyslog() {
        for (URI target : config.syslog) {
            List<String> pending = store.pending(target.toString());
            if (pending.isEmpty()) continue;
            try {
                SyslogSender.send(target, pending, tls);
                store.sent(target.toString(), pending.size());
            } catch (IOException | RuntimeException e) {
                Log.i(TAG, "syslog " + Config.redact(target.toString()) + ": " + e.getMessage());
            }
        }
    }

    private void publishState() {
        if (mqtt == null || current == null) return;
        Long left = AutoClose.minutesLeft(current, store.number(AutoClose.KEY_ON_SINCE, 0L),
                System.currentTimeMillis(), config.adbAutocloseMinutes);
        mqtt.publish(ha.stateTopic(), HomeAssistant.state(current, left, lastEvent, System.currentTimeMillis()).toString(),
                true);
    }

    private void alert(SecurityEvent e) {
        main.post(() -> Toast.makeText(this, getString(R.string.alert_toast, e.title), Toast.LENGTH_LONG).show());
        Notification n = new Notification.Builder(this, ALERTS)
                .setSmallIcon(R.drawable.ic_shield)
                .setContentTitle(e.title)
                .setContentText(e.detail)
                .setStyle(new Notification.BigTextStyle().bigText(e.detail))
                .setAutoCancel(true)
                .build();
        // Android 13+ shows it only with POST_NOTIFICATIONS, which install.sh grants; the toast shows either way.
        if (Build.VERSION.SDK_INT < 33
                || checkSelfPermission(android.Manifest.permission.POST_NOTIFICATIONS) == PackageManager.PERMISSION_GRANTED) {
            getSystemService(NotificationManager.class).notify(alertId++, n);
            if (alertId > 150) alertId = 100;
        }
    }

    private void broadcastStatus() {
        sendBroadcast(new Intent(STATUS_CHANGED).setPackage(getPackageName()));
    }
}
