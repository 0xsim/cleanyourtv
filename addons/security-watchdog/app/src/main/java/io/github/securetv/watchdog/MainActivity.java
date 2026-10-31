package io.github.securetv.watchdog;

import android.app.Activity;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.graphics.Color;
import android.graphics.Typeface;
import android.graphics.drawable.GradientDrawable;
import android.os.Build;
import android.os.Bundle;
import android.util.TypedValue;
import android.view.Gravity;
import android.view.View;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;

import java.text.DateFormat;
import java.util.Date;
import java.util.List;

/** The watchdog's one screen: debugging status, the buttons that change it, and the newest events. */
public class MainActivity extends Activity {
    private LinearLayout status;
    private LinearLayout events;
    private Button closeButton;
    private Button extendButton;

    private final BroadcastReceiver changed = new BroadcastReceiver() {
        @Override
        public void onReceive(Context context, Intent intent) {
            refresh();
        }
    };

    @Override
    protected void onCreate(Bundle saved) {
        super.onCreate(saved);
        ScrollView scroll = new ScrollView(this);
        scroll.setBackgroundColor(Color.rgb(16, 18, 22));
        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        int pad = dp(48);
        root.setPadding(pad, dp(32), pad, dp(32));
        scroll.addView(root);

        TextView title = text(getString(R.string.app_name), 30, Color.WHITE);
        title.setTypeface(Typeface.DEFAULT_BOLD);
        root.addView(title);

        status = new LinearLayout(this);
        status.setOrientation(LinearLayout.VERTICAL);
        status.setPadding(0, dp(16), 0, dp(16));
        root.addView(status);

        LinearLayout buttons = new LinearLayout(this);
        buttons.setOrientation(LinearLayout.HORIZONTAL);
        closeButton = button(getString(R.string.button_close), WatchdogService.ACTION_CLOSE_ADB);
        extendButton = button(getString(R.string.button_extend), WatchdogService.ACTION_EXTEND);
        buttons.addView(closeButton);
        buttons.addView(extendButton);
        buttons.addView(button(getString(R.string.button_recheck), WatchdogService.ACTION_SWEEP));
        root.addView(buttons);

        TextView heading = text(getString(R.string.recent_events), 20, Color.rgb(200, 205, 215));
        heading.setPadding(0, dp(24), 0, dp(8));
        root.addView(heading);
        events = new LinearLayout(this);
        events.setOrientation(LinearLayout.VERTICAL);
        root.addView(events);

        setContentView(scroll);
        closeButton.requestFocus();
    }

    @Override
    protected void onResume() {
        super.onResume();
        WatchdogService.start(this);
        IntentFilter f = new IntentFilter(WatchdogService.STATUS_CHANGED);
        // The flag is ignored before Android 13; the three-argument form exists since Android 8.
        registerReceiver(changed, f, Context.RECEIVER_NOT_EXPORTED);
        refresh();
    }

    @Override
    protected void onPause() {
        unregisterReceiver(changed);
        super.onPause();
    }

    private void refresh() {
        Store store = new Store(getFilesDir());
        Config config;
        try {
            String text = store.read(ConfigProvider.NAME);
            config = text == null ? Config.defaults(Build.MODEL) : Config.parse(text, Build.MODEL);
        } catch (IllegalArgumentException e) {
            config = Config.defaults(Build.MODEL);
        }
        Snapshot s = store.snapshot();
        status.removeAllViews();
        if (s == null) {
            status.addView(text(getString(R.string.status_starting), 18, Color.LTGRAY));
        } else {
            boolean on = AutoClose.debuggingOn(s);
            StringBuilder adb = new StringBuilder();
            if (s.adbUsbOn()) adb.append(getString(R.string.adb_usb_on));
            if (s.adbWifiOn()) adb.append(adb.length() > 0 ? " · " : "").append(getString(R.string.adb_wireless_on));
            if (s.adbListening) adb.append(adb.length() > 0 ? " · " : "")
                    .append(getString(R.string.adb_network_on, Snapshot.ADB_PORT));
            row(getString(R.string.label_debugging), on ? adb.toString() : getString(R.string.adb_off),
                    on ? Color.rgb(255, 120, 110) : Color.rgb(120, 220, 150));
            Long left = AutoClose.minutesLeft(s, store.number(AutoClose.KEY_ON_SINCE, 0L), System.currentTimeMillis(),
                    config.adbAutocloseMinutes);
            String auto;
            if (config.adbAutocloseMinutes == 0) auto = getString(R.string.autoclose_disabled);
            else if (!Probe.holdsWriteSecureSettings(this)) auto = getString(R.string.autoclose_no_permission);
            else if (left == null) auto = getString(R.string.autoclose_idle, config.adbAutocloseMinutes);
            else auto = getString(R.string.autoclose_in, left);
            row(getString(R.string.label_autoclose), auto, Color.WHITE);
            String proxy = s.proxy();
            row(getString(R.string.label_network), (proxy.isEmpty() ? getString(R.string.no_proxy)
                    : getString(R.string.proxy, proxy)) + " · " + getString(R.string.private_dns, s.privateDns()),
                    proxy.isEmpty() ? Color.WHITE : Color.rgb(255, 120, 110));
            row(getString(R.string.label_apps), getString(R.string.apps_count, s.apps.size(),
                    s.components(Snapshot.A11Y).size()), Color.WHITE);
            closeButton.setEnabled(on);
            extendButton.setEnabled(on && config.adbAutocloseMinutes > 0);
        }
        String mqtt = config.mqtt == null ? getString(R.string.off)
                : store.number("mqtt_connected", 0L) == 1L ? getString(R.string.connected) : getString(R.string.not_connected);
        row(getString(R.string.label_reporting), getString(R.string.reporting, config.syslog.size(), mqtt), Color.WHITE);

        events.removeAllViews();
        List<SecurityEvent> recent = store.recent(25);
        if (recent.isEmpty()) events.addView(text(getString(R.string.no_events), 16, Color.LTGRAY));
        DateFormat when = DateFormat.getDateTimeInstance(DateFormat.SHORT, DateFormat.SHORT);
        for (SecurityEvent e : recent) {
            LinearLayout line = new LinearLayout(this);
            line.setOrientation(LinearLayout.HORIZONTAL);
            line.setGravity(Gravity.CENTER_VERTICAL);
            line.setPadding(0, dp(4), 0, dp(4));
            View dot = new View(this);
            GradientDrawable circle = new GradientDrawable();
            circle.setShape(GradientDrawable.OVAL);
            circle.setColor(color(e.severity));
            dot.setBackground(circle);
            LinearLayout.LayoutParams size = new LinearLayout.LayoutParams(dp(12), dp(12));
            size.setMarginEnd(dp(12));
            line.addView(dot, size);
            TextView t = text(when.format(new Date(e.timeMs)) + "   " + e.title, 16, Color.WHITE);
            line.addView(t);
            line.setFocusable(true);
            events.addView(line);
        }
    }

    private static int color(String severity) {
        switch (severity) {
            case SecurityEvent.HIGH: return Color.rgb(255, 90, 80);
            case SecurityEvent.MEDIUM: return Color.rgb(255, 175, 60);
            case SecurityEvent.LOW: return Color.rgb(240, 220, 90);
            default: return Color.rgb(130, 140, 160);
        }
    }

    private void row(String label, String value, int valueColor) {
        LinearLayout line = new LinearLayout(this);
        line.setOrientation(LinearLayout.HORIZONTAL);
        line.setPadding(0, dp(6), 0, dp(6));
        TextView l = text(label, 18, Color.rgb(160, 168, 180));
        line.addView(l, new LinearLayout.LayoutParams(dp(220), LinearLayout.LayoutParams.WRAP_CONTENT));
        line.addView(text(value, 18, valueColor));
        status.addView(line);
    }

    private Button button(String label, String action) {
        Button b = new Button(this);
        b.setText(label);
        b.setAllCaps(false);
        b.setOnClickListener(v -> {
            WatchdogService.send(this, action);
            v.postDelayed(this::refresh, 1500);
        });
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(LinearLayout.LayoutParams.WRAP_CONTENT,
                LinearLayout.LayoutParams.WRAP_CONTENT);
        lp.setMarginEnd(dp(16));
        b.setLayoutParams(lp);
        return b;
    }

    private TextView text(String s, int sp, int color) {
        TextView t = new TextView(this);
        t.setText(s);
        t.setTextSize(TypedValue.COMPLEX_UNIT_SP, sp);
        t.setTextColor(color);
        return t;
    }

    private int dp(int value) {
        return Math.round(value * getResources().getDisplayMetrics().density);
    }
}
