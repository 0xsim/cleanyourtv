package io.github.securetv.watchdog;

import android.app.admin.DevicePolicyManager;
import android.content.ComponentName;
import android.content.ContentResolver;
import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.os.Build;
import android.provider.Settings;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/** Reads the TV's current state into a Snapshot. Read-only; call it off the main thread (it opens a socket). */
final class Probe {
    private Probe() {
    }

    static Snapshot read(Context context) {
        ContentResolver cr = context.getContentResolver();
        Map<String, String> settings = new HashMap<>();
        for (String key : Snapshot.KEYS) settings.put(key, setting(cr, key));
        return new Snapshot(settings, installedApps(context), admins(context), adbListening());
    }

    static String setting(ContentResolver cr, String key) {
        int slash = key.indexOf('/');
        String space = key.substring(0, slash), name = key.substring(slash + 1);
        try {
            switch (space) {
                case "global": return Settings.Global.getString(cr, name);
                case "secure": return Settings.Secure.getString(cr, name);
                case "prop": return property(name);
                default: return null;
            }
        } catch (RuntimeException unreadable) {
            return null;
        }
    }

    /** android.os.SystemProperties, which apps may read but the SDK does not expose. */
    static String property(String name) {
        try {
            Object value = Class.forName("android.os.SystemProperties").getMethod("get", String.class)
                    .invoke(null, name);
            return value == null ? null : value.toString();
        } catch (ReflectiveOperationException | RuntimeException e) {
            return null;
        }
    }

    /** Apps that are not part of the firmware, with the app that installed each one. */
    static Map<String, String> installedApps(Context context) {
        PackageManager pm = context.getPackageManager();
        Map<String, String> apps = new HashMap<>();
        List<ApplicationInfo> all;
        try {
            all = pm.getInstalledApplications(0);
        } catch (RuntimeException e) {
            return apps;
        }
        for (ApplicationInfo info : all) {
            if ((info.flags & ApplicationInfo.FLAG_SYSTEM) != 0) continue;
            apps.put(info.packageName, installer(pm, info.packageName));
        }
        return apps;
    }

    @SuppressWarnings("deprecation")
    static String installer(PackageManager pm, String pkg) {
        try {
            if (Build.VERSION.SDK_INT >= 30) {
                String name = pm.getInstallSourceInfo(pkg).getInstallingPackageName();
                return name == null ? "" : name;
            }
            String name = pm.getInstallerPackageName(pkg);
            return name == null ? "" : name;
        } catch (PackageManager.NameNotFoundException | RuntimeException e) {
            return "";
        }
    }

    static Set<String> admins(Context context) {
        Set<String> out = new LinkedHashSet<>();
        DevicePolicyManager dpm = context.getSystemService(DevicePolicyManager.class);
        if (dpm == null) return out;
        try {
            List<ComponentName> active = dpm.getActiveAdmins();
            if (active != null) for (ComponentName c : active) out.add(c.flattenToString());
        } catch (RuntimeException ignored) {
        }
        return out;
    }

    /** Whether adbd accepts TCP connections. A bare connect sends nothing, so it never prompts on the TV. */
    static boolean adbListening() {
        try (Socket s = new Socket()) {
            s.connect(new InetSocketAddress("127.0.0.1", Snapshot.ADB_PORT), 500);
            return true;
        } catch (IOException closed) {
            return false;
        }
    }

    static boolean holdsWriteSecureSettings(Context context) {
        return context.checkSelfPermission(android.Manifest.permission.WRITE_SECURE_SETTINGS)
                == PackageManager.PERMISSION_GRANTED;
    }
}
