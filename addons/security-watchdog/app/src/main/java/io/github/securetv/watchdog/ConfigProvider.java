package io.github.securetv.watchdog;

import android.content.ContentProvider;
import android.content.ContentValues;
import android.database.Cursor;
import android.database.MatrixCursor;
import android.net.Uri;
import android.os.Binder;
import android.os.Build;
import android.util.Base64;

import java.nio.charset.StandardCharsets;

/**
 * The shell's way in, for install.sh and the host tools:
 *
 *   content insert --uri content://io.github.securetv.watchdog.config/config --bind b64:s:<base64 of config.json>
 *   content query  --uri content://io.github.securetv.watchdog.config/status
 *   content query  --uri content://io.github.securetv.watchdog.config/events
 *
 * Two locks: the manifest requires WRITE_SECURE_SETTINGS, and every call checks that the caller is the
 * shell (ADB) or root. The second matters because other apps can hold WRITE_SECURE_SETTINGS too (vendor
 * system apps, or an add-on that install.sh granted it to). `content insert` exists on every Android
 * this app runs on, unlike `content write`, so no version needs a file in shared storage.
 *
 * A pushed config is checked before it replaces the old one, so a typo never switches reporting off.
 */
public class ConfigProvider extends ContentProvider {
    static final String NAME = "config.json";
    private static final String STATUS = "config_status.txt";
    private static final int SHELL_UID = 2000;
    private static final int ROOT_UID = 0;

    private static void requireShell() {
        int uid = Binder.getCallingUid();
        if (uid != SHELL_UID && uid != ROOT_UID) throw new SecurityException("only ADB may use this provider");
    }

    @Override
    public Uri insert(Uri uri, ContentValues values) {
        requireShell();
        if (!"config".equals(uri.getLastPathSegment()) || values == null) return null;
        String b64 = values.getAsString("b64");
        Store store = new Store(getContext().getFilesDir());
        String text;
        try {
            text = new String(Base64.decode(b64 == null ? "" : b64, Base64.DEFAULT), StandardCharsets.UTF_8);
        } catch (IllegalArgumentException e) {
            store.write(STATUS, "error: the config was not valid base64");
            return null;
        }
        if (install(store, text)) WatchdogService.send(getContext(), WatchdogService.ACTION_RELOAD);
        return uri;
    }

    /** Checks a pushed config and, only if it parses, makes it the one in use. Records the outcome. */
    static boolean install(Store store, String text) {
        try {
            Config.parse(text, Build.MODEL);
        } catch (IllegalArgumentException bad) {
            store.write(STATUS, "error: " + bad.getMessage());   // Config's messages never carry a password
            return false;
        }
        store.write(NAME, text);
        store.write(STATUS, "ok");
        return true;
    }

    @Override
    public Cursor query(Uri uri, String[] projection, String selection, String[] args, String sortOrder) {
        requireShell();
        Store store = new Store(getContext().getFilesDir());
        String what = uri.getLastPathSegment();
        if ("status".equals(what)) {
            MatrixCursor c = new MatrixCursor(new String[]{"result"});
            String status = store.read(STATUS);
            c.addRow(new Object[]{status == null ? "no config pushed yet" : status.trim()});
            return c;
        }
        if ("events".equals(what)) {
            MatrixCursor c = new MatrixCursor(new String[]{"time", "severity", "event", "title", "package"});
            for (SecurityEvent e : store.recent(50)) {
                c.addRow(new Object[]{Iso.format(e.timeMs), e.severity, e.type, e.title, e.packageName});
            }
            return c;
        }
        return null;
    }

    @Override
    public boolean onCreate() {
        return true;
    }

    @Override
    public String getType(Uri uri) {
        return null;
    }

    @Override
    public int update(Uri uri, ContentValues values, String selection, String[] args) {
        return 0;
    }

    @Override
    public int delete(Uri uri, String selection, String[] args) {
        return 0;
    }
}
