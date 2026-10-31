package io.github.securetv.watchdog;

import android.content.ContentProvider;
import android.content.ContentValues;
import android.database.Cursor;
import android.database.MatrixCursor;
import android.net.Uri;
import android.os.Build;
import android.os.Handler;
import android.os.Looper;
import android.os.ParcelFileDescriptor;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;

/**
 * The shell's way in, for install.sh and the host tools. Only callers holding WRITE_SECURE_SETTINGS
 * reach it (the manifest says so), which on a TV means ADB. No app can read or change anything here.
 *
 *   content write --uri content://io.github.securetv.watchdog.config/config.json   push a new config
 *   content query --uri content://io.github.securetv.watchdog.config/status        did it take?
 *   content query --uri content://io.github.securetv.watchdog.config/events        the newest events
 *
 * A pushed config is checked before it replaces the old one, so a typo never switches reporting off.
 */
public class ConfigProvider extends ContentProvider {
    static final String NAME = "config.json";
    private static final String INCOMING = "config.json.incoming";
    private static final String STATUS = "config_status.txt";

    @Override
    public ParcelFileDescriptor openFile(Uri uri, String mode) throws FileNotFoundException {
        if (!mode.contains("w") || !NAME.equals(uri.getLastPathSegment())) throw new FileNotFoundException(uri.toString());
        Store store = new Store(getContext().getFilesDir());
        File incoming = store.file(INCOMING);
        try {
            return ParcelFileDescriptor.open(incoming,
                    ParcelFileDescriptor.MODE_WRITE_ONLY | ParcelFileDescriptor.MODE_CREATE | ParcelFileDescriptor.MODE_TRUNCATE,
                    new Handler(Looper.getMainLooper()),
                    e -> {
                        if (e == null) accept(store, incoming);
                    });
        } catch (IOException e) {
            throw new FileNotFoundException(e.getMessage());
        }
    }

    private void accept(Store store, File incoming) {
        String text = store.read(INCOMING);
        //noinspection ResultOfMethodCallIgnored
        incoming.delete();
        if (text != null && install(store, text)) WatchdogService.send(getContext(), WatchdogService.ACTION_RELOAD);
    }

    /** Checks a pushed config and, only if it parses, makes it the one in use. Records the outcome. */
    static boolean install(Store store, String text) {
        try {
            Config.parse(text, Build.MODEL);
        } catch (IllegalArgumentException bad) {
            store.write(STATUS, "error: " + bad.getMessage());
            return false;
        }
        store.write(NAME, text);
        store.write(STATUS, "ok");
        return true;
    }

    /**
     * Android 8 and 9 have no `content write`, so install.sh copies config.json into the app's external
     * folder instead. Other apps with storage access can read that folder on those versions, so the file
     * is taken in and deleted as soon as the service starts or reloads.
     */
    static void importExternal(android.content.Context context, Store store) {
        File dir = context.getExternalFilesDir(null);
        if (dir == null) return;
        File pushed = new File(dir, NAME);
        if (!pushed.isFile()) return;
        try {
            String text = new String(java.nio.file.Files.readAllBytes(pushed.toPath()),
                    java.nio.charset.StandardCharsets.UTF_8);
            install(store, text);
        } catch (IOException e) {
            store.write(STATUS, "error: could not read the pushed config.json");
        } finally {
            //noinspection ResultOfMethodCallIgnored
            pushed.delete();
        }
    }

    @Override
    public Cursor query(Uri uri, String[] projection, String selection, String[] args, String sortOrder) {
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
    public Uri insert(Uri uri, ContentValues values) {
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
