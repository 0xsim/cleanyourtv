package io.github.securetv.watchdog;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;

/** Starts watching at boot and after an update of the watchdog itself. */
public class BootReceiver extends BroadcastReceiver {
    @Override
    public void onReceive(Context context, Intent intent) {
        String action = intent.getAction();
        if (Intent.ACTION_BOOT_COMPLETED.equals(action) || Intent.ACTION_MY_PACKAGE_REPLACED.equals(action)) {
            WatchdogService.start(context);
        }
    }
}
