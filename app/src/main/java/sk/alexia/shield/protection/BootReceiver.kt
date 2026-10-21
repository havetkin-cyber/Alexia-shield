package sk.alexia.shield.protection

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent

/** Po reštarte telefónu alebo aktualizácii Alexia Shield znova zapne ochranu v reálnom čase. */
class BootReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        when (intent.action) {
            Intent.ACTION_BOOT_COMPLETED, Intent.ACTION_MY_PACKAGE_REPLACED ->
                RealtimeProtectionService.startIfEnabled(context)
        }
    }
}
