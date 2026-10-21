package sk.alexia.shield.update

import android.app.PendingIntent
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.pm.PackageInstaller
import android.os.Build
import sk.alexia.shield.core.Notifications

/** Výsledok inštalácie aktualizácie. */
class UpdateStatusReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        when (intent.getIntExtra(PackageInstaller.EXTRA_STATUS, PackageInstaller.STATUS_FAILURE)) {
            PackageInstaller.STATUS_PENDING_USER_ACTION -> {
                @Suppress("DEPRECATION")
                val confirm: Intent = (if (Build.VERSION.SDK_INT >= 33) {
                    intent.getParcelableExtra(Intent.EXTRA_INTENT, Intent::class.java)
                } else {
                    intent.getParcelableExtra(Intent.EXTRA_INTENT)
                }) ?: return
                confirm.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                // Ak je appka otvorená, potvrdenie sa zobrazí hneď; inak cez notifikáciu
                runCatching { context.startActivity(confirm) }
                val pi = PendingIntent.getActivity(
                    context, 7, confirm, PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
                )
                Notifications.action(
                    context, NOTIF_ID, "Aktualizácia Alexia Shield je pripravená",
                    "Ťukni a potvrď inštaláciu. Ďalšie aktualizácie sa už nainštalujú samé.", pi,
                )
            }
            PackageInstaller.STATUS_SUCCESS -> Unit // appka sa reštartuje v novej verzii
            else -> {
                val msg = intent.getStringExtra(PackageInstaller.EXTRA_STATUS_MESSAGE) ?: "neznáma chyba"
                Notifications.alert(context, "Aktualizácia sa nepodarila", msg)
            }
        }
    }

    companion object {
        const val NOTIF_ID = 77
    }
}
