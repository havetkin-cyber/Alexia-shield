package sk.alexia.shield.linkscan

import android.app.Notification
import android.service.notification.NotificationListenerService
import android.service.notification.StatusBarNotification
import sk.alexia.shield.core.EventType
import sk.alexia.shield.core.Notifications
import sk.alexia.shield.core.Prefs
import sk.alexia.shield.core.Severity
import sk.alexia.shield.core.ShieldEvent
import sk.alexia.shield.core.ShieldLog

/**
 * Číta text prichádzajúcich notifikácií (SMS, WhatsApp, Messenger, e-mail…)
 * a varuje pred podozrivými odkazmi. Nepotrebuje oprávnenie na SMS.
 */
class ShieldNotificationListener : NotificationListenerService() {

    private val recentAlerts = LinkedHashMap<String, Long>()

    override fun onNotificationPosted(sbn: StatusBarNotification) {
        if (sbn.packageName == packageName || sbn.isOngoing) return
        if (!Prefs.linkScanEnabled(this)) return

        val extras = sbn.notification.extras
        val text = buildString {
            append(extras.getCharSequence(Notification.EXTRA_TITLE) ?: "").append(' ')
            append(extras.getCharSequence(Notification.EXTRA_TEXT) ?: "").append(' ')
            append(extras.getCharSequence(Notification.EXTRA_BIG_TEXT) ?: "")
            extras.getCharSequenceArray(Notification.EXTRA_TEXT_LINES)?.forEach { append(' ').append(it) }
        }
        if (!text.contains('.')) return

        val worst = LinkAnalyzer.analyzeMessage(text).firstOrNull() ?: return
        if (worst.level == Severity.INFO) return

        val appLabel = runCatching {
            packageManager.getApplicationLabel(packageManager.getApplicationInfo(sbn.packageName, 0)).toString()
        }.getOrDefault(sbn.packageName)

        val key = "${sbn.packageName}|${worst.host}"
        val now = System.currentTimeMillis()
        synchronized(recentAlerts) {
            recentAlerts.entries.removeAll { now - it.value > 10 * 60_000 }
            if (recentAlerts.containsKey(key)) return
            recentAlerts[key] = now
        }

        val reasons = worst.reasons.take(2).joinToString("; ")
        ShieldLog.add(
            ShieldEvent(
                time = now,
                type = EventType.LINK,
                severity = worst.level,
                title = "${worst.host} (z appky $appLabel)",
                detail = "Riziko ${worst.score}/100 – $reasons",
            )
        )

        if (worst.level == Severity.DANGER) {
            Notifications.alert(
                this,
                title = "⚠️ Podozrivý odkaz v appke $appLabel",
                text = "${worst.host} – $reasons. Neklikaj naň a nezadávaj žiadne údaje.",
                tab = "links",
            )
        }
    }
}
