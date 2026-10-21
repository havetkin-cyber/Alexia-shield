package sk.alexia.shield.protection

import android.app.Service
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.ServiceInfo
import android.os.Build
import android.os.IBinder
import androidx.core.app.ServiceCompat
import androidx.core.content.ContextCompat
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import sk.alexia.shield.audit.PrivacyAuditor
import sk.alexia.shield.core.EventType
import sk.alexia.shield.core.Notifications
import sk.alexia.shield.core.Prefs
import sk.alexia.shield.core.Severity
import sk.alexia.shield.core.ShieldEvent
import sk.alexia.shield.core.ShieldLog

/**
 * Ochrana v reálnom čase: zachytí každú novú alebo aktualizovanú appku a hneď ju skontroluje
 * (databáza malvéru, bankové trójske kone, falošné appky, heuristika kódu).
 */
class RealtimeProtectionService : Service() {

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private var registered = false

    private val receiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context, intent: Intent) {
            val pkg = intent.data?.schemeSpecificPart ?: return
            if (pkg == packageName) return
            val replacing = intent.getBooleanExtra(Intent.EXTRA_REPLACING, false)
            // Pri aktualizácii prichádza ADDED aj REPLACED – stačí jedno
            if (intent.action == Intent.ACTION_PACKAGE_ADDED && replacing) return
            scope.launch { scanNewApp(pkg, isUpdate = intent.action == Intent.ACTION_PACKAGE_REPLACED) }
        }
    }

    private suspend fun scanNewApp(pkg: String, isUpdate: Boolean) {
        val risk = PrivacyAuditor.scanSingle(this, pkg) ?: return
        val verb = if (isUpdate) "Aktualizovaná" else "Nová"
        when {
            risk.malware != null -> {
                val title = "🦠 MALVÉR v appke ${risk.label}!"
                val detail = "${risk.malware}. Appku hneď odinštaluj a nič do nej nezadávaj."
                ShieldLog.add(ShieldEvent(System.currentTimeMillis(), EventType.MALWARE, Severity.DANGER, title, detail))
                Notifications.alert(this, title, detail, tab = "apps")
            }
            risk.threat != null -> {
                val title = "⚠️ Podozrivá appka: ${risk.label}"
                val detail = "${risk.threat}. " + risk.findings.take(2).joinToString("; ") { it.text }
                ShieldLog.add(ShieldEvent(System.currentTimeMillis(), EventType.MALWARE, Severity.WARNING, title, detail))
                Notifications.alert(this, title, detail, tab = "apps")
            }
            else -> {
                val title = "✅ $verb appka ${risk.label} je bez známych hrozieb"
                val detail = "Riziko súkromia ${risk.score}/100 (známka ${risk.grade})"
                ShieldLog.add(ShieldEvent(System.currentTimeMillis(), EventType.MALWARE, Severity.INFO, title, detail))
                if (!isUpdate) Notifications.info(this, title, detail, tab = "apps")
            }
        }
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val notification = Notifications.serviceNotification(
            this, "Ochrana v reálnom čase je zapnutá", "Kontrolujem každú novú appku", "apps"
        )
        val type = if (Build.VERSION.SDK_INT >= 34) ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE else 0
        ServiceCompat.startForeground(this, NOTIF_ID, notification, type)
        if (!registered) {
            val filter = IntentFilter().apply {
                addAction(Intent.ACTION_PACKAGE_ADDED)
                addAction(Intent.ACTION_PACKAGE_REPLACED)
                addDataScheme("package")
            }
            ContextCompat.registerReceiver(this, receiver, filter, ContextCompat.RECEIVER_EXPORTED)
            registered = true
        }
        _running.value = true
        return START_STICKY
    }

    override fun onDestroy() {
        if (registered) {
            runCatching { unregisterReceiver(receiver) }
            registered = false
        }
        scope.cancel()
        _running.value = false
        super.onDestroy()
    }

    override fun onBind(intent: Intent?): IBinder? = null

    companion object {
        private const val NOTIF_ID = 43
        private val _running = MutableStateFlow(false)
        val running: StateFlow<Boolean> = _running.asStateFlow()

        fun start(ctx: Context) {
            runCatching {
                ContextCompat.startForegroundService(ctx, Intent(ctx, RealtimeProtectionService::class.java))
            }
        }

        fun stop(ctx: Context) {
            ctx.stopService(Intent(ctx, RealtimeProtectionService::class.java))
        }

        /** Spustí ochranu, ak ju má používateľ zapnutú. */
        fun startIfEnabled(ctx: Context) {
            if (Prefs.realtimeEnabled(ctx)) start(ctx)
        }
    }
}
