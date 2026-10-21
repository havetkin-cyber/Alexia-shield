package sk.alexia.shield.audit

import android.content.Context
import androidx.work.Constraints
import androidx.work.CoroutineWorker
import androidx.work.ExistingPeriodicWorkPolicy
import androidx.work.PeriodicWorkRequestBuilder
import androidx.work.WorkManager
import androidx.work.WorkerParameters
import java.util.concurrent.TimeUnit

/**
 * Raz denne na pozadí prejde appky: hľadá bankové trójske kone a (s kľúčom)
 * overí nové alebo aktualizované appky v MalwareBazaar. Nálezy oznámi notifikáciou.
 */
class ThreatScanWorker(ctx: Context, params: WorkerParameters) : CoroutineWorker(ctx, params) {

    override suspend fun doWork(): Result {
        PrivacyAuditor.scan(applicationContext, includeSystem = false)
        return Result.success()
    }

    companion object {
        fun schedule(ctx: Context) {
            val request = PeriodicWorkRequestBuilder<ThreatScanWorker>(1, TimeUnit.DAYS)
                .setConstraints(Constraints.Builder().setRequiresBatteryNotLow(true).build())
                .build()
            WorkManager.getInstance(ctx)
                .enqueueUniquePeriodicWork("threat_scan", ExistingPeriodicWorkPolicy.KEEP, request)
        }
    }
}
