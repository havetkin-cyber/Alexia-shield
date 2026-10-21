package sk.alexia.shield.update

import android.content.Context
import androidx.work.Constraints
import androidx.work.CoroutineWorker
import androidx.work.ExistingPeriodicWorkPolicy
import androidx.work.NetworkType
import androidx.work.PeriodicWorkRequestBuilder
import androidx.work.WorkManager
import androidx.work.WorkerParameters
import sk.alexia.shield.core.Notifications
import sk.alexia.shield.core.Prefs
import java.util.concurrent.TimeUnit

/** Každých 6 hodín skontroluje GitHub a nainštaluje novú verziu. */
class UpdateWorker(ctx: Context, params: WorkerParameters) : CoroutineWorker(ctx, params) {

    override suspend fun doWork(): Result {
        val ctx = applicationContext
        val check = AppUpdater.check(ctx)
        if (check !is AppUpdater.Check.Available) return Result.success()
        val release = check.release
        if (Prefs.autoUpdate(ctx) && AppUpdater.canInstall(ctx)) {
            val error = AppUpdater.downloadAndInstall(ctx, release)
            if (error != null) return Result.retry()
        } else if (Prefs.lastNotifiedUpdate(ctx) != release.build) {
            Prefs.setLastNotifiedUpdate(ctx, release.build)
            Notifications.info(
                ctx, "Dostupná nová verzia Alexia Shield",
                "${release.name} – otvor Prehľad a ťukni na Aktualizovať.", tab = "overview",
            )
        }
        return Result.success()
    }

    companion object {
        fun schedule(ctx: Context) {
            val request = PeriodicWorkRequestBuilder<UpdateWorker>(6, TimeUnit.HOURS)
                .setConstraints(Constraints.Builder().setRequiredNetworkType(NetworkType.CONNECTED).build())
                .build()
            WorkManager.getInstance(ctx)
                .enqueueUniquePeriodicWork("app_update", ExistingPeriodicWorkPolicy.KEEP, request)
        }
    }
}
