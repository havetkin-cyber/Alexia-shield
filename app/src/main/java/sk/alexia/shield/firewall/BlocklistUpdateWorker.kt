package sk.alexia.shield.firewall

import android.content.Context
import androidx.work.Constraints
import androidx.work.CoroutineWorker
import androidx.work.ExistingPeriodicWorkPolicy
import androidx.work.ExistingWorkPolicy
import androidx.work.NetworkType
import androidx.work.OneTimeWorkRequestBuilder
import androidx.work.PeriodicWorkRequestBuilder
import androidx.work.WorkManager
import androidx.work.WorkerParameters
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.File
import java.net.HttpURLConnection
import java.net.URL
import java.util.concurrent.TimeUnit

/** Raz denne stiahne aktuálne zoznamy reklám, trackerov a phishingu. */
class BlocklistUpdateWorker(ctx: Context, params: WorkerParameters) : CoroutineWorker(ctx, params) {

    override suspend fun doWork(): Result = withContext(Dispatchers.IO) {
        val domains = HashSet<String>(200_000)
        var okSources = 0
        for (source in SOURCES) {
            runCatching {
                val conn = (URL(source).openConnection() as HttpURLConnection).apply {
                    connectTimeout = 15_000
                    readTimeout = 30_000
                }
                try {
                    conn.inputStream.bufferedReader().useLines { lines ->
                        lines.forEach { Blocklist.parseLine(it)?.let(domains::add) }
                    }
                    okSources++
                } finally {
                    conn.disconnect()
                }
            }
        }
        if (okSources == 0 || domains.isEmpty()) return@withContext Result.retry()

        val dir = applicationContext.filesDir
        val tmp = File(dir, "${Blocklist.FILE_NAME}.tmp")
        tmp.bufferedWriter().use { w -> domains.forEach { w.write(it); w.newLine() } }
        tmp.renameTo(File(dir, Blocklist.FILE_NAME))
        Blocklist.replace(domains)
        Result.success()
    }

    companion object {
        private val SOURCES = listOf(
            "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
            "https://phishing.army/download/phishing_army_blocklist.txt",
        )

        fun schedule(ctx: Context) {
            val request = PeriodicWorkRequestBuilder<BlocklistUpdateWorker>(1, TimeUnit.DAYS)
                .setConstraints(Constraints.Builder().setRequiredNetworkType(NetworkType.UNMETERED).build())
                .build()
            WorkManager.getInstance(ctx)
                .enqueueUniquePeriodicWork("blocklist_update", ExistingPeriodicWorkPolicy.KEEP, request)
        }

        fun runNow(ctx: Context) {
            val request = OneTimeWorkRequestBuilder<BlocklistUpdateWorker>()
                .setConstraints(Constraints.Builder().setRequiredNetworkType(NetworkType.CONNECTED).build())
                .build()
            WorkManager.getInstance(ctx)
                .enqueueUniqueWork("blocklist_now", ExistingWorkPolicy.REPLACE, request)
        }
    }
}
