package sk.alexia.shield.core

import android.app.AppOpsManager
import android.app.usage.UsageEvents
import android.app.usage.UsageStatsManager
import android.content.Context
import android.os.Build
import android.os.Process

/** Prístup k štatistikám využitia (Nastavenia › Prístup k využitiu). */
object UsageHelper {
    private const val DAY = 24L * 60 * 60 * 1000

    @Suppress("DEPRECATION")
    fun hasAccess(ctx: Context): Boolean {
        val aom = ctx.getSystemService(AppOpsManager::class.java)
        val mode = if (Build.VERSION.SDK_INT >= 29) {
            aom.unsafeCheckOpNoThrow(AppOpsManager.OPSTR_GET_USAGE_STATS, Process.myUid(), ctx.packageName)
        } else {
            aom.checkOpNoThrow(AppOpsManager.OPSTR_GET_USAGE_STATS, Process.myUid(), ctx.packageName)
        }
        return mode == AppOpsManager.MODE_ALLOWED
    }

    /** Balík → čas posledného použitia za posledných 180 dní. */
    fun lastUsedMap(ctx: Context): Map<String, Long> {
        if (!hasAccess(ctx)) return emptyMap()
        val usm = ctx.getSystemService(UsageStatsManager::class.java)
        val end = System.currentTimeMillis()
        return runCatching {
            usm.queryAndAggregateUsageStats(end - 180 * DAY, end)
                .mapValues { it.value.lastTimeUsed }
        }.getOrDefault(emptyMap())
    }

    /** Odhad appky v popredí za poslednú minútu (null bez prístupu). */
    @Suppress("DEPRECATION")
    fun foregroundApp(ctx: Context): String? {
        if (!hasAccess(ctx)) return null
        val usm = ctx.getSystemService(UsageStatsManager::class.java)
        val end = System.currentTimeMillis()
        return runCatching {
            val events = usm.queryEvents(end - 60_000, end)
            val e = UsageEvents.Event()
            var last: String? = null
            while (events.hasNextEvent()) {
                events.getNextEvent(e)
                if (e.eventType == UsageEvents.Event.MOVE_TO_FOREGROUND) last = e.packageName
            }
            last
        }.getOrNull()
    }
}
