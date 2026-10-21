package sk.alexia.shield.core

import android.content.Context
import android.content.SharedPreferences

enum class FirewallMode {
    /** Filtrovanie DNS pre všetky appky (reklamy, trackery, phishing). */
    DNS_FILTER,

    /** Úplné odrezanie internetu vybraným appkám. */
    BLOCK_APPS,
}

object Prefs {
    private const val FILE = "alexia_shield"

    private fun sp(ctx: Context): SharedPreferences =
        ctx.applicationContext.getSharedPreferences(FILE, Context.MODE_PRIVATE)

    fun linkScanEnabled(ctx: Context) = sp(ctx).getBoolean("link_scan", true)
    fun setLinkScanEnabled(ctx: Context, value: Boolean) =
        sp(ctx).edit().putBoolean("link_scan", value).apply()

    fun firewallMode(ctx: Context): FirewallMode =
        runCatching { FirewallMode.valueOf(sp(ctx).getString("fw_mode", null) ?: "") }
            .getOrDefault(FirewallMode.DNS_FILTER)

    fun setFirewallMode(ctx: Context, mode: FirewallMode) =
        sp(ctx).edit().putString("fw_mode", mode.name).apply()

    fun blockedApps(ctx: Context): Set<String> =
        sp(ctx).getStringSet("blocked_apps", emptySet())?.toSet() ?: emptySet()

    fun setBlockedApps(ctx: Context, packages: Set<String>) =
        sp(ctx).edit().putStringSet("blocked_apps", HashSet(packages)).apply()

    fun sensorAlertAlways(ctx: Context) = sp(ctx).getBoolean("sensor_alert_always", false)
    fun setSensorAlertAlways(ctx: Context, value: Boolean) =
        sp(ctx).edit().putBoolean("sensor_alert_always", value).apply()

    fun trackerCache(ctx: Context): SharedPreferences =
        ctx.applicationContext.getSharedPreferences("tracker_cache", Context.MODE_PRIVATE)

    fun malwareApiKey(ctx: Context): String = sp(ctx).getString("mb_key", "").orEmpty()
    fun setMalwareApiKey(ctx: Context, key: String) =
        sp(ctx).edit().putString("mb_key", key.trim()).apply()

    fun notifiedThreats(ctx: Context): Set<String> =
        sp(ctx).getStringSet("notified_threats", emptySet())?.toSet() ?: emptySet()
    fun setNotifiedThreats(ctx: Context, ids: Set<String>) =
        sp(ctx).edit().putStringSet("notified_threats", HashSet(ids)).apply()

    fun malwareCache(ctx: Context): SharedPreferences =
        ctx.applicationContext.getSharedPreferences("malware_cache", Context.MODE_PRIVATE)

    fun hashCache(ctx: Context): SharedPreferences =
        ctx.applicationContext.getSharedPreferences("hash_cache", Context.MODE_PRIVATE)

    fun heuristicsCache(ctx: Context): SharedPreferences =
        ctx.applicationContext.getSharedPreferences("heuristics_cache", Context.MODE_PRIVATE)

    fun realtimeEnabled(ctx: Context) = sp(ctx).getBoolean("realtime", true)
    fun setRealtimeEnabled(ctx: Context, value: Boolean) =
        sp(ctx).edit().putBoolean("realtime", value).apply()

    fun autoUpdate(ctx: Context) = sp(ctx).getBoolean("auto_update", true)
    fun setAutoUpdate(ctx: Context, value: Boolean) =
        sp(ctx).edit().putBoolean("auto_update", value).apply()

    fun lastNotifiedUpdate(ctx: Context) = sp(ctx).getInt("last_update_notified", 0)
    fun setLastNotifiedUpdate(ctx: Context, build: Int) =
        sp(ctx).edit().putInt("last_update_notified", build).apply()
}
