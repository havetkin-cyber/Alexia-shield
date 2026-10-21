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
}
