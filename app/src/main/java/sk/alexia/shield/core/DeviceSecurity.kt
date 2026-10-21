package sk.alexia.shield.core

import android.app.AppOpsManager
import android.app.KeyguardManager
import android.content.Context
import android.content.Intent
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.os.Build
import android.provider.Settings
import java.io.File
import java.text.SimpleDateFormat
import java.util.Locale
import java.util.concurrent.TimeUnit

/** Kontrola nastavení telefónu, ktoré rozhodujú o tom, ako ľahko sa doň malvér dostane. */
object DeviceSecurity {

    data class Check(
        val title: String,
        val ok: Boolean,
        val detail: String,
        /** Kam poslať používateľa na opravu (null = nedá sa opraviť v nastaveniach). */
        val fix: Intent? = null,
        val severe: Boolean = false,
    )

    fun run(ctx: Context): List<Check> = buildList {
        val km = ctx.getSystemService(KeyguardManager::class.java)
        val secure = km?.isDeviceSecure == true
        add(
            Check(
                "Zámok obrazovky", secure,
                if (secure) "PIN, heslo alebo vzor je nastavený" else "Telefón nemá zámok – ktokoľvek sa doň dostane",
                Intent(Settings.ACTION_SECURITY_SETTINGS), severe = !secure,
            )
        )

        val adb = Settings.Global.getInt(ctx.contentResolver, Settings.Global.ADB_ENABLED, 0) == 1
        add(
            Check(
                "USB ladenie", !adb,
                if (adb) "Zapnuté – cez kábel sa dá do telefónu nahrať čokoľvek" else "Vypnuté",
                Intent(Settings.ACTION_APPLICATION_DEVELOPMENT_SETTINGS),
            )
        )

        val dev = Settings.Global.getInt(ctx.contentResolver, Settings.Global.DEVELOPMENT_SETTINGS_ENABLED, 0) == 1
        add(
            Check(
                "Možnosti pre vývojárov", !dev,
                if (dev) "Zapnuté – ak ich nepotrebuješ, vypni ich" else "Vypnuté",
                Intent(Settings.ACTION_APPLICATION_DEVELOPMENT_SETTINGS),
            )
        )

        val patchAgeDays = runCatching {
            val patch = SimpleDateFormat("yyyy-MM-dd", Locale.US).parse(Build.VERSION.SECURITY_PATCH)!!
            TimeUnit.MILLISECONDS.toDays(System.currentTimeMillis() - patch.time)
        }.getOrNull()
        val patchOk = patchAgeDays != null && patchAgeDays <= 120
        add(
            Check(
                "Bezpečnostná aktualizácia", patchOk,
                "Záplata z ${Build.VERSION.SECURITY_PATCH}" + when {
                    patchAgeDays == null -> ""
                    patchAgeDays > 365 -> " – viac ako rok stará, telefón má známe diery"
                    patchAgeDays > 120 -> " – skontroluj aktualizácie systému"
                    else -> ""
                },
                Intent(Settings.ACTION_DEVICE_INFO_SETTINGS), severe = (patchAgeDays ?: 0) > 365,
            )
        )

        val rooted = listOf("/system/xbin/su", "/system/bin/su", "/sbin/su", "/system/app/Superuser.apk", "/data/adb/magisk")
            .any { File(it).exists() } || Build.TAGS?.contains("test-keys") == true
        add(
            Check(
                "Root", !rooted,
                if (rooted) "Telefón je rootnutý – malvér môže získať úplnú kontrolu" else "Nezistený",
                null, severe = rooted,
            )
        )

        val installers = appsAllowedToInstall(ctx)
        add(
            Check(
                "Inštalácia z neznámych zdrojov", installers.isEmpty(),
                if (installers.isEmpty()) "Žiadna appka nemôže inštalovať ďalšie appky"
                else "Povolené pre: " + installers.take(5).joinToString(", ") + if (installers.size > 5) "…" else "",
                if (Build.VERSION.SDK_INT >= 26) Intent(Settings.ACTION_MANAGE_UNKNOWN_APP_SOURCES) else null,
            )
        )
    }

    /** Appky, ktoré majú povolené inštalovať ďalšie appky (hlavná cesta malvéru do telefónu). */
    private fun appsAllowedToInstall(ctx: Context): List<String> {
        if (Build.VERSION.SDK_INT < 26) return emptyList()
        val pm = ctx.packageManager
        val ops = ctx.getSystemService(AppOpsManager::class.java) ?: return emptyList()
        @Suppress("DEPRECATION")
        val apps = runCatching { pm.getInstalledApplications(0) }.getOrDefault(emptyList())
        return apps.filter { ai ->
            if (ai.packageName == ctx.packageName) return@filter false
            if ((ai.flags and ApplicationInfo.FLAG_SYSTEM) != 0) return@filter false
            runCatching {
                val mode = if (Build.VERSION.SDK_INT >= 29) {
                    ops.unsafeCheckOpNoThrow("android:request_install_packages", ai.uid, ai.packageName)
                } else {
                    @Suppress("DEPRECATION")
                    ops.checkOpNoThrow("android:request_install_packages", ai.uid, ai.packageName)
                }
                mode == AppOpsManager.MODE_ALLOWED && requests(pm, ai.packageName)
            }.getOrDefault(false)
        }.map { runCatching { pm.getApplicationLabel(it).toString() }.getOrDefault(it.packageName) }
    }

    @Suppress("DEPRECATION")
    private fun requests(pm: PackageManager, pkg: String): Boolean = runCatching {
        pm.getPackageInfo(pkg, PackageManager.GET_PERMISSIONS).requestedPermissions
            ?.contains("android.permission.REQUEST_INSTALL_PACKAGES") == true
    }.getOrDefault(false)
}
