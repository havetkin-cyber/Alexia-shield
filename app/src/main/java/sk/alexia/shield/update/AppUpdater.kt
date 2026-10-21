package sk.alexia.shield.update

import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.PackageInstaller
import android.content.pm.PackageManager
import android.os.Build
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.json.JSONObject
import java.io.File
import java.net.HttpURLConnection
import java.net.URL

/**
 * Automatické aktualizácie z GitHub Releases.
 *
 * Každý push na GitHub spustí build, ktorý vydá release `build-N` (N = číslo behu = versionCode).
 * Appka porovná N so svojou verziou, stiahne nové APK a nainštaluje ho cez PackageInstaller.
 * Od Androidu 12 sa aktualizácia nainštaluje bez potvrdenia, keď bola predošlá verzia
 * nainštalovaná samotnou Alexia Shield (prvá aktualizácia teda raz vyžiada potvrdenie).
 */
object AppUpdater {
    const val REPO = "havetkin-cyber/Alexia-shield"
    private const val API = "https://api.github.com/repos/$REPO/releases/latest"

    data class Release(val build: Int, val tag: String, val name: String, val apkUrl: String, val sizeBytes: Long)

    sealed class Check {
        data class Available(val release: Release) : Check()
        data object UpToDate : Check()
        data class Error(val message: String) : Check()
    }

    @Suppress("DEPRECATION")
    fun currentBuild(ctx: Context): Long = runCatching {
        val info = ctx.packageManager.getPackageInfo(ctx.packageName, 0)
        if (Build.VERSION.SDK_INT >= 28) info.longVersionCode else info.versionCode.toLong()
    }.getOrDefault(0L)

    fun currentVersionName(ctx: Context): String = runCatching {
        ctx.packageManager.getPackageInfo(ctx.packageName, 0).versionName
    }.getOrNull() ?: "?"

    fun canInstall(ctx: Context): Boolean = ctx.packageManager.canRequestPackageInstalls()

    suspend fun check(ctx: Context): Check = withContext(Dispatchers.IO) {
        runCatching {
            val conn = URL(API).openConnection() as HttpURLConnection
            val text = try {
                conn.connectTimeout = 10_000
                conn.readTimeout = 15_000
                conn.setRequestProperty("Accept", "application/vnd.github+json")
                conn.setRequestProperty("User-Agent", "AlexiaShield")
                if (conn.responseCode != 200) error("GitHub odpovedal ${conn.responseCode}")
                conn.inputStream.bufferedReader().use { it.readText() }
            } finally {
                conn.disconnect()
            }
            val json = JSONObject(text)
            val tag = json.optString("tag_name")
            val build = tag.removePrefix("build-").toIntOrNull() ?: error("Neznáma verzia $tag")
            val assets = json.optJSONArray("assets")
            var apk: JSONObject? = null
            for (i in 0 until (assets?.length() ?: 0)) {
                val a = assets!!.getJSONObject(i)
                if (a.optString("name").endsWith(".apk")) { apk = a; break }
            }
            apk ?: error("Release neobsahuje APK")
            val release = Release(
                build, tag, json.optString("name", tag),
                apk.getString("browser_download_url"), apk.optLong("size"),
            )
            if (build > currentBuild(ctx)) Check.Available(release) else Check.UpToDate
        }.getOrElse { Check.Error(it.message ?: "Kontrola aktualizácií zlyhala") }
    }

    /** Stiahne a spustí inštaláciu. Vráti chybu ako text, alebo null pri úspešnom spustení. */
    suspend fun downloadAndInstall(ctx: Context, release: Release): String? = withContext(Dispatchers.IO) {
        if (!canInstall(ctx)) return@withContext "Najprv povoľ Alexia Shield inštaláciu aktualizácií"
        val file = File(ctx.cacheDir, "update.apk")
        runCatching {
            val conn = URL(release.apkUrl).openConnection() as HttpURLConnection
            try {
                conn.instanceFollowRedirects = true
                conn.connectTimeout = 15_000
                conn.readTimeout = 60_000
                conn.setRequestProperty("User-Agent", "AlexiaShield")
                if (conn.responseCode != 200) error("Sťahovanie zlyhalo (${conn.responseCode})")
                conn.inputStream.use { input -> file.outputStream().use { input.copyTo(it) } }
            } finally {
                conn.disconnect()
            }
            if (release.sizeBytes > 0 && file.length() != release.sizeBytes) error("Stiahnutý súbor je neúplný")
            install(ctx, file)
            null
        }.getOrElse { file.delete(); it.message ?: "Aktualizácia zlyhala" }
    }

    private fun install(ctx: Context, apk: File) {
        val installer = ctx.packageManager.packageInstaller
        val params = PackageInstaller.SessionParams(PackageInstaller.SessionParams.MODE_FULL_INSTALL).apply {
            setAppPackageName(ctx.packageName)
            if (Build.VERSION.SDK_INT >= 31) {
                setRequireUserAction(PackageInstaller.SessionParams.USER_ACTION_NOT_REQUIRED)
            }
        }
        val sessionId = installer.createSession(params)
        installer.openSession(sessionId).use { session ->
            session.openWrite("alexia-shield.apk", 0, apk.length()).use { out ->
                apk.inputStream().use { it.copyTo(out) }
                session.fsync(out)
            }
            val flags = PendingIntent.FLAG_UPDATE_CURRENT or
                (if (Build.VERSION.SDK_INT >= 31) PendingIntent.FLAG_MUTABLE else 0)
            val status = PendingIntent.getBroadcast(
                ctx, sessionId, Intent(ctx, UpdateStatusReceiver::class.java), flags
            )
            session.commit(status.intentSender)
        }
        apk.delete()
    }
}
