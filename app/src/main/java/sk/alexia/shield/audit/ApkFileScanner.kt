package sk.alexia.shield.audit

import android.content.Context
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.File

/** Kontrola APK súboru ešte pred inštaláciou (napr. stiahnutého z webu alebo z Telegramu). */
object ApkFileScanner {

    data class Verdict(
        val fileName: String,
        val appLabel: String?,
        val packageName: String?,
        val sha256: String,
        val malware: String?,
        val findings: List<Finding>,
        val error: String?,
    ) {
        val score: Int get() = if (malware != null) 100 else findings.sumOf { it.points }.coerceAtMost(100)
        val dangerous: Boolean get() = malware != null || score >= 50
    }

    suspend fun scan(ctx: Context, uri: Uri, fileName: String): Verdict = withContext(Dispatchers.IO) {
        val tmp = File(ctx.cacheDir, "scan.apk")
        try {
            ctx.contentResolver.openInputStream(uri)?.use { input ->
                tmp.outputStream().use { input.copyTo(it) }
            } ?: return@withContext Verdict(fileName, null, null, "", null, emptyList(), "Súbor sa nedá otvoriť")

            val sha = MalwareChecker.sha256(tmp)
            val findings = mutableListOf<Finding>()
            var malware: String? = null
            var error: String? = null
            when (val r = MalwareChecker.checkHash(ctx, sha)) {
                is MalwareChecker.Result.Malware -> {
                    malware = r.signature
                    findings += Finding("🦠 MALVÉR: ${r.signature} (databáza MalwareBazaar)", 100)
                }
                is MalwareChecker.Result.Error -> error = r.message
                MalwareChecker.Result.Clean -> Unit
            }

            val pm = ctx.packageManager
            @Suppress("DEPRECATION")
            val flags = PackageManager.GET_PERMISSIONS or PackageManager.GET_SERVICES or
                PackageManager.GET_RECEIVERS or
                (if (Build.VERSION.SDK_INT >= 28) PackageManager.GET_SIGNING_CERTIFICATES else PackageManager.GET_SIGNATURES)
            val info = runCatching { pm.getPackageArchiveInfo(tmp.path, flags) }.getOrNull()
            var label: String? = null
            if (info == null) {
                if (malware == null) findings += Finding("Súbor nie je platná Android appka", 0)
            } else {
                info.applicationInfo?.let { ai ->
                    ai.sourceDir = tmp.path
                    ai.publicSourceDir = tmp.path
                    label = runCatching { pm.getApplicationLabel(ai).toString() }.getOrNull()
                }
                val requested = info.requestedPermissions.orEmpty().toSet()
                ThreatHeuristics.impersonation(label ?: "", info.packageName, sideloaded = true)?.let { findings += it }
                ThreatHeuristics.debugSigned(info, sideloaded = true)?.let { findings += it }

                val a11y = info.services.orEmpty().any { it.permission == "android.permission.BIND_ACCESSIBILITY_SERVICE" }
                BankerDetector.evaluate(
                    BankerDetector.Signals(
                        accessibility = a11y,
                        accessibilityEnabled = false,
                        overlay = "android.permission.SYSTEM_ALERT_WINDOW" in requested,
                        sms = "android.permission.READ_SMS" in requested || "android.permission.RECEIVE_SMS" in requested,
                        deviceAdmin = info.receivers.orEmpty().any { it.permission == "android.permission.BIND_DEVICE_ADMIN" },
                        installsApps = "android.permission.REQUEST_INSTALL_PACKAGES" in requested,
                        sideloaded = true,
                    )
                )?.let { findings += Finding(it.text, it.points) }
                if (a11y) findings += Finding("Obsahuje službu prístupnosti – bude chcieť vidieť obsah obrazovky", 10)

                CodeHeuristics.evaluate(CodeHeuristics.scan(listOf(tmp.path)))?.let { findings += it }

                val risky = PermissionWeights.rules.filterKeys { it in requested }.values
                    .sortedByDescending { it.weight }.take(5)
                if (risky.isNotEmpty()) {
                    findings += Finding("Oprávnenia: " + risky.joinToString(", ") { it.label }, 0)
                }
            }
            Verdict(fileName, label, info?.packageName, sha, malware, findings.sortedByDescending { it.points }, error)
        } catch (e: Exception) {
            Verdict(fileName, null, null, "", null, emptyList(), "Kontrola zlyhala: ${e.message}")
        } finally {
            tmp.delete()
        }
    }
}
