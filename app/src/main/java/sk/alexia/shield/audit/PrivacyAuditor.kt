package sk.alexia.shield.audit

import android.app.admin.DevicePolicyManager
import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.os.Build
import android.provider.Settings
import androidx.core.app.NotificationManagerCompat
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import sk.alexia.shield.core.EventType
import sk.alexia.shield.core.Notifications
import sk.alexia.shield.core.Prefs
import sk.alexia.shield.core.Severity
import sk.alexia.shield.core.ShieldEvent
import sk.alexia.shield.core.ShieldLog
import sk.alexia.shield.core.UsageHelper
import kotlin.math.roundToInt

data class Finding(val text: String, val points: Int)

data class AppRisk(
    val packageName: String,
    val label: String,
    /** 0 = bez rizika, 100 = maximálne riziko. */
    val score: Int,
    val findings: List<Finding>,
    val trackers: List<String>,
    val isSystem: Boolean,
    /** Názov malvéru z MalwareBazaar, ak sa odtlačok appky našiel v databáze. */
    val malware: String? = null,
    /** Appka má kombináciu schopností typickú pre bankové trójske kone. */
    val banker: Boolean = false,
) {
    val grade: Char get() = PrivacyAuditor.grade(score)
}

data class DeviceReport(
    val apps: List<AppRisk>,
    /** 0–100, vyššie = lepšie chránený telefón. */
    val protectionScore: Int,
    val scannedAt: Long,
    /** Počet appiek overených v MalwareBazaar (0 = kontrola neprebehla). */
    val malwareChecked: Int = 0,
    /** Chyba antivírusovej kontroly (napr. neplatný kľúč), inak null. */
    val malwareError: String? = null,
)

object PrivacyAuditor {
    private const val DAY = 24L * 60 * 60 * 1000

    private val trustedInstallers = setOf(
        "com.android.vending", "com.sec.android.app.samsungapps", "com.huawei.appmarket",
        "com.amazon.venezia", "org.fdroid.fdroid", "com.xiaomi.market", "com.heytap.market",
        "com.oppo.market", "com.google.android.feedback",
    )

    /** Appky, ktoré by nemali potrebovať takmer žiadne citlivé oprávnenia. */
    private val lightweightHints = listOf(
        "flashlight", "torch", "svietidl", "baterk", "calculator", "kalkul", "compass", "kompas",
        "qrscan", "qr_scan", "qrcode", "qrreader", "wallpaper", "tapet", "ringtone", "vyzvan",
    )

    fun grade(score: Int): Char = when {
        score <= 10 -> 'A'
        score <= 25 -> 'B'
        score <= 40 -> 'C'
        score <= 60 -> 'D'
        score <= 80 -> 'E'
        else -> 'F'
    }

    suspend fun scan(
        ctx: Context,
        includeSystem: Boolean,
        checkMalware: Boolean = true,
        onProgress: (done: Int, total: Int) -> Unit = { _, _ -> },
    ): DeviceReport = withContext(Dispatchers.IO) {
        val pm = ctx.packageManager
        val packages = installedPackages(pm, PackageManager.GET_PERMISSIONS)
        val hasUsage = UsageHelper.hasAccess(ctx)
        val lastUsed = UsageHelper.lastUsedMap(ctx)
        val enabledA11y = Settings.Secure.getString(
            ctx.contentResolver, Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES
        ).orEmpty()
        val enabledListeners = NotificationManagerCompat.getEnabledListenerPackages(ctx)
        val activeAdmins = runCatching {
            ctx.getSystemService(DevicePolicyManager::class.java)?.activeAdmins
                ?.map { it.packageName }?.toSet()
        }.getOrNull().orEmpty()

        val candidates = packages.filter { p ->
            val ai = p.applicationInfo
            ai != null && p.packageName != ctx.packageName && (includeSystem || !isSystem(ai))
        }

        // Antivírusová kontrola len pre appky, ktoré si používateľ nainštaloval sám
        val malwareTargets = if (checkMalware && MalwareChecker.hasKey(ctx)) {
            candidates.filter { !isSystem(it.applicationInfo!!) }.map { it.packageName }.toSet()
        } else emptySet()
        val total = candidates.size + malwareTargets.size

        val audited = candidates.mapIndexed { index, p ->
            onProgress(index + 1, total)
            auditPackage(ctx, pm, p, hasUsage, lastUsed, enabledA11y, enabledListeners, activeAdmins)
        }

        var checked = 0
        var malwareError: String? = null
        val byPackage = candidates.associateBy { it.packageName }
        val results = audited.map { risk ->
            if (risk.packageName !in malwareTargets || malwareError != null) return@map risk
            onProgress(candidates.size + checked + 1, total)
            val ai = byPackage.getValue(risk.packageName).applicationInfo!!
            val apks = listOfNotNull(ai.sourceDir) + ai.splitSourceDirs.orEmpty()
            when (val r = MalwareChecker.check(
                ctx, risk.packageName, byPackage.getValue(risk.packageName).lastUpdateTime, apks
            )) {
                is MalwareChecker.Result.Clean -> { checked++; risk }
                is MalwareChecker.Result.Malware -> {
                    checked++
                    val text = "🦠 MALVÉR: ${r.signature} (databáza MalwareBazaar)" +
                        if (r.tags.isNotEmpty()) " – " + r.tags.take(3).joinToString(", ") else ""
                    risk.copy(
                        score = 100,
                        malware = r.signature,
                        findings = listOf(Finding(text, 100)) + risk.findings,
                    )
                }
                is MalwareChecker.Result.Error -> { malwareError = r.message; risk }
            }
        }.sortedWith(compareByDescending<AppRisk> { it.malware != null }.thenByDescending { it.score })

        notifyThreats(ctx, results)

        val protection = if (results.isEmpty()) 100 else {
            val avg = results.map { it.score }.average()
            val worst = results.first().score
            (100 - (avg * 0.6 + worst * 0.4)).roundToInt().coerceIn(0, 100)
        }
        DeviceReport(results, protection, System.currentTimeMillis(), checked, malwareError)
    }

    /** Upozorní na nové nálezy malvéru a bankových trójskych koní (každý len raz). */
    private fun notifyThreats(ctx: Context, results: List<AppRisk>) {
        val already = Prefs.notifiedThreats(ctx)
        val current = mutableSetOf<String>()
        results.forEach { app ->
            val id = when {
                app.malware != null -> "M:${app.packageName}"
                app.banker -> "B:${app.packageName}"
                else -> return@forEach
            }
            current += id
            if (id in already) return@forEach
            val title = if (app.malware != null) "🦠 Nájdený malvér: ${app.label}"
            else "⚠️ Podozrivá appka: ${app.label}"
            val detail = if (app.malware != null) "${app.malware} – odporúčame appku hneď odinštalovať."
            else "Má schopnosti typické pre bankové trójske kone. Ak ju nepoznáš, odinštaluj ju."
            ShieldLog.add(
                ShieldEvent(
                    System.currentTimeMillis(), EventType.MALWARE,
                    if (app.malware != null || app.findings.any { it.points >= 60 }) Severity.DANGER else Severity.WARNING,
                    title, detail,
                )
            )
            Notifications.alert(ctx, title, detail, tab = "apps")
        }
        // Zabudni na odinštalované appky, aby sa pri opätovnej inštalácii znova upozornilo
        Prefs.setNotifiedThreats(ctx, current)
    }

    private fun auditPackage(
        ctx: Context,
        pm: PackageManager,
        p: PackageInfo,
        hasUsage: Boolean,
        lastUsed: Map<String, Long>,
        enabledA11y: String,
        enabledListeners: Set<String>,
        activeAdmins: Set<String>,
    ): AppRisk {
        val ai = p.applicationInfo!!
        val label = runCatching { pm.getApplicationLabel(ai).toString() }.getOrDefault(p.packageName)
        val findings = mutableListOf<Finding>()

        // 1) Oprávnenia × nesúlad s typom appky
        val nameKey = (p.packageName + " " + label).lowercase()
        val lightweight = lightweightHints.any { it in nameKey }
        val expected = if (lightweight) emptySet() else PermissionWeights.expectedGroups(ai.category)

        val requested = p.requestedPermissions.orEmpty()
        val flags = p.requestedPermissionsFlags
        // Oprávnenia sa nesčitujú lineárne: appka typu WhatsApp ich má veľa a väčšina je pre ňu normálna.
        // Bežné oprávnenia idú do „klesajúceho“ súčtu (max. ~35 b.), nesúlad pri jednoduchých appkách
        // (baterka s kontaktmi…) sa pripočíta zvlášť (max. 30 b.).
        data class PermHit(val text: String, val raw: Double, val lightMismatch: Boolean)
        val permHits = mutableListOf<PermHit>()
        requested.forEachIndexed { i, perm ->
            val rule = PermissionWeights.rules[perm] ?: return@forEachIndexed
            val granted = flags != null && i < flags.size &&
                (flags[i] and PackageInfo.REQUESTED_PERMISSION_GRANTED) != 0
            val mismatch = expected != null && rule.group !in expected
            val normal = expected != null && rule.group in expected
            var pts = rule.weight.toDouble()
            if (!granted) pts *= 0.3
            pts *= when {
                mismatch && lightweight -> 2.5
                mismatch -> 1.5
                normal -> 0.25
                else -> 0.6 // kategória neznáma
            }
            val text = buildString {
                append(rule.label)
                if (!granted) append(" (nepovolené)")
                if (mismatch) append(" – nesedí s typom appky")
                else if (normal) append(" – bežné pre tento typ appky")
            }
            permHits += PermHit(text, pts, mismatch && lightweight)
        }
        val poolRaw = permHits.filterNot { it.lightMismatch }.sumOf { it.raw }
        val lightRaw = permHits.filter { it.lightMismatch }.sumOf { it.raw }
        val poolScore = 35.0 * (1 - kotlin.math.exp(-poolRaw / 60.0))
        val lightScore = minOf(30.0, lightRaw * 0.5)
        permHits.forEach { h ->
            val share = if (h.lightMismatch) {
                if (lightRaw > 0) h.raw / lightRaw * lightScore else 0.0
            } else {
                if (poolRaw > 0) h.raw / poolRaw * poolScore else 0.0
            }
            val rounded = share.roundToInt()
            if (rounded >= 1) findings += Finding(h.text, rounded)
        }

        // 2) Silné systémové služby
        val detail = runCatching {
            packageInfo(pm, p.packageName, PackageManager.GET_SERVICES or PackageManager.GET_RECEIVERS)
        }.getOrNull()
        detail?.services?.forEach { s ->
            when (s.permission) {
                "android.permission.BIND_ACCESSIBILITY_SERVICE" -> {
                    val on = enabledA11y.contains(p.packageName + "/")
                    findings += if (on) Finding("Služba prístupnosti je ZAPNUTÁ – vidí obsah obrazovky", 30)
                    else Finding("Obsahuje službu prístupnosti (vypnutú)", 8)
                }
                "android.permission.BIND_NOTIFICATION_LISTENER_SERVICE" -> {
                    val on = p.packageName in enabledListeners
                    findings += if (on) Finding("Číta všetky notifikácie (zapnuté)", 15)
                    else Finding("Môže čítať notifikácie (vypnuté)", 5)
                }
                "android.permission.BIND_VPN_SERVICE" -> findings += Finding("Obsahuje VPN službu", 6)
            }
        }
        detail?.receivers?.forEach { r ->
            if (r.permission == "android.permission.BIND_DEVICE_ADMIN") {
                findings += Finding("Môže sa stať správcom zariadenia", 20)
            }
        }

        // 3) Pôvod inštalácie
        var sideloaded = false
        if (!isSystem(ai)) {
            val installer = installerOf(pm, p.packageName)
            if (installer !in trustedInstallers) {
                sideloaded = true
                findings += Finding(
                    "Nainštalovaná mimo obchodu" + (installer?.let { " ($it)" } ?: ""), 10
                )
            }
        }

        // 4) Nepoužívané appky
        if (hasUsage) {
            val ref = maxOf(lastUsed[p.packageName] ?: 0L, p.firstInstallTime)
            if (System.currentTimeMillis() - ref >= 90 * DAY) {
                findings += Finding("Nepoužitá aspoň 90 dní – zváž odinštalovanie", 5)
            }
        }

        // 5) Sledovacie SDK
        val apks = listOfNotNull(ai.sourceDir) + ai.splitSourceDirs.orEmpty()
        val trackers = TrackerDetector.scanCached(ctx, p.packageName, p.lastUpdateTime, apks)
        if (trackers.isNotEmpty()) {
            findings += Finding("Sledovacie SDK: ${trackers.size}", (trackers.size * 5).coerceAtMost(25))
        }

        // 6) Bankový trójsky kôň
        var banker = false
        if (!isSystem(ai)) {
            val a11yServices = detail?.services.orEmpty()
                .filter { it.permission == "android.permission.BIND_ACCESSIBILITY_SERVICE" }
            val signals = BankerDetector.Signals(
                accessibility = a11yServices.isNotEmpty(),
                accessibilityEnabled = enabledA11y.contains(p.packageName + "/"),
                overlay = "android.permission.SYSTEM_ALERT_WINDOW" in requested,
                sms = "android.permission.READ_SMS" in requested || "android.permission.RECEIVE_SMS" in requested,
                deviceAdmin = p.packageName in activeAdmins ||
                    detail?.receivers.orEmpty().any { it.permission == "android.permission.BIND_DEVICE_ADMIN" },
                installsApps = "android.permission.REQUEST_INSTALL_PACKAGES" in requested,
                sideloaded = sideloaded,
            )
            BankerDetector.evaluate(signals)?.let { v ->
                banker = true
                findings += Finding(v.text, v.points)
            }
        }

        val unique = findings.distinctBy { it.text }.sortedByDescending { it.points }
        return AppRisk(
            packageName = p.packageName,
            label = label,
            score = unique.sumOf { it.points }.coerceAtMost(100),
            findings = unique,
            trackers = trackers,
            isSystem = isSystem(ai),
            banker = banker,
        )
    }

    fun isSystem(ai: ApplicationInfo): Boolean =
        (ai.flags and (ApplicationInfo.FLAG_SYSTEM or ApplicationInfo.FLAG_UPDATED_SYSTEM_APP)) != 0

    @Suppress("DEPRECATION")
    private fun installedPackages(pm: PackageManager, flags: Int): List<PackageInfo> =
        if (Build.VERSION.SDK_INT >= 33) {
            pm.getInstalledPackages(PackageManager.PackageInfoFlags.of(flags.toLong()))
        } else {
            pm.getInstalledPackages(flags)
        }

    @Suppress("DEPRECATION")
    private fun packageInfo(pm: PackageManager, pkg: String, flags: Int): PackageInfo =
        if (Build.VERSION.SDK_INT >= 33) {
            pm.getPackageInfo(pkg, PackageManager.PackageInfoFlags.of(flags.toLong()))
        } else {
            pm.getPackageInfo(pkg, flags)
        }

    @Suppress("DEPRECATION")
    private fun installerOf(pm: PackageManager, pkg: String): String? = runCatching {
        if (Build.VERSION.SDK_INT >= 30) pm.getInstallSourceInfo(pkg).installingPackageName
        else pm.getInstallerPackageName(pkg)
    }.getOrNull()
}
