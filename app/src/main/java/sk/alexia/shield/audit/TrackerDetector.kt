package sk.alexia.shield.audit

import android.content.Context
import sk.alexia.shield.core.Prefs
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.util.zip.ZipFile

/**
 * Hľadá sledovacie SDK v DEX súboroch APK podľa prefixov tried
 * (rovnaký princíp ako Exodus Privacy). Číta tabuľku reťazcov DEX,
 * takže nespúšťa ani nedekompiluje kód.
 */
object TrackerDetector {

    private val signatures: List<Pair<String, String>> = listOf(
        "Lcom/google/firebase/analytics/" to "Firebase Analytics",
        "Lcom/google/android/gms/ads/" to "Google AdMob",
        "Lcom/google/firebase/crashlytics/" to "Firebase Crashlytics",
        "Lcom/crashlytics/" to "Crashlytics",
        "Lcom/facebook/ads/" to "Facebook Audience Network",
        "Lcom/facebook/appevents/" to "Facebook Analytics",
        "Lcom/appsflyer/" to "AppsFlyer",
        "Lcom/adjust/sdk/" to "Adjust",
        "Lcom/unity3d/ads/" to "Unity Ads",
        "Lcom/applovin/" to "AppLovin",
        "Lcom/ironsource/" to "ironSource",
        "Lcom/vungle/" to "Vungle",
        "Lcom/chartboost/" to "Chartboost",
        "Lcom/bytedance/sdk/openadsdk/" to "Pangle (ByteDance)",
        "Lcom/inmobi/" to "InMobi",
        "Lcom/startapp/" to "Start.io",
        "Lcom/mixpanel/" to "Mixpanel",
        "Lcom/amplitude/" to "Amplitude",
        "Lcom/flurry/" to "Flurry",
        "Lio/branch/" to "Branch",
        "Lcom/onesignal/" to "OneSignal",
        "Lcom/yandex/metrica/" to "Yandex AppMetrica",
        "Lcom/huawei/hms/analytics/" to "Huawei Analytics",
        "Lcom/moengage/" to "MoEngage",
        "Lcom/clevertap/" to "CleverTap",
        "Lcom/segment/analytics/" to "Segment",
    )

    private val sigBytes = signatures.map { it.first.toByteArray(Charsets.US_ASCII) to it.second }
    private const val MAX_DEX_BYTES = 64L * 1024 * 1024
    private const val CACHE_VERSION = "v1"

    fun scanCached(ctx: Context, packageName: String, lastUpdate: Long, apkPaths: List<String>): List<String> {
        val cache = Prefs.trackerCache(ctx)
        val key = "$CACHE_VERSION:$packageName@$lastUpdate"
        cache.getString(key, null)?.let { return if (it.isEmpty()) emptyList() else it.split('|') }
        val found = scan(apkPaths)
        cache.edit().putString(key, found.joinToString("|")).apply()
        return found
    }

    fun scan(apkPaths: List<String>): List<String> {
        val found = linkedSetOf<String>()
        for (path in apkPaths) {
            runCatching {
                ZipFile(path).use { zip ->
                    for (entry in zip.entries()) {
                        val name = entry.name
                        if (!name.startsWith("classes") || !name.endsWith(".dex")) continue
                        if (entry.size > MAX_DEX_BYTES) continue
                        val bytes = zip.getInputStream(entry).use { it.readBytes() }
                        scanDex(bytes, found)
                        if (found.size == signatures.size) return found.toList()
                    }
                }
            }
        }
        return found.toList()
    }

    private fun scanDex(dex: ByteArray, found: MutableSet<String>) {
        if (dex.size < 0x70) return
        val buf = ByteBuffer.wrap(dex).order(ByteOrder.LITTLE_ENDIAN)
        val count = buf.getInt(0x38)
        val idsOff = buf.getInt(0x3C)
        if (count <= 0 || idsOff <= 0 || idsOff.toLong() + count.toLong() * 4 > dex.size) return

        for (i in 0 until count) {
            var p = buf.getInt(idsOff + i * 4)
            if (p < 0 || p >= dex.size) continue
            // preskoč ULEB128 dĺžku reťazca
            while (p < dex.size && (dex[p].toInt() and 0x80) != 0) p++
            p++
            if (p >= dex.size || dex[p] != 'L'.code.toByte()) continue
            for ((sig, label) in sigBytes) {
                if (label in found) continue
                if (startsWith(dex, p, sig)) found += label
            }
        }
    }

    private fun startsWith(data: ByteArray, start: Int, prefix: ByteArray): Boolean {
        if (start + prefix.size > data.size) return false
        for (j in prefix.indices) if (data[start + j] != prefix[j]) return false
        return true
    }
}
