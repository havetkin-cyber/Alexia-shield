package sk.alexia.shield.audit

import android.content.Context
import sk.alexia.shield.core.Prefs
import java.util.zip.ZipFile

/**
 * Statická heuristika kódu: hľadá v DEX súboroch reťazce typické pre malvér
 * (bez spúšťania či dekompilácie). Jednotlivé znaky môžu mať aj legitímne appky,
 * preto sa hodnotí až ich kombinácia.
 */
object CodeHeuristics {

    data class Indicator(val id: String, val label: String, val points: Int)

    private class Rule(val id: String, val label: String, val points: Int, val all: List<String>)

    private val rules = listOf(
        Rule("miner", "Ťažba kryptomien (miner)", 45, listOf("stratum+tcp")),
        Rule("xmrig", "Ťažba kryptomien (XMRig)", 45, listOf("xmrig")),
        Rule("tg_exfil", "Posiela dáta cez Telegram bota", 20, listOf("api.telegram.org/bot")),
        Rule("sms_intercept", "Zachytáva a skrýva prichádzajúce SMS", 25,
            listOf("android.provider.Telephony.SMS_RECEIVED", "abortBroadcast")),
        Rule("sms_send", "Môže potajomky odosielať SMS", 10, listOf("sendTextMessage", "SmsManager")),
        Rule("lock_device", "Môže zamknúť telefón a zmeniť heslo (ransomvér)", 30,
            listOf("lockNow", "resetPassword")),
        Rule("device_admin", "Žiada o práva správcu zariadenia", 10, listOf("android.app.action.ADD_DEVICE_ADMIN")),
        Rule("a11y_automation", "Ovláda telefón cez prístupnosť (klikanie, gestá)", 15,
            listOf("dispatchGesture", "performGlobalAction")),
        Rule("hide_icon", "Vie skryť svoju ikonu", 10, listOf("setComponentEnabledSetting", "COMPONENT_ENABLED_STATE_DISABLED")),
        Rule("dyn_code", "Načítava kód stiahnutý za behu", 8, listOf("Ldalvik/system/DexClassLoader;")),
        Rule("root", "Pokúša sa získať root", 15, listOf("/system/xbin/su")),
        Rule("overlay_inject", "Kreslí okná cez iné appky", 5, listOf("TYPE_APPLICATION_OVERLAY")),
        Rule("keylog", "Číta písaný text z iných appiek", 15,
            listOf("TYPE_VIEW_TEXT_CHANGED", "getEventType")),
        Rule("vnc", "Vzdialené ovládanie / snímanie obrazovky", 15, listOf("createVirtualDisplay", "MediaProjection")),
    )

    private const val MAX_DEX_BYTES = 48L * 1024 * 1024
    private const val CACHE_VERSION = "h1"

    fun scanCached(ctx: Context, packageName: String, lastUpdate: Long, apkPaths: List<String>): List<Indicator> {
        val cache = Prefs.heuristicsCache(ctx)
        val key = "$CACHE_VERSION:$packageName@$lastUpdate"
        cache.getString(key, null)?.let { saved ->
            val ids = saved.split('|').filter { it.isNotBlank() }.toSet()
            return rules.filter { it.id in ids }.map { Indicator(it.id, it.label, it.points) }
        }
        val found = scan(apkPaths)
        cache.edit().putString(key, found.joinToString("|") { it.id }).apply()
        return found
    }

    fun scan(apkPaths: List<String>): List<Indicator> {
        // Pre každé pravidlo si pamätáme, ktoré jeho reťazce sme už videli (môžu byť v rôznych DEX)
        val seen = HashMap<String, MutableSet<String>>()
        for (path in apkPaths) {
            runCatching {
                ZipFile(path).use { zip ->
                    for (entry in zip.entries()) {
                        val name = entry.name
                        if (!name.startsWith("classes") || !name.endsWith(".dex")) continue
                        if (entry.size > MAX_DEX_BYTES) continue
                        val text = zip.getInputStream(entry).use { String(it.readBytes(), Charsets.ISO_8859_1) }
                        for (rule in rules) {
                            val got = seen.getOrPut(rule.id) { mutableSetOf() }
                            for (needle in rule.all) if (needle !in got && text.contains(needle)) got += needle
                        }
                    }
                }
            }
        }
        return rules.filter { r -> seen[r.id]?.size == r.all.size }.map { Indicator(it.id, it.label, it.points) }
    }

    /**
     * Celkové hodnotenie. Vracia null, ak kombinácia nie je podozrivá.
     * Prah 30 b. odfiltruje bežné appky, ktoré používajú 1–2 z týchto techník legitímne.
     */
    fun evaluate(indicators: List<Indicator>): Finding? {
        val total = indicators.sumOf { it.points }
        if (total < 30) return null
        val pts = when {
            total >= 70 -> 60
            total >= 45 -> 40
            else -> 25
        }
        return Finding("🧬 Podozrivý kód: " + indicators.sortedByDescending { it.points }.take(4).joinToString(", ") { it.label }, pts)
    }
}
