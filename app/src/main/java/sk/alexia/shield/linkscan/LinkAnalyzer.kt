package sk.alexia.shield.linkscan

import android.net.Uri
import sk.alexia.shield.core.Severity
import sk.alexia.shield.firewall.Blocklist
import java.text.Normalizer

data class LinkVerdict(
    val url: String,
    val host: String,
    /** 0–100, vyššie = podozrivejšie. */
    val score: Int,
    val reasons: List<String>,
) {
    val level: Severity
        get() = when {
            score >= 50 -> Severity.DANGER
            score >= 25 -> Severity.WARNING
            else -> Severity.INFO
        }
}

/** Lokálna heuristická analýza odkazov (smishing / phishing). Nič neodosiela na internet. */
object LinkAnalyzer {

    private val suspiciousTlds = setOf(
        "top", "xyz", "click", "link", "live", "shop", "online", "site", "icu", "buzz", "rest",
        "cfd", "sbs", "cyou", "monster", "vip", "win", "bond", "lol", "quest", "support", "info",
    )

    private val shorteners = setOf(
        "bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "cutt.ly", "rb.gy", "ow.ly",
        "shorturl.at", "t.ly", "s.id", "tiny.cc", "rebrand.ly", "buff.ly", "bitly.com",
    )

    /** Značka → oficiálne domény. */
    private val brands: Map<String, List<String>> = mapOf(
        "paypal" to listOf("paypal.com", "paypal.me"),
        "dpd" to listOf("dpd.sk", "dpd.com", "dpd.cz", "dpdgroup.com"),
        "posta" to listOf("posta.sk", "ceskaposta.cz", "postaonline.cz"),
        "packeta" to listOf("packeta.sk", "packeta.com", "packeta.cz"),
        "zasielkovna" to listOf("zasielkovna.sk"),
        "zasilkovna" to listOf("zasilkovna.cz"),
        "dhl" to listOf("dhl.com", "dhl.sk", "dhl.cz", "dhl.de"),
        "slsp" to listOf("slsp.sk"),
        "tatrabanka" to listOf("tatrabanka.sk"),
        "vub" to listOf("vub.sk"),
        "csob" to listOf("csob.sk", "csob.cz"),
        "revolut" to listOf("revolut.com", "revolut.me"),
        "apple" to listOf("apple.com", "icloud.com"),
        "icloud" to listOf("icloud.com", "apple.com"),
        "microsoft" to listOf("microsoft.com", "live.com", "microsoftonline.com"),
        "netflix" to listOf("netflix.com"),
        "amazon" to listOf("amazon.com", "amazon.de", "amazon.co.uk", "amazonaws.com"),
        "facebook" to listOf("facebook.com", "fb.com"),
        "instagram" to listOf("instagram.com"),
        "whatsapp" to listOf("whatsapp.com", "whatsapp.net"),
        "financnasprava" to listOf("financnasprava.sk"),
        "socpoist" to listOf("socpoist.sk"),
    )

    /** Kľúčové slová bez diakritiky. */
    private val scamKeywords = listOf(
        "balik", "zasielk", "zasilk", "doplat", "colny", "clo ", "overte", "overit", "overenie",
        "zablokovan", "pozastaven", "obmedzen", "vyhral", "vyhra", "kliknite", "posledna vyzva",
        "vratenie", "preplatok", "platba zlyhala", "aktualizujte", "nezaplaten", "urgent",
        "package", "parcel", "delivery", "verify", "suspended", "refund", "prize", "account locked",
    )

    private const val URL_CHARS = """[^\s<>"'()\[\]{}]"""
    private val schemeUrl = Regex("""(?i)\b(?:https?://|www\.)$URL_CHARS+""")
    private val bareWithPath = Regex(
        """(?i)(?<![@\w.-])(?:[\p{L}\p{N}](?:[\p{L}\p{N}-]{0,61}[\p{L}\p{N}])?\.)+\p{L}{2,24}/$URL_CHARS*"""
    )
    private val bareSuspicious = Regex(
        """(?i)(?<![@\w.-])(?:[\p{L}\p{N}](?:[\p{L}\p{N}-]{0,61}[\p{L}\p{N}])?\.)+(?:""" +
            suspiciousTlds.joinToString("|") + """)\b"""
    )
    private val ipv4 = Regex("""^\d{1,3}(\.\d{1,3}){3}$""")
    private val hasScheme = Regex("""(?i)^[a-z][a-z0-9+.-]*://""")

    fun extractUrls(text: String): List<String> {
        val found = mutableListOf<String>()
        var rest = text
        for (re in listOf(schemeUrl, bareWithPath, bareSuspicious)) {
            re.findAll(rest).forEach { found += it.value.trimEnd('.', ',', ';', ':', '!', '?') }
            rest = re.replace(rest, " ")
        }
        return found.filter { it.isNotBlank() }.distinct()
    }

    fun analyzeMessage(text: String): List<LinkVerdict> =
        extractUrls(text).map { analyzeUrl(it, text) }.sortedByDescending { it.score }

    fun analyzeUrl(url: String, messageText: String = ""): LinkVerdict {
        val full = if (hasScheme.containsMatchIn(url)) url else "http://$url"
        val uri = Uri.parse(full)
        val host = (uri.host ?: "").lowercase().trimEnd('.')
        if (host.isEmpty()) return LinkVerdict(url, host, 0, emptyList())

        var score = 0
        val reasons = mutableListOf<String>()
        fun add(points: Int, reason: String) {
            score += points
            reasons += reason
        }

        if (ipv4.matches(host) || host.startsWith("[")) add(40, "IP adresa namiesto domény")
        if (host.contains("xn--")) add(45, "Punycode doména (možné falošné znaky)")
        if (host.any { it.code > 127 }) add(45, "Neštandardné znaky v doméne")
        if (uri.encodedAuthority?.contains('@') == true) add(35, "Klamlivý odkaz so znakom @")

        val registrable = registrableDomain(host)
        if (registrable in shorteners) add(25, "Skrátený odkaz – skutočný cieľ je skrytý")

        val tld = host.substringAfterLast('.')
        if (tld in suspiciousTlds) add(20, "Riziková koncovka .$tld")

        impersonatedBrand(host)?.let { add(45, "Napodobňuje značku ${it.replaceFirstChar(Char::uppercase)}") }

        if (host.split('.').size > 4) add(10, "Neobvykle veľa subdomén")
        if (host.count { it == '-' } >= 3) add(10, "Veľa pomlčiek v doméne")
        if (url.startsWith("http://", ignoreCase = true)) add(10, "Nešifrované spojenie (http)")
        if (Blocklist.isBlocked(host)) add(50, "Doména je na blokovacom zozname")

        val keywords = matchedKeywords(messageText)
        if (keywords.isNotEmpty()) {
            add(
                (keywords.size * 8).coerceAtMost(24),
                "Text správy pôsobí podvodne (" + keywords.take(3).joinToString(", ") + ")"
            )
        }

        return LinkVerdict(url, host, score.coerceAtMost(100), reasons)
    }

    private fun impersonatedBrand(host: String): String? {
        val labels = host.split('.').dropLast(1)
        for ((brand, official) in brands) {
            if (labels.none { it.contains(brand) }) continue
            val isOfficial = official.any { host == it || host.endsWith(".$it") }
            if (!isOfficial) return brand
        }
        return null
    }

    private fun registrableDomain(host: String): String {
        val parts = host.split('.')
        if (parts.size <= 2) return host
        val secondLevel = parts[parts.size - 2]
        return if (secondLevel in setOf("co", "com", "org", "net", "gov", "ac", "edu") && parts.size >= 3) {
            parts.takeLast(3).joinToString(".")
        } else {
            parts.takeLast(2).joinToString(".")
        }
    }

    private fun matchedKeywords(text: String): List<String> {
        if (text.isBlank()) return emptyList()
        val normalized = normalize(text)
        return scamKeywords.filter { normalized.contains(it) }.map { it.trim() }
    }

    private fun normalize(s: String): String =
        Normalizer.normalize(s.lowercase(), Normalizer.Form.NFD).replace(Regex("\\p{Mn}+"), "")
}
