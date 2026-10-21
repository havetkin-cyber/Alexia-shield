package sk.alexia.shield.audit

import android.content.pm.PackageInfo
import android.os.Build
import java.io.ByteArrayInputStream
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.text.Normalizer

/** Heuristiky nad metadátami appky: falošné appky, skryté appky, podpis. */
object ThreatHeuristics {

    private class Brand(
        val name: String,
        val keywords: List<String>,
        val official: Set<String>,
        /** Pre bežné slová (signal, chrome…) musí názov appky znieť presne takto. */
        val exact: List<String> = emptyList(),
    )

    /**
     * Značky, za ktoré sa malvér najčastejšie vydáva. Kontroluje sa len pri appkách mimo obchodu,
     * takže pravá appka z Google Play nikdy nebude označená.
     */
    private val brands = listOf(
        Brand("WhatsApp", listOf("whatsapp"), setOf("com.whatsapp", "com.whatsapp.w4b")),
        Brand("Facebook", listOf("facebook"), setOf("com.facebook.katana", "com.facebook.lite")),
        Brand("Messenger", listOf("facebook messenger"), setOf("com.facebook.orca", "com.facebook.mlite"), exact = listOf("messenger")),
        Brand("Instagram", listOf("instagram"), setOf("com.instagram.android", "com.instagram.lite")),
        Brand("TikTok", listOf("tiktok"), setOf("com.zhiliaoapp.musically", "com.ss.android.ugc.trill", "com.zhiliaoapp.musically.go")),
        Brand("Telegram", listOf("telegram"), setOf("org.telegram.messenger", "org.telegram.messenger.web")),
        Brand("Signal", listOf("signal messenger", "signal private messenger"), setOf("org.thoughtcrime.securesms"), exact = listOf("signal")),
        Brand("Viber", listOf("viber"), setOf("com.viber.voip")),
        Brand("Snapchat", listOf("snapchat"), setOf("com.snapchat.android")),
        Brand("YouTube", listOf("youtube"), setOf("com.google.android.youtube", "com.google.android.apps.youtube.music")),
        Brand("Chrome", listOf("google chrome", "chrome update", "chrome browser"), setOf("com.android.chrome", "com.chrome.beta", "com.chrome.dev"), exact = listOf("chrome")),
        Brand("Netflix", listOf("netflix"), setOf("com.netflix.mediaclient")),
        Brand("Spotify", listOf("spotify"), setOf("com.spotify.music")),
        Brand("Google Play", listOf("google play", "play store", "play services"), setOf("com.android.vending", "com.google.android.gms")),
        Brand("PayPal", listOf("paypal"), setOf("com.paypal.android.p2pmobile")),
        Brand("Revolut", listOf("revolut"), setOf("com.revolut.revolut")),
        // Slovenské a české banky – pravé appky sa inštalujú z Google Play
        Brand("George (Slovenská sporiteľňa)", listOf("george slsp", "slovenska sporitelna", "sporitelna"), emptySet(), exact = listOf("george")),
        Brand("Tatra banka", listOf("tatra banka", "tatrabanka", "tatra banking"), emptySet()),
        Brand("VÚB", listOf("vub banka", "vub mobile", "vub wallet"), emptySet()),
        Brand("ČSOB", listOf("csob"), emptySet()),
        Brand("365.bank", listOf("365 bank", "365.bank"), emptySet()),
        Brand("mBank", listOf("mbank"), emptySet()),
        Brand("Prima banka", listOf("prima banka"), emptySet()),
        Brand("UniCredit", listOf("unicredit"), emptySet()),
        Brand("Fio banka", listOf("fio banka", "fio smartbanking"), emptySet()),
        Brand("Raiffeisen", listOf("raiffeisen"), emptySet()),
        Brand("Kurier/Pošta", listOf("dhl", "fedex", "packeta", "zasielkovna", "slovenska posta", "ceska posta"), emptySet(), exact = listOf("dpd", "gls")),
    )

    /** Názvy typické pre „droppery“ – appky, ktoré po inštalácii stiahnu skutočný malvér. */
    private val dropperNames = listOf(
        "flash player", "adobe flash", "system update", "android update", "aktualizacia systemu",
        "aktualizace systemu", "security update", "chrome update", "update service", "sledovanie zasielky",
        "sledovani zasilky", "voicemail", "hlasova schranka", "hlasova sprava",
    )

    fun impersonation(label: String, packageName: String, sideloaded: Boolean): Finding? {
        if (!sideloaded) return null
        val name = normalize(label)
        val brand = brands.firstOrNull { b ->
            (b.keywords.any { k -> containsWord(name, k) } || name in b.exact) && packageName !in b.official
        }
        if (brand != null) {
            return Finding("🎭 Možná falošná appka: vydáva sa za „${brand.name}“, ale nepochádza z obchodu", 50)
        }
        val dropper = dropperNames.firstOrNull { containsWord(name, it) }
        if (dropper != null) {
            return Finding("🎭 Podozrivý názov „$label“ – takto sa často maskuje malvér", 35)
        }
        return null
    }

    fun hiddenApp(hasLauncher: Boolean, sideloaded: Boolean): Finding? =
        if (sideloaded && !hasLauncher) Finding("👻 Appka nemá ikonu – beží skrytá", 20) else null

    fun debugSigned(p: PackageInfo, sideloaded: Boolean): Finding? {
        if (!sideloaded) return null
        val subject = signerSubject(p) ?: return null
        return if ("CN=Android Debug" in subject) {
            Finding("Podpísaná testovacím kľúčom vývojára (neoficiálna verzia)", 10)
        } else null
    }

    @Suppress("DEPRECATION")
    private fun signerSubject(p: PackageInfo): String? = runCatching {
        val bytes = if (Build.VERSION.SDK_INT >= 28) {
            p.signingInfo?.apkContentsSigners?.firstOrNull()?.toByteArray()
        } else {
            p.signatures?.firstOrNull()?.toByteArray()
        } ?: return null
        val cert = CertificateFactory.getInstance("X.509")
            .generateCertificate(ByteArrayInputStream(bytes)) as X509Certificate
        cert.subjectX500Principal.name
    }.getOrNull()

    private fun normalize(s: String): String =
        Normalizer.normalize(s.lowercase(), Normalizer.Form.NFD)
            .replace(Regex("\\p{Mn}+"), "")
            .replace(Regex("[^a-z0-9.]+"), " ")
            .trim()

    private fun containsWord(text: String, word: String): Boolean =
        Regex("(^|\\s)" + Regex.escape(word) + "($|\\s)").containsMatchIn(text)
}
