package sk.alexia.shield.firewall

import android.content.Context
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import java.io.File
import kotlin.concurrent.thread

/** Zoznam blokovaných domén v pamäti (formát hosts alebo jedna doména na riadok). */
object Blocklist {
    const val FILE_NAME = "blocklist.txt"

    @Volatile
    private var domains: Set<String> = emptySet()

    private val _size = MutableStateFlow(0)
    val size: StateFlow<Int> = _size.asStateFlow()

    private val ignored = setOf(
        "localhost", "localhost.localdomain", "local", "broadcasthost", "0.0.0.0",
        "ip6-localhost", "ip6-loopback", "ip6-localnet", "ip6-mcastprefix",
        "ip6-allnodes", "ip6-allrouters", "ip6-allhosts",
    )
    private val sinkholes = setOf("0.0.0.0", "127.0.0.1", "::1", "::")

    fun loadAsync(ctx: Context) {
        val app = ctx.applicationContext
        thread(name = "blocklist-load", isDaemon = true) {
            runCatching {
                val file = File(app.filesDir, FILE_NAME)
                val reader = if (file.exists()) file.bufferedReader()
                else app.assets.open("blocklist_default.txt").bufferedReader()
                val set = HashSet<String>()
                reader.useLines { lines -> lines.forEach { line -> parseLine(line)?.let(set::add) } }
                replace(set)
            }
        }
    }

    fun replace(newDomains: Set<String>) {
        domains = newDomains
        _size.value = newDomains.size
    }

    fun parseLine(raw: String): String? {
        val line = raw.substringBefore('#').trim()
        if (line.isEmpty()) return null
        val tokens = line.split(Regex("\\s+"))
        val domain = when {
            tokens.size >= 2 && tokens[0] in sinkholes -> tokens[1]
            tokens.size == 1 -> tokens[0]
            else -> return null
        }.lowercase().trimEnd('.')
        if (domain in ignored || !domain.contains('.')) return null
        return domain
    }

    /** true, ak je doména alebo ktorákoľvek jej nadradená doména v zozname. */
    fun isBlocked(host: String): Boolean {
        val set = domains
        if (set.isEmpty()) return false
        var h = host.lowercase().trimEnd('.')
        while (true) {
            if (h in set) return true
            val dot = h.indexOf('.')
            if (dot < 0) return false
            h = h.substring(dot + 1)
        }
    }
}
