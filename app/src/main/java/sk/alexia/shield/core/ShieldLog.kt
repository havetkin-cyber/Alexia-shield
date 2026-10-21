package sk.alexia.shield.core

import android.content.Context
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.util.concurrent.Executors

enum class EventType { LINK, CAMERA, MICROPHONE, FIREWALL, MALWARE }
enum class Severity { INFO, WARNING, DANGER }

data class ShieldEvent(
    val time: Long,
    val type: EventType,
    val severity: Severity,
    val title: String,
    val detail: String,
)

/** Jednoduchý trvalý denník udalostí (posledných [MAX] záznamov v JSON súbore). */
object ShieldLog {
    private const val MAX = 300

    private var file: File? = null
    private val io = Executors.newSingleThreadExecutor()
    private val _events = MutableStateFlow<List<ShieldEvent>>(emptyList())
    val events: StateFlow<List<ShieldEvent>> = _events.asStateFlow()

    fun init(ctx: Context) {
        val f = File(ctx.filesDir, "events.json")
        file = f
        io.execute {
            val loaded = read(f)
            _events.update { current -> (current + loaded).distinct().take(MAX) }
        }
    }

    fun add(event: ShieldEvent) {
        _events.update { (listOf(event) + it).take(MAX) }
        persist()
    }

    fun clear(types: Set<EventType>? = null) {
        _events.update { list -> if (types == null) emptyList() else list.filterNot { it.type in types } }
        persist()
    }

    private fun persist() {
        val snapshot = _events.value
        val f = file ?: return
        io.execute { write(f, snapshot) }
    }

    private fun read(f: File): List<ShieldEvent> {
        if (!f.exists()) return emptyList()
        return parse(f)
    }

    private fun parse(f: File): List<ShieldEvent> = runCatching {
        val arr = JSONArray(f.readText())
        (0 until arr.length()).map { i ->
            val o = arr.getJSONObject(i)
            ShieldEvent(
                time = o.getLong("t"),
                type = EventType.valueOf(o.getString("type")),
                severity = Severity.valueOf(o.getString("sev")),
                title = o.getString("title"),
                detail = o.optString("detail"),
            )
        }
    }.getOrDefault(emptyList())

    private fun write(f: File, events: List<ShieldEvent>) {
        runCatching {
            val arr = JSONArray()
            events.forEach { e ->
                arr.put(
                    JSONObject()
                        .put("t", e.time)
                        .put("type", e.type.name)
                        .put("sev", e.severity.name)
                        .put("title", e.title)
                        .put("detail", e.detail)
                )
            }
            f.writeText(arr.toString())
        }
    }
}
