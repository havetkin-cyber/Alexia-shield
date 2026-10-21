package sk.alexia.shield.ui.screens

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.compose.ui.unit.dp
import sk.alexia.shield.core.EventType
import sk.alexia.shield.core.Permissions
import sk.alexia.shield.core.Prefs
import sk.alexia.shield.core.ShieldLog
import sk.alexia.shield.core.UsageHelper
import sk.alexia.shield.sensors.SensorMonitorService
import sk.alexia.shield.ui.EventRow
import sk.alexia.shield.ui.HintText
import sk.alexia.shield.ui.SectionCard
import sk.alexia.shield.ui.StatusRow
import sk.alexia.shield.ui.rememberResumeCounter

@Composable
fun SensorsScreen() {
    val ctx = LocalContext.current
    val running by SensorMonitorService.running.collectAsStateWithLifecycle()
    val events by ShieldLog.events.collectAsStateWithLifecycle()
    var alertAlways by remember { mutableStateOf(Prefs.sensorAlertAlways(ctx)) }
    val resume = rememberResumeCounter()
    val usageOn = remember(resume) { UsageHelper.hasAccess(ctx) }
    val timeline = events.filter { it.type == EventType.CAMERA || it.type == EventType.MICROPHONE }

    LazyColumn(
        contentPadding = PaddingValues(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        item {
            SectionCard {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Column(Modifier.weight(1f)) {
                        Text("Kamera a mikrofón", style = MaterialTheme.typography.titleLarge, fontWeight = FontWeight.Bold)
                        HintText(if (running) "Monitor beží" else "Monitor je vypnutý")
                    }
                    Switch(checked = running, onCheckedChange = {
                        if (it) SensorMonitorService.start(ctx) else SensorMonitorService.stop(ctx)
                    })
                }
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Text("Upozorniť vždy, aj keď telefón používam", modifier = Modifier.weight(1f))
                    Switch(checked = alertAlways, onCheckedChange = {
                        alertAlways = it
                        Prefs.setSensorAlertAlways(ctx, it)
                    })
                }
                StatusRow("Odhad appky (Prístup k využitiu)", usageOn, if (usageOn) null else "Povoliť") {
                    Permissions.openUsageAccessSettings(ctx)
                }
                HintText(
                    "Android neprezradí, ktorá appka kameru či mikrofón používa. Zobrazíme appku, " +
                        "ktorá bola v tej chvíli v popredí. Výstraha príde vždy, ak sa senzor zapne " +
                        "pri vypnutej obrazovke alebo zamknutom telefóne."
                )
            }
        }

        item {
            SectionCard("História") {
                if (timeline.isEmpty()) HintText("Zatiaľ žiadne záznamy.")
                timeline.take(50).forEach { EventRow(it) }
                if (timeline.isNotEmpty()) {
                    TextButton(onClick = { ShieldLog.clear(setOf(EventType.CAMERA, EventType.MICROPHONE)) }) {
                        Text("Vymazať históriu")
                    }
                }
            }
        }
    }
}
