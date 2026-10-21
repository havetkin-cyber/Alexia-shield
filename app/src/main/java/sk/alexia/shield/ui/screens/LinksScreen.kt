package sk.alexia.shield.ui.screens

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import sk.alexia.shield.core.EventType
import sk.alexia.shield.core.Permissions
import sk.alexia.shield.core.Prefs
import sk.alexia.shield.core.Severity
import sk.alexia.shield.core.ShieldLog
import sk.alexia.shield.linkscan.LinkAnalyzer
import sk.alexia.shield.linkscan.LinkVerdict
import sk.alexia.shield.ui.EventRow
import sk.alexia.shield.ui.HintText
import sk.alexia.shield.ui.SectionCard
import sk.alexia.shield.ui.StatusRow
import sk.alexia.shield.ui.rememberResumeCounter
import sk.alexia.shield.ui.theme.severityColor

@Composable
fun LinksScreen() {
    val ctx = LocalContext.current
    val resume = rememberResumeCounter()
    val listenerOn = remember(resume) { Permissions.notificationListenerEnabled(ctx) }
    var scanEnabled by remember { mutableStateOf(Prefs.linkScanEnabled(ctx)) }
    var input by rememberSaveable { mutableStateOf("") }
    var results by remember { mutableStateOf<List<LinkVerdict>?>(null) }
    val events by ShieldLog.events.collectAsStateWithLifecycle()
    val history = events.filter { it.type == EventType.LINK }

    LazyColumn(
        contentPadding = PaddingValues(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        item {
            SectionCard("Automatická kontrola") {
                StatusRow("Prístup k notifikáciám", listenerOn, if (listenerOn) null else "Povoliť") {
                    Permissions.openNotificationListenerSettings(ctx)
                }
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Text("Kontrolovať odkazy v správach", modifier = Modifier.weight(1f))
                    Switch(checked = scanEnabled, onCheckedChange = {
                        scanEnabled = it
                        Prefs.setLinkScanEnabled(ctx, it)
                    })
                }
                HintText("Funguje pre SMS, WhatsApp, Messenger, e-mail a ďalšie appky, ktoré zobrazujú text v notifikácii.")
            }
        }

        item {
            SectionCard("Skontrolovať ručne") {
                OutlinedTextField(
                    value = input,
                    onValueChange = { input = it },
                    modifier = Modifier.fillMaxWidth().heightIn(min = 96.dp),
                    placeholder = { Text("Vlož text správy alebo odkaz") },
                )
                Button(onClick = { results = LinkAnalyzer.analyzeMessage(input) }, enabled = input.isNotBlank()) {
                    Text("Skontrolovať")
                }
                results?.let { list ->
                    if (list.isEmpty()) HintText("V texte som nenašiel žiadny odkaz.")
                    list.forEach { VerdictBlock(it) }
                }
            }
        }

        if (history.isNotEmpty()) {
            item {
                SectionCard("Zachytené odkazy") {
                    history.take(30).forEach { EventRow(it) }
                    TextButton(onClick = { ShieldLog.clear(setOf(EventType.LINK)) }) { Text("Vymazať históriu") }
                }
            }
        }
    }
}

@Composable
private fun VerdictBlock(v: LinkVerdict) {
    val color = severityColor(v.level)
    val label = when (v.level) {
        Severity.DANGER -> "Nebezpečný"
        Severity.WARNING -> "Podozrivý"
        Severity.INFO -> "Bez zjavných znakov podvodu"
    }
    Row(verticalAlignment = Alignment.CenterVertically) {
        Text(v.host.ifEmpty { v.url }, modifier = Modifier.weight(1f), fontWeight = FontWeight.SemiBold)
        Text("$label • ${v.score}/100", color = color, style = MaterialTheme.typography.labelLarge)
    }
    v.reasons.forEach { HintText("• $it") }
}
