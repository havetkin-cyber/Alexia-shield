package sk.alexia.shield.ui.screens

import android.app.Activity
import android.content.Context
import android.net.VpnService
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.selection.selectable
import androidx.compose.material3.Checkbox
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.produceState
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import sk.alexia.shield.core.FirewallMode
import sk.alexia.shield.core.Permissions
import sk.alexia.shield.core.Prefs
import sk.alexia.shield.firewall.Blocklist
import sk.alexia.shield.firewall.BlocklistUpdateWorker
import sk.alexia.shield.firewall.ShieldVpnService
import sk.alexia.shield.ui.HintText
import sk.alexia.shield.ui.SectionCard

private data class InstalledApp(val packageName: String, val label: String)

private fun loadLaunchableApps(ctx: Context): List<InstalledApp> {
    val pm = ctx.packageManager
    @Suppress("DEPRECATION")
    val apps = pm.getInstalledApplications(0)
    return apps.asSequence()
        .filter { it.packageName != ctx.packageName && pm.getLaunchIntentForPackage(it.packageName) != null }
        .map { InstalledApp(it.packageName, runCatching { pm.getApplicationLabel(it).toString() }.getOrDefault(it.packageName)) }
        .sortedBy { it.label.lowercase() }
        .toList()
}

@Composable
fun FirewallScreen() {
    val ctx = LocalContext.current
    val running by ShieldVpnService.running.collectAsStateWithLifecycle()
    val blocked by ShieldVpnService.blockedCount.collectAsStateWithLifecycle()
    val recent by ShieldVpnService.recentBlocked.collectAsStateWithLifecycle()
    val listSize by Blocklist.size.collectAsStateWithLifecycle()

    var mode by remember { mutableStateOf(Prefs.firewallMode(ctx)) }
    var blockedApps by remember { mutableStateOf(Prefs.blockedApps(ctx)) }

    val vpnConsent = rememberLauncherForActivityResult(ActivityResultContracts.StartActivityForResult()) {
        if (it.resultCode == Activity.RESULT_OK) ShieldVpnService.start(ctx)
    }

    fun setEnabled(on: Boolean) {
        if (on) {
            val consent = VpnService.prepare(ctx)
            if (consent != null) vpnConsent.launch(consent) else ShieldVpnService.start(ctx)
        } else {
            ShieldVpnService.stop(ctx)
        }
    }

    val apps by produceState(initialValue = emptyList<InstalledApp>(), mode) {
        if (mode == FirewallMode.BLOCK_APPS) value = withContext(Dispatchers.IO) { loadLaunchableApps(ctx) }
    }

    LazyColumn(
        contentPadding = PaddingValues(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        item {
            SectionCard {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Column(Modifier.weight(1f)) {
                        Text("Firewall", style = MaterialTheme.typography.titleLarge, fontWeight = FontWeight.Bold)
                        HintText(if (running) "Zapnutý – lokálna VPN beží" else "Vypnutý")
                    }
                    Switch(checked = running, onCheckedChange = ::setEnabled)
                }
                HintText("VPN je len lokálna, dáta neodchádzajú na žiadny server. Naraz môže bežať iba jedna VPN.")
            }
        }

        item {
            SectionCard("Režim") {
                FirewallMode.entries.forEach { m ->
                    Row(
                        Modifier.fillMaxWidth().selectable(selected = mode == m, onClick = {
                            if (mode != m) {
                                mode = m
                                Prefs.setFirewallMode(ctx, m)
                                if (running) ShieldVpnService.restart(ctx)
                            }
                        }),
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        RadioButton(selected = mode == m, onClick = null)
                        Column(Modifier.weight(1f)) {
                            Text(
                                if (m == FirewallMode.DNS_FILTER) "Filtrovať DNS" else "Odrezať vybrané appky",
                                fontWeight = FontWeight.Medium,
                            )
                            HintText(
                                if (m == FirewallMode.DNS_FILTER) "Blokuje reklamy, trackery a phishing pre všetky appky"
                                else "Vybrané appky nedostanú vôbec žiadny internet"
                            )
                        }
                    }
                }
            }
        }

        if (mode == FirewallMode.DNS_FILTER) {
            item {
                SectionCard("Štatistiky") {
                    Text("Domén v zozname: $listSize")
                    Text("Zablokované dopyty (od spustenia): $blocked")
                    OutlinedButton(onClick = { BlocklistUpdateWorker.runNow(ctx) }) { Text("Aktualizovať zoznamy") }
                    HintText(
                        "Ak máš zapnuté Súkromné DNS (Nastavenia › Sieť a internet), filter ho obíde – " +
                            "nastav ho na Vypnuté alebo Automaticky."
                    )
                    TextButton(onClick = { Permissions.openVpnSettings(ctx) }) { Text("Nastaviť „Vždy zapnutá VPN“") }
                }
            }
            if (recent.isNotEmpty()) {
                item {
                    SectionCard("Naposledy zablokované") {
                        recent.take(20).forEach { HintText(it) }
                    }
                }
            }
        } else {
            item {
                HintText("Vyber appky, ktoré nemajú mať internet (napr. kalkulačka, hry offline):")
            }
            items(apps, key = { it.packageName }) { app ->
                val checked = app.packageName in blockedApps
                Row(
                    Modifier.fillMaxWidth().selectable(selected = checked, onClick = {
                        blockedApps = if (checked) blockedApps - app.packageName else blockedApps + app.packageName
                        Prefs.setBlockedApps(ctx, blockedApps)
                        if (running) ShieldVpnService.restart(ctx)
                    }),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Checkbox(checked = checked, onCheckedChange = null)
                    Column {
                        Text(app.label)
                        HintText(app.packageName)
                    }
                }
            }
        }
    }
}
