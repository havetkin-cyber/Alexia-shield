package sk.alexia.shield.ui.screens

import android.content.Intent
import android.net.Uri
import android.provider.Settings
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Switch
import androidx.compose.material3.TextButton
import androidx.compose.runtime.LaunchedEffect
import sk.alexia.shield.update.AppUpdater
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import sk.alexia.shield.core.Permissions
import sk.alexia.shield.core.ShieldLog
import sk.alexia.shield.core.UsageHelper
import sk.alexia.shield.firewall.ShieldVpnService
import sk.alexia.shield.sensors.SensorMonitorService
import sk.alexia.shield.ui.EventRow
import sk.alexia.shield.ui.GradeBadge
import sk.alexia.shield.ui.HintText
import sk.alexia.shield.ui.MainViewModel
import sk.alexia.shield.ui.SectionCard
import sk.alexia.shield.ui.StatusRow
import sk.alexia.shield.ui.Tab
import sk.alexia.shield.ui.rememberResumeCounter
import sk.alexia.shield.ui.theme.protectionColor

@Composable
fun OverviewScreen(vm: MainViewModel, onNavigate: (Tab) -> Unit) {
    val ctx = LocalContext.current
    val report by vm.report.collectAsStateWithLifecycle()
    val progress by vm.progress.collectAsStateWithLifecycle()
    val vpnOn by ShieldVpnService.running.collectAsStateWithLifecycle()
    val sensorsOn by SensorMonitorService.running.collectAsStateWithLifecycle()
    val events by ShieldLog.events.collectAsStateWithLifecycle()

    val resume = rememberResumeCounter()
    val listenerOn = remember(resume) { Permissions.notificationListenerEnabled(ctx) }
    val usageOn = remember(resume) { UsageHelper.hasAccess(ctx) }

    LazyColumn(
        contentPadding = PaddingValues(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        item {
            Column {
                Text("Alexia Shield", style = MaterialTheme.typography.headlineMedium, fontWeight = FontWeight.Bold)
                HintText("Všetko beží lokálne v telefóne. Nič neodosielame na server.")
            }
        }

        item {
            SectionCard {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    val score = report?.protectionScore
                    Box(Modifier.size(112.dp), contentAlignment = Alignment.Center) {
                        if (progress != null || score == null) {
                            CircularProgressIndicator(Modifier.size(112.dp), strokeWidth = 10.dp)
                        } else {
                            CircularProgressIndicator(
                                progress = { score / 100f },
                                modifier = Modifier.size(112.dp),
                                strokeWidth = 10.dp,
                                color = protectionColor(score),
                            )
                            Text("$score", fontSize = 34.sp, fontWeight = FontWeight.Bold)
                        }
                    }
                    Spacer(Modifier.width(16.dp))
                    Column(Modifier.weight(1f)) {
                        Text("Skóre ochrany", style = MaterialTheme.typography.titleMedium)
                        val p = progress
                        HintText(
                            when {
                                p != null -> "Kontrolujem appky… ${p.first}/${p.second}"
                                score == null -> "Pripravujem audit"
                                score >= 80 -> "Telefón je v dobrej kondícii"
                                score >= 60 -> "Pár vecí stojí za pozornosť"
                                else -> "Niektoré appky sú rizikové"
                            }
                        )
                        Spacer(Modifier.height(8.dp))
                        Button(onClick = vm::runAudit, enabled = progress == null) { Text("Skontrolovať znova") }
                    }
                }
            }
        }

        report?.let { r ->
            item {
                SectionCard("Appky podľa rizika") {
                    Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                        "ABCDEF".forEach { g ->
                            Column(horizontalAlignment = Alignment.CenterHorizontally) {
                                GradeBadge(g, 36)
                                Text("${r.apps.count { it.grade == g }}", style = MaterialTheme.typography.labelLarge)
                            }
                        }
                    }
                    val threats = r.apps.filter { it.isThreat }
                    if (threats.isNotEmpty()) {
                        Text(
                            "🦠 Hrozby: " + threats.joinToString { it.label },
                            color = MaterialTheme.colorScheme.error,
                            style = MaterialTheme.typography.bodyMedium,
                            fontWeight = FontWeight.Bold,
                        )
                    }
                    val worst = r.apps.take(3).filter { it.score > 25 }
                    if (worst.isNotEmpty()) {
                        HintText("Najrizikovejšie: " + worst.joinToString { it.label })
                        Button(onClick = { onNavigate(Tab.APPS) }) { Text("Zobraziť appky") }
                    }
                }
            }
        }

        item {
            val checks by vm.deviceChecks.collectAsStateWithLifecycle()
            LaunchedEffect(resume) { vm.refreshDevice() }
            if (checks.isNotEmpty()) {
                SectionCard("Bezpečnosť telefónu") {
                    checks.forEach { c ->
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Text(if (c.ok) "✅" else if (c.severe) "🔴" else "⚠️")
                            Spacer(Modifier.width(10.dp))
                            Column(Modifier.weight(1f)) {
                                Text(c.title, style = MaterialTheme.typography.bodyMedium, fontWeight = FontWeight.Medium)
                                HintText(c.detail)
                            }
                            val fix = c.fix
                            if (!c.ok && fix != null) {
                                TextButton(onClick = {
                                    runCatching { ctx.startActivity(fix.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)) }
                                }) { Text("Opraviť") }
                            }
                        }
                    }
                }
            }
        }

        item {
            val update by vm.update.collectAsStateWithLifecycle()
            val updating by vm.updating.collectAsStateWithLifecycle()
            val updateMessage by vm.updateMessage.collectAsStateWithLifecycle()
            val autoUpdate by vm.autoUpdate.collectAsStateWithLifecycle()
            val canInstall = remember(resume) { AppUpdater.canInstall(ctx) }
            SectionCard("Aktualizácie") {
                HintText("Verzia ${AppUpdater.currentVersionName(ctx)} (build ${AppUpdater.currentBuild(ctx)})")
                when (val u = update) {
                    is AppUpdater.Check.Available -> {
                        Text("🆕 Dostupná nová verzia: ${u.release.name}", fontWeight = FontWeight.SemiBold)
                        Button(onClick = vm::installUpdate, enabled = !updating && canInstall) {
                            Text(if (updating) "Aktualizujem…" else "Aktualizovať teraz")
                        }
                    }
                    is AppUpdater.Check.UpToDate -> HintText("✅ Máš najnovšiu verziu")
                    is AppUpdater.Check.Error -> HintText("Kontrola zlyhala: ${u.message}")
                    null -> HintText("Kontrolujem…")
                }
                updateMessage?.let { HintText(it) }
                if (!canInstall) {
                    HintText("Na automatické aktualizácie povoľ Alexia Shield inštaláciu appiek (iba raz).")
                    OutlinedButton(onClick = {
                        runCatching {
                            ctx.startActivity(
                                Intent(Settings.ACTION_MANAGE_UNKNOWN_APP_SOURCES, Uri.parse("package:" + ctx.packageName))
                                    .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                            )
                        }
                    }) { Text("Povoliť aktualizácie") }
                }
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Column(Modifier.weight(1f)) {
                        Text("Automaticky aktualizovať", style = MaterialTheme.typography.bodyMedium)
                        HintText("Kontrola každých 6 hodín, nová verzia sa nainštaluje sama")
                    }
                    Switch(checked = autoUpdate, onCheckedChange = vm::setAutoUpdate)
                }
                TextButton(onClick = vm::checkUpdate) { Text("Skontrolovať teraz") }
            }
        }

        item {
            SectionCard("Ochrana") {
                StatusRow("Firewall", vpnOn, "Otvoriť") { onNavigate(Tab.FIREWALL) }
                StatusRow("Kontrola odkazov v notifikáciách", listenerOn, if (listenerOn) null else "Povoliť") {
                    Permissions.openNotificationListenerSettings(ctx)
                }
                StatusRow("Monitor kamery a mikrofónu", sensorsOn, "Otvoriť") { onNavigate(Tab.SENSORS) }
                StatusRow("Prístup k využitiu (presnejší audit)", usageOn, if (usageOn) null else "Povoliť") {
                    Permissions.openUsageAccessSettings(ctx)
                }
            }
        }

        if (events.isNotEmpty()) {
            item {
                SectionCard("Posledné udalosti") {
                    events.take(5).forEach { EventRow(it) }
                }
            }
        }
    }
}
