package sk.alexia.shield.ui.screens

import androidx.compose.foundation.Image
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Search
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.TextButton
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalUriHandler
import androidx.compose.ui.text.input.PasswordVisualTransformation
import sk.alexia.shield.audit.DeviceReport
import sk.alexia.shield.audit.MalwareChecker
import sk.alexia.shield.ui.SectionCard
import androidx.compose.material3.Checkbox
import androidx.compose.material3.Icon
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.core.graphics.drawable.toBitmap
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import sk.alexia.shield.audit.AppRisk
import sk.alexia.shield.core.Permissions
import sk.alexia.shield.ui.GradeBadge
import sk.alexia.shield.ui.HintText
import sk.alexia.shield.ui.MainViewModel

@Composable
fun AppsScreen(vm: MainViewModel) {
    val report by vm.report.collectAsStateWithLifecycle()
    val progress by vm.progress.collectAsStateWithLifecycle()
    val includeSystem by vm.includeSystem.collectAsStateWithLifecycle()
    var query by rememberSaveable { mutableStateOf("") }
    var expanded by rememberSaveable { mutableStateOf<String?>(null) }

    val apps = report?.apps.orEmpty().filter {
        query.isBlank() || it.label.contains(query, ignoreCase = true) || it.packageName.contains(query, ignoreCase = true)
    }

    Column(Modifier.fillMaxSize()) {
        Column(Modifier.padding(horizontal = 16.dp, vertical = 8.dp)) {
            OutlinedTextField(
                value = query,
                onValueChange = { query = it },
                modifier = Modifier.fillMaxWidth(),
                singleLine = true,
                leadingIcon = { Icon(Icons.Filled.Search, contentDescription = null) },
                placeholder = { Text("Hľadať appku") },
            )
            Row(verticalAlignment = Alignment.CenterVertically) {
                Checkbox(checked = includeSystem, onCheckedChange = vm::setIncludeSystem, enabled = progress == null)
                Text("Zahrnúť systémové appky", style = MaterialTheme.typography.bodyMedium)
            }
            progress?.let { (done, total) ->
                LinearProgressIndicator(
                    progress = { if (total == 0) 0f else done / total.toFloat() },
                    modifier = Modifier.fillMaxWidth(),
                )
            }
        }

        LazyColumn(
            contentPadding = PaddingValues(start = 16.dp, end = 16.dp, bottom = 16.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            item(key = "antivirus") {
                AntivirusCard(vm, report, scanning = progress != null)
            }
            items(apps, key = { it.packageName }) { app ->
                AppCard(
                    app = app,
                    expanded = expanded == app.packageName,
                    onToggle = { expanded = if (expanded == app.packageName) null else app.packageName },
                )
            }
        }
    }
}

private val DangerRed = Color(0xFFD32F2F)

@Composable
private fun AntivirusCard(vm: MainViewModel, report: DeviceReport?, scanning: Boolean) {
    val keySet by vm.malwareKeySet.collectAsStateWithLifecycle()
    val message by vm.keyMessage.collectAsStateWithLifecycle()
    val verifying by vm.verifyingKey.collectAsStateWithLifecycle()
    val uri = LocalUriHandler.current
    var keyInput by rememberSaveable { mutableStateOf("") }

    val malware = report?.apps.orEmpty().filter { it.malware != null }
    val bankers = report?.apps.orEmpty().filter { it.banker && it.malware == null }

    SectionCard("Antivírus") {
        when {
            malware.isNotEmpty() -> Text(
                "🦠 Nájdený malvér: " + malware.joinToString { it.label },
                color = DangerRed, fontWeight = FontWeight.Bold,
            )
            bankers.isNotEmpty() -> Text(
                "⚠️ Podozrivé appky (bankový trójsky kôň): " + bankers.joinToString { it.label },
                color = DangerRed, fontWeight = FontWeight.SemiBold,
            )
            report != null && !scanning -> Text("✅ Žiadne známe hrozby", fontWeight = FontWeight.SemiBold)
        }
        HintText("Detektor bankových trójskych koní beží vždy, aj bez internetu.")

        if (keySet) {
            val r = report
            when {
                scanning -> HintText("Prebieha kontrola…")
                r?.malwareError != null -> Text(r.malwareError, color = DangerRed, style = MaterialTheme.typography.bodySmall)
                r != null && r.malwareChecked > 0 ->
                    HintText("Databáza MalwareBazaar: overených ${r.malwareChecked} appiek. Kontrola beží aj raz denne na pozadí.")
            }
            Row(verticalAlignment = Alignment.CenterVertically) {
                Button(onClick = vm::runAudit, enabled = !scanning) { Text("Skontrolovať teraz") }
                Spacer(Modifier.width(8.dp))
                TextButton(onClick = vm::removeMalwareKey) { Text("Odstrániť kľúč") }
            }
        } else {
            HintText(
                "Na kontrolu podľa databázy známeho malvéru (MalwareBazaar) treba bezplatný kľúč. " +
                    "Posiela sa iba odtlačok (SHA-256) appiek, žiadne osobné údaje."
            )
            TextButton(onClick = { uri.openUri(MalwareChecker.KEY_PORTAL) }) { Text("Získať kľúč zdarma (auth.abuse.ch)") }
            OutlinedTextField(
                value = keyInput,
                onValueChange = { keyInput = it },
                modifier = Modifier.fillMaxWidth(),
                singleLine = true,
                label = { Text("Auth-Key") },
                visualTransformation = PasswordVisualTransformation(),
            )
            Button(onClick = { vm.saveMalwareKey(keyInput) }, enabled = keyInput.isNotBlank() && !verifying) {
                Text(if (verifying) "Overujem…" else "Uložiť a skontrolovať")
            }
        }
        message?.let { HintText(it) }
    }
}

@Composable
private fun AppCard(app: AppRisk, expanded: Boolean, onToggle: () -> Unit) {
    val ctx = LocalContext.current
    val icon = remember(app.packageName) {
        runCatching {
            ctx.packageManager.getApplicationIcon(app.packageName).toBitmap(96, 96).asImageBitmap()
        }.getOrNull()
    }

    val threat = app.malware != null || app.banker
    Card(
        modifier = Modifier.fillMaxWidth().clickable(onClick = onToggle),
        shape = RoundedCornerShape(16.dp),
        colors = if (threat) CardDefaults.cardColors(containerColor = DangerRed.copy(alpha = 0.15f))
        else CardDefaults.cardColors(),
    ) {
        Column(Modifier.padding(12.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                if (icon != null) {
                    Image(icon, contentDescription = null, modifier = Modifier.size(40.dp))
                    Spacer(Modifier.width(12.dp))
                }
                Column(Modifier.weight(1f)) {
                    Text(app.label, style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.SemiBold)
                    when {
                        app.malware != null -> Text("🦠 Malvér: ${app.malware}", color = DangerRed, style = MaterialTheme.typography.bodySmall, fontWeight = FontWeight.Bold)
                        app.banker -> Text("⚠️ Možný bankový trójsky kôň", color = DangerRed, style = MaterialTheme.typography.bodySmall, fontWeight = FontWeight.SemiBold)
                        else -> HintText("Riziko ${app.score}/100 • ${app.findings.size} zistení")
                    }
                }
                GradeBadge(app.grade)
            }

            if (expanded) {
                Column(Modifier.padding(top = 8.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                    if (app.findings.isEmpty()) HintText("Žiadne rizikové zistenia 👍")
                    app.findings.forEach { f ->
                        Row {
                            Text("• ${f.text}", modifier = Modifier.weight(1f), style = MaterialTheme.typography.bodySmall)
                            Text("+${f.points}", style = MaterialTheme.typography.labelSmall)
                        }
                    }
                    if (app.trackers.isNotEmpty()) {
                        HintText("Trackery: " + app.trackers.joinToString(", "))
                    }
                    HintText(app.packageName)
                    Row {
                        OutlinedButton(onClick = { Permissions.openAppDetails(ctx, app.packageName) }) {
                            Text(if (threat) "Odinštalovať / nastavenia" else "Upraviť oprávnenia")
                        }
                    }
                }
            }
        }
    }
}
