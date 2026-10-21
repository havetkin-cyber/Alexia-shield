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
import androidx.compose.material3.Card
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

@Composable
private fun AppCard(app: AppRisk, expanded: Boolean, onToggle: () -> Unit) {
    val ctx = LocalContext.current
    val icon = remember(app.packageName) {
        runCatching {
            ctx.packageManager.getApplicationIcon(app.packageName).toBitmap(96, 96).asImageBitmap()
        }.getOrNull()
    }

    Card(
        modifier = Modifier.fillMaxWidth().clickable(onClick = onToggle),
        shape = RoundedCornerShape(16.dp),
    ) {
        Column(Modifier.padding(12.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                if (icon != null) {
                    Image(icon, contentDescription = null, modifier = Modifier.size(40.dp))
                    Spacer(Modifier.width(12.dp))
                }
                Column(Modifier.weight(1f)) {
                    Text(app.label, style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.SemiBold)
                    HintText("Riziko ${app.score}/100 • ${app.findings.size} zistení")
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
                    OutlinedButton(onClick = { Permissions.openAppDetails(ctx, app.packageName) }) {
                        Text("Upraviť oprávnenia")
                    }
                }
            }
        }
    }
}
