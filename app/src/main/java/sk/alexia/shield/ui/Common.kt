package sk.alexia.shield.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.BugReport
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.Dns
import androidx.compose.material.icons.filled.Link
import androidx.compose.material.icons.filled.Mic
import androidx.compose.material.icons.filled.RadioButtonUnchecked
import androidx.compose.material.icons.filled.Videocam
import androidx.compose.material3.Card
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.compose.LifecycleEventEffect
import sk.alexia.shield.core.EventType
import sk.alexia.shield.core.ShieldEvent
import sk.alexia.shield.ui.theme.gradeColor
import sk.alexia.shield.ui.theme.severityColor
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/** Zvýši sa pri každom návrate do appky – na prečítanie stavu oprávnení. */
@Composable
fun rememberResumeCounter(): Int {
    var counter by remember { mutableIntStateOf(0) }
    LifecycleEventEffect(Lifecycle.Event.ON_RESUME) { counter++ }
    return counter
}

@Composable
fun SectionCard(title: String? = null, content: @Composable ColumnScope.() -> Unit) {
    Card(modifier = Modifier.fillMaxWidth(), shape = RoundedCornerShape(20.dp)) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            if (title != null) {
                Text(title, style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
            }
            content()
        }
    }
}

@Composable
fun GradeBadge(grade: Char, size: Int = 40) {
    Box(
        modifier = Modifier
            .size(size.dp)
            .background(gradeColor(grade), CircleShape),
        contentAlignment = Alignment.Center,
    ) {
        Text(grade.toString(), color = Color.White, fontWeight = FontWeight.Bold, fontSize = (size / 2).sp)
    }
}

@Composable
fun StatusRow(title: String, ok: Boolean, actionLabel: String?, onAction: () -> Unit) {
    Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
        Icon(
            if (ok) Icons.Filled.CheckCircle else Icons.Filled.RadioButtonUnchecked,
            contentDescription = null,
            tint = if (ok) Color(0xFF2E7D32) else MaterialTheme.colorScheme.outline,
        )
        Spacer(Modifier.width(12.dp))
        Text(title, modifier = Modifier.weight(1f), style = MaterialTheme.typography.bodyMedium)
        if (actionLabel != null) TextButton(onClick = onAction) { Text(actionLabel) }
    }
}

private val timeFormat = SimpleDateFormat("d. M. HH:mm", Locale.forLanguageTag("sk"))

@Composable
fun EventRow(event: ShieldEvent) {
    Row(Modifier.fillMaxWidth().padding(vertical = 4.dp), verticalAlignment = Alignment.Top) {
        Icon(
            when (event.type) {
                EventType.LINK -> Icons.Filled.Link
                EventType.CAMERA -> Icons.Filled.Videocam
                EventType.MICROPHONE -> Icons.Filled.Mic
                EventType.FIREWALL -> Icons.Filled.Dns
                EventType.MALWARE -> Icons.Filled.BugReport
            },
            contentDescription = null,
            tint = severityColor(event.severity),
        )
        Spacer(Modifier.width(12.dp))
        Column(Modifier.weight(1f)) {
            Text(event.title, style = MaterialTheme.typography.bodyMedium, fontWeight = FontWeight.Medium)
            if (event.detail.isNotBlank()) {
                Text(
                    event.detail,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }
        Text(
            timeFormat.format(Date(event.time)),
            style = MaterialTheme.typography.labelSmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
    }
}

@Composable
fun HintText(text: String) {
    Text(text, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
}
