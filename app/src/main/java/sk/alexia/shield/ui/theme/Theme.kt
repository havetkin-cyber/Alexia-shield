package sk.alexia.shield.ui.theme

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color
import sk.alexia.shield.core.Severity

private val LightColors = lightColorScheme(
    primary = Color(0xFF00897B),
    onPrimary = Color.White,
    primaryContainer = Color(0xFFB2EFE4),
    onPrimaryContainer = Color(0xFF00201C),
    secondary = Color(0xFF3949AB),
    background = Color(0xFFF6F8FA),
    surface = Color(0xFFF6F8FA),
)

private val DarkColors = darkColorScheme(
    primary = Color(0xFF3DDC97),
    onPrimary = Color(0xFF00382A),
    primaryContainer = Color(0xFF00513F),
    onPrimaryContainer = Color(0xFFB2EFE4),
    secondary = Color(0xFF9FA8DA),
    background = Color(0xFF0F1418),
    surface = Color(0xFF0F1418),
)

@Composable
fun ShieldTheme(content: @Composable () -> Unit) {
    MaterialTheme(
        colorScheme = if (isSystemInDarkTheme()) DarkColors else LightColors,
        content = content,
    )
}

fun gradeColor(grade: Char): Color = when (grade) {
    'A' -> Color(0xFF2E7D32)
    'B' -> Color(0xFF7CB342)
    'C' -> Color(0xFFF9A825)
    'D' -> Color(0xFFFB8C00)
    'E' -> Color(0xFFE64A19)
    else -> Color(0xFFC62828)
}

fun severityColor(s: Severity): Color = when (s) {
    Severity.INFO -> Color(0xFF607D8B)
    Severity.WARNING -> Color(0xFFFB8C00)
    Severity.DANGER -> Color(0xFFC62828)
}

/** Farba pre skóre ochrany telefónu (vyššie = lepšie). */
fun protectionColor(score: Int): Color = when {
    score >= 80 -> Color(0xFF2E7D32)
    score >= 60 -> Color(0xFF7CB342)
    score >= 40 -> Color(0xFFF9A825)
    else -> Color(0xFFC62828)
}
