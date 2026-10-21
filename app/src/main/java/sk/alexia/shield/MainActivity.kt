package sk.alexia.shield

import android.content.Intent
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.runtime.mutableStateOf
import sk.alexia.shield.ui.ShieldRoot
import sk.alexia.shield.ui.theme.ShieldTheme

class MainActivity : ComponentActivity() {

    companion object {
        const val EXTRA_TAB = "sk.alexia.shield.TAB"
    }

    /** Záložka, ktorú si vyžiadala notifikácia (napr. "links", "sensors"). */
    private val requestedTab = mutableStateOf<String?>(null)

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        requestedTab.value = intent?.getStringExtra(EXTRA_TAB)
        setContent {
            ShieldTheme {
                ShieldRoot(requestedTab)
            }
        }
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        intent.getStringExtra(EXTRA_TAB)?.let { requestedTab.value = it }
    }
}
