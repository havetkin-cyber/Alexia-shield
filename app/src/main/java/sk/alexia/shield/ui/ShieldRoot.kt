package sk.alexia.shield.ui

import android.Manifest
import android.content.pm.PackageManager
import android.os.Build
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Apps
import androidx.compose.material.icons.filled.Dns
import androidx.compose.material.icons.filled.Link
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material.icons.filled.Videocam
import androidx.compose.material3.Icon
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.MutableState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalContext
import androidx.core.content.ContextCompat
import androidx.lifecycle.viewmodel.compose.viewModel
import sk.alexia.shield.ui.screens.AppsScreen
import sk.alexia.shield.ui.screens.FirewallScreen
import sk.alexia.shield.ui.screens.LinksScreen
import sk.alexia.shield.ui.screens.OverviewScreen
import sk.alexia.shield.ui.screens.SensorsScreen

enum class Tab(val key: String, val label: String, val icon: ImageVector) {
    OVERVIEW("overview", "Prehľad", Icons.Filled.Shield),
    APPS("apps", "Appky", Icons.Filled.Apps),
    LINKS("links", "Odkazy", Icons.Filled.Link),
    FIREWALL("firewall", "Firewall", Icons.Filled.Dns),
    SENSORS("sensors", "Senzory", Icons.Filled.Videocam),
}

@Composable
fun ShieldRoot(requestedTab: MutableState<String?>) {
    val vm: MainViewModel = viewModel()
    var tab by rememberSaveable { mutableStateOf(Tab.OVERVIEW) }

    val pending = requestedTab.value
    LaunchedEffect(pending) {
        if (pending != null) {
            Tab.entries.firstOrNull { it.key == pending }?.let { tab = it }
            requestedTab.value = null
        }
    }

    NotificationPermissionRequest()

    Scaffold(
        bottomBar = {
            NavigationBar {
                Tab.entries.forEach { t ->
                    NavigationBarItem(
                        selected = tab == t,
                        onClick = { tab = t },
                        icon = { Icon(t.icon, contentDescription = null) },
                        label = { Text(t.label) },
                    )
                }
            }
        }
    ) { padding ->
        Box(Modifier.fillMaxSize().padding(padding)) {
            when (tab) {
                Tab.OVERVIEW -> OverviewScreen(vm) { tab = it }
                Tab.APPS -> AppsScreen(vm)
                Tab.LINKS -> LinksScreen()
                Tab.FIREWALL -> FirewallScreen()
                Tab.SENSORS -> SensorsScreen()
            }
        }
    }
}

@Composable
private fun NotificationPermissionRequest() {
    if (Build.VERSION.SDK_INT < 33) return
    val ctx = LocalContext.current
    val launcher = rememberLauncherForActivityResult(ActivityResultContracts.RequestPermission()) { }
    LaunchedEffect(Unit) {
        val granted = ContextCompat.checkSelfPermission(ctx, Manifest.permission.POST_NOTIFICATIONS) ==
            PackageManager.PERMISSION_GRANTED
        if (!granted) launcher.launch(Manifest.permission.POST_NOTIFICATIONS)
    }
}
