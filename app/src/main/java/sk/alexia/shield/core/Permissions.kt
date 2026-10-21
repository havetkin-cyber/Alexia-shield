package sk.alexia.shield.core

import android.content.Context
import android.content.Intent
import android.net.Uri
import android.provider.Settings
import androidx.core.app.NotificationManagerCompat

object Permissions {

    fun notificationListenerEnabled(ctx: Context): Boolean =
        NotificationManagerCompat.getEnabledListenerPackages(ctx).contains(ctx.packageName)

    fun openNotificationListenerSettings(ctx: Context) =
        start(ctx, Intent(Settings.ACTION_NOTIFICATION_LISTENER_SETTINGS))

    fun openUsageAccessSettings(ctx: Context) =
        start(ctx, Intent(Settings.ACTION_USAGE_ACCESS_SETTINGS))

    fun openAppDetails(ctx: Context, packageName: String) =
        start(
            ctx,
            Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS, Uri.fromParts("package", packageName, null))
        )

    fun openVpnSettings(ctx: Context) = start(ctx, Intent(Settings.ACTION_VPN_SETTINGS))

    private fun start(ctx: Context, intent: Intent) {
        runCatching { ctx.startActivity(intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)) }
    }
}
