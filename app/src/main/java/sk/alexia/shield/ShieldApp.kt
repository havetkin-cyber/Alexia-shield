package sk.alexia.shield

import android.app.Application
import sk.alexia.shield.audit.ThreatScanWorker
import sk.alexia.shield.update.UpdateWorker
import sk.alexia.shield.core.Notifications
import sk.alexia.shield.core.ShieldLog
import sk.alexia.shield.firewall.Blocklist
import sk.alexia.shield.firewall.BlocklistUpdateWorker

class ShieldApp : Application() {
    override fun onCreate() {
        super.onCreate()
        Notifications.createChannels(this)
        ShieldLog.init(this)
        Blocklist.loadAsync(this)
        BlocklistUpdateWorker.schedule(this)
        ThreatScanWorker.schedule(this)
        UpdateWorker.schedule(this)
    }
}
