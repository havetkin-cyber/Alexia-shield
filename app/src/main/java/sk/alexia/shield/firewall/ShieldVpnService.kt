package sk.alexia.shield.firewall

import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.os.ParcelFileDescriptor
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import sk.alexia.shield.core.EventType
import sk.alexia.shield.core.FirewallMode
import sk.alexia.shield.core.Notifications
import sk.alexia.shield.core.Prefs
import sk.alexia.shield.core.Severity
import sk.alexia.shield.core.ShieldEvent
import sk.alexia.shield.core.ShieldLog
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.IOException
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress

/**
 * Lokálna „loopback“ VPN – dáta nikam neodchádzajú.
 *
 * DNS_FILTER: do tunela ide iba DNS (fiktívny server [VPN_DNS]). Blokované domény
 *             dostanú NXDOMAIN, ostatné sa prepošlú na [UPSTREAM_DNS] cez chránený socket.
 * BLOCK_APPS: do tunela idú len vybrané appky a všetky ich pakety sa zahodia.
 */
class ShieldVpnService : VpnService() {

    companion object {
        const val ACTION_START = "sk.alexia.shield.vpn.START"
        const val ACTION_STOP = "sk.alexia.shield.vpn.STOP"
        const val ACTION_RESTART = "sk.alexia.shield.vpn.RESTART"

        private const val VPN_ADDR = "10.111.222.1"
        private const val VPN_DNS = "10.111.222.53"
        private const val VPN_ADDR6 = "fd00:a1e:5::1"
        private const val UPSTREAM_DNS = "1.1.1.1"

        private val _running = MutableStateFlow(false)
        val running: StateFlow<Boolean> = _running.asStateFlow()

        private val _blockedCount = MutableStateFlow(0)
        val blockedCount: StateFlow<Int> = _blockedCount.asStateFlow()

        private val _recentBlocked = MutableStateFlow<List<String>>(emptyList())
        val recentBlocked: StateFlow<List<String>> = _recentBlocked.asStateFlow()

        fun start(ctx: Context) = send(ctx, ACTION_START)
        fun stop(ctx: Context) = send(ctx, ACTION_STOP)
        fun restart(ctx: Context) = send(ctx, ACTION_RESTART)

        private fun send(ctx: Context, action: String) {
            ctx.startService(Intent(ctx, ShieldVpnService::class.java).setAction(action))
        }
    }

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private var tun: ParcelFileDescriptor? = null
    private var loopJob: Job? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_STOP -> {
                stopVpn(log = true)
                stopSelf()
                return START_NOT_STICKY
            }
            ACTION_RESTART -> {
                stopVpn(log = false)
                startVpn()
            }
            else -> startVpn() // ACTION_START alebo systémové „Vždy zapnutá VPN“
        }
        return START_STICKY
    }

    private fun startVpn() {
        if (tun != null) return
        val mode = Prefs.firewallMode(this)
        val builder = Builder()
            .setSession("Alexia Shield")
            .setMtu(1500)
            .setBlocking(true)
            .addAddress(VPN_ADDR, 32)
            .setConfigureIntent(Notifications.openAppIntent(this, "firewall"))

        when (mode) {
            FirewallMode.DNS_FILTER -> {
                builder.addDnsServer(VPN_DNS)
                builder.addRoute(VPN_DNS, 32)
                runCatching { builder.addDisallowedApplication(packageName) }
            }
            FirewallMode.BLOCK_APPS -> {
                val apps = Prefs.blockedApps(this)
                if (apps.isEmpty()) {
                    stopSelf()
                    return
                }
                var added = 0
                apps.forEach { pkg -> if (runCatching { builder.addAllowedApplication(pkg) }.isSuccess) added++ }
                if (added == 0) {
                    stopSelf()
                    return
                }
                builder.addAddress(VPN_ADDR6, 128)
                builder.addRoute("0.0.0.0", 0)
                builder.addRoute("::", 0)
                builder.addDnsServer(VPN_DNS)
            }
        }

        val pfd = runCatching { builder.establish() }.getOrNull() ?: run {
            stopSelf() // appka nemá súhlas (VpnService.prepare) alebo VPN prevzala iná appka
            return
        }
        tun = pfd
        _running.value = true
        ShieldLog.add(
            ShieldEvent(
                System.currentTimeMillis(), EventType.FIREWALL, Severity.INFO,
                "Firewall zapnutý",
                if (mode == FirewallMode.DNS_FILTER) "Režim: filtrovanie DNS" else "Režim: blokovanie appiek",
            )
        )
        loopJob = scope.launch { packetLoop(pfd, mode) }
    }

    private suspend fun packetLoop(pfd: ParcelFileDescriptor, mode: FirewallMode) {
        val input = FileInputStream(pfd.fileDescriptor)
        val output = FileOutputStream(pfd.fileDescriptor)
        val upstream = InetAddress.getByName(UPSTREAM_DNS)
        val buffer = ByteArray(32_767)

        while (scope.isActive) {
            val len = try {
                input.read(buffer)
            } catch (e: IOException) {
                break
            }
            if (len < 0) break
            if (len == 0) continue
            if (mode == FirewallMode.BLOCK_APPS) continue // zahoď všetko

            val query = DnsPacket.parse(buffer, len) ?: continue
            scope.launch { handleQuery(query, output, upstream) }
        }
    }

    private fun handleQuery(q: DnsQuery, output: FileOutputStream, upstream: InetAddress) {
        val response: ByteArray = if (Blocklist.isBlocked(q.qname)) {
            _blockedCount.update { it + 1 }
            _recentBlocked.update { (listOf(q.qname) + it.filterNot { d -> d == q.qname }).take(50) }
            val dns = DnsPacket.nxDomain(q)
            DnsPacket.wrapResponse(q, dns, dns.size)
        } else {
            val socket = DatagramSocket()
            try {
                protect(socket)
                socket.soTimeout = 5_000
                socket.send(DatagramPacket(q.payload, q.payload.size, upstream, 53))
                val buf = ByteArray(4096)
                val reply = DatagramPacket(buf, buf.size)
                socket.receive(reply)
                DnsPacket.wrapResponse(q, buf, reply.length)
            } catch (e: IOException) {
                return
            } finally {
                socket.close()
            }
        }
        runCatching { synchronized(output) { output.write(response) } }
    }

    private fun stopVpn(log: Boolean) {
        loopJob?.cancel()
        loopJob = null
        runCatching { tun?.close() }
        val wasRunning = tun != null
        tun = null
        _running.value = false
        if (log && wasRunning) {
            ShieldLog.add(
                ShieldEvent(System.currentTimeMillis(), EventType.FIREWALL, Severity.INFO, "Firewall vypnutý", "")
            )
        }
    }

    override fun onRevoke() {
        stopVpn(log = true)
        stopSelf()
    }

    override fun onDestroy() {
        stopVpn(log = false)
        scope.cancel()
        super.onDestroy()
    }
}
