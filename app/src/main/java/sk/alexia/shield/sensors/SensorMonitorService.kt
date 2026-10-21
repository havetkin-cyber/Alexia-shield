package sk.alexia.shield.sensors

import android.app.KeyguardManager
import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.hardware.camera2.CameraManager
import android.media.AudioManager
import android.media.AudioRecordingConfiguration
import android.os.Build
import android.os.Handler
import android.os.IBinder
import android.os.Looper
import android.os.PowerManager
import androidx.core.app.ServiceCompat
import androidx.core.content.ContextCompat
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import sk.alexia.shield.core.EventType
import sk.alexia.shield.core.Notifications
import sk.alexia.shield.core.Prefs
import sk.alexia.shield.core.Severity
import sk.alexia.shield.core.ShieldEvent
import sk.alexia.shield.core.ShieldLog
import sk.alexia.shield.core.UsageHelper

/**
 * Sleduje, kedy sa kamera alebo mikrofón zapnú v inej appke.
 * Android neprezradí, KTORÁ appka to je – odhadujeme ju podľa appky v popredí
 * (ak je povolený Prístup k využitiu).
 */
class SensorMonitorService : Service() {

    companion object {
        private const val NOTIF_ID = 42

        private val _running = MutableStateFlow(false)
        val running: StateFlow<Boolean> = _running.asStateFlow()

        fun start(ctx: Context) =
            ContextCompat.startForegroundService(ctx, Intent(ctx, SensorMonitorService::class.java))

        fun stop(ctx: Context) {
            ctx.stopService(Intent(ctx, SensorMonitorService::class.java))
        }
    }

    private val handler = Handler(Looper.getMainLooper())
    private val camerasInUse = mutableSetOf<String>()
    private var micActive = false
    private var registered = false

    private lateinit var cameraManager: CameraManager
    private lateinit var audioManager: AudioManager

    private val cameraCallback = object : CameraManager.AvailabilityCallback() {
        override fun onCameraUnavailable(cameraId: String) {
            val wasIdle = camerasInUse.isEmpty()
            camerasInUse.add(cameraId)
            if (wasIdle) report(EventType.CAMERA, "Kamera sa zapla")
        }

        override fun onCameraAvailable(cameraId: String) {
            camerasInUse.remove(cameraId)
        }
    }

    private val audioCallback = object : AudioManager.AudioRecordingCallback() {
        override fun onRecordingConfigChanged(configs: MutableList<AudioRecordingConfiguration>) {
            val active = isRecording(configs)
            if (active && !micActive) report(EventType.MICROPHONE, "Mikrofón sa zapol")
            micActive = active
        }
    }

    override fun onCreate() {
        super.onCreate()
        cameraManager = getSystemService(CameraManager::class.java)
        audioManager = getSystemService(AudioManager::class.java)
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val notification = Notifications.serviceNotification(
            this, "Alexia Shield stráži", "Sledujem použitie kamery a mikrofónu", "sensors"
        )
        val type = if (Build.VERSION.SDK_INT >= 34) ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE else 0
        ServiceCompat.startForeground(this, NOTIF_ID, notification, type)

        if (!registered) {
            micActive = isRecording(audioManager.activeRecordingConfigurations)
            cameraManager.registerAvailabilityCallback(cameraCallback, handler)
            audioManager.registerAudioRecordingCallback(audioCallback, handler)
            registered = true
        }
        _running.value = true
        return START_STICKY
    }

    private fun isRecording(configs: List<AudioRecordingConfiguration>): Boolean =
        configs.any { Build.VERSION.SDK_INT < 29 || !it.isClientSilenced }

    private fun report(type: EventType, title: String) {
        val screenOff = !getSystemService(PowerManager::class.java).isInteractive
        val locked = getSystemService(KeyguardManager::class.java).isKeyguardLocked
        val foreground = UsageHelper.foregroundApp(this)
            ?.takeIf { it != packageName }
            ?.let { pkg ->
                runCatching {
                    packageManager.getApplicationLabel(packageManager.getApplicationInfo(pkg, 0)).toString()
                }.getOrDefault(pkg)
            }

        val detail = buildString {
            append(
                when {
                    screenOff -> "Obrazovka bola vypnutá"
                    locked -> "Telefón bol zamknutý"
                    else -> "Telefón sa používal"
                }
            )
            if (foreground != null) append(" • v popredí: $foreground")
        }
        val severity = if (screenOff || locked) Severity.DANGER else Severity.INFO

        ShieldLog.add(ShieldEvent(System.currentTimeMillis(), type, severity, title, detail))
        if (severity == Severity.DANGER || Prefs.sensorAlertAlways(this)) {
            Notifications.alert(this, "🔴 $title", detail, tab = "sensors")
        }
    }

    override fun onDestroy() {
        if (registered) {
            cameraManager.unregisterAvailabilityCallback(cameraCallback)
            audioManager.unregisterAudioRecordingCallback(audioCallback)
            registered = false
        }
        _running.value = false
        super.onDestroy()
    }

    override fun onBind(intent: Intent?): IBinder? = null
}
