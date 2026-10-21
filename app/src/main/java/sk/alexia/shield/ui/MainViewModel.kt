package sk.alexia.shield.ui

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import android.net.Uri
import sk.alexia.shield.audit.ApkFileScanner
import sk.alexia.shield.audit.MalwareChecker
import sk.alexia.shield.audit.MalwareDatabase
import sk.alexia.shield.core.DeviceSecurity
import sk.alexia.shield.protection.RealtimeProtectionService
import sk.alexia.shield.update.AppUpdater
import sk.alexia.shield.core.Prefs
import sk.alexia.shield.audit.DeviceReport
import sk.alexia.shield.audit.PrivacyAuditor

class MainViewModel(app: Application) : AndroidViewModel(app) {

    private val _report = MutableStateFlow<DeviceReport?>(null)
    val report: StateFlow<DeviceReport?> = _report.asStateFlow()

    /** (hotové, spolu) počas auditu, inak null. */
    private val _progress = MutableStateFlow<Pair<Int, Int>?>(null)
    val progress: StateFlow<Pair<Int, Int>?> = _progress.asStateFlow()

    private val _includeSystem = MutableStateFlow(false)
    val includeSystem: StateFlow<Boolean> = _includeSystem.asStateFlow()

    private val _malwareKeySet = MutableStateFlow(MalwareChecker.hasKey(app))
    val malwareKeySet: StateFlow<Boolean> = _malwareKeySet.asStateFlow()

    /** Správa po overení kľúča (null = nič na zobrazenie). */
    private val _keyMessage = MutableStateFlow<String?>(null)
    val keyMessage: StateFlow<String?> = _keyMessage.asStateFlow()

    private val _verifyingKey = MutableStateFlow(false)
    val verifyingKey: StateFlow<Boolean> = _verifyingKey.asStateFlow()

    // --- Offline databáza malvéru ---
    private val _dbSize = MutableStateFlow(0)
    val dbSize: StateFlow<Int> = _dbSize.asStateFlow()
    private val _dbUpdated = MutableStateFlow(0L)
    val dbUpdated: StateFlow<Long> = _dbUpdated.asStateFlow()
    private val _dbBusy = MutableStateFlow(false)
    val dbBusy: StateFlow<Boolean> = _dbBusy.asStateFlow()
    private val _dbMessage = MutableStateFlow<String?>(null)
    val dbMessage: StateFlow<String?> = _dbMessage.asStateFlow()

    // --- Ochrana v reálnom čase ---
    private val _realtime = MutableStateFlow(Prefs.realtimeEnabled(app))
    val realtime: StateFlow<Boolean> = _realtime.asStateFlow()

    // --- Kontrola APK súboru ---
    private val _apkVerdict = MutableStateFlow<ApkFileScanner.Verdict?>(null)
    val apkVerdict: StateFlow<ApkFileScanner.Verdict?> = _apkVerdict.asStateFlow()
    private val _apkScanning = MutableStateFlow(false)
    val apkScanning: StateFlow<Boolean> = _apkScanning.asStateFlow()

    // --- Bezpečnosť zariadenia ---
    private val _deviceChecks = MutableStateFlow<List<DeviceSecurity.Check>>(emptyList())
    val deviceChecks: StateFlow<List<DeviceSecurity.Check>> = _deviceChecks.asStateFlow()

    // --- Aktualizácie ---
    private val _update = MutableStateFlow<AppUpdater.Check?>(null)
    val update: StateFlow<AppUpdater.Check?> = _update.asStateFlow()
    private val _updating = MutableStateFlow(false)
    val updating: StateFlow<Boolean> = _updating.asStateFlow()
    private val _updateMessage = MutableStateFlow<String?>(null)
    val updateMessage: StateFlow<String?> = _updateMessage.asStateFlow()
    private val _autoUpdate = MutableStateFlow(Prefs.autoUpdate(app))
    val autoUpdate: StateFlow<Boolean> = _autoUpdate.asStateFlow()

    init {
        runAudit()
        refreshDb()
        refreshDevice()
        checkUpdate()
    }

    private fun refreshDb() {
        viewModelScope.launch(Dispatchers.IO) {
            _dbSize.value = MalwareDatabase.size(getApplication())
            _dbUpdated.value = MalwareDatabase.lastUpdated(getApplication())
        }
    }

    fun updateDatabase(thenAudit: Boolean = false) {
        val key = Prefs.malwareApiKey(getApplication())
        if (key.isBlank() || _dbBusy.value) return
        _dbBusy.value = true
        _dbMessage.value = null
        viewModelScope.launch {
            val r = withContext(Dispatchers.IO) { MalwareDatabase.update(getApplication(), key) }
            _dbBusy.value = false
            _dbMessage.value = r.fold(
                { n -> if (n > 0) "Pridaných $n nových vzoriek malvéru" else "Databáza je aktuálna" },
                { e -> "Aktualizácia databázy zlyhala: ${e.message}" },
            )
            refreshDb()
            if (thenAudit) runAudit()
        }
    }

    fun setRealtime(on: Boolean) {
        Prefs.setRealtimeEnabled(getApplication(), on)
        _realtime.value = on
        if (on) RealtimeProtectionService.start(getApplication()) else RealtimeProtectionService.stop(getApplication())
    }

    fun scanApk(uri: Uri, name: String) {
        if (_apkScanning.value) return
        _apkScanning.value = true
        _apkVerdict.value = null
        viewModelScope.launch {
            _apkVerdict.value = ApkFileScanner.scan(getApplication(), uri, name)
            _apkScanning.value = false
        }
    }

    fun clearApkVerdict() { _apkVerdict.value = null }

    fun refreshDevice() {
        viewModelScope.launch(Dispatchers.IO) { _deviceChecks.value = DeviceSecurity.run(getApplication()) }
    }

    fun checkUpdate() {
        viewModelScope.launch { _update.value = AppUpdater.check(getApplication()) }
    }

    fun installUpdate() {
        val available = _update.value as? AppUpdater.Check.Available ?: return
        if (_updating.value) return
        _updating.value = true
        _updateMessage.value = "Sťahujem ${available.release.name}…"
        viewModelScope.launch {
            val error = AppUpdater.downloadAndInstall(getApplication(), available.release)
            _updating.value = false
            _updateMessage.value = error ?: "Inštalujem… appka sa o chvíľu reštartuje."
        }
    }

    fun setAutoUpdate(on: Boolean) {
        Prefs.setAutoUpdate(getApplication(), on)
        _autoUpdate.value = on
    }

    fun saveMalwareKey(key: String) {
        val trimmed = key.trim()
        if (trimmed.isEmpty() || _verifyingKey.value) return
        _verifyingKey.value = true
        _keyMessage.value = null
        viewModelScope.launch {
            val error = withContext(Dispatchers.IO) { MalwareChecker.verifyKey(trimmed) }
            _verifyingKey.value = false
            if (error == null) {
                Prefs.setMalwareApiKey(getApplication(), trimmed)
                _malwareKeySet.value = true
                _keyMessage.value = "Kľúč je platný ✓ Sťahujem databázu malvéru…"
                updateDatabase(thenAudit = true)
            } else {
                _keyMessage.value = error
            }
        }
    }

    fun removeMalwareKey() {
        Prefs.setMalwareApiKey(getApplication(), "")
        _malwareKeySet.value = false
        _keyMessage.value = null
    }

    fun setIncludeSystem(value: Boolean) {
        if (_includeSystem.value == value) return
        _includeSystem.value = value
        runAudit()
    }

    fun runAudit() {
        if (_progress.value != null) return
        _progress.value = 0 to 0
        viewModelScope.launch {
            try {
                _report.value = PrivacyAuditor.scan(getApplication(), _includeSystem.value) { done, total ->
                    _progress.value = done to total
                }
            } finally {
                _progress.value = null
                if (_keyMessage.value?.startsWith("Kľúč je platný") == true) _keyMessage.value = null
            }
        }
    }
}
