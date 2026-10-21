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
import sk.alexia.shield.audit.MalwareChecker
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

    init {
        runAudit()
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
                _keyMessage.value = "Kľúč je platný ✓ Spúšťam antivírusovú kontrolu…"
                runAudit()
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
