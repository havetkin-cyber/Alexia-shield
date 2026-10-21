package sk.alexia.shield.ui

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
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

    init {
        runAudit()
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
            }
        }
    }
}
