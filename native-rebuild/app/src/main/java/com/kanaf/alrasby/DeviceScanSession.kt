package com.kanaf.alrasby

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.kanaf.alrasby.engine.AutomaticDeviceScan
import com.kanaf.alrasby.engine.ProtectionHealth
import java.util.concurrent.atomic.AtomicBoolean
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/** Owns user-requested scans across Activity recreation. The checkpoint contains only counters. */
internal class DeviceScanSession(application: Application) : AndroidViewModel(application) {
    data class State(
        val active: Boolean = false,
        val progress: AutomaticDeviceScan.Progress? = null,
        val result: Result<AutomaticDeviceScan.Report>? = null,
        val interruptedAt: Int? = null
    )

    private val checkpoint = application.getSharedPreferences("device_scan_checkpoint", 0)
    private val current = MutableStateFlow(State(interruptedAt =
        checkpoint.getInt("attempted", -1).takeIf { it >= 0 }))
    val state = current.asStateFlow()
    private val cancellation = AtomicBoolean(false)

    fun start(includeSharedStorage: Boolean) {
        if (current.value.active) return
        cancellation.set(false)
        current.value = State(active = true)
        viewModelScope.launch {
            val result = withContext(Dispatchers.IO) {
                checkpoint.edit().putInt("attempted", 0).commit()
                try {
                    var lastSaved = 0
                    val report = AutomaticDeviceScan().run(getApplication(), includeSharedStorage,
                        cancelled = cancellation::get, progress = { progress ->
                            current.value = State(active = true, progress = progress)
                            if (progress.attempted - lastSaved >= 48) {
                                checkpoint.edit().putInt("attempted", progress.attempted).commit()
                                lastSaved = progress.attempted
                            }
                        })
                    ProtectionHealth.recordScan(getApplication(), report.matches, report.incomplete)
                    checkpoint.edit().remove("attempted").commit()
                    Result.success(report)
                } catch (cancelled: CancellationException) {
                    throw cancelled
                } catch (failure: Exception) {
                    checkpoint.edit().remove("attempted").commit()
                    Result.failure(failure)
                }
            }
            current.value = State(result = result)
        }
    }

    fun stop() {
        cancellation.set(true)
    }

    override fun onCleared() {
        stop()
    }
}
