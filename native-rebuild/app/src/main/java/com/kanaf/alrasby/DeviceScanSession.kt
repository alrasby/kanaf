package com.kanaf.alrasby

import android.app.ActivityManager
import android.app.Application
import android.app.ApplicationExitInfo
import android.os.Build
import android.os.Process
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.kanaf.alrasby.engine.AutomaticDeviceScan
import com.kanaf.alrasby.engine.ProtectionHealth
import java.util.concurrent.atomic.AtomicBoolean
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/** Owns scans across Activity recreation and keeps a local, file-name-free checkpoint. */
internal class DeviceScanSession(application: Application) : AndroidViewModel(application) {
    data class State(
        val active: Boolean = false,
        val progress: AutomaticDeviceScan.Progress? = null,
        val result: Result<AutomaticDeviceScan.Report>? = null,
        val interruption: Interruption? = null
    )

    data class Interruption(
        val attempted: Int, val phase: String, val build: String?, val exitReason: Int? = null
    )

    private val checkpoint = application.getSharedPreferences("device_scan_checkpoint", 0)
    private val current = MutableStateFlow(State(interruption =
        checkpoint.getInt("attempted", -1).takeIf { it >= 0 }?.let {
            Interruption(it, checkpoint.getString("phase", "").orEmpty(),
                checkpoint.getString("build", null))
        }))
    val state = current.asStateFlow()
    private val cancellation = AtomicBoolean(false)

    init {
        val previous = current.value.interruption
        if (previous != null && Build.VERSION.SDK_INT >= 30) {
            val pid = checkpoint.getInt("pid", 0)
            val started = checkpoint.getLong("started", 0L)
            if (pid > 0 && pid != Process.myPid() && started > 0) {
                viewModelScope.launch {
                    val reason = withContext(Dispatchers.IO) {
                        runCatching {
                            val manager = application.getSystemService(ActivityManager::class.java)
                            manager.getHistoricalProcessExitReasons(application.packageName, pid, 8)
                                .firstOrNull { it.processName == application.packageName &&
                                    it.timestamp >= started }?.reason
                        }.getOrNull()
                    }
                    current.update { state ->
                        if (state.interruption === previous) state.copy(
                            interruption = previous.copy(exitReason = reason)) else state
                    }
                }
            }
        }
    }

    fun start(includeSharedStorage: Boolean) {
        if (current.value.active) return
        cancellation.set(false)
        current.value = State(active = true, progress = AutomaticDeviceScan.Progress(0, 0, "inventory"))
        viewModelScope.launch {
            val result = withContext(Dispatchers.IO) {
                try {
                    checkpoint.edit().putInt("attempted", 0).putInt("pid", Process.myPid())
                        .putLong("started", System.currentTimeMillis()).putString("phase", "inventory")
                        .putString("build", BuildConfig.KANAF_BUILD_REVISION).commit()
                    var lastSaved = 0
                    var phase = "inventory"
                    val report = AutomaticDeviceScan().run(getApplication(), includeSharedStorage,
                        cancelled = cancellation::get, progress = { progress ->
                            current.value = State(active = true, progress = progress)
                            if (progress.attempted - lastSaved >= 48 || progress.phase != phase) {
                                checkpoint.edit().putInt("attempted", progress.attempted)
                                    .putString("phase", progress.phase).commit()
                                lastSaved = progress.attempted
                                phase = progress.phase
                            }
                        })
                    ProtectionHealth.recordScan(getApplication(), report.matches, report.incomplete)
                    checkpoint.edit().clear().commit()
                    Result.success(report)
                } catch (cancelled: CancellationException) {
                    throw cancelled
                } catch (failure: Exception) {
                    checkpoint.edit().clear().commit()
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

internal fun DeviceScanSession.Interruption.description(): KanafMessage {
    val phaseAr = when (phase) {
        "inventory" -> "حصر التطبيقات"
        "apps" -> "التطبيقات المثبتة"
        "files" -> "الملفات المشتركة"
        "done" -> "حفظ النتيجة"
        else -> "غير معروفة"
    }
    val phaseEn = when (phase) {
        "inventory" -> "listing installed apps"
        "apps" -> "installed apps"
        "files" -> "shared files"
        "done" -> "saving the result"
        else -> "unknown"
    }
    val reason = when (exitReason) {
        ApplicationExitInfo.REASON_CRASH -> KanafMessage("انهيار التطبيق", "App crash")
        ApplicationExitInfo.REASON_CRASH_NATIVE -> KanafMessage("انهيار في الكود الأصلي للتطبيق", "Native app crash")
        ApplicationExitInfo.REASON_LOW_MEMORY -> KanafMessage("أوقف أندرويد التطبيق بسبب الذاكرة", "Android stopped the app due to memory pressure")
        ApplicationExitInfo.REASON_ANR -> KanafMessage("توقف التطبيق عن الاستجابة", "App stopped responding")
        null -> KanafMessage("لم يبلّغ أندرويد عن السبب", "Android did not report a reason")
        else -> KanafMessage("رمز أندرويد $exitReason", "Android code $exitReason")
    }
    return KanafMessage(
        "توقف فحص الجهاز. آخر مرحلة محفوظة: $phaseAr · آخر عدّاد: $attempted. ${reason.ar}. البناء ${build ?: "غير معروف"}.",
        "Device scan interrupted. Last saved phase: $phaseEn · Last counter: $attempted. ${reason.en}. Build ${build ?: "unknown"}."
    )
}
