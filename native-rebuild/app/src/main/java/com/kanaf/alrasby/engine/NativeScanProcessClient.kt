package com.kanaf.alrasby.engine

import android.app.ActivityManager
import android.app.ApplicationExitInfo
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.pm.ApplicationInfo
import android.content.ServiceConnection
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.util.Log
import android.os.Handler
import android.os.IBinder
import android.os.Looper
import android.os.Message
import android.os.Messenger
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference

/** Bounded synchronous IPC facade; MUST be invoked from Dispatchers.IO, never the UI thread. */
internal object NativeScanProcessClient {
    fun execute(context: Context, mode: Int, uri: Uri?, allowOfficial: Boolean = true,
                allowYara: Boolean = true, debugStopAtYara: Boolean = false): NativeScannerBridge.Report {
        if (Looper.myLooper() == Looper.getMainLooper()) {
            return NativeScanProtocol.unavailable("scanner-called-on-main-thread")
        }
        if (mode == NativeScanProtocol.REQUEST_DEBUG_CRASH &&
            context.applicationInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE == 0) {
            return NativeScanProtocol.unavailable("debug-crash-disabled")
        }
        if (mode != NativeScanProtocol.REQUEST_FILE &&
            mode != NativeScanProtocol.REQUEST_SELF_TEST &&
            mode != NativeScanProtocol.REQUEST_DEBUG_CRASH) {
            return NativeScanProtocol.unavailable("invalid-scan-request")
        }
        val started = System.currentTimeMillis()
        val done = CountDownLatch(1)
        val response = AtomicReference<NativeScannerBridge.Report>()
        val stage = AtomicReference<NativeScanProtocol.Stage>()
        fun finish(result: NativeScannerBridge.Report) {
            if (response.compareAndSet(null, result)) done.countDown()
        }
        val callback = Messenger(Handler(Looper.getMainLooper()) { msg ->
            if (msg.what == NativeScanProtocol.RESPONSE_STAGE) {
                NativeScanProtocol.Stage.entries.getOrNull(msg.arg1)?.let(stage::set)
                return@Handler true
            }
            if (msg.what != NativeScanProtocol.RESPONSE) return@Handler false
            val report = try {
                val data = msg.data
                val fields = NativeScanProtocol.responseKeys.associateWith { data.getString(it).orEmpty() }
                NativeScanProtocol.decode(fields)
            } catch (_: Exception) {
                NativeScanProtocol.unavailable("malformed-scanner-response")
            }
            finish(report)
            true
        })
        val connection = object : ServiceConnection {
            private var requestSent = false

            override fun onServiceConnected(name: ComponentName, binder: IBinder) {
                if (requestSent || response.get() != null) return
                requestSent = true
                try {
                    val request = Message.obtain(null, mode)
                    request.replyTo = callback
                    request.data = Bundle().apply {
                        if (uri != null) putParcelable(NativeScanProtocol.URI_KEY, uri)
                        putBoolean(NativeScanProtocol.ALLOW_OFFICIAL_KEY, allowOfficial)
                        putBoolean(NativeScanProtocol.ALLOW_YARA_KEY, allowYara)
                        if (debugStopAtYara) putBoolean(NativeScanProtocol.DEBUG_STOP_AT_YARA_KEY, true)
                    }
                    Messenger(binder).send(request)
                } catch (_: Exception) {
                    finish(NativeScanProtocol.unavailable("scanner-ipc-failed"))
                }
            }
            override fun onServiceDisconnected(name: ComponentName) {
                finish(NativeScanProtocol.unavailable("scanner-process-disconnected"))
            }
            override fun onBindingDied(name: ComponentName) {
                finish(NativeScanProtocol.unavailable("scanner-binding-died"))
            }
            override fun onNullBinding(name: ComponentName) {
                finish(NativeScanProtocol.unavailable("scanner-null-binding"))
            }
        }
        val app = context.applicationContext
        var bound = false
        return try {
            bound = app.bindService(
                Intent(app, NativeScannerService::class.java),
                connection, Context.BIND_AUTO_CREATE
            )
            if (!bound) {
                NativeScanProtocol.unavailable("scanner-bind-failed")
            } else {
                try {
                    val waitMs = if (mode == NativeScanProtocol.REQUEST_DEBUG_CRASH) 20_000L
                    else NativeScanProtocol.watchdogMs(mode, allowOfficial && OfficialClamDatabase.bundled) + 10_000L
                    if (!done.await(waitMs, TimeUnit.MILLISECONDS)) {
                        NativeScanProtocol.unavailable("scanner-timeout").copy(interruptedStage = stage.get()?.name)
                    } else {
                        val report = response.get() ?: NativeScanProtocol.unavailable("scanner-missing-response")
                        val reason = (report.clamav as? AntivirusEngine.Verdict.Incomplete)?.reason
                        if (mode == NativeScanProtocol.REQUEST_FILE &&
                            (reason == "scanner-process-disconnected" || reason == "scanner-binding-died")) {
                            val cause = exitReason(context, started)
                            (cause?.let(NativeScanProtocol::unavailable) ?: report)
                                .copy(interruptedStage = stage.get()?.name)
                        } else report.copy(interruptedStage = if (reason == "scanner-watchdog-timeout")
                            stage.get()?.name else null)
                    }
                } catch (_: InterruptedException) {
                    Thread.currentThread().interrupt()
                    NativeScanProtocol.unavailable("scanner-interrupted")
                }
            }
        } catch (_: Exception) {
            NativeScanProtocol.unavailable("scanner-process-unavailable")
        } finally {
            if (bound) try { app.unbindService(connection) } catch (_: Exception) {}
        }
    }

    private fun exitReason(context: Context, requestStarted: Long): String? {
        if (Build.VERSION.SDK_INT < 30) return null
        val manager = context.getSystemService(ActivityManager::class.java)
        val exit = runCatching { manager.getHistoricalProcessExitReasons(null, 0, 8) }
            .getOrNull()?.firstOrNull {
                it.processName == context.packageName + ":scanner" && it.timestamp >= requestStarted
            } ?: return null
        Log.w("KanafScanner", "Scanner exit reason=${exit.reason} status=${exit.status}")
        return when (exit.reason) {
            ApplicationExitInfo.REASON_CRASH_NATIVE -> "scanner-native-crash"
            ApplicationExitInfo.REASON_CRASH -> "scanner-worker-crash"
            ApplicationExitInfo.REASON_LOW_MEMORY -> "scanner-worker-out-of-memory"
            ApplicationExitInfo.REASON_ANR -> "scanner-worker-unresponsive"
            else -> null
        }
    }
}
