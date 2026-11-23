package com.kanaf.alrasby.engine

import android.app.Service
import android.content.Intent
import android.content.pm.ApplicationInfo
import android.net.Uri
import android.os.Bundle
import android.os.Handler
import android.os.IBinder
import android.os.Looper
import android.os.Message
import android.os.Messenger
import android.os.Process
import android.util.Log
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Runs native parsing in a distinct app-private process (:scanner), not in the
 * UI process. This is crash containment, NOT a separate security UID or sandbox.
 */
class NativeScannerService : Service() {
    private val mainHandler = Handler(Looper.getMainLooper())
    private val running = AtomicBoolean(false)

    private val incoming = Messenger(object : Handler(Looper.getMainLooper()) {
        override fun handleMessage(message: Message) {
            if (message.what == NativeScanProtocol.REQUEST_DEBUG_CRASH) {
                // Only the non-exported service in a DEBUGGABLE app can be terminated by tests.
                // No production release can activate this fault injection path.
                if (applicationInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE == 0) {
                    message.replyTo?.let {
                        send(it, NativeScanProtocol.unavailable("debug-crash-disabled"))
                    }
                    return
                }
                if (message.replyTo == null) return
                Process.killProcess(Process.myPid())
                return
            }
            if (message.what != NativeScanProtocol.REQUEST_FILE &&
                message.what != NativeScanProtocol.REQUEST_SELF_TEST) {
                return
            }
            val reply = message.replyTo ?: return
            if (!running.compareAndSet(false, true)) {
                send(reply, NativeScanProtocol.unavailable("scanner-busy"))
                return
            }
            val uri: Uri? = try {
                @Suppress("DEPRECATION")
                message.data.getParcelable(NativeScanProtocol.URI_KEY)
            } catch (_: Exception) { null }
            if (message.what == NativeScanProtocol.REQUEST_FILE && uri == null) {
                running.set(false)
                send(reply, NativeScanProtocol.unavailable("scan-uri-unavailable"))
                return
            }
            // Independent main-looper watchdog: kills only :scanner if JNI/IO hangs.
            // The bound client receives a disconnect or its own timeout; never CLEAN.
            val requestType = message.what
            val allowOfficial = message.data.getBoolean(NativeScanProtocol.ALLOW_OFFICIAL_KEY, true)
            val allowYara = message.data.getBoolean(NativeScanProtocol.ALLOW_YARA_KEY, true)
            val debugStopAtYara = applicationInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE != 0 &&
                message.data.getBoolean(NativeScanProtocol.DEBUG_STOP_AT_YARA_KEY)
            val deadlineMs = NativeScanProtocol.watchdogMs(requestType, allowOfficial && OfficialClamDatabase.bundled)
            val watchdog = Runnable {
                Log.w("KanafScanner", "Scanner watchdog expired for request type $requestType")
                send(reply, NativeScanProtocol.unavailable("scanner-watchdog-timeout"))
                Process.killProcess(Process.myPid())
            }
            mainHandler.postDelayed(watchdog, deadlineMs)
            Thread({
                val result = try {
                    if (requestType == NativeScanProtocol.REQUEST_SELF_TEST) {
                        NativeScannerBridge.selfTestInWorker(this@NativeScannerService)
                    } else {
                        NativeScannerBridge.scanInWorker(
                            this@NativeScannerService, requireNotNull(uri), allowOfficial, allowYara
                        ) { stage ->
                            val update = Message.obtain(null, NativeScanProtocol.RESPONSE_STAGE)
                            update.arg1 = stage.ordinal
                            try { reply.send(update) } catch (_: Exception) { /* Client ended the request. */ }
                            if (debugStopAtYara && stage == NativeScanProtocol.Stage.YARA_X) {
                                Process.killProcess(Process.myPid())
                            }
                        }
                    }
                } catch (failure: Exception) {
                    Log.w("KanafScanner", "Worker exception: " + failure.javaClass.simpleName)
                    NativeScanProtocol.unavailable("worker-scan-failed")
                } catch (_: OutOfMemoryError) {
                    Log.e("KanafScanner", "Worker exhausted its Java heap")
                    NativeScanProtocol.unavailable("scanner-worker-out-of-memory")
                } catch (_: UnsatisfiedLinkError) {
                    NativeScanProtocol.unavailable("native-library-failed")
                }
                mainHandler.post {
                    mainHandler.removeCallbacks(watchdog)
                    running.set(false)
                    send(reply, result)
                }
            }, "kanaf-scanner-worker").start()
        }
    })

    override fun onBind(intent: Intent?): IBinder = incoming.binder

    override fun onCreate() {
        super.onCreate()
        // A crashed worker may leave partial copies; clear only scanner-owned names.
        val names = listOf("kanaf-scan-", "kanaf-clam-", "kanaf-eicar-", "kanaf-benign-")
        cacheDir.listFiles()?.forEach { file ->
            if (file.isFile && names.any { file.name.startsWith(it) }) file.delete()
        }
    }

    private fun send(target: Messenger, result: NativeScannerBridge.Report) {
        val response = Message.obtain(null, NativeScanProtocol.RESPONSE)
        response.data = Bundle().also { data ->
            NativeScanProtocol.encode(result).forEach { (key, value) ->
                data.putString(key, value)
            }
        }
        try { target.send(response) } catch (_: Exception) { /* Caller may have unbound. */ }
    }
}
