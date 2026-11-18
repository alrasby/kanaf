package com.kanaf.alrasby.engine

import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.pm.ApplicationInfo
import android.content.ServiceConnection
import android.net.Uri
import android.os.Bundle
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
    fun execute(context: Context, mode: Int, uri: Uri?): NativeScannerBridge.Report {
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
        val done = CountDownLatch(1)
        val response = AtomicReference<NativeScannerBridge.Report>()
        fun finish(result: NativeScannerBridge.Report) {
            if (response.compareAndSet(null, result)) done.countDown()
        }
        val callback = Messenger(Handler(Looper.getMainLooper()) { msg ->
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
            override fun onServiceConnected(name: ComponentName, binder: IBinder) {
                try {
                    val request = Message.obtain(null, mode)
                    request.replyTo = callback
                    request.data = Bundle().apply {
                        if (uri != null) putParcelable(NativeScanProtocol.URI_KEY, uri)
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
                    val waitSeconds = if (mode == NativeScanProtocol.REQUEST_DEBUG_CRASH) 20L else 100L
                    if (!done.await(waitSeconds, TimeUnit.SECONDS)) {
                        NativeScanProtocol.unavailable("scanner-timeout")
                    } else {
                        response.get() ?: NativeScanProtocol.unavailable("scanner-missing-response")
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
}
