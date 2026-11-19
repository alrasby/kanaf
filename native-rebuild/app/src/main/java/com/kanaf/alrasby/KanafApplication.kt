package com.kanaf.alrasby

import android.app.Application
import android.content.Intent
import android.content.IntentFilter
import android.os.Build
import androidx.core.content.ContextCompat
import com.kanaf.alrasby.engine.InstallWatchScheduler
import com.kanaf.alrasby.engine.PackageChangeReceiver
import com.kanaf.alrasby.engine.ProtectionControl

class KanafApplication : Application() {
    override fun onCreate() {
        super.onCreate()
        val process = if (Build.VERSION.SDK_INT >= 28) Application.getProcessName() else {
            getSystemService(android.app.ActivityManager::class.java)?.runningAppProcesses
                ?.firstOrNull { it.pid == android.os.Process.myPid() }?.processName
        }
        if (process != packageName) return // Never register duplicate scanner-process listeners.
        val filter = IntentFilter(Intent.ACTION_PACKAGE_ADDED).apply {
            addAction(Intent.ACTION_PACKAGE_REPLACED)
            addDataScheme("package")
        }
        ContextCompat.registerReceiver(this, PackageChangeReceiver(), filter, ContextCompat.RECEIVER_NOT_EXPORTED)
        if (ProtectionControl.installWatchEnabled(this)) InstallWatchScheduler.schedule(this)
    }
}
