package com.kanaf.alrasby.engine

import android.app.ActivityManager
import android.content.Context
import com.kanaf.alrasby.BuildConfig
import java.io.File

/** Only called by the serial scanner worker. The APK contains original, unmodified Cisco CVDs. */
internal object OfficialClamDatabase {
    private val names = listOf("main.cvd", "daily.cvd", "bytecode.cvd")
    private val digests = BuildConfig.KANAF_OFFICIAL_CLAM_DIGESTS.split(',')
    private val limit = 256L * 1024 * 1024
    val bundled = digests.size == names.size && digests.all(ProductionNativeRulePolicy::validHash)
    private var staged: File? = null

    fun prepare(context: Context): File {
        check(bundled)
        staged?.let { return it }
        val memory = ActivityManager.MemoryInfo()
        val manager = context.getSystemService(ActivityManager::class.java)
        manager.getMemoryInfo(memory)
        // Cisco recommends 3 GiB RAM. Keep the established mobile engine available on smaller devices.
        check(!manager.isLowRamDevice && !memory.lowMemory &&
            memory.totalMem >= 3L * 1024 * 1024 * 1024 &&
            memory.availMem >= 1200L * 1024 * 1024) {
            "clamav-official-device-memory"
        }
        val root = File(context.noBackupFilesDir, "official-clamav")
        check(root.isDirectory || root.mkdirs())
        val folder = File(root, digests.joinToString("-") { it.take(16) })
        check(folder.isDirectory || folder.mkdirs())
        names.zip(digests).forEach { (name, sha) ->
            val file = File(folder, name)
            if (file.isFile && StagedFileIntegrity.verify(file, sha, file.length())) return@forEach
            val partial = File(folder, "$name.partial")
            try {
                val copied = context.assets.open("official-clamav/$name").use { input ->
                    partial.outputStream().use { BoundedStreamCopier(maxBytes = limit).copy(input, it) }
                }
                check(copied is BoundedStreamCopier.Result.Complete && copied.sha256 == sha)
                check(partial.renameTo(file))
            } finally {
                partial.delete()
            }
        }
        root.listFiles()?.filter { it.isDirectory && it != folder }?.forEach { it.deleteRecursively() }
        staged = folder
        return folder
    }
}
