package com.kanaf.alrasby.engine

import java.io.InputStream
import java.util.zip.ZipInputStream

/**
 * Bounded structural APK inspection, not malware detection or manifest decoding.
 * Rejects incomplete input instead of reporting an APK as valid.
 */
class ApkStructureInspector(
    private val maxEntries: Int = 4096,
    private val maxEntryBytes: Long = 64L * 1024 * 1024,
    private val maxExpandedBytes: Long = 256L * 1024 * 1024,
    private val maxDurationNanos: Long = 25_000_000_000L,
    private val nanoTime: () -> Long = System::nanoTime
) {
    private companion object {
        val dexName = Regex("^classes(?:[2-9]|[1-9][0-9]+)?\\.dex$")
        val libraryName = Regex("^lib/[^/]+/[^/]+\\.so$")
    }
    init {
        require(maxEntries > 0 && maxEntryBytes > 0 &&
            maxExpandedBytes > 0 && maxDurationNanos > 0)
    }

    data class Summary(
        val entries: Int,
        val dexFiles: Int,
        val nativeLibraries: Int,
        val hasManifest: Boolean,
        val hasResources: Boolean,
        val unsafePaths: Int,
        val expandedBytes: Long
    )
    sealed interface Result {
        data class Complete(val summary: Summary) : Result
        data class Incomplete(val reason: String) : Result
    }

    fun inspect(input: InputStream, cancelled: () -> Boolean = { false }): Result =
        inspect(input, requireDex = true, cancelled)

    internal fun inspect(input: InputStream, requireDex: Boolean, cancelled: () -> Boolean): Result {
        val startedAt = nanoTime()
        fun stopReason(): String? = when {
            cancelled() -> "cancelled"
            nanoTime() - startedAt >= maxDurationNanos -> "time-limit"
            else -> null
        }
        var entries = 0
        var dex = 0
        var libraries = 0
        var manifest = false
        var resources = false
        var unsafe = 0
        var total = 0L
        val names = HashSet<String>()
        val buffer = ByteArray(64 * 1024)
        var zeroReads = 0
        try {
            ZipInputStream(input).use { zip ->
                while (true) {
                    stopReason()?.let { return Result.Incomplete(it) }
                    val entry = zip.nextEntry ?: break
                    stopReason()?.let { return Result.Incomplete(it) }
                    entries++
                    if (entries > maxEntries) return Result.Incomplete("entry-limit")
                    val name = entry.name
                    val normalized = name.replace('\\', '/')
                    if (normalized.startsWith("/") || normalized.split('/').any { it == ".." } ||
                        name.contains('\\') || !names.add(normalized)) unsafe++
                    if (normalized == "AndroidManifest.xml") manifest = true
                    if (normalized == "resources.arsc") resources = true
                    if (dexName.matches(normalized)) dex++
                    if (libraryName.matches(normalized)) libraries++
                    var entryBytes = 0L
                    if (!entry.isDirectory) {
                        zeroReads = 0
                        while (true) {
                            stopReason()?.let { return Result.Incomplete(it) }
                            val n = zip.read(buffer)
                            stopReason()?.let { return Result.Incomplete(it) }
                            if (n < 0) break
                            if (n == 0) {
                                if (++zeroReads >= 16) return Result.Incomplete("stalled-stream")
                                continue
                            }
                            zeroReads = 0
                            if (n.toLong() > maxEntryBytes - entryBytes) return Result.Incomplete("entry-size-limit")
                            if (n.toLong() > maxExpandedBytes - total) return Result.Incomplete("expanded-size-limit")
                            entryBytes += n
                            total += n
                        }
                    }
                    zip.closeEntry()
                }
            }
        } catch (_: Exception) {
            return Result.Incomplete("invalid-or-unreadable-apk")
        }
        stopReason()?.let { return Result.Incomplete(it) }
        if (!manifest || (requireDex && dex == 0)) return Result.Incomplete("missing-required-apk-components")
        return Result.Complete(Summary(entries, dex, libraries, manifest, resources, unsafe, total))
    }
}
