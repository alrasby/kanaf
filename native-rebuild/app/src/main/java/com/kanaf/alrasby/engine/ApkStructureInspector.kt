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
    private val maxExpandedBytes: Long = 256L * 1024 * 1024
) {
    init { require(maxEntries > 0 && maxEntryBytes > 0 && maxExpandedBytes > 0) }

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

    fun inspect(input: InputStream, cancelled: () -> Boolean = { false }): Result {
        var entries = 0
        var dex = 0
        var libraries = 0
        var manifest = false
        var resources = false
        var unsafe = 0
        var total = 0L
        val names = HashSet<String>()
        val buffer = ByteArray(64 * 1024)
        try {
            ZipInputStream(input).use { zip ->
                while (true) {
                    if (cancelled()) return Result.Incomplete("cancelled")
                    val entry = zip.nextEntry ?: break
                    entries++
                    if (entries > maxEntries) return Result.Incomplete("entry-limit")
                    val name = entry.name
                    val normalized = name.replace('\\', '/')
                    if (normalized.startsWith("/") || normalized.split('/').any { it == ".." } ||
                        name.contains('\\') || !names.add(normalized)) unsafe++
                    if (normalized == "AndroidManifest.xml") manifest = true
                    if (normalized == "resources.arsc") resources = true
                    if (Regex("^classes([2-9][0-9]*)?\\.dex$").matches(normalized)) dex++
                    if (Regex("^lib/[^/]+/[^/]+\\.so$").matches(normalized)) libraries++
                    var entryBytes = 0L
                    if (!entry.isDirectory) {
                        while (true) {
                            if (cancelled()) return Result.Incomplete("cancelled")
                            val n = zip.read(buffer)
                            if (n < 0) break
                            if (n == 0) continue
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
        if (!manifest || dex == 0) return Result.Incomplete("missing-required-apk-components")
        return Result.Complete(Summary(entries, dex, libraries, manifest, resources, unsafe, total))
    }
}
