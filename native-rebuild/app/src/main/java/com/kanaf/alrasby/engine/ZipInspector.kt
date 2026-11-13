package com.kanaf.alrasby.engine

import java.io.InputStream
import java.util.zip.ZipEntry
import java.util.zip.ZipInputStream

/** Bounded archive inspection. It does not execute or extract archive paths. */
class ZipInspector(
    private val maxEntries: Int = 2_000,
    private val maxEntryBytes: Long = 32L * 1024 * 1024,
    private val maxTotalBytes: Long = 128L * 1024 * 1024
) {
    init { require(maxEntries > 0 && maxEntryBytes > 0 && maxTotalBytes > 0) }
    data class Summary(val entries: Int, val bytesExpanded: Long, val unsafeNames: Int)
    sealed interface Result {
        data class Complete(val summary: Summary) : Result
        data class Incomplete(val reason: String, val summary: Summary) : Result
    }
    fun inspect(stream: InputStream, cancelled: () -> Boolean = { false }): Result {
        var count = 0
        var total = 0L
        var unsafe = 0
        val buffer = ByteArray(64 * 1024)
        try {
            ZipInputStream(stream).use { zip ->
                while (true) {
                    if (cancelled()) return Result.Incomplete("cancelled", Summary(count, total, unsafe))
                    val entry: ZipEntry = zip.nextEntry ?: break
                    count++
                    if (count > maxEntries) return Result.Incomplete("entry-limit", Summary(count, total, unsafe))
                    if (entry.name.startsWith("/") || entry.name.startsWith("\\") ||
                        entry.name.replace('\\', '/').split('/').any { it == ".." }) unsafe++
                    if (!entry.isDirectory) {
                        var entryBytes = 0L
                        while (true) {
                            if (cancelled()) return Result.Incomplete("cancelled", Summary(count, total, unsafe))
                            val read = zip.read(buffer)
                            if (read < 0) break
                            if (read == 0) continue
                            if (read.toLong() > maxEntryBytes - entryBytes)
                                return Result.Incomplete("entry-size-limit", Summary(count, total, unsafe))
                            if (read.toLong() > maxTotalBytes - total)
                                return Result.Incomplete("total-size-limit", Summary(count, total, unsafe))
                            entryBytes += read
                            total += read
                        }
                    }
                    zip.closeEntry()
                }
            }
            return Result.Complete(Summary(count, total, unsafe))
        } catch (_: Exception) {
            return Result.Incomplete("invalid-or-unreadable-archive", Summary(count, total, unsafe))
        }
    }
}
