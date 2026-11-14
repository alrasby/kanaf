package com.kanaf.alrasby.engine

import java.io.InputStream
import java.util.zip.ZipEntry
import java.util.zip.ZipInputStream

/** Bounded archive inspection. It never executes or extracts archive paths. */
class ZipInspector(
    private val maxEntries: Int = 2_000,
    private val maxEntryBytes: Long = 32L * 1024 * 1024,
    private val maxTotalBytes: Long = 128L * 1024 * 1024,
    private val maxDurationNanos: Long = 20L * 1_000_000_000,
    private val nanoTime: () -> Long = System::nanoTime
) {
    init { require(maxEntries > 0 && maxEntryBytes > 0 && maxTotalBytes > 0 && maxDurationNanos > 0) }
    data class Summary(val entries: Int, val bytesExpanded: Long, val unsafeNames: Int)
    sealed interface Result {
        data class Complete(val summary: Summary) : Result
        data class Incomplete(val reason: String, val summary: Summary) : Result
    }
    fun inspect(stream: InputStream, cancelled: () -> Boolean = { false }): Result {
        val startedAt = nanoTime()
        var count = 0
        var total = 0L
        var unsafe = 0
        val buffer = ByteArray(64 * 1024)
        var emptyReads = 0
        fun summary() = Summary(count, total, unsafe)
        fun interrupted(): String? = when {
            cancelled() -> "cancelled"
            nanoTime() - startedAt >= maxDurationNanos -> "time-limit"
            else -> null
        }
        try {
            ZipInputStream(stream).use { zip ->
                while (true) {
                    interrupted()?.let { return Result.Incomplete(it, summary()) }
                    val entry: ZipEntry = zip.nextEntry ?: break
                    interrupted()?.let { return Result.Incomplete(it, summary()) }
                    count++
                    if (count > maxEntries) return Result.Incomplete("entry-limit", summary())
                    val normalized = entry.name.replace('\\', '/')
                    if (normalized.startsWith('/') ||
                        (normalized.length >= 3 && normalized[0].isLetter() && normalized[1] == ':' && normalized[2] == '/') ||
                        normalized.split('/').any { it == ".." }) unsafe++
                    if (!entry.isDirectory) {
                        var entryBytes = 0L
                        emptyReads = 0
                        while (true) {
                            interrupted()?.let { return Result.Incomplete(it, summary()) }
                            val read = zip.read(buffer)
                            interrupted()?.let { return Result.Incomplete(it, summary()) }
                            if (read < 0) break
                            if (read == 0) {
                                if (++emptyReads >= 16) return Result.Incomplete("stalled-stream", summary())
                                continue
                            }
                            emptyReads = 0
                            if (read.toLong() > maxEntryBytes - entryBytes)
                                return Result.Incomplete("entry-size-limit", summary())
                            if (read.toLong() > maxTotalBytes - total)
                                return Result.Incomplete("total-size-limit", summary())
                            entryBytes += read
                            total += read
                        }
                    }
                    interrupted()?.let { return Result.Incomplete(it, summary()) }
                    zip.closeEntry()
                }
            }
            interrupted()?.let { return Result.Incomplete(it, summary()) }
            return Result.Complete(summary())
        } catch (_: Exception) {
            return Result.Incomplete("invalid-or-unreadable-archive", summary())
        }
    }
}
