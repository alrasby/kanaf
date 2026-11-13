package com.kanaf.alrasby.engine

import java.io.InputStream
import java.security.MessageDigest

/** A bounded, streaming local scanner primitive. No network or file modification. */
class StreamScanner(
    private val maxBytes: Long = 512L * 1024 * 1024,
    private val signatures: Map<String, String> = emptyMap()
) {
    init { require(maxBytes > 0) }
    sealed interface Result {
        data class Completed(val sha256: String, val bytesRead: Long, val signature: String?) : Result
        data class Skipped(val reason: String, val bytesRead: Long) : Result
    }
    fun scan(stream: InputStream, cancelled: () -> Boolean = { false }): Result {
        val digest = MessageDigest.getInstance("SHA-256")
        val buffer = ByteArray(64 * 1024)
        var total = 0L
        var emptyReads = 0
        while (true) {
            if (cancelled()) return Result.Skipped("cancelled", total)
            val read = stream.read(buffer)
            if (read == -1) break
            if (read == 0) {
                if (++emptyReads >= 16) return Result.Skipped("stalled-stream", total)
                continue
            }
            emptyReads = 0
            if (read.toLong() > maxBytes - total) return Result.Skipped("size-limit", total)
            digest.update(buffer, 0, read)
            total += read
        }
        val hash = digest.digest().joinToString("") { "%02x".format(it) }
        return Result.Completed(hash, total, signatures[hash.lowercase()])
    }
}
