package com.kanaf.alrasby.engine

import java.io.InputStream
import java.io.OutputStream
import java.security.MessageDigest

/** Copies untrusted bytes without buffering the full file. Callers own stream closing and temporary-file cleanup. */
class BoundedStreamCopier(
    private val maxBytes: Long = 16L * 1024 * 1024,
    private val maxDurationNanos: Long = 30L * 1_000_000_000,
    private val nanoTime: () -> Long = System::nanoTime
) {
    init { require(maxBytes > 0 && maxDurationNanos > 0) }

    sealed interface Result {
        data class Complete(val sha256: String, val bytesCopied: Long) : Result
        data class Incomplete(val reason: String, val bytesCopied: Long) : Result
    }

    /** Cooperative deadline: a permanently blocked InputStream or native parser still requires isolation. */
    fun copy(source: InputStream, dest: OutputStream, cancelled: () -> Boolean = { false }): Result {
        val started = nanoTime()
        val hash = MessageDigest.getInstance("SHA-256")
        val buffer = ByteArray(64 * 1024)
        var total = 0L
        var emptyReads = 0
        fun stopped(): String? = when {
            cancelled() -> "cancelled"
            nanoTime() - started >= maxDurationNanos -> "time-limit"
            else -> null
        }
        while (true) {
            stopped()?.let { return Result.Incomplete(it, total) }
            val n = source.read(buffer)
            stopped()?.let { return Result.Incomplete(it, total) }
            if (n < 0) break
            if (n == 0) {
                if (++emptyReads >= 4) return Result.Incomplete("stalled-stream", total)
                continue
            }
            emptyReads = 0
            if (n.toLong() > maxBytes - total) return Result.Incomplete("size-limit", total)
            hash.update(buffer, 0, n)
            dest.write(buffer, 0, n)
            total += n
        }
        dest.flush()
        stopped()?.let { return Result.Incomplete(it, total) }
        return Result.Complete(hash.digest().joinToString("") { "%02x".format(it.toInt() and 0xff) }, total)
    }
}
