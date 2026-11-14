package com.kanaf.alrasby.engine

import java.io.InputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.util.zip.ZipInputStream

/**
 * Bounded DEX header validation inside APK entries.
 * Structural checks only: does not classify malware or execute code.
 */
class DexHeaderInspector(
    private val maxEntries: Int = 4096,
    private val maxDexBytes: Long = 64L * 1024 * 1024,
    private val maxTotalBytes: Long = 256L * 1024 * 1024
) {
    data class Summary(val dexFiles: Int, val invalidHeaders: Int, val bytesExpanded: Long)
    sealed interface Result {
        data class Complete(val summary: Summary) : Result
        data class Incomplete(val reason: String) : Result
    }

    fun inspect(input: InputStream, cancelled: () -> Boolean = { false }): Result {
        var entries = 0
        var dexCount = 0
        var invalid = 0
        var total = 0L
        val buffer = ByteArray(64 * 1024)
        try {
            ZipInputStream(input).use { zip ->
                while (true) {
                    if (cancelled()) return Result.Incomplete("cancelled")
                    val entry = zip.nextEntry ?: break
                    entries++
                    if (entries > maxEntries) return Result.Incomplete("entry-limit")
                    val isDex = Regex("^classes([2-9][0-9]*)?\\.dex$").matches(entry.name)
                    if (isDex) dexCount++
                    val header = ByteArray(112)
                    var headerSize = 0
                    var entryBytes = 0L
                    while (true) {
                        if (cancelled()) return Result.Incomplete("cancelled")
                        val n = zip.read(buffer)
                        if (n < 0) break
                        if (n == 0) continue
                        if (n.toLong() > maxTotalBytes - total) return Result.Incomplete("expanded-size-limit")
                        if (isDex && n.toLong() > maxDexBytes - entryBytes) return Result.Incomplete("dex-size-limit")
                        if (isDex && headerSize < header.size) {
                            val copy = minOf(n, header.size - headerSize)
                            System.arraycopy(buffer, 0, header, headerSize, copy)
                            headerSize += copy
                        }
                        total += n
                        entryBytes += n
                    }
                    if (isDex && !validDexHeader(header, headerSize, entryBytes)) invalid++
                    zip.closeEntry()
                }
            }
        } catch (_: Exception) {
            return Result.Incomplete("invalid-or-unreadable-apk")
        }
        if (dexCount == 0) return Result.Incomplete("no-dex-files")
        return Result.Complete(Summary(dexCount, invalid, total))
    }

    companion object {
        fun validDexHeader(header: ByteArray, count: Int, actualBytes: Long): Boolean {
            if (count < 112 || actualBytes < 112) return false
            if (header[0] != 'd'.code.toByte() || header[1] != 'e'.code.toByte() ||
                header[2] != 'x'.code.toByte() || header[3] != '\n'.code.toByte() ||
                header[7] != 0.toByte() || header[4] !in '0'.code.toByte()..'9'.code.toByte() ||
                header[5] !in '0'.code.toByte()..'9'.code.toByte() ||
                header[6] !in '0'.code.toByte()..'9'.code.toByte()) return false
            val view = ByteBuffer.wrap(header).order(ByteOrder.LITTLE_ENDIAN)
            val declaredSize = view.getInt(32).toLong() and 0xffffffffL
            val headerSize = view.getInt(36)
            val endianTag = view.getInt(40)
            return declaredSize == actualBytes && headerSize == 112 && endianTag == 0x12345678
        }
    }
}
