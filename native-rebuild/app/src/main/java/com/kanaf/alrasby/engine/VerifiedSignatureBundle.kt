package com.kanaf.alrasby.engine

import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.InputStream
import java.io.OutputStream
import java.security.MessageDigest

/**
 * Single bounded on-disk unit for a previously authenticated signature feed.
 * The SHA-256 detects corruption; it is NOT a substitute for verifying a signed
 * manifest against an app-pinned production key before installation.
 */
internal object VerifiedSignatureBundle {
    private const val MAGIC = 0x4b4e5347 // KNSG
    private const val FORMAT = 1
    const val MAX_DATABASE_BYTES = 32 * 1024 * 1024
    private val SHA256 = Regex("[0-9a-f]{64}")

    data class Record(val version: Long, val sha256: String, val bytes: ByteArray)

    fun write(out: OutputStream, version: Long, sha256: String, bytes: ByteArray) {
        require(version > 0 && SHA256.matches(sha256)) { "Invalid signature bundle metadata" }
        require(bytes.isNotEmpty() && bytes.size <= MAX_DATABASE_BYTES) { "Invalid database size" }
        val actual = MessageDigest.getInstance("SHA-256").digest(bytes)
        require(actual.contentEquals(hexToBytes(sha256))) { "Database digest mismatch" }
        DataOutputStream(out).apply {
            writeInt(MAGIC)
            writeInt(FORMAT)
            writeLong(version)
            writeInt(bytes.size)
            write(actual)
            write(bytes)
            flush()
        }
    }

    fun read(input: InputStream): Record = DataInputStream(input).use { source ->
        require(source.readInt() == MAGIC && source.readInt() == FORMAT) {
            "Invalid signature bundle format"
        }
        val version = source.readLong()
        val size = source.readInt()
        require(version > 0 && size > 0 && size <= MAX_DATABASE_BYTES) {
            "Invalid signature bundle version or length"
        }
        val expected = ByteArray(32)
        source.readFully(expected)
        val bytes = ByteArray(size)
        source.readFully(bytes)
        require(source.read() == -1) { "Trailing signature bundle data" }
        val actual = MessageDigest.getInstance("SHA-256").digest(bytes)
        require(MessageDigest.isEqual(expected, actual)) { "Signature bundle digest mismatch" }
        Record(version, actual.joinToString("") { "%02x".format(it.toInt() and 0xff) }, bytes)
    }

    /** The legacy version floor is retained after migration; it may never be bypassed. */
    fun requireNewer(candidateVersion: Long, currentVersion: Long, legacyVersion: Long) {
        require(candidateVersion > 0 && currentVersion >= 0 && legacyVersion >= 0) {
            "Invalid database version"
        }
        require(candidateVersion > maxOf(currentVersion, legacyVersion)) {
            "Database version rollback rejected"
        }
    }

    private fun hexToBytes(value: String): ByteArray = ByteArray(value.length / 2) { index ->
        value.substring(index * 2, index * 2 + 2).toInt(16).toByte()
    }
}
