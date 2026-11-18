package com.kanaf.alrasby.engine

import java.security.MessageDigest

/**
 * Only a publisher-controlled, digest-pinned native rule pack may produce
 * production NoKnownMatch. A bundled EICAR-only fixture is NEVER a substitute.
 * Digests are public, supplied by the independently reviewed release build.
 */
internal object ProductionNativeRulePolicy {
    const val MAX_CLAM_BYTES = 8 * 1024 * 1024
    const val MAX_YARA_BYTES = 4 * 1024 * 1024
    private val sha256 = Regex("[0-9a-f]{64}")

    fun validHash(expected: String) = sha256.matches(expected)

    fun verified(bytes: ByteArray, expectedSha: String, limit: Int): Boolean {
        if (bytes.isEmpty() || bytes.size > limit || !validHash(expectedSha)) return false
        val actual = MessageDigest.getInstance("SHA-256").digest(bytes)
            .joinToString("") { "%02x".format(it.toInt() and 255) }
        return MessageDigest.isEqual(
            actual.toByteArray(Charsets.US_ASCII),
            expectedSha.toByteArray(Charsets.US_ASCII)
        )
    }
}
