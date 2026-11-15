package com.kanaf.alrasby.engine

import java.io.DataInputStream
import java.io.ByteArrayOutputStream
import java.security.GeneralSecurityException
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import javax.crypto.Cipher
import javax.crypto.CipherOutputStream
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * Versioned AES-256-GCM envelope for local, explicitly selected files.
 * Never decrypt directly into a SAF provider: authenticate the entire bounded
 * GCM envelope before writing plaintext into private in-memory staging.
 */
internal object VaultCipher {
    private val magic = byteArrayOf('K'.code.toByte(), 'Q'.code.toByte(), '0'.code.toByte(), '1'.code.toByte())
    private const val IV_BYTES = 12
    private const val TAG_BITS = 128
    const val MAX_PLAINTEXT_BYTES = 16L * 1024 * 1024
    const val MAX_ENVELOPE_BYTES = MAX_PLAINTEXT_BYTES + 4 + IV_BYTES + TAG_BITS / 8

    fun encrypt(input: InputStream, destination: OutputStream, key: SecretKey, itemId: String): Long {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, key)
        val iv = cipher.iv
        require(iv.size == IV_BYTES) { "Unsupported vault nonce" }
        cipher.updateAAD(aad(itemId))
        destination.write(magic)
        destination.write(iv)
        return CipherOutputStream(destination, cipher).use { sealed ->
            when (val copied = BoundedStreamCopier(MAX_PLAINTEXT_BYTES).copy(input, sealed)) {
                is BoundedStreamCopier.Result.Complete -> copied.bytesCopied
                is BoundedStreamCopier.Result.Incomplete -> throw IOException("vault-copy-${copied.reason}")
            }
        }
    }

    /** Never write to staging until the AEAD tag is authenticated by Cipher.doFinal. */
    fun decrypt(input: InputStream, staging: OutputStream, key: SecretKey, itemId: String): Long {
        val source = DataInputStream(input)
        val header = ByteArray(magic.size)
        source.readFully(header)
        if (!header.contentEquals(magic)) throw IOException("vault-header-invalid")
        val iv = ByteArray(IV_BYTES)
        source.readFully(iv)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(TAG_BITS, iv))
        cipher.updateAAD(aad(itemId))
        // CipherInputStream is not suitable for authenticated decryption:
        // providers may suppress AEAD authentication exceptions during close.
        // Buffer only the already bounded ciphertext, call doFinal (which MUST
        // authenticate the tag), then write plaintext to private staging.
        val encrypted = ByteArrayOutputStream()
        val chunk = ByteArray(16 * 1024)
        val maxEncrypted = MAX_PLAINTEXT_BYTES + TAG_BITS / 8
        while (true) {
            val count = source.read(chunk)
            if (count < 0) break
            if (count > maxEncrypted - encrypted.size()) {
                throw IOException("vault-ciphertext-size-invalid")
            }
            if (count > 0) encrypted.write(chunk, 0, count)
        }
        if (encrypted.size() < TAG_BITS / 8) {
            throw IOException("vault-authentication-tag-truncated")
        }
        val ciphertext = encrypted.toByteArray()
        try {
            val plaintext = try {
                cipher.doFinal(ciphertext)
            } catch (error: GeneralSecurityException) {
                throw IOException("vault-authentication-failed", error)
            }
            try {
                if (plaintext.size.toLong() > MAX_PLAINTEXT_BYTES) {
                    throw IOException("vault-plaintext-size-invalid")
                }
                staging.write(plaintext)
                return plaintext.size.toLong()
            } finally {
                plaintext.fill(0)
            }
        } finally {
            ciphertext.fill(0)
        }
    }

    private fun aad(itemId: String): ByteArray =
        ("Kanaf:EncryptedVault:v1:" + itemId).toByteArray(Charsets.US_ASCII)
}
