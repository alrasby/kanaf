package com.kanaf.alrasby.engine

import java.io.DataInputStream
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import javax.crypto.Cipher
import javax.crypto.CipherInputStream
import javax.crypto.CipherOutputStream
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * Versioned AES-256-GCM envelope for local, explicitly selected files.
 * Never decrypt directly into a SAF provider: decrypt into a PRIVATE temporary
 * file and verify the authentication tag before copying any bytes outside.
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

    /** The destination MUST be private staging; incomplete/auth-failed staging is discarded. */
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
        return CipherInputStream(source, cipher).use { plaintext ->
            when (val copied = BoundedStreamCopier(MAX_PLAINTEXT_BYTES).copy(plaintext, staging)) {
                is BoundedStreamCopier.Result.Complete -> copied.bytesCopied
                is BoundedStreamCopier.Result.Incomplete -> throw IOException("vault-restore-${copied.reason}")
            }
        }
    }

    private fun aad(itemId: String): ByteArray =
        ("Kanaf:EncryptedVault:v1:" + itemId).toByteArray(Charsets.US_ASCII)
}
