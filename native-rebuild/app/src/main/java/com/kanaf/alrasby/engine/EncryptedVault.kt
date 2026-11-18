package com.kanaf.alrasby.engine

import android.content.Context
import android.net.Uri
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.FilterOutputStream
import java.io.FileOutputStream
import java.io.IOException
import java.security.KeyStore
import java.util.UUID
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey

/**
 * User-directed, encrypted COPY vault (not automatic quarantine).
 * The SAF source is NEVER modified, moved or deleted. No backup: Android Keystore
 * keys do not survive data-clear/reinstall, so backing up ciphertext is misleading.
 * Only ciphertext and anonymous UUIDs are persisted; no original filenames/URIs.
 */
class EncryptedVault {
    data class Entry(val id: String, val storedBytes: Long, val savedAtMillis: Long)
    private val ids = Regex("[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}")
    private val alias = "kanaf_vault_aes_gcm_v1"
    private val maxEntries = 32
    private val maxStoredBytes = 128L * 1024 * 1024

    private fun root(context: Context): File =
        File(context.noBackupFilesDir, "encrypted-vault").also {
            check(it.isDirectory || it.mkdirs()) { "vault-directory-unavailable" }
        }

    private fun file(context: Context, id: String): File {
        require(ids.matches(id)) { "Invalid vault item id" }
        return File(root(context), "$id.vault")
    }

    private fun key(): SecretKey {
        val store = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        val current = store.getKey(alias, null)
        if (current != null) return current as? SecretKey ?: error("vault-key-invalid")
        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
        generator.init(KeyGenParameterSpec.Builder(
            alias, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
        ).setKeySize(256)
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setRandomizedEncryptionRequired(true)
            .build())
        return generator.generateKey()
    }

    fun list(context: Context): List<Entry> =
        root(context).listFiles().orEmpty()
            .filter { it.isFile && !java.nio.file.Files.isSymbolicLink(it.toPath()) &&
                it.name.endsWith(".vault") && ids.matches(it.name.removeSuffix(".vault")) }
            .map { Entry(it.name.removeSuffix(".vault"), it.length(), it.lastModified()) }
            .sortedByDescending { it.savedAtMillis }

    /** Call only after explicit user choice + confirmation, on Dispatchers.IO. */
    @Synchronized
    fun store(context: Context, sourceUri: Uri): Entry {
        require(sourceUri.scheme == "content") { "Only SAF content URIs may be stored" }
        val existing = list(context)
        if (existing.size >= maxEntries) throw IOException("vault-entry-limit")
        val id = UUID.randomUUID().toString()
        val destination = file(context, id)
        val partial = File(root(context), ".$id.partial")
        try {
            val input = context.contentResolver.openInputStream(sourceUri)
                ?: throw IOException("vault-source-unavailable")
            input.use { source ->
                FileOutputStream(partial).use { output ->
                    // Close the AEAD stream and sync the completed tag before
                    // atomically publishing this encrypted file.
                    val durable = object : FilterOutputStream(output) {
                        override fun close() {
                            flush()
                            output.fd.sync()
                        }
                    }
                    VaultCipher.encrypt(source, durable, key(), id)
                }
            }
            if (partial.length() !in 32L..VaultCipher.MAX_ENVELOPE_BYTES) {
                throw IOException("vault-size-invalid")
            }
            if (existing.sumOf { it.storedBytes } + partial.length() > maxStoredBytes) {
                throw IOException("vault-storage-limit")
            }
            if (!partial.renameTo(destination)) throw IOException("vault-commit-failed")
            return Entry(id, destination.length(), destination.lastModified())
        } finally {
            partial.delete()
        }
    }

    /**
     * Decrypt and authenticate in bounded MEMORY before the first SAF write.
     * No persistent plaintext staging file survives an app crash.
     * If the destination provider fails, it may retain a partial document;
     * the caller must tell the user to discard that document.
     */
    @Synchronized
    fun restore(context: Context, id: String, destinationUri: Uri): Long {
        require(destinationUri.scheme == "content") { "Only user-selected SAF destination supported" }
        val encrypted = file(context, id)
        if (!encrypted.isFile || java.nio.file.Files.isSymbolicLink(encrypted.toPath()) ||
            encrypted.length() !in 32L..VaultCipher.MAX_ENVELOPE_BYTES) {
            throw IOException("vault-file-unavailable-or-invalid")
        }
        val staging = ByteArrayOutputStream()
        val count = encrypted.inputStream().use { source ->
            VaultCipher.decrypt(source, staging, key(), id)
        }
        val plain = staging.toByteArray()
        try {
            if (count != plain.size.toLong()) throw IOException("vault-restore-incomplete")
            val destination = context.contentResolver.openOutputStream(destinationUri, "w")
                ?: throw IOException("vault-destination-unavailable")
            destination.use { output ->
                ByteArrayInputStream(plain).use { input ->
                    when (val copied = BoundedStreamCopier(VaultCipher.MAX_PLAINTEXT_BYTES)
                        .copy(input, output)) {
                        is BoundedStreamCopier.Result.Complete ->
                            if (copied.bytesCopied != count) throw IOException("vault-restore-size-mismatch")
                        is BoundedStreamCopier.Result.Incomplete ->
                            throw IOException("vault-restore-${copied.reason}")
                    }
                }
            }
            return count
        } finally {
            plain.fill(0)
        }
    }

    /** Authenticate the stored ciphertext and stream its verified plaintext to
     * an in-memory SHA-256 sink, without writing plaintext to disk. */
    @Synchronized
    fun verifiedPlaintextDigest(context: Context, id: String): String {
        val sealed = file(context, id)
        if (!sealed.isFile || java.nio.file.Files.isSymbolicLink(sealed.toPath()) ||
            sealed.length() !in 32L..VaultCipher.MAX_ENVELOPE_BYTES) {
            throw IOException("vault-copy-invalid")
        }
        val digest = java.security.MessageDigest.getInstance("SHA-256")
        val sink = object : java.io.OutputStream() {
            override fun write(value: Int) { digest.update(value.toByte()) }
            override fun write(bytes: ByteArray, off: Int, len: Int) {
                digest.update(bytes, off, len)
            }
        }
        sealed.inputStream().use { input -> VaultCipher.decrypt(input, sink, key(), id) }
        return digest.digest().joinToString("") { "%02x".format(it.toInt() and 0xff) }
    }

    /** Deletes only the local encrypted copy; never the source or a restored file. */
    @Synchronized
    fun delete(context: Context, id: String): Boolean {
        val entry = file(context, id)
        return entry.isFile && !java.nio.file.Files.isSymbolicLink(entry.toPath()) &&
            entry.delete()
    }
}
