package com.kanaf.alrasby

import androidx.test.ext.junit.runners.AndroidJUnit4
import com.kanaf.alrasby.engine.VaultCipher
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.security.KeyStore
import java.util.UUID
import javax.crypto.KeyGenerator
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith

/** Real Android Keystore hardware/software provider + authenticated envelope. */
@RunWith(AndroidJUnit4::class)
class VaultAndroidKeyStoreTest {
    @Test fun actualAndroidKeystoreRoundTripAndTamperRejection() {
        val alias = "kanaf_vault_instrumented_" + UUID.randomUUID()
        val store = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        try {
            val generator = KeyGenerator.getInstance("AES", "AndroidKeyStore")
            generator.init(KeyGenParameterSpec.Builder(
                alias, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
            ).setKeySize(256).setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setRandomizedEncryptionRequired(true).build())
            val generated = generator.generateKey()
            val key = store.getKey(alias, null) as javax.crypto.SecretKey
            assertEquals("AES", generated.algorithm)
            val id = "cc02e245-fccc-4a18-a1db-abf855aee09d"
            val expected = ByteArray(102_401) { (it % 239).toByte() }
            val envelope = ByteArrayOutputStream().also { dest ->
                assertEquals(expected.size.toLong(),
                    VaultCipher.encrypt(ByteArrayInputStream(expected), dest, key, id))
            }.toByteArray()
            val staging = ByteArrayOutputStream()
            assertEquals(expected.size.toLong(),
                VaultCipher.decrypt(ByteArrayInputStream(envelope), staging, key, id))
            assertArrayEquals(expected, staging.toByteArray())
            val tampered = envelope.copyOf().also {
                it[it.lastIndex] = (it.last().toInt() xor 0x01).toByte()
            }
            assertThrows(Exception::class.java) {
                VaultCipher.decrypt(ByteArrayInputStream(tampered),
                    ByteArrayOutputStream(), key, id)
            }
        } finally {
            store.deleteEntry(alias)
        }
    }
}
