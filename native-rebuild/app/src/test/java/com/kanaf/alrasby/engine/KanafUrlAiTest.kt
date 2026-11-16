package com.kanaf.alrasby.engine

import java.security.KeyPairGenerator
import java.security.Signature
import java.util.Base64
import org.junit.Assert.*
import org.junit.Test

class KanafUrlAiTest {
    private val pair = KeyPairGenerator.getInstance("RSA").apply {
        initialize(2048)
    }.generateKeyPair()
    private val valid = listOf(
        "KanafURLML-1", "12", "pilot-v1", "-2.5",
        "0.1", "0.2", "0.3", "0.4", "0.5", "0.6", "0.7", "-0.8",
        "0.2", "0.8", "0.1", "0.3"
    ).joinToString("\n", postfix = "\n").toByteArray(Charsets.US_ASCII)
    private fun sign(bytes: ByteArray) = Signature.getInstance("SHA256withRSA").run {
        initSign(pair.private)
        update(bytes)
        Base64.getEncoder().encodeToString(sign())
    }
    private fun load(data: ByteArray = valid) =
        KanafUrlAi.parseVerified(data, sign(data), pair.public.encoded)

    @Test fun scoreIsFiniteAndFullyLocal() {
        val model = load()
        assertEquals("pilot-v1", model.version)
        val a = model.evaluate("https://example.org/account")
        val b = model.evaluate("http://192.0.2.5:8080/signin?confirm=1")
        assertNotNull(a)
        assertNotNull(b)
        assertTrue(a!! in 0f..1f && b!! in 0f..1f)
        assertNotEquals(a, b)
    }
    @Test fun missingInvalidUnicodeAndUnsupportedProtocolsFailClosed() {
        assertNull(load().evaluate("javascript:alert(1)"))
        assertNull(load().evaluate("https://مثال.اختبار/a"))
        assertNull(load().evaluate("https://"))
        assertNull(load().evaluate("https://example.org/" + "a".repeat(2100)))
    }
    @Test fun alteredWeightsAndForeignKeyFailVerification() {
        val fake = valid.copyOf().apply { this[lastIndex - 3] = '9'.code.toByte() }
        assertThrows(Exception::class.java) {
            KanafUrlAi.parseVerified(fake, sign(valid), pair.public.encoded)
        }
        val other = KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.generateKeyPair()
        assertThrows(Exception::class.java) {
            KanafUrlAi.parseVerified(valid, sign(valid), other.public.encoded)
        }
    }
    @Test fun featureRegressionForAnExampleUrl() {
        val feature = KanafUrlAi.features("https://example.com/a?b=1")!!
        assertEquals(12, feature.size)
        assertEquals(1.0, feature[7], 0.00001)
        assertEquals(0.0, feature[8], 0.00001)
        assertEquals(0.0, feature[9], 0.00001)
        assertEquals(kotlin.math.ln(3.0), feature[5], 0.00001)
    }
}
