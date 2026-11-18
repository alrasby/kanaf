package com.kanaf.alrasby.engine

import org.junit.Assert.*
import org.junit.Test
import java.security.KeyPairGenerator
import java.security.Signature
import java.util.Base64

class SignedSignatureUpdateTest {
    @Test fun validatesSignatureAndRejectsTampering() {
        val keys = KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.generateKeyPair()
        val hash = "a".repeat(64)
        val bytes = "Kanaf-DB-v1\n7\n$hash\n".toByteArray(Charsets.US_ASCII)
        val signer = Signature.getInstance("SHA256withRSA")
        signer.initSign(keys.private)
        signer.update(bytes)
        val sig = Base64.getEncoder().encodeToString(signer.sign())
        val valid = SignedSignatureUpdate.Manifest(7, hash, sig)
        assertTrue(SignedSignatureUpdate.verify(valid, keys.public.encoded))
        assertFalse(SignedSignatureUpdate.verify(valid.copy(version = 8), keys.public.encoded))
        assertFalse(SignedSignatureUpdate.verify(valid.copy(sha256 = "b".repeat(64)), keys.public.encoded))
        assertFalse(SignedSignatureUpdate.verify(valid.copy(signatureBase64 = "bad"), keys.public.encoded))
    }
}
