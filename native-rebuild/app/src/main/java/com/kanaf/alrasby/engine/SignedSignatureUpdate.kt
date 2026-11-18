package com.kanaf.alrasby.engine

import java.security.KeyFactory
import java.security.Signature
import java.security.spec.X509EncodedKeySpec
import java.util.Base64

/**
 * Authenticates a database release with an application-pinned RSA public key.
 * The signature covers the exact ASCII manifest: "Kanaf-DB-v1\n<version>\n<sha256>\n".
 * A caller must persist the highest accepted version to prevent rollback.
 */
object SignedSignatureUpdate {
    data class Manifest(val version: Long, val sha256: String, val signatureBase64: String)

    fun verify(manifest: Manifest, publicKeyDer: ByteArray): Boolean {
        if (manifest.version <= 0 || !manifest.sha256.matches(Regex("[0-9a-f]{64}"))) return false
        val payload = "Kanaf-DB-v1\n${manifest.version}\n${manifest.sha256}\n"
            .toByteArray(Charsets.US_ASCII)
        return try {
            val key = KeyFactory.getInstance("RSA")
                .generatePublic(X509EncodedKeySpec(publicKeyDer))
            val verifier = Signature.getInstance("SHA256withRSA")
            verifier.initVerify(key)
            verifier.update(payload)
            verifier.verify(Base64.getDecoder().decode(manifest.signatureBase64))
        } catch (_: Exception) {
            false
        }
    }
}
