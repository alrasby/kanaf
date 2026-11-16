package com.kanaf.alrasby

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.kanaf.alrasby.engine.SignatureRepository
import com.kanaf.alrasby.engine.SignedSignatureUpdate
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.Signature
import java.util.Base64
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.util.zip.ZipOutputStream
import java.util.zip.ZipEntry
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith

/**
 * End-to-end ephemeral-key signed update on Android AtomicFile storage.
 * Never embeds a production private key or introduces a real threat database.
 */
@RunWith(AndroidJUnit4::class)
class TrustedSignatureRepositoryAndroidTest {
    private val context get() = InstrumentationRegistry.getInstrumentation().targetContext
    private fun payload(label: String): ByteArray =
        ("a".repeat(64) + "\t" + label + "\n").toByteArray(Charsets.US_ASCII)

    private fun sha(data: ByteArray): String =
        MessageDigest.getInstance("SHA-256").digest(data)
            .joinToString("") { "%02x".format(it.toInt() and 0xff) }

    private fun signed(
        version: Long, database: ByteArray,
        pair: java.security.KeyPair
    ): SignedSignatureUpdate.Manifest {
        val checksum = sha(database)
        val text = "Kanaf-DB-v1\n$version\n$checksum\n".toByteArray(Charsets.US_ASCII)
        val signer = Signature.getInstance("SHA256withRSA").apply {
            initSign(pair.private)
            update(text)
        }
        return SignedSignatureUpdate.Manifest(
            version, checksum, Base64.getEncoder().encodeToString(signer.sign())
        )
    }

    private fun asZip(data: ByteArray, manifest: SignedSignatureUpdate.Manifest): ByteArray {
        val metadata = ("${manifest.version}\n${manifest.sha256}\n" +
            manifest.signatureBase64 + "\n").toByteArray(Charsets.US_ASCII)
        return ByteArrayOutputStream().also { bytes ->
            ZipOutputStream(bytes).use { zip ->
                zip.putNextEntry(ZipEntry("signatures.tsv"))
                zip.write(data)
                zip.closeEntry()
                zip.putNextEntry(ZipEntry("manifest.txt"))
                zip.write(metadata)
                zip.closeEntry()
            }
        }.toByteArray()
    }

    @Test fun firstUsePublisherFeedBootstrapsAtomicallyAndRejectsWrongSigner() {
        val repo = SignatureRepository(context)
        val directory = context.filesDir.resolve("signature-db")
        listOf("verified.bundle", "verified.bundle.bak", "verified.bundle.new").forEach {
            directory.resolve(it).delete()
        }
        val trusted = KeyPairGenerator.getInstance("RSA").apply {
            initialize(2048)
        }.generateKeyPair()
        val attacker = KeyPairGenerator.getInstance("RSA").apply {
            initialize(2048)
        }.generateKeyPair()
        val db = payload("Kanaf.Test.Only")
        val rejected = asZip(db, signed(201L, db, attacker))
        assertThrows(Exception::class.java) {
            repo.installBundledIfAbsent(ByteArrayInputStream(rejected),
                trusted.public.encoded, 200L)
        }
        assertFalse("Untrusted ZIP cannot publish a database",
            directory.resolve("verified.bundle").exists())
        val valid = asZip(db, signed(201L, db, trusted))
        assertTrue(repo.installBundledIfAbsent(ByteArrayInputStream(valid),
            trusted.public.encoded, 200L))
        assertEquals("Kanaf.Test.Only", repo.load()["a".repeat(64)])
        assertFalse("Existing signed database cannot be overwritten by bootstrap",
            repo.installBundledIfAbsent(ByteArrayInputStream(rejected),
                trusted.public.encoded, 200L))
        assertEquals("Kanaf.Test.Only", repo.load()["a".repeat(64)])
    }

    @Test fun verifiedInstallPersistsAndRejectsRollbackWrongKeyOrTampering() {
        val repo = SignatureRepository(context)
        // Instrumented test app data is ephemeral, but delete any previous
        // test bundle to avoid same-version collisions on repeated runs.
        context.filesDir.resolve("signature-db/verified.bundle").delete()
        context.filesDir.resolve("signature-db/verified.bundle.bak").delete()
        context.filesDir.resolve("signature-db/verified.bundle.new").delete()
        val publisher = KeyPairGenerator.getInstance("RSA").apply {
            initialize(2048)
        }.generateKeyPair()
        val attacker = KeyPairGenerator.getInstance("RSA").apply {
            initialize(2048)
        }.generateKeyPair()
        val db = payload("TEST_EICAR_ONLY")
        val release = signed(100L, db, publisher)
        repo.installVerified(db, release, publisher.public.encoded)
        assertEquals("TEST_EICAR_ONLY", repo.load()["a".repeat(64)])
        assertThrows(Exception::class.java) {
            repo.installVerified(db, signed(100L, db, publisher), publisher.public.encoded)
        }
        assertThrows(Exception::class.java) {
            repo.installVerified(db, signed(101L, db, attacker), publisher.public.encoded)
        }
        assertThrows(Exception::class.java) {
            repo.installVerified(payload("OTHER_LABEL"), release, publisher.public.encoded)
        }
        assertEquals("TEST_EICAR_ONLY", repo.load()["a".repeat(64)])
    }
}
