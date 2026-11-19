package com.kanaf.alrasby

import android.net.Uri
import android.os.Build
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.kanaf.alrasby.engine.AntivirusEngine
import com.kanaf.alrasby.engine.NativeScannerBridge
import com.kanaf.alrasby.engine.HashSignatureEngine
import com.kanaf.alrasby.engine.SignatureRepository
import java.io.File
import java.security.MessageDigest
import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith

/** Static scanning only. APK samples are private data; never installed or executed. */
@RunWith(AndroidJUnit4::class)
class IndependentCorpusAndroidTest {
    private fun digest(file: File): String {
        val hash = MessageDigest.getInstance("SHA-256")
        file.inputStream().use { input ->
            val buffer = ByteArray(65536)
            while (true) {
                val n = input.read(buffer)
                if (n < 0) break
                hash.update(buffer, 0, n)
            }
        }
        return hash.digest().joinToString("") { "%02x".format(it.toInt() and 255) }
    }

    private fun verdict(value: AntivirusEngine.Verdict, expected: String): JSONObject = when (value) {
        is AntivirusEngine.Verdict.Detected -> {
            assertEquals(expected, value.sha256)
            JSONObject().put("kind", "matched").put("name", value.threatName)
        }
        is AntivirusEngine.Verdict.NoKnownMatch -> {
            assertEquals(expected, value.sha256)
            JSONObject().put("kind", "unmatched")
        }
        is AntivirusEngine.Verdict.Incomplete -> JSONObject().put("kind", "incomplete").put("reason", value.reason)
    }

    @Test fun measureFrozenExternalCorpusWithoutInstallingSamples() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        assertTrue(Build.SUPPORTED_ABIS.contains("arm64-v8a"))
        val folder = File(context.filesDir, "independent-evaluation")
        val manifestFile = File(folder, "corpus-manifest.json")
        val manifest = JSONObject(manifestFile.readText())
        assertEquals("4cb2ea8366a6a39def42a33c0104dc144d905d46", manifest.getString("rules_frozen_at"))
        val samples = manifest.getJSONArray("samples")
        assertEquals(120, samples.length())
        val selfTest = NativeScannerBridge.selfTest(context)
        assertTrue("ClamAV readiness failed: $selfTest", selfTest.clamav is AntivirusEngine.Verdict.Detected)
        assertTrue("YARA-X readiness failed: $selfTest", selfTest.yaraX is AntivirusEngine.Verdict.Detected)
        assertTrue(selfTest.gates.all { it.ready })
        val repository = SignatureRepository(context)
        val hashEngine = HashSignatureEngine(repository.load())
        val status = repository.status()
        val results = JSONArray()
        val output = File(folder, "android-results.json")
        val report = JSONObject().put("format", 1).put("platform", "Android emulator ARM64 translation")
            .put("api", Build.VERSION.SDK_INT).put("abis", JSONArray(Build.SUPPORTED_ABIS.toList()))
            .put("manifest_sha256", digest(manifestFile)).put("rules_frozen_at", manifest.getString("rules_frozen_at"))
            .put("sample_execution", false).put("self_test_passed", true)
            .put("signed_feed_version", status.version).put("signed_feed_sha256", status.sha256)
            .put("cases", results).put("complete", false)
        for (i in 0 until samples.length()) {
            val row = samples.getJSONObject(i)
            val sha = row.getString("sha256")
            assertTrue(sha.matches(Regex("[a-f0-9]{64}")))
            val file = File(folder, "$sha.sample")
            assertEquals(row.getLong("size"), file.length())
            assertEquals(sha, digest(file))
            val started = System.nanoTime()
            val hash = hashEngine.scan({ file.inputStream() })
            val native = NativeScannerBridge.scan(context, Uri.fromFile(file))
            results.put(JSONObject().put("sha256", sha).put("label", row.getString("label"))
                .put("group", row.getString("group")).put("hash", verdict(hash, sha))
                .put("clamav", verdict(native.clamav, sha)).put("yara_x", verdict(native.yaraX, sha))
                .put("duration_ms", (System.nanoTime() - started) / 1_000_000))
            output.writeText(report.toString(2))
            if ((i + 1) % 10 == 0) println("Kanaf external corpus: ${i + 1}/${samples.length()}")
        }
        report.put("complete", true)
        output.writeText(report.toString(2))
        // No accuracy assertion: a valid poor result must remain visible.
    }
}
