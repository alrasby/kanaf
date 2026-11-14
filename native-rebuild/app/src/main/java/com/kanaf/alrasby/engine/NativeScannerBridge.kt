package com.kanaf.alrasby.engine

import android.content.Context
import android.net.Uri
import java.io.File
import java.io.InputStream
import java.security.MessageDigest

/**
 * Experimental native scanning path. The bundled rules ONLY recognize the harmless EICAR
 * test string. This is not a production antivirus database or whole-device protection.
 * All failures and partial reads are INCOMPLETE, never clean.
 */
object NativeScannerBridge {
    private const val MAX_FILE_BYTES = 16L * 1024 * 1024
    private const val CLAM_RULE_HASH = "579191ed0267e5cacf5dd1b69d83cfd890ba6f180a56a1ea7746d79249156514"
    private const val YARA_RULE_HASH = "6512c037bf11c594476492bd9e1cef968349a79a3a06f50aafa26e4ef3fc0993"

    data class Report(
        val clamav: AntivirusEngine.Verdict,
        val yaraX: AntivirusEngine.Verdict,
        val gates: List<NativeEngineGate>
    )

    private external fun clamScanNative(path: String, database: String): String
    private external fun yaraScanNative(path: String, rules: String): String

    // These are the official non-executable EICAR test bytes, used only for an engine self-test.
    private val eicar = (
        "X5O!P%@AP[4\\PZX54(P^)7CC)7}" + 36.toChar() +
            "EICAR-STANDARD-ANTIVIRUS-TEST-FILE!" + 36.toChar() + "H+H*"
    ).toByteArray(Charsets.US_ASCII)

    private fun digest(bytes: ByteArray): String =
        MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") {
            "%02x".format(it.toInt() and 0xff)
        }

    private fun incomplete(reason: String) = AntivirusEngine.Verdict.Incomplete(reason)

    private fun verdict(raw: String, sha256: String): AntivirusEngine.Verdict = when {
        raw.startsWith("DETECTED:") && raw.length > 9 ->
            AntivirusEngine.Verdict.Detected(raw.substringAfter(':').take(128), sha256)
        raw == "NO_MATCH" -> AntivirusEngine.Verdict.NoKnownMatch(sha256)
        else -> incomplete(raw.take(120))
    }

    private fun stagedFile(context: Context, prefix: String, suffix: String, bytes: ByteArray): File =
        File.createTempFile(prefix, suffix, context.cacheDir).also {
            it.outputStream().use { output -> output.write(bytes) }
        }

    private fun copyBounded(source: InputStream, dest: File): String {
        val hash = MessageDigest.getInstance("SHA-256")
        var count = 0L
        dest.outputStream().use { output ->
            source.use { input ->
                val chunk = ByteArray(64 * 1024)
                var emptyReads = 0
                while (true) {
                    val n = input.read(chunk)
                    if (n == -1) break
                    if (n == 0) {
                        if (++emptyReads >= 4) error("input-stream-stalled")
                        continue
                    }
                    emptyReads = 0
                    count += n
                    if (count > MAX_FILE_BYTES) error("file-exceeds-native-16MiB-limit")
                    hash.update(chunk, 0, n)
                    output.write(chunk, 0, n)
                }
            }
        }
        return hash.digest().joinToString("") { "%02x".format(it.toInt() and 0xff) }
    }

    /**
     * Must be called on Dispatchers.IO, after the user selects one SAF file.
     * No file is deleted or modified at its original location.
     */
    fun scan(context: Context, uri: Uri): Report {
        var clamGate = NativeEngineGate("clamav", false, false, false)
        var yaraGate = NativeEngineGate("yara-x", false, false, false)
        fun report(clam: AntivirusEngine.Verdict, yara: AntivirusEngine.Verdict) =
            Report(clam, yara, listOf(clamGate, yaraGate))

        val libraries = NativeLibraryLoader.probe()
        val bridgeLoaded = runCatching { System.loadLibrary("kanaf_scan"); true }.getOrDefault(false)
        if (!bridgeLoaded) return report(incomplete("jni-bridge-unavailable"), incomplete("jni-bridge-unavailable"))

        var db: File? = null
        var test: File? = null
        var target: File? = null
        try {
            val clamBytes = context.assets.open("kanaf_test.hdb").use { it.readBytes() }
            val yaraBytes = context.assets.open("kanaf_test.yar").use { it.readBytes() }
            val clamRulesOK = digest(clamBytes) == CLAM_RULE_HASH
            val yaraRulesOK = digest(yaraBytes) == YARA_RULE_HASH
            val rulesFile = stagedFile(context, "kanaf-clam-", ".hdb", clamBytes)
            db = rulesFile
            val testFile = stagedFile(context, "kanaf-eicar-", ".txt", eicar)
            test = testFile
            val yaraRules = yaraBytes.toString(Charsets.UTF_8)
            // Positive self-test: the real native engine MUST find the harmless EICAR pattern.
            // Negative self-test prevents a scanner that reports every file as infected.
            val benign = stagedFile(context, "kanaf-benign-", ".txt", "kanaf-scan-control".toByteArray())
            val clamOK: Boolean
            val yaraOK: Boolean
            try {
                clamOK = libraries.clamavLoaded && clamRulesOK &&
                    clamScanNative(testFile.absolutePath, rulesFile.absolutePath).startsWith("DETECTED:") &&
                    clamScanNative(benign.absolutePath, rulesFile.absolutePath) == "NO_MATCH"
                yaraOK = libraries.yaraXLoaded && yaraRulesOK &&
                    yaraScanNative(testFile.absolutePath, yaraRules).startsWith("DETECTED:") &&
                    yaraScanNative(benign.absolutePath, yaraRules) == "NO_MATCH"
            } finally {
                benign.delete()
            }
            clamGate = NativeEngineGate("clamav", libraries.clamavLoaded, clamRulesOK, clamOK,
                engineVersion = "1.4.3", rulesVersion = "EICAR-test-v1")
            yaraGate = NativeEngineGate("yara-x", libraries.yaraXLoaded, yaraRulesOK, yaraOK,
                engineVersion = "0.13.0", rulesVersion = "EICAR-test-v1")

            val selected = File.createTempFile("kanaf-scan-", ".bin", context.cacheDir)
            target = selected
            val sha256 = try {
                context.contentResolver.openInputStream(uri)?.let { copyBounded(it, selected) }
                    ?: return report(incomplete("file-unavailable"), incomplete("file-unavailable"))
            } catch (_: Exception) {
                return report(incomplete("file-unreadable-or-exceeds-16MiB"), incomplete("file-unreadable-or-exceeds-16MiB"))
            }
            val clamVerdict = if (clamGate.ready) verdict(
                clamScanNative(selected.absolutePath, rulesFile.absolutePath), sha256
            ) else incomplete(clamGate.unavailableReason() ?: "clamav-not-ready")
            val yaraVerdict = if (yaraGate.ready) verdict(
                yaraScanNative(selected.absolutePath, yaraRules), sha256
            ) else incomplete(yaraGate.unavailableReason() ?: "yara-not-ready")
            return report(clamVerdict, yaraVerdict)
        } catch (_: Exception) {
            return report(incomplete("native-initialization-failed"), incomplete("native-initialization-failed"))
        } catch (_: UnsatisfiedLinkError) {
            return report(incomplete("native-symbol-unavailable"), incomplete("native-symbol-unavailable"))
        } finally {
            db?.delete()
            test?.delete()
            target?.delete()
        }
    }
}
}EICAR-STANDARD-ANTIVIRUS-TEST-FILE!${'
    ).toByteArray(Charsets.US_ASCII)

    private fun digest(bytes: ByteArray): String =
        MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") {
            "%02x".format(it.toInt() and 0xff)
        }

    private fun incomplete(reason: String) = AntivirusEngine.Verdict.Incomplete(reason)

    private fun verdict(raw: String, sha256: String): AntivirusEngine.Verdict = when {
        raw.startsWith("DETECTED:") && raw.length > 9 ->
            AntivirusEngine.Verdict.Detected(raw.substringAfter(':').take(128), sha256)
        raw == "NO_MATCH" -> AntivirusEngine.Verdict.NoKnownMatch(sha256)
        else -> incomplete(raw.take(120))
    }

    private fun stagedFile(context: Context, prefix: String, suffix: String, bytes: ByteArray): File =
        File.createTempFile(prefix, suffix, context.cacheDir).also {
            it.outputStream().use { output -> output.write(bytes) }
        }

    private fun copyBounded(source: InputStream, dest: File): String {
        val hash = MessageDigest.getInstance("SHA-256")
        var count = 0L
        dest.outputStream().use { output ->
            source.use { input ->
                val chunk = ByteArray(64 * 1024)
                while (true) {
                    val n = input.read(chunk)
                    if (n == -1) break
                    if (n == 0) continue
                    count += n
                    if (count > MAX_FILE_BYTES) error("file-exceeds-native-16MiB-limit")
                    hash.update(chunk, 0, n)
                    output.write(chunk, 0, n)
                }
            }
        }
        return hash.digest().joinToString("") { "%02x".format(it.toInt() and 0xff) }
    }

    /**
     * Must be called on Dispatchers.IO, after the user selects one SAF file.
     * No file is deleted or modified at its original location.
     */
    fun scan(context: Context, uri: Uri): Report {
        var clamGate = NativeEngineGate("clamav", false, false, false)
        var yaraGate = NativeEngineGate("yara-x", false, false, false)
        fun report(clam: AntivirusEngine.Verdict, yara: AntivirusEngine.Verdict) =
            Report(clam, yara, listOf(clamGate, yaraGate))

        val libraries = NativeLibraryLoader.probe()
        val bridgeLoaded = runCatching { System.loadLibrary("kanaf_scan"); true }.getOrDefault(false)
        if (!bridgeLoaded) return report(incomplete("jni-bridge-unavailable"), incomplete("jni-bridge-unavailable"))

        var db: File? = null
        var test: File? = null
        var target: File? = null
        try {
            val clamBytes = context.assets.open("kanaf_test.hdb").use { it.readBytes() }
            val yaraBytes = context.assets.open("kanaf_test.yar").use { it.readBytes() }
            val clamRulesOK = digest(clamBytes) == CLAM_RULE_HASH
            val yaraRulesOK = digest(yaraBytes) == YARA_RULE_HASH
            db = stagedFile(context, "kanaf-clam-", ".hdb", clamBytes)
            test = stagedFile(context, "kanaf-eicar-", ".txt", eicar)
            val yaraRules = yaraBytes.toString(Charsets.UTF_8)
            // Positive self-test: the real native engine MUST find the harmless EICAR pattern.
            // Negative self-test prevents a scanner that reports every file as infected.
            val benign = stagedFile(context, "kanaf-benign-", ".txt", "kanaf-scan-control".toByteArray())
            val clamOK: Boolean
            val yaraOK: Boolean
            try {
                clamOK = libraries.clamavLoaded && clamRulesOK &&
                    clamScanNative(test.absolutePath, db.absolutePath).startsWith("DETECTED:") &&
                    clamScanNative(benign.absolutePath, db.absolutePath) == "NO_MATCH"
                yaraOK = libraries.yaraXLoaded && yaraRulesOK &&
                    yaraScanNative(test.absolutePath, yaraRules).startsWith("DETECTED:") &&
                    yaraScanNative(benign.absolutePath, yaraRules) == "NO_MATCH"
            } finally {
                benign.delete()
            }
            clamGate = NativeEngineGate("clamav", libraries.clamavLoaded, clamRulesOK, clamOK,
                engineVersion = "1.4.3", rulesVersion = "EICAR-test-v1")
            yaraGate = NativeEngineGate("yara-x", libraries.yaraXLoaded, yaraRulesOK, yaraOK,
                engineVersion = "0.13.0", rulesVersion = "EICAR-test-v1")

            target = File.createTempFile("kanaf-scan-", ".bin", context.cacheDir)
            val sha256 = try {
                context.contentResolver.openInputStream(uri)?.let { copyBounded(it, target) }
                    ?: return report(incomplete("file-unavailable"), incomplete("file-unavailable"))
            } catch (_: Exception) {
                return report(incomplete("file-unreadable-or-exceeds-16MiB"), incomplete("file-unreadable-or-exceeds-16MiB"))
            }
            val clamVerdict = if (clamGate.ready) verdict(
                clamScanNative(target.absolutePath, db.absolutePath), sha256
            ) else incomplete(clamGate.unavailableReason() ?: "clamav-not-ready")
            val yaraVerdict = if (yaraGate.ready) verdict(
                yaraScanNative(target.absolutePath, yaraRules), sha256
            ) else incomplete(yaraGate.unavailableReason() ?: "yara-not-ready")
            return report(clamVerdict, yaraVerdict)
        } catch (_: Exception) {
            return report(incomplete("native-initialization-failed"), incomplete("native-initialization-failed"))
        } catch (_: UnsatisfiedLinkError) {
            return report(incomplete("native-symbol-unavailable"), incomplete("native-symbol-unavailable"))
        } finally {
            db?.delete()
            test?.delete()
            target?.delete()
        }
    }
}
}H+H*"
    ).toByteArray(Charsets.US_ASCII)

    private fun digest(bytes: ByteArray): String =
        MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") {
            "%02x".format(it.toInt() and 0xff)
        }

    private fun incomplete(reason: String) = AntivirusEngine.Verdict.Incomplete(reason)

    private fun verdict(raw: String, sha256: String): AntivirusEngine.Verdict = when {
        raw.startsWith("DETECTED:") && raw.length > 9 ->
            AntivirusEngine.Verdict.Detected(raw.substringAfter(':').take(128), sha256)
        raw == "NO_MATCH" -> AntivirusEngine.Verdict.NoKnownMatch(sha256)
        else -> incomplete(raw.take(120))
    }

    private fun stagedFile(context: Context, prefix: String, suffix: String, bytes: ByteArray): File =
        File.createTempFile(prefix, suffix, context.cacheDir).also {
            it.outputStream().use { output -> output.write(bytes) }
        }

    private fun copyBounded(source: InputStream, dest: File): String {
        val hash = MessageDigest.getInstance("SHA-256")
        var count = 0L
        dest.outputStream().use { output ->
            source.use { input ->
                val chunk = ByteArray(64 * 1024)
                while (true) {
                    val n = input.read(chunk)
                    if (n == -1) break
                    if (n == 0) continue
                    count += n
                    if (count > MAX_FILE_BYTES) error("file-exceeds-native-16MiB-limit")
                    hash.update(chunk, 0, n)
                    output.write(chunk, 0, n)
                }
            }
        }
        return hash.digest().joinToString("") { "%02x".format(it.toInt() and 0xff) }
    }

    /**
     * Must be called on Dispatchers.IO, after the user selects one SAF file.
     * No file is deleted or modified at its original location.
     */
    fun scan(context: Context, uri: Uri): Report {
        var clamGate = NativeEngineGate("clamav", false, false, false)
        var yaraGate = NativeEngineGate("yara-x", false, false, false)
        fun report(clam: AntivirusEngine.Verdict, yara: AntivirusEngine.Verdict) =
            Report(clam, yara, listOf(clamGate, yaraGate))

        val libraries = NativeLibraryLoader.probe()
        val bridgeLoaded = runCatching { System.loadLibrary("kanaf_scan"); true }.getOrDefault(false)
        if (!bridgeLoaded) return report(incomplete("jni-bridge-unavailable"), incomplete("jni-bridge-unavailable"))

        var db: File? = null
        var test: File? = null
        var target: File? = null
        try {
            val clamBytes = context.assets.open("kanaf_test.hdb").use { it.readBytes() }
            val yaraBytes = context.assets.open("kanaf_test.yar").use { it.readBytes() }
            val clamRulesOK = digest(clamBytes) == CLAM_RULE_HASH
            val yaraRulesOK = digest(yaraBytes) == YARA_RULE_HASH
            db = stagedFile(context, "kanaf-clam-", ".hdb", clamBytes)
            test = stagedFile(context, "kanaf-eicar-", ".txt", eicar)
            val yaraRules = yaraBytes.toString(Charsets.UTF_8)
            // Positive self-test: the real native engine MUST find the harmless EICAR pattern.
            // Negative self-test prevents a scanner that reports every file as infected.
            val benign = stagedFile(context, "kanaf-benign-", ".txt", "kanaf-scan-control".toByteArray())
            val clamOK: Boolean
            val yaraOK: Boolean
            try {
                clamOK = libraries.clamavLoaded && clamRulesOK &&
                    clamScanNative(test.absolutePath, db.absolutePath).startsWith("DETECTED:") &&
                    clamScanNative(benign.absolutePath, db.absolutePath) == "NO_MATCH"
                yaraOK = libraries.yaraXLoaded && yaraRulesOK &&
                    yaraScanNative(test.absolutePath, yaraRules).startsWith("DETECTED:") &&
                    yaraScanNative(benign.absolutePath, yaraRules) == "NO_MATCH"
            } finally {
                benign.delete()
            }
            clamGate = NativeEngineGate("clamav", libraries.clamavLoaded, clamRulesOK, clamOK,
                engineVersion = "1.4.3", rulesVersion = "EICAR-test-v1")
            yaraGate = NativeEngineGate("yara-x", libraries.yaraXLoaded, yaraRulesOK, yaraOK,
                engineVersion = "0.13.0", rulesVersion = "EICAR-test-v1")

            target = File.createTempFile("kanaf-scan-", ".bin", context.cacheDir)
            val sha256 = try {
                context.contentResolver.openInputStream(uri)?.let { copyBounded(it, target) }
                    ?: return report(incomplete("file-unavailable"), incomplete("file-unavailable"))
            } catch (_: Exception) {
                return report(incomplete("file-unreadable-or-exceeds-16MiB"), incomplete("file-unreadable-or-exceeds-16MiB"))
            }
            val clamVerdict = if (clamGate.ready) verdict(
                clamScanNative(target.absolutePath, db.absolutePath), sha256
            ) else incomplete(clamGate.unavailableReason() ?: "clamav-not-ready")
            val yaraVerdict = if (yaraGate.ready) verdict(
                yaraScanNative(target.absolutePath, yaraRules), sha256
            ) else incomplete(yaraGate.unavailableReason() ?: "yara-not-ready")
            return report(clamVerdict, yaraVerdict)
        } catch (_: Exception) {
            return report(incomplete("native-initialization-failed"), incomplete("native-initialization-failed"))
        } catch (_: UnsatisfiedLinkError) {
            return report(incomplete("native-symbol-unavailable"), incomplete("native-symbol-unavailable"))
        } finally {
            db?.delete()
            test?.delete()
            target?.delete()
        }
    }
}
