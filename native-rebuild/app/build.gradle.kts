import java.security.KeyFactory
import java.security.MessageDigest
import java.security.Signature
import java.security.PublicKey
import java.security.interfaces.RSAPublicKey
import java.security.spec.X509EncodedKeySpec
import java.util.Base64
import java.util.zip.ZipFile

plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("org.jetbrains.kotlin.plugin.compose")
}
android {
    namespace = "com.kanaf.alrasby"
    compileSdk = 36
    ndkVersion = "27.2.12479018"
    externalNativeBuild {
        cmake {
            path = file("src/main/cpp/CMakeLists.txt")
            version = "3.22.1"
        }
    }
    defaultConfig {
        applicationId = "com.kanaf.alrasby"
        minSdk = 26
        targetSdk = 36
        versionCode = 1
        versionName = "1.0"
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
        // Supply only a trusted PUBLIC key through an explicit release Gradle
        // property or CI configuration; no key = authenticated updates disabled.
        val publicKey = providers.gradleProperty("kanafSignaturePublicKeyBase64")
            .orNull.orEmpty()
        require(publicKey.matches(Regex("[A-Za-z0-9+/=]*"))) {
            "Invalid Base64 public-key configuration"
        }
        val minFeedVersion = providers.gradleProperty("kanafSignatureMinVersion")
            .orNull?.toLong() ?: 0L
        require(minFeedVersion >= 0L) { "Negative production signature feed floor" }
        require(publicKey.isBlank() || minFeedVersion > 0L) {
            "A production signing key requires a positive app-pinned minimum feed version"
        }
        buildConfigField("long", "KANAF_SIGNATURE_MIN_VERSION", "${minFeedVersion}L")
        buildConfigField("String", "KANAF_SIGNATURE_PUBLIC_KEY_BASE64", "\"$publicKey\"")
        val feedUrl = providers.gradleProperty("kanafSignatureFeedHttpsUrl")
            .orNull.orEmpty()
        require(feedUrl.isBlank() ||
            feedUrl.matches(Regex("https://[A-Za-z0-9.-]+(?::443)?/[A-Za-z0-9/_-]+\\.zip"))) {
            "Threat feed URL must be an HTTPS publisher ZIP without credentials or redirects"
        }
        buildConfigField("String", "KANAF_SIGNATURE_FEED_URL", "\"$feedUrl\"")
        val modelKey = providers.gradleProperty("kanafModelPublicKeyBase64")
            .orNull.orEmpty()
        require(modelKey.matches(Regex("[A-Za-z0-9+/=]*"))) {
            "Invalid machine-learning signing public key"
        }
        buildConfigField("String", "KANAF_MODEL_PUBLIC_KEY_BASE64", "\"$modelKey\"")
        // Production native rules are independently reviewed binary assets.
        // Missing/mismatched digests make native release scans INCOMPLETE;
        // debug builds continue to use EICAR-only self-test fixtures.
        val nativeHashPattern = Regex("[0-9a-f]{64}")
        val clamHash = providers.gradleProperty("kanafNativeClamRuleSha256").orNull.orEmpty()
        val yaraHash = providers.gradleProperty("kanafNativeYaraRuleSha256").orNull.orEmpty()
        require(clamHash.isEmpty() || nativeHashPattern.matches(clamHash)) {
            "Invalid pinned ClamAV production rule digest"
        }
        require(yaraHash.isEmpty() || nativeHashPattern.matches(yaraHash)) {
            "Invalid pinned YARA-X production rule digest"
        }
        buildConfigField("String", "KANAF_NATIVE_CLAM_RULE_SHA256", "\"$clamHash\"")
        buildConfigField("String", "KANAF_NATIVE_YARA_RULE_SHA256", "\"$yaraHash\"")
        val urlModelKey = providers.gradleProperty("kanafUrlModelPublicKeyBase64")
            .orNull.orEmpty()
        require(urlModelKey.matches(Regex("[A-Za-z0-9+/=]*"))) {
            "Invalid URL model verification key"
        }
        val urlWeights = file("src/main/assets/url_risk_model.txt")
        val urlProof = file("src/main/assets/url_risk_model.sig")
        require(if (urlModelKey.isBlank()) !urlWeights.exists() && !urlProof.exists()
                else urlWeights.isFile && urlProof.isFile) {
            "Experimental URL AI requires signed weights and build-pinned key, or NONE."
        }
        buildConfigField("String", "KANAF_URL_MODEL_PUBLIC_KEY_BASE64", "\"$urlModelKey\"")
        val modelFile = file("src/main/assets/validated_model.txt")
        val modelSignature = file("src/main/assets/validated_model.sig")
        require(if (modelKey.isBlank()) !modelFile.exists() && !modelSignature.exists()
                else modelFile.isFile && modelSignature.isFile) {
            "Kanaf AI requires BOTH signed model assets and a build-pinned public key, or NONE."
        }
        // ARM64-only packaging for the experimental runtime CI. Normal APKs unchanged.
        if (providers.gradleProperty("kanafArm64Runtime").orNull == "true") {
            ndk { abiFilters += "arm64-v8a" }
        }
    }
    // Never release an unsigned package. Signing secrets are supplied only
    // through the publisher's secure local/CI environment, never Gradle files.
    signingConfigs {
        create("kanafPublisher") {
            val location = System.getenv("KANAF_RELEASE_KEYSTORE_FILE")
            if (!location.isNullOrBlank()) storeFile = file(location)
            storePassword = System.getenv("KANAF_RELEASE_STORE_PASSWORD")
            keyAlias = System.getenv("KANAF_RELEASE_KEY_ALIAS")
            keyPassword = System.getenv("KANAF_RELEASE_KEY_PASSWORD")
        }
    }
    buildTypes {
        getByName("release") {
            signingConfig = signingConfigs.getByName("kanafPublisher")
        }
    }
    buildFeatures { compose = true; buildConfig = true }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions { jvmTarget = "17" }
}
/**
 * A release fails CLOSED unless real publisher assets + independent review
 * exist. This does not issue a certification: a signed APK and device tests
 * must still pass the separate post-package check_release_readiness.py.
 *
 * Run: gradle :app:verifyKanafProductionInputs
 */
val verifyKanafProductionInputs = tasks.register("verifyKanafProductionInputs") {
    group = "verification"
    description = "Refuse production builds backed only by EICAR/debug or unsigned inputs"
    doLast {
        fun block(reason: String): Nothing =
            error("KANAF_PRODUCTION_RELEASE_BLOCKED: $reason")
        fun property(name: String): String =
            providers.gradleProperty(name).orNull.orEmpty().trim()
        fun sha(bytes: ByteArray): String =
            MessageDigest.getInstance("SHA-256").digest(bytes)
                .joinToString("") { "%02x".format(it.toInt() and 255) }
        fun publisherKey(name: String): RSAPublicKey {
            val encoded = property(name)
            if (encoded.isBlank()) block("missing-publisher-key:$name")
            val key = runCatching {
                KeyFactory.getInstance("RSA").generatePublic(
                    X509EncodedKeySpec(
                        Base64.getDecoder().decode(encoded)
                    )
                ) as RSAPublicKey
            }.getOrNull() ?: block("invalid-publisher-key:$name")
            if (key.modulus.bitLength() < 2048) block("weak-publisher-key:$name")
            return key
        }
        fun verified(bytes: ByteArray, signature: ByteArray,
                     key: PublicKey, label: String) {
            val ok = runCatching {
                Signature.getInstance("SHA256withRSA").run {
                    initVerify(key)
                    update(bytes)
                    verify(signature)
                }
            }.getOrDefault(false)
            if (!ok) block("invalid-signature:$label")
        }
        val feedKey = publisherKey("kanafSignaturePublicKeyBase64")
        val modelKey = publisherKey("kanafModelPublicKeyBase64")
        val minVersion = property("kanafSignatureMinVersion").toLongOrNull()
            ?: block("missing-minimum-threat-feed-version")
        if (minVersion <= 0) block("invalid-minimum-threat-feed-version")
        if (property("kanafSignatureFeedHttpsUrl").isBlank()) {
            block("missing-production-HTTPS-feed")
        }
        val fileRoot = file("src/main/assets")
        val nativeFiles = listOf(
            Triple("production_clamav.ndb", "kanafNativeClamRuleSha256", 8 * 1024 * 1024),
            Triple("production_yara.yar", "kanafNativeYaraRuleSha256", 4 * 1024 * 1024)
        )
        val nativeHashes = nativeFiles.map { (name, key, max) ->
            val input = fileRoot.resolve(name)
            if (!input.isFile || input.length() !in 1L..max.toLong())
                block("missing-or-oversized-production-native-rule:$name")
            val digest = sha(input.readBytes())
            if (property(key) != digest) block("native-rule-digest-mismatch:$name")
            digest
        }
        val model = fileRoot.resolve("validated_model.txt")
        val signature = fileRoot.resolve("validated_model.sig")
        if (!model.isFile || model.length() !in 1L..4096L || !signature.isFile)
            block("missing-signed-production-malware-model")
        val modelBytes = model.readBytes()
        val modelSignature = runCatching {
            Base64.getDecoder().decode(signature.readText().trim())
        }.getOrNull() ?: block("invalid-production-malware-model-signature")
        verified(modelBytes, modelSignature, modelKey, "production-malware-model")
        val lines = modelBytes.toString(Charsets.US_ASCII).split("\n")
        if (lines.size != 18 || lines[0] != "KanafML-1" || lines[1] != "1" ||
            lines.last() != "" || lines[2].contains("fixture", true) ||
            lines[2].contains("synthetic", true) || lines[2].contains("pilot", true)) {
            block("production-model-format-or-provenance-invalid")
        }
        val feedFile = fileRoot.resolve("production_signatures.zip")
        if (!feedFile.isFile || feedFile.length() !in 1L..(32L * 1024 * 1024 + 16384))
            block("missing-or-oversized-signed-threat-feed")
        val database: ByteArray
        val manifest: String
        ZipFile(feedFile).use { archive ->
            val entries = archive.entries().asSequence().toList()
            if (entries.map { it.name }.toSet() !=
                setOf("signatures.tsv", "manifest.txt") || entries.size != 2)
                block("invalid-threat-feed-archive-layout")
            fun read(name: String, max: Long): ByteArray {
                val entry = archive.getEntry(name)
                    ?: block("missing-threat-feed-entry:$name")
                if (entry.size !in 1L..max) block("oversized-threat-feed-entry:$name")
                val bytes = archive.getInputStream(entry).use { it.readBytes() }
                if (bytes.size.toLong() != entry.size) block("truncated-feed-entry:$name")
                return bytes
            }
            database = read("signatures.tsv", 32L * 1024 * 1024)
            manifest = read("manifest.txt", 4096).toString(Charsets.US_ASCII)
        }
        val meta = Regex("([1-9][0-9]*)\\n([0-9a-f]{64})\\n([A-Za-z0-9+/]+={0,2})\\n")
            .matchEntire(manifest) ?: block("malformed-threat-feed-manifest")
        val version = meta.groupValues[1].toLongOrNull() ?: block("bad-feed-version")
        if (version < minVersion) block("signed-threat-feed-below-version-floor")
        if (meta.groupValues[2] != sha(database)) block("signed-feed-digest-mismatch")
        val feedSignature = runCatching {
            Base64.getDecoder().decode(meta.groupValues[3])
        }.getOrNull() ?: block("invalid-threat-feed-signature-encoding")
        verified("Kanaf-DB-v1\n$version\n${meta.groupValues[2]}\n".toByteArray(Charsets.US_ASCII),
            feedSignature, feedKey, "production-threat-feed")
        // A binary release can never be protected only by EICAR/demo records.
        val rows = database.toString(Charsets.UTF_8).lineSequence()
            .filter { it.isNotBlank() && !it.startsWith("#") }.toList()
        if (rows.isEmpty() || rows.any {
            !it.matches(Regex("[0-9a-fA-F]{64}\\t[A-Za-z0-9_.:+-]{1,128}"))
        } || rows.none { !it.contains("eicar", true) && !it.contains("test", true) }) {
            block("test-only-or-malformed-production-threat-feed")
        }
        // Independent approval is intentionally NOT minted from this job.
        // It must be a separately signed QA report against these exact hashes.
        val qaFile = System.getenv("KANAF_QA_ATTESTATION")?.let { file(it) }
            ?: block("missing-independent-QA-attestation")
        val qaSig = System.getenv("KANAF_QA_ATTESTATION_SIGNATURE")?.let { file(it) }
            ?: block("missing-independent-QA-signature")
        val qaKeyPath = System.getenv("KANAF_QA_PUBLIC_KEY_DER")?.let { file(it) }
            ?: block("missing-independent-QA-public-key")
        if (!qaFile.isFile || !qaSig.isFile || !qaKeyPath.isFile)
            block("missing-independent-QA-artifact")
        val qaKey = runCatching {
            KeyFactory.getInstance("RSA").generatePublic(
                X509EncodedKeySpec(qaKeyPath.readBytes())
            ) as RSAPublicKey
        }.getOrNull() ?: block("invalid-independent-QA-key")
        if (qaKey.modulus.bitLength() < 2048 ||
            qaKey.encoded.contentEquals(feedKey.encoded) ||
            qaKey.encoded.contentEquals(modelKey.encoded)) {
            block("QA-signing-key-must-be-independent-and-strong")
        }
        verified(qaFile.readBytes(), qaSig.readBytes(), qaKey, "independent-QA-attestation")
        // Canonical strict line format: independently reviewed exact release inputs.
        val expected = listOf(
            "Kanaf-Production-Assets-v1", sha(modelBytes), sha(database),
            nativeHashes[0], nativeHashes[1]
        )
        val declared = qaFile.readLines(Charsets.US_ASCII)
        if (declared.size < 7 || declared.take(5) != expected ||
            declared[5].isBlank() || declared[6].isBlank()) {
            block("QA-reviewed-assets-differ-from-build-or-audit-IDs-missing")
        }
        val store = System.getenv("KANAF_RELEASE_KEYSTORE_FILE")?.let { file(it) }
        if (store?.isFile != true ||
            listOf("KANAF_RELEASE_STORE_PASSWORD", "KANAF_RELEASE_KEY_ALIAS",
                "KANAF_RELEASE_KEY_PASSWORD").any {
                    System.getenv(it).isNullOrBlank()
                }) {
            block("owner-controlled-release-keystore-unconfigured")
        }
        logger.lifecycle("Kanaf production input cryptographic preflight passed; final signed-artifact + hardware QA gate remains mandatory.")
    }
}
tasks.matching { it.name == "preReleaseBuild" }.configureEach {
    dependsOn(verifyKanafProductionInputs)
}

dependencies {
    implementation(platform("androidx.compose:compose-bom:2024.12.01"))
    implementation("androidx.compose.material3:material3")
    implementation("androidx.activity:activity-compose:1.9.3")
    implementation("androidx.lifecycle:lifecycle-runtime-ktx:2.8.7")
    implementation("androidx.work:work-runtime-ktx:2.10.2")
    implementation("androidx.documentfile:documentfile:1.0.1")
    testImplementation("junit:junit:4.13.2")
    androidTestImplementation("androidx.test.ext:junit:1.2.1")
    androidTestImplementation("androidx.test:runner:1.6.2")
    // Android test and debug configurations do not inherit main Compose BOM
    // constraints reliably; pin the matching platform explicitly.
    androidTestImplementation(platform("androidx.compose:compose-bom:2024.12.01"))
    debugImplementation(platform("androidx.compose:compose-bom:2024.12.01"))
    androidTestImplementation("androidx.compose.ui:ui-test-junit4")
    debugImplementation("androidx.compose.ui:ui-test-manifest")
}
