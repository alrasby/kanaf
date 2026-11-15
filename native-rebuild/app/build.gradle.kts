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
    buildFeatures { compose = true; buildConfig = true }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions { jvmTarget = "17" }
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
