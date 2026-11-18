package com.kanaf.alrasby.engine

/**
 * Explicit readiness gate for optional native scanners.
 * An engine is NEVER considered available just because a .so is packaged.
 * Native initialization, compatible rules and a completed self-test are required.
 */
data class NativeEngineGate(
    val engineId: String,
    val libraryLoaded: Boolean,
    val rulesVerified: Boolean,
    val selfTestPassed: Boolean,
    val engineVersion: String? = null,
    val rulesVersion: String? = null
) {
    init { require(engineId == "clamav" || engineId == "yara-x") }
    val ready: Boolean
        get() = libraryLoaded && rulesVerified && selfTestPassed &&
            !engineVersion.isNullOrBlank() && !rulesVersion.isNullOrBlank()

    fun unavailableReason(): String? = when {
        ready -> null
        !libraryLoaded -> "native-library-unavailable"
        !rulesVerified -> "rules-not-verified"
        !selfTestPassed -> "self-test-not-passed"
        else -> "version-metadata-unavailable"
    }
}

/** Fail closed until a verified native integration supplies actual scan results. */
class GatedNativeEngine(private val gate: NativeEngineGate) : AntivirusEngine {
    override val id: String = gate.engineId
    override fun scan(openStream: () -> java.io.InputStream?, cancelled: () -> Boolean): AntivirusEngine.Verdict =
        AntivirusEngine.Verdict.Incomplete(
            gate.unavailableReason() ?: "native-scanner-not-integrated"
        )
}
