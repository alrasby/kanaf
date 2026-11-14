package com.kanaf.alrasby.engine

/**
 * Loading native code is NOT equivalent to a successful antivirus scan.
 * Keep NativeEngineGate closed until rules, initialization and a known-sample self-test pass.
 */
object NativeLibraryLoader {
    data class Result(
        val clamavLoaded: Boolean,
        val yaraXLoaded: Boolean,
        val errors: List<String>
    )

    @Synchronized
    fun probe(): Result {
        val errors = mutableListOf<String>()
        fun load(name: String): Boolean = try {
            System.loadLibrary(name)
            true
        } catch (error: UnsatisfiedLinkError) {
            errors += "$name: ${error.javaClass.simpleName}"
            false
        } catch (error: SecurityException) {
            errors += "$name: ${error.javaClass.simpleName}"
            false
        }

        // ClamAV has an explicit DT_NEEDED dependency on libclammspack.
        val mspack = load("clammspack")
        val clamav = mspack && load("clamav")
        val yara = load("yara_x_capi")
        return Result(clamav, yara, errors.toList())
    }

    fun gates(result: Result): List<NativeEngineGate> = listOf(
        NativeEngineGate("clamav", result.clamavLoaded, false, false),
        NativeEngineGate("yara-x", result.yaraXLoaded, false, false)
    )
}
