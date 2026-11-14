package com.kanaf.alrasby.engine

/** Native EICAR self-test must match the intended test signature, not an arbitrary rule. */
internal object NativeSelfTestPolicy {
    fun expected(engine: String, outcome: String): Boolean = when (engine) {
        "clamav" -> outcome == "DETECTED:Kanaf.EICAR.Test" ||
            outcome == "DETECTED:Kanaf.EICAR.Test.UNOFFICIAL"
        "yara-x" -> outcome == "DETECTED:Kanaf_EICAR_Test"
        else -> false
    }
}
