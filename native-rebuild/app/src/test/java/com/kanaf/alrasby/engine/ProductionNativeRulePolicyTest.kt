package com.kanaf.alrasby.engine

import java.security.MessageDigest
import org.junit.Assert.*
import org.junit.Test

/** Production must never silently fall back to the EICAR-only rule pack. */
class ProductionNativeRulePolicyTest {
    private fun hash(bytes: ByteArray) = MessageDigest.getInstance("SHA-256")
        .digest(bytes).joinToString("") { "%02x".format(it.toInt() and 255) }

    @Test fun correctPinnedBytesOnly() {
        val rules = "example safe rule, no malware assertion".toByteArray()
        assertTrue(ProductionNativeRulePolicy.verified(rules, hash(rules), 4096))
        assertFalse(ProductionNativeRulePolicy.verified(rules + byteArrayOf(1), hash(rules), 4096))
        assertFalse(ProductionNativeRulePolicy.verified(rules, hash(rules).uppercase(), 4096))
        assertFalse(ProductionNativeRulePolicy.verified(rules, "", 4096))
        assertFalse(ProductionNativeRulePolicy.verified(byteArrayOf(), hash(rules), 4096))
        assertFalse(ProductionNativeRulePolicy.verified(rules, hash(rules), 1))
    }
}
