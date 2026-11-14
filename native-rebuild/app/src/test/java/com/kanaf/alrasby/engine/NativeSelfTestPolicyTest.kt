package com.kanaf.alrasby.engine

import org.junit.Assert.*
import org.junit.Test

class NativeSelfTestPolicyTest {
    @Test fun correctClamRuleOnly() {
        assertTrue(NativeSelfTestPolicy.expected("clamav", "DETECTED:Kanaf.EICAR.Test"))
        assertTrue(NativeSelfTestPolicy.expected("clamav", "DETECTED:Kanaf.EICAR.Test.UNOFFICIAL"))
        assertFalse(NativeSelfTestPolicy.expected("clamav", "DETECTED:Unrelated"))
        assertFalse(NativeSelfTestPolicy.expected("clamav", "DETECTED:Kanaf.EICAR.Test.extra"))
    }
    @Test fun correctYaraRuleOnly() {
        assertTrue(NativeSelfTestPolicy.expected("yara-x", "DETECTED:Kanaf_EICAR_Test"))
        assertFalse(NativeSelfTestPolicy.expected("yara-x", "DETECTED:Unrelated"))
        assertFalse(NativeSelfTestPolicy.expected("yara-x", "DETECTED:Kanaf_EICAR_Test_Other"))
    }
    @Test fun absentOrFailedEngineIsNeverReady() {
        for (id in listOf("clamav", "yara-x")) {
            assertFalse(NativeSelfTestPolicy.expected(id, ""))
            assertFalse(NativeSelfTestPolicy.expected(id, "NO_MATCH"))
            assertFalse(NativeSelfTestPolicy.expected(id, "INCOMPLETE:timeout"))
        }
        assertFalse(NativeSelfTestPolicy.expected("unexpected", "DETECTED:EICAR"))
    }
}
