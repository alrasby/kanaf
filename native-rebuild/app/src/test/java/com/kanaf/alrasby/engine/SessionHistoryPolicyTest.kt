package com.kanaf.alrasby.engine

import org.junit.Assert.*
import org.junit.Test

class SessionHistoryPolicyTest {
    @Test fun disabledHistoryNeverRecords() {
        val history = mutableListOf<String>()
        SessionHistoryPolicy.record(history, "Scan done", false)
        assertTrue(history.isEmpty())
    }

    @Test fun resultIsBoundedAndOnlyFirstThreeLinesAreRetained() {
        val history = mutableListOf<String>()
        SessionHistoryPolicy.record(history, "A".repeat(900) + "\nB\nC\nFOURTH-LINE", true)
        assertEquals(1, history.size)
        assertEquals(600, history.single().length)
        assertFalse(history.single().contains("FOURTH-LINE"))
    }

    @Test fun onlyTenLatestRecordsSurvive() {
        val history = mutableListOf<String>()
        repeat(13) { SessionHistoryPolicy.record(history, "scan-$it", true) }
        assertEquals(10, history.size)
        assertEquals("scan-12", history.first())
        assertEquals("scan-3", history.last())
    }

    @Test fun disablingCanImmediatelyClearPreviouslyHeldResults() {
        val history = mutableListOf("old")
        SessionHistoryPolicy.onEnabledChanged(history, false)
        SessionHistoryPolicy.record(history, "new", false)
        assertTrue(history.isEmpty())
    }
}
