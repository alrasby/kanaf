package com.kanaf.alrasby.engine

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class NativeLibraryLoaderTest {
    @Test fun packagedLibrariesDoNotBypassReadinessGate() {
        val loaded = NativeLibraryLoader.Result(
            clamavLoaded = true,
            yaraXLoaded = true,
            errors = emptyList()
        )
        val gates = NativeLibraryLoader.gates(loaded)
        assertTrue(gates.all { it.libraryLoaded })
        assertTrue(gates.all { !it.ready })
        assertTrue(gates.all { it.unavailableReason() == "rules-not-verified" })
    }

    @Test fun missingLibraryIsReportedUnavailable() {
        val unavailable = NativeLibraryLoader.Result(
            clamavLoaded = false,
            yaraXLoaded = false,
            errors = listOf("library missing")
        )
        val gates = NativeLibraryLoader.gates(unavailable)
        assertTrue(gates.all { !it.ready })
        assertFalse(gates.any { it.libraryLoaded })
        assertTrue(gates.all { it.unavailableReason() == "native-library-unavailable" })
    }
}
