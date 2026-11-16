package com.kanaf.alrasby.engine
import org.junit.Assert.*
import org.junit.Test

class NativeScanAllocationTest {
    @Test fun installedPackagesCannotStarveSharedApks() {
        val budget = NativeScanAllocation(100, true)
        repeat(50) { assertTrue(budget.reserve(true, false)) }
        repeat(100) { assertFalse(budget.reserve(true, false)) }
        repeat(25) { assertTrue(budget.reserve(false, false)) }
        assertFalse(budget.reserve(false, false))
        repeat(25) { assertTrue(budget.reserve(false, true)) }
        assertEquals(100, budget.totalReserved)
        assertEquals(50, budget.installedReserved)
        assertEquals(50, budget.sharedReserved)
        assertFalse(budget.reserve(false, true))
    }

    @Test fun appOnlyScanRetainsFullNativeCapacity() {
        val budget = NativeScanAllocation(6, false)
        repeat(6) { assertTrue(budget.reserve(true, false)) }
        assertFalse(budget.reserve(true, false))
        assertFalse(budget.reserve(false, true))
    }

    @Test fun noBudgetMeansNoNativeChecks() {
        val budget = NativeScanAllocation(0, true)
        assertFalse(budget.reserve(true, false))
        assertFalse(budget.reserve(false, true))
    }
}
