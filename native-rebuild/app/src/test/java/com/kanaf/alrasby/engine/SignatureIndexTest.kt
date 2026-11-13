package com.kanaf.alrasby.engine

import org.junit.Assert.*
import org.junit.Test
import java.io.StringReader

class SignatureIndexTest {
    private val sha = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    @Test fun parsesValidFeed() {
        assertEquals("test", SignatureIndex.parse(StringReader("# header\n$sha\ttest\n"))[sha])
    }
    @Test fun rejectsMalformedDigest() {
        assertThrows(IllegalArgumentException::class.java) {
            SignatureIndex.parse(StringReader("abc\tbad\n"))
        }
    }
    @Test fun rejectsConflictingRecords() {
        assertThrows(IllegalArgumentException::class.java) {
            SignatureIndex.parse(StringReader("$sha\tfirst\n$sha\tsecond\n"))
        }
    }
    @Test fun rejectsOversizedFeed() {
        assertThrows(IllegalArgumentException::class.java) {
            SignatureIndex.parse(StringReader("$sha\ttest\n"), 0)
        }
    }
}
