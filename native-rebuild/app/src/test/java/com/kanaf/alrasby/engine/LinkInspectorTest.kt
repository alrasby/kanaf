package com.kanaf.alrasby.engine

import org.junit.Assert.*
import org.junit.Test

class LinkInspectorTest {
    private fun only(text: String) = LinkInspector.inspectText(text).items.single()

    @Test fun ordinaryHttpsLinkRemainsUnverifiedNotSafe() {
        val result = only("https://example.com/a")
        assertEquals(LinkInspector.Verdict.NOT_VERIFIED, result.verdict)
        assertTrue(result.signals.isEmpty())
    }
    @Test fun httpNeedsReview() {
        assertTrue(LinkInspector.Signal.UNENCRYPTED_HTTP in only("http://example.com").signals)
    }
    @Test fun userInfoDisguiseUsesRealHost() {
        val result = only("https://trusted.example@attacker.example/login")
        assertEquals("attacker.example", result.host)
        assertTrue(LinkInspector.Signal.USER_INFO in result.signals)
        assertEquals(LinkInspector.Verdict.REVIEW, result.verdict)
    }
    @Test fun punycodeAndDirectIpAreReviewSignals() {
        assertTrue(LinkInspector.Signal.PUNYCODE in only("https://xn--e1afmkfd.example").signals)
        assertTrue(LinkInspector.Signal.IP_ADDRESS in only("https://203.0.113.10").signals)
    }
    @Test fun customPortNeedsReview() {
        assertTrue(LinkInspector.Signal.NONSTANDARD_PORT in only("https://example.com:8443/a").signals)
    }
    @Test fun ambiguousUnicodeHostIsInvalidNotSafe() {
        assertEquals(LinkInspector.Verdict.INVALID, only("https://مثال.إختبار").verdict)
    }
    @Test fun unsupportedSchemesAreNotClaimedAnalyzed() {
        assertTrue(LinkInspector.inspectText("javascript:alert(1) mailto:test@example.com").items.isEmpty())
    }
    @Test fun extractsMultipleUrlsAndTrimsPunctuation() {
        val result = LinkInspector.inspectText("See https://example.com/a, or http://example.org/b!")
        assertEquals(2, result.items.size)
        assertEquals("https://example.com/a", result.items.first().url)
        assertEquals("http://example.org/b", result.items.last().url)
    }
    @Test fun textAndLinkCapsAreReportedAsPartial() {
        assertTrue(LinkInspector.inspectText("a".repeat(LinkInspector.MAX_TEXT_CHARS + 1)).truncated)
        val report = LinkInspector.inspectText("https://example.com/ ".repeat(LinkInspector.MAX_LINKS + 1))
        assertEquals(LinkInspector.MAX_LINKS, report.items.size)
        assertTrue(report.truncated)
    }
    @Test fun invalidAuthorityFailsClosed() {
        assertEquals(LinkInspector.Verdict.INVALID, only("https://example.com:badport/").verdict)
    }
}
