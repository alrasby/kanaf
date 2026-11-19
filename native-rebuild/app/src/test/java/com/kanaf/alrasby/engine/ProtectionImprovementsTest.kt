package com.kanaf.alrasby.engine

import org.junit.After
import org.junit.Assert.*
import org.junit.Test
import java.net.InetAddress
import java.net.URI

class ProtectionImprovementsTest {
    private val sha = "a".repeat(64)
    private val benign = AntivirusEngine.Verdict.NoKnownMatch(sha)
    @After fun reset() { DnsActivityLog.setEnabled(false); DnsActivityLog.setAllowed(emptySet()) }

    @Test fun cachedVerdictsCannotSurviveRuleContentEngineOrPolicyChanges() {
        val cache = NativeVerdictCache(1)
        val key = NativeVerdictCache.Key(sha, "clam-rules-v1", "yara-rules-v1")
        cache.put(key, benign, benign)
        assertNotNull(cache.get(key))
        assertNull(cache.get(key.copy(fileSha256 = "b".repeat(64))))
        assertNull(cache.get(key.copy(clamRules = "clam-rules-v2")))
        assertNull(cache.get(key.copy(yaraRules = "yara-rules-v2")))
        assertNull(cache.get(key.copy(policy = "new-engine-or-policy")))
        val next = key.copy(policy = "next")
        cache.put(next, benign, AntivirusEngine.Verdict.Incomplete("timeout"))
        assertNull(cache.get(next))
        cache.put(next, benign, benign)
        assertNull(cache.get(key))
    }
    @Test fun signedRowsAreRenderedAsExactFileRulesWithoutRuleInjection() {
        assertEquals("$sha:*:Android.SpyLoan:73\n", NativeHashRules.clam(mapOf(sha to "Android.SpyLoan")).toString(Charsets.US_ASCII))
        assertTrue(NativeHashRules.yara(mapOf(sha to "Android.SpyLoan")).contains("hash.sha256(0, filesize) == \"$sha\""))
        assertThrows(IllegalArgumentException::class.java) { NativeHashRules.yara(mapOf(sha to "\" } rule injected { condition: true }")) }
        assertThrows(IllegalArgumentException::class.java) { NativeHashRules.clam(mapOf("bad" to "Android.Test")) }
    }
    @Test fun signingRotationAndPermissionChangesAreSeparatedFromMalware() {
        val previous = PackageBaseline.Snapshot(1, setOf("old"), setOf("camera"))
        val current = PackageBaseline.Snapshot(2, setOf("new"), setOf("camera", "microphone"))
        assertFalse(PackageBaseline.compare(previous, current, true).unverifiedSignerChange)
        assertTrue(PackageBaseline.compare(previous, current, false).unverifiedSignerChange)
        assertEquals(setOf("microphone"), PackageBaseline.compare(previous, current, true).addedPermissions)
        assertFalse(PackageBaseline.compare(null, current, false).baselineExists)
        assertTrue(PackageBaseline.compare(null, current, false).addedPermissions.isEmpty())
    }
    @Test fun privacyAuditDistinguishesGrantedRequestedAndSpecialAccess() {
        val text = PrivacyAudit.describe(listOf(
            PrivacyAudit.Permission("android.permission.CAMERA", true),
            PrivacyAudit.Permission("android.permission.RECORD_AUDIO", false),
            PrivacyAudit.Permission("android.permission.SYSTEM_ALERT_WINDOW", true)), false)
        assertTrue(text.contains("Camera · Granted"))
        assertTrue(text.contains("Microphone · Requested, not granted"))
        assertTrue(text.contains("Check active access in Android Settings"))
        assertFalse(PrivacyAudit.isSensitive("android.permission.INTERNET"))
    }
    @Test fun dnsLogRequiresConsentIsBoundedAndClearedOnDisable() {
        DnsActivityLog.record("example.com", "blocked", "local")
        assertTrue(DnsActivityLog.snapshot().isEmpty())
        DnsActivityLog.setEnabled(true)
        repeat(80) { DnsActivityLog.record("host$it.example.com", "blocked", "local") }
        assertEquals(64, DnsActivityLog.snapshot().size)
        assertEquals("host79.example.com", DnsActivityLog.snapshot().first().host)
        DnsActivityLog.setEnabled(false)
        assertTrue(DnsActivityLog.snapshot().isEmpty())
    }
    @Test fun dnsExceptionsNeverBypassSecurityRulesOrUnrelatedSubdomains() {
        DnsActivityLog.setAllowed(setOf("danger.example.com"))
        assertEquals(DnsRuleCategory.SECURITY_THREAT,
            DnsDomainPolicy(setOf("danger.example.com"), true).classify("danger.example.com"))
        assertFalse(DnsActivityLog.locallyAllowed("sub.danger.example.com"))
        assertNull(DnsActivityLog.validHost("https://example.com/path"))
    }
    @Test fun redirectInspectorRejectsCredentialsDowngradesAndPrivateAddresses() {
        assertFalse(SafeRedirectInspector.permitted(URI("https://user:pass@example.com")))
        assertFalse(SafeRedirectInspector.permitted(URI("http://example.com")))
        assertFalse(SafeRedirectInspector.publicAddress(InetAddress.getByName("127.0.0.1")))
        assertFalse(SafeRedirectInspector.publicAddress(InetAddress.getByName("100.64.0.1")))
        assertFalse(SafeRedirectInspector.publicAddress(InetAddress.getByName("192.168.1.1")))
        assertFalse(SafeRedirectInspector.publicAddress(InetAddress.getByName("::1")))
        assertFalse(SafeRedirectInspector.publicAddress(InetAddress.getByName("fc00::1")))
        assertTrue(SafeRedirectInspector.publicAddress(InetAddress.getByName("1.1.1.1")))
        var requests = 0
        val result = SafeRedirectInspector.inspect("https://example.com/a") {
            requests++
            SafeRedirectInspector.Response(302, "http://example.com/b")
        }
        assertEquals(1, requests)
        assertFalse(result.complete)
    }
    @Test fun redirectsResolveRelativeLocationsAndDetectLoops() {
        val chain = SafeRedirectInspector.inspect("https://example.com/start") { uri ->
            if (uri.path == "/start") SafeRedirectInspector.Response(302, "/finish")
            else SafeRedirectInspector.Response(200, null)
        }
        assertEquals(listOf("https://example.com/start", "https://example.com/finish"), chain.chain)
        assertTrue(chain.complete)
        val loop = SafeRedirectInspector.inspect("https://example.com/start") { SafeRedirectInspector.Response(302, "/start") }
        assertFalse(loop.complete)
        assertEquals("Redirect loop", loop.reason)
    }
}
