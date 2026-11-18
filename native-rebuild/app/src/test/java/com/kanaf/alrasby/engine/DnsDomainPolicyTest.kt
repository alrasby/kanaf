package com.kanaf.alrasby.engine

import com.kanaf.alrasby.BuildConfig
import org.junit.Assert.*
import org.junit.Test

/** Security classification is never inferred from ad inventory. */
class DnsDomainPolicyTest {
    @Test fun threatAndAdCategoriesDoNotLeakAcrossPolicies() {
        val safe = DnsDomainPolicy(setOf("confirmed-threat.invalid"), false)
        assertEquals(DnsRuleCategory.SECURITY_THREAT,
            safe.classify("sub.confirmed-threat.invalid"))
        assertEquals(DnsRuleCategory.ALLOWED, safe.classify("ads.doubleclick.net"))
        assertEquals(DnsRuleCategory.ALLOWED, safe.classify("doubleclick.net.example.com"))
        assertEquals(DnsRuleCategory.ALLOWED,
            safe.classify("confirmed-threat.invalid.attacker.invalid"))
        val community = DnsDomainPolicy(setOf("confirmed-threat.invalid"), true)
        assertEquals(DnsRuleCategory.SECURITY_THREAT,
            community.classify("confirmed-threat.invalid"))
        assertEquals(DnsRuleCategory.AD_TRACKER,
            community.classify("ads.doubleclick.net"))
    }

    @Test fun compiledDistributionEnforcesProviderAndLocalRuleBoundaries() {
        val result = DnsDomainPolicy.forBuild().classify("ads.doubleclick.net")
        if (BuildConfig.KANAF_PLAY_DNS_SECURITY_ONLY) {
            assertEquals(DnsRuleCategory.ALLOWED, result)
            assertEquals(listOf(DnsProviderStore.PLAY_SECURITY), DnsProviderStore.choices)
            assertEquals(DnsProviderStore.PLAY_SECURITY, DnsProviderStore.defaultProvider)
            assertEquals("https://security.cloudflare-dns.com/dns-query",
                DnsProviderStore.endpoint(DnsProviderStore.PLAY_SECURITY))
            assertNull(DnsProviderStore.endpoint(DnsProviderStore.STANDARD))
            assertNull(DnsProviderStore.endpoint(DnsProviderStore.FAMILY))
            assertNull(DnsProviderStore.endpoint(DnsProviderStore.LEGACY))
        } else {
            assertEquals(DnsRuleCategory.AD_TRACKER, result)
            assertEquals(DnsProviderStore.STANDARD, DnsProviderStore.defaultProvider)
            assertEquals("https://dns.adguard-dns.com/dns-query",
                DnsProviderStore.endpoint(DnsProviderStore.STANDARD))
            assertNull(DnsProviderStore.endpoint(DnsProviderStore.PLAY_SECURITY))
        }
    }
}
