package com.kanaf.alrasby.engine

import org.junit.Assert.*
import org.junit.Test

class DnsProviderStoreTest {
    @Test fun exactlyOnePublishedProviderIsActiveWithLegacyAlias() {
        if (com.kanaf.alrasby.BuildConfig.KANAF_PLAY_DNS_SECURITY_ONLY) {
            assertEquals(listOf(DnsProviderStore.PLAY_SECURITY), DnsProviderStore.choices)
            assertEquals("https://security.cloudflare-dns.com/dns-query",
                DnsProviderStore.endpoint(DnsProviderStore.PLAY_SECURITY))
            assertNull(DnsProviderStore.endpoint(DnsProviderStore.STANDARD))
            assertNull(DnsProviderStore.endpoint(DnsProviderStore.LEGACY))
            assertNull(DnsProviderStore.endpoint(DnsProviderStore.FAMILY))
        } else {
            assertEquals(3, DnsProviderStore.choices.distinct().size)
            assertEquals("https://dns.adguard-dns.com/dns-query",
                DnsProviderStore.endpoint(DnsProviderStore.STANDARD))
            assertEquals(DnsProviderStore.endpoint(DnsProviderStore.STANDARD),
                DnsProviderStore.endpoint(DnsProviderStore.LEGACY))
            assertEquals("https://family.adguard-dns.com/dns-query",
                DnsProviderStore.endpoint(DnsProviderStore.FAMILY))
        }
    }

    @Test fun customAndMaliciousHostsCannotRedirectDnsRequests() {
        assertNull(DnsProviderStore.endpoint("https://attacker.invalid"))
        assertNull(DnsProviderStore.endpoint("dns.adguard-dns.com.attacker.invalid"))
        assertNull(DnsProviderStore.endpoint(""))
    }
}
