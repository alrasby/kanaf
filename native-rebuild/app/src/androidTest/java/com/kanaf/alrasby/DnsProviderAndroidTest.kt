package com.kanaf.alrasby

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.kanaf.alrasby.engine.DnsProviderStore
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class DnsProviderAndroidTest {
    @Test fun selectedProviderPersistsAndLegacyAliasUsesModernEncryptedEndpoint() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val original = DnsProviderStore.selected(context)
        try {
            assertTrue(DnsProviderStore.choose(context, DnsProviderStore.FAMILY))
            assertEquals(DnsProviderStore.FAMILY, DnsProviderStore.selected(context))
            assertEquals("https://family.adguard-dns.com/dns-query",
                DnsProviderStore.endpoint(DnsProviderStore.selected(context)))

            assertTrue(DnsProviderStore.choose(context, DnsProviderStore.LEGACY))
            assertEquals(DnsProviderStore.LEGACY, DnsProviderStore.selected(context))
            assertEquals("https://dns.adguard-dns.com/dns-query",
                DnsProviderStore.endpoint(DnsProviderStore.selected(context)))

            assertFalse(DnsProviderStore.choose(context, "attacker.invalid"))
            assertEquals(DnsProviderStore.LEGACY, DnsProviderStore.selected(context))
        } finally {
            assertTrue(DnsProviderStore.choose(context, original))
        }
    }
}
