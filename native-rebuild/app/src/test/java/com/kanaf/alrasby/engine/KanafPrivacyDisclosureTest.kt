package com.kanaf.alrasby.engine

import org.junit.Assert.assertTrue
import org.junit.Test

/** No real DNS requests or private files; deterministic user-data disclosure contract. */
class KanafPrivacyDisclosureTest {
    @Test fun bothLanguagesDiscloseThirdPartyDnsAndVpnLimits() {
        val en = KanafPrivacyDisclosure.VPN_EN
        val ar = KanafPrivacyDisclosure.VPN_AR
        assertTrue(en.contains(if (com.kanaf.alrasby.BuildConfig.KANAF_PLAY_DNS_SECURITY_ONLY)
            "Cloudflare" else "AdGuard DNS"))
        assertTrue(en.contains("connecting IP"))
        assertTrue(en.contains("64 events in RAM until stop or disable"))
        assertTrue(en.contains("explicitly agree"))
        assertTrue(en.contains(if (com.kanaf.alrasby.BuildConfig.KANAF_PLAY_DNS_SECURITY_ONLY)
            "NOT ad or tracker blocking" else "other apps"))
        assertTrue(ar.contains(if (com.kanaf.alrasby.BuildConfig.KANAF_PLAY_DNS_SECURITY_ONLY)
            "Cloudflare" else "AdGuard DNS"))
        assertTrue(ar.contains("عنوان"))
        assertTrue(ar.contains("64 حدثًا في الذاكرة"))
        assertTrue(ar.contains("هل توافق صراحة"))
    }

    @Test fun inAppPrivacyPolicyNamesActualThirdPartyAndLocalProcessing() {
        assertTrue(KanafPrivacyDisclosure.PRIVACY_EN.contains(
            if (com.kanaf.alrasby.BuildConfig.KANAF_PLAY_DNS_SECURITY_ONLY)
                "Cloudflare" else "AdGuard DNS"))
        assertTrue(KanafPrivacyDisclosure.PRIVACY_EN.contains("NabdhServ.Net"))
        assertTrue(KanafPrivacyDisclosure.PRIVACY_EN.contains("Android Keystore"))
        assertTrue(KanafPrivacyDisclosure.PRIVACY_AR.contains(
            if (com.kanaf.alrasby.BuildConfig.KANAF_PLAY_DNS_SECURITY_ONLY)
                "Cloudflare" else "AdGuard DNS"))
        assertTrue(KanafPrivacyDisclosure.PRIVACY_AR.contains("الناشر"))
    }
}
