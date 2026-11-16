package com.kanaf.alrasby.engine

import org.junit.Assert.assertTrue
import org.junit.Test

/** No real DNS requests or private files; deterministic user-data disclosure contract. */
class KanafPrivacyDisclosureTest {
    @Test fun bothLanguagesDiscloseThirdPartyDnsAndVpnLimits() {
        val en = KanafPrivacyDisclosure.VPN_EN
        val ar = KanafPrivacyDisclosure.VPN_AR
        assertTrue(en.contains("AdGuard DNS"))
        assertTrue(en.contains("connecting IP"))
        assertTrue(en.contains("no DNS domain history"))
        assertTrue(en.contains("explicitly agree"))
        assertTrue(en.contains("other apps"))
        assertTrue(ar.contains("AdGuard DNS"))
        assertTrue(ar.contains("عنوان"))
        assertTrue(ar.contains("لا يحتفظ"))
        assertTrue(ar.contains("هل توافق صراحة"))
    }

    @Test fun inAppPrivacyPolicyNamesActualThirdPartyAndLocalProcessing() {
        assertTrue(KanafPrivacyDisclosure.PRIVACY_EN.contains("AdGuard DNS"))
        assertTrue(KanafPrivacyDisclosure.PRIVACY_EN.contains("NabdhServ.Net"))
        assertTrue(KanafPrivacyDisclosure.PRIVACY_EN.contains("Android Keystore"))
        assertTrue(KanafPrivacyDisclosure.PRIVACY_AR.contains("AdGuard DNS"))
        assertTrue(KanafPrivacyDisclosure.PRIVACY_AR.contains("الناشر"))
    }
}
