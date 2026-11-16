package com.kanaf.alrasby.engine

import android.app.Activity
import android.app.AlertDialog
import android.content.Intent
import android.net.VpnService
import android.os.Bundle
import com.kanaf.alrasby.KanafUiPreferences

/**
 * Foreground user gesture launched from Quick Settings. Only the Android
 * system VPN prompt can grant VPN use; no attempt to bypass user consent.
 */
class DnsTileControlActivity : Activity() {
    private val vpnPermissionRequest = 513

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        if (KanafDnsVpnService.isRunning()) {
            stopService(Intent(this, KanafDnsVpnService::class.java))
            finish()
            return
        }
        val state = PrivateDnsCompatibility.read(this)
        if (PrivateDnsToggle.decision(state) ==
            PrivateDnsToggle.Decision.MANUAL_REQUIRED) {
            AlertDialog.Builder(this).setTitle("Kanaf DNS")
                .setMessage("Android Private DNS uses a strict provider. " +
                    "Kanaf cannot override your provider without a special system permission. " +
                    "Choose Automatic in Android Private DNS settings to use Kanaf securely. " +
                    "No ADB is required.")
                .setPositiveButton("Android DNS settings") { _, _ ->
                    PrivateDnsSettingsNavigator.open(this)
                    finish()
                }
                .setNegativeButton("Cancel") { _, _ -> finish() }
                .setOnCancelListener { finish() }.show()
            return
        }
        // Android's system VPN permission is NOT a substitute for Google
        // Play's prominent in-app disclosure and affirmative consent.
        val arabic = KanafUiPreferences(this).language().isArabic()
        AlertDialog.Builder(this)
            .setTitle(if (arabic) KanafPrivacyDisclosure.VPN_TITLE_AR
                else KanafPrivacyDisclosure.VPN_TITLE_EN)
            .setMessage(if (arabic) KanafPrivacyDisclosure.VPN_AR
                else KanafPrivacyDisclosure.VPN_EN)
            .setPositiveButton(if (arabic) "أوافق وأفعّل DNS" else "Agree & enable DNS") { _, _ ->
                requestSystemVpnConsent()
            }
            .setNegativeButton(if (arabic) "إلغاء" else "Cancel") { _, _ -> finish() }
            .setOnCancelListener { finish() }
            .show()
    }

    private fun requestSystemVpnConsent() {
        runCatching {
            val request = VpnService.prepare(this)
            if (request == null) startFilter()
            else startActivityForResult(request, vpnPermissionRequest)
        }.onFailure { finish() }
    }

    private fun startFilter() {
        runCatching {
            startForegroundService(Intent(this, KanafDnsVpnService::class.java)
                .setAction(KanafDnsVpnService.ACTION_START))
        }
        finish()
    }

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == vpnPermissionRequest && resultCode == RESULT_OK) startFilter()
        else finish()
    }
}
