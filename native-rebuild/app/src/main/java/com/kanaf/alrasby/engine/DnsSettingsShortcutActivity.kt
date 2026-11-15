package com.kanaf.alrasby.engine

import android.app.Activity
import android.os.Bundle

/** Explicit activity target required by Android 14+ Quick Settings tile API. */
class DnsSettingsShortcutActivity : Activity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        PrivateDnsSettingsNavigator.open(this)
        finish()
    }
}
