package com.kanaf.alrasby.engine

import android.annotation.SuppressLint
import android.app.PendingIntent
import android.content.Intent
import android.graphics.drawable.Icon
import android.os.Build
import android.service.quicksettings.Tile
import android.service.quicksettings.TileService
import com.kanaf.alrasby.R

/**
 * User-added Quick Settings tile. Opens Android DNS settings, it never changes
 * privileged DNS settings or starts the optional VPN without explicit consent.
 */
class KanafDnsTileService : TileService() {
    override fun onStartListening() {
        super.onStartListening()
        PrivateDnsToggle.recoverIfStopped(this)
        val snapshot = PrivateDnsCompatibility.read(this)
        val running = KanafDnsVpnService.isRunning()
        qsTile?.apply {
            label = "Kanaf DNS"
            if (Build.VERSION.SDK_INT >= 29) {
                subtitle = when (snapshot.mode) {
                    PrivateDnsCompatibility.Mode.OFF ->
                        if (running) "Filtering" else "DNS off"
                    PrivateDnsCompatibility.Mode.AUTOMATIC -> "DNS auto"
                    PrivateDnsCompatibility.Mode.PROVIDER -> "Private DNS"
                    PrivateDnsCompatibility.Mode.UNKNOWN -> "Unavailable"
                }
            }
            state = if (running) Tile.STATE_ACTIVE else Tile.STATE_INACTIVE
            icon = Icon.createWithResource(
                this@KanafDnsTileService, R.drawable.kanaf_status_icon)
            contentDescription = if (running) "Stop Kanaf DNS" else "Start Kanaf DNS"
            updateTile()
        }
    }

    // Android <= 13 requires Intent; API 34+ requires PendingIntent.
    // The deprecated overload is called only behind a strict version check.
    @SuppressLint("StartActivityAndCollapseDeprecated")
    override fun onClick() {
        super.onClick()
        if (KanafDnsVpnService.isRunning()) {
            stopService(Intent(this, KanafDnsVpnService::class.java))
            qsTile?.apply { state = Tile.STATE_INACTIVE; updateTile() }
            return
        }
        val intent = Intent(this, DnsTileControlActivity::class.java)
            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        if (Build.VERSION.SDK_INT >= 34) {
            val pending = PendingIntent.getActivity(this, 417, intent,
                PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE)
            startActivityAndCollapse(pending)
        } else {
            @Suppress("DEPRECATION")
            startActivityAndCollapse(intent)
        }
    }
}
