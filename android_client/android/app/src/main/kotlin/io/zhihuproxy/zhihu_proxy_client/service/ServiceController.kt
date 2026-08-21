package io.zhihuproxy.zhihu_proxy_client.service

import android.content.Context
import android.content.Intent
import androidx.core.content.ContextCompat

/**
 * Thin entry point for the Flutter layer: VPN authorization check and
 * start/stop of the foreground {@link VpnService}.
 */
object ServiceController {

    /** Returns `null` when VPN usage is already authorized, otherwise the
     * permission intent that must be surfaced to the user. */
    fun prepare(context: Context): Intent? =
        android.net.VpnService.prepare(context)

    /** Starts the VPN foreground service; the caller must have run
     * [prepare] first. */
    fun start(context: Context, socksPort: Int): Boolean {
        if (socksPort <= 0 || android.net.VpnService.prepare(context) != null) {
            return false
        }
        val intent = Intent(context, VpnService::class.java)
            .setAction(VpnService.ACTION_START)
            .putExtra(VpnService.EXTRA_SOCKS_PORT, socksPort)
        ContextCompat.startForegroundService(context, intent)
        return true
    }

    /** Requests the VPN service to tear the tunnel down (and stop itself). */
    fun stop(context: Context) {
        context.startService(
            Intent(context, VpnService::class.java).setAction(VpnService.ACTION_STOP),
        )
    }
}