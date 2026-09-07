package io.zproxy.zproxy_client.service

import android.content.Context
import android.content.Intent
import android.util.Log
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
    fun start(context: Context, socksPort: Int, dnsServer: String? = null): Boolean {
        return try {
            if (socksPort <= 0 || android.net.VpnService.prepare(context) != null) {
                false
            } else {
                val intent = Intent(context, VpnService::class.java)
                    .setAction(VpnService.ACTION_START)
                    .putExtra(VpnService.EXTRA_SOCKS_PORT, socksPort)
                    .putExtra(VpnService.EXTRA_DNS_SERVER, dnsServer ?: VpnService.DNS_ADDRESS)
                ContextCompat.startForegroundService(context, intent)
                true
            }
        } catch (t: Throwable) {
            Log.e("ServiceController", "start failed", t)
            false
        }
    }

    /** Requests the VPN service to tear the tunnel down (and stop itself). */
    fun stop(context: Context) {
        context.startService(
            Intent(context, VpnService::class.java).setAction(VpnService.ACTION_STOP),
        )
    }
}