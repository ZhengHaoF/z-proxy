package io.zproxy.zproxy_client.service

import android.content.Context
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.os.Handler
import android.os.Looper
import android.util.Log
import androidx.core.content.getSystemService
import java.util.concurrent.ConcurrentHashMap

/**
 * Restarts the tunnel when the underlying network actually changes.
 *
 * Decision rule: a rebuild happens only when a *new* network appears or a
 * known one disappears. Re-issued `onAvailable` events for an already known
 * network (Android re-evaluates Wi-Fi whenever the VPN comes up, which would
 * otherwise loop forever) and events owned by the VPN itself
 * (TRANSPORT_VPN) are ignored. De-bounced as well.
 */
class NetworkObserveModule(
    private val context: Context,
    private val onNetworkChanged: () -> Unit,
) {
    private val handler = Handler(Looper.getMainLooper())
    private val connectivity by lazy { context.getSystemService<ConnectivityManager>() }
    private val vpnNetworks = ConcurrentHashMap.newKeySet<Network>()
    private val knownNetworks = ConcurrentHashMap.newKeySet<Network>()
    @Volatile
    private var restartScheduled = false

    private val callback = object : ConnectivityManager.NetworkCallback() {
        override fun onAvailable(network: Network) {
            if (vpnNetworks.contains(network)) {
                return
            }
            if (!knownNetworks.add(network)) {
                // Same network re-evaluated (VPN came up): not a real switch.
                Log.d(TAG, "ignored re-available: $network")
                return
            }
            onEvent(network)
        }

        override fun onLost(network: Network) {
            knownNetworks.remove(network)
            onEvent(network)
        }

        override fun onCapabilitiesChanged(
            network: Network,
            networkCapabilities: NetworkCapabilities,
        ) {
            if (networkCapabilities.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) {
                vpnNetworks.add(network)
            }
        }
    }

    private fun onEvent(network: Network) {
        if (vpnNetworks.remove(network)) {
            return
        }
        val caps = connectivity?.getNetworkCapabilities(network)
        if (caps?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) == true) {
            vpnNetworks.add(network)
            return
        }
        scheduleRestart()
    }

    private fun scheduleRestart() {
        if (restartScheduled) {
            return
        }
        restartScheduled = true
        handler.postDelayed({
            restartScheduled = false
            onNetworkChanged()
        }, RESTART_DEBOUNCE_MS)
    }

    fun register() {
        connectivity ?: return
        connectivity!!.registerDefaultNetworkCallback(callback, handler)
    }

    fun unregister() {
        connectivity ?: return
        connectivity!!.unregisterNetworkCallback(callback)
        handler.removeCallbacksAndMessages(null)
    }

    private companion object {
        const val RESTART_DEBOUNCE_MS = 500L
        const val TAG = "NetObserve"
    }
}