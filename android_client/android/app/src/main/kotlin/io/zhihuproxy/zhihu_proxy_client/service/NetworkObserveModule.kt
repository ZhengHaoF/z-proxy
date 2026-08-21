package io.zhihuproxy.zhihu_proxy_client.service

import android.content.Context
import android.net.ConnectivityManager
import android.net.Network
import android.os.Handler
import android.os.Looper
import androidx.core.content.getSystemService

/**
 * Listens for underlying network changes (Wi-Fi <-> mobile data, etc.) and
 * fires [onNetworkChanged]; the VPN route set must be re-established after a
 * switch, so the tunnel is rebuilt. De-bounced to ignore route churn.
 */
class NetworkObserveModule(
    private val context: Context,
    private val onNetworkChanged: () -> Unit,
) {
    private val handler = Handler(Looper.getMainLooper())
    private var restartScheduled = false

    private val callback = object : ConnectivityManager.NetworkCallback() {
        override fun onAvailable(network: Network) {
            scheduleRestart()
        }

        override fun onLost(network: Network) {
            scheduleRestart()
        }
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
        val cm = context.getSystemService<ConnectivityManager>() ?: return
        cm.registerDefaultNetworkCallback(callback, handler)
    }

    fun unregister() {
        val cm = context.getSystemService<ConnectivityManager>() ?: return
        cm.unregisterNetworkCallback(callback)
        handler.removeCallbacksAndMessages(null)
    }

    private companion object {
        const val RESTART_DEBOUNCE_MS = 500L
    }
}