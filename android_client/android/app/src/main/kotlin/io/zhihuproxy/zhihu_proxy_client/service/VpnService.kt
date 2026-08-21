package io.zhihuproxy.zhihu_proxy_client.service

import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.net.VpnService as SystemVpnService
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.os.ParcelFileDescriptor
import android.util.Log
import androidx.core.app.NotificationCompat
import io.zhihuproxy.zhihu_proxy_client.MainActivity
import io.zhihuproxy.zhihu_proxy_client.R
import java.net.InetAddress

/**
 * VPN session lifecycle: builds the tun device, hands the fd to tun2socks
 * (which forwards every packet to the local SOCKS5 engine), runs as a
 * foreground service and reports state changes to the Flutter layer.
 *
 * The app itself is excluded from the VPN (`addDisallowedApplication`), so
 * the engine's DIRECT sockets leave through the physical interface instead
 * of looping back into the tun.
 */
class VpnService : SystemVpnService() {

    companion object {
        private const val TAG = "ZhihuProxyVpn"

        const val ACTION_START = "io.zhihuproxy.zhihu_proxy_client.action.VPN_START"
        const val ACTION_STOP = "io.zhihuproxy.zhihu_proxy_client.action.VPN_STOP"
        const val EXTRA_SOCKS_PORT = "socks_port"

        private const val CHANNEL_ID = "vpn_channel"
        private const val NOTIFICATION_ID = 1001

        const val IPV4_ADDRESS = "172.19.0.1"
        const val IPV4_PREFIX = 30
        const val DNS_ADDRESS = "172.19.0.2"
        const val MTU = 9000

        @Volatile
        var isRunning = false
            private set

        @Volatile
        var socksPort = 0
            private set

        /** Fires state changes to the Flutter layer (AppPlugin registers it). */
        var stateListener: ((running: Boolean) -> Unit)? = null
    }

    private var tunFd: ParcelFileDescriptor? = null
    private var starting = false
    private val mainHandler = Handler(Looper.getMainLooper())
    private lateinit var networkWatch: NetworkObserveModule

    override fun onCreate() {
        super.onCreate()
        networkWatch = NetworkObserveModule(this) {
            if (isRunning) {
                restartTun()
            }
        }
        networkWatch.register()
    }

    override fun onBind(intent: Intent): android.os.IBinder? = super.onBind(intent)

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        return try {
            when (intent?.action) {
                ACTION_START -> {
                    val port = intent.getIntExtra(EXTRA_SOCKS_PORT, 0)
                    if (port <= 0) {
                        // Always-on may restart the service while the UI (which owns
                        // the SOCKS engine) is dead; ask the UI layer to restore.
                        stateListener?.invoke(false)
                        stopSelf()
                        return START_NOT_STICKY
                    }
                    socksPort = port
                    startTun()
                }

                ACTION_STOP -> {
                    stopTun()
                    stopSelf()
                }

                else -> {
                    // Started by the system (Always-on VPN) again; the UI must
                    // restore the engine before a tunnel can be established.
                    stateListener?.invoke(false)
                }
            }
            START_STICKY
        } catch (t: Throwable) {
            Log.e(TAG, "onStartCommand failed", t)
            stopSelf()
            START_NOT_STICKY
        }
    }

    override fun onRevoke() {
        Log.i(TAG, "onRevoke: VPN authorization revoked")
        stopTun()
        stopSelf()
    }

    override fun onDestroy() {
        stopTun()
        if (::networkWatch.isInitialized) {
            networkWatch.unregister()
        }
        super.onDestroy()
    }

    /** Establishes the tun session and launches the in-process engine.
     * Runs async: the foreground notification must be posted before the
     * (potentially slow, emulator-translated) engine startup finishes,
     * otherwise Android kills the service for missing `startForeground`
     * within the 5s window. */
    fun startTun() {
        if (isRunning || starting) {
            return
        }
        starting = true
        Log.i(TAG, "startTun: socksPort=$socksPort")
        startForeground(connecting = true)
        Thread {
            try {
                val fd = establishTun()
                if (fd == null) {
                    Log.e(TAG, "VPN establishment was rejected by the system")
                    postTunFailure("establish rejected")
                    return@Thread
                }
                tunFd = fd
                Log.i(TAG, "tun established fd=${fd.fd}")
                val started = Tun2Socks.start(fd = fd.fd, socksPort = socksPort, mtu = MTU)
                Log.i(TAG, "engine launched=$started")
                if (!started) {
                    fd.close()
                    tunFd = null
                    postTunFailure("engine start failed")
                    return@Thread
                }
                // The engine now owns the tun fd: detach the Java handle so
                // nothing can double-close it (fdsan aborts the process).
                fd.detachFd()
                tunFd = null
                isRunning = true
                starting = false
                runOnMain {
                    startForeground(connecting = false)
                    Log.i(TAG, "vpn running")
                    stateListener?.invoke(true)
                }
            } catch (t: Throwable) {
                Log.e(TAG, "startTun failed", t)
                postTunFailure("exception: ${t.message}")
            }
        }.apply { name = "vpn-tun"; start() }
    }

    private fun postTunFailure(reason: String) {
        starting = false
        isRunning = false
        Log.e(TAG, "tunnel failed: $reason")
        runOnMain {
            stopForeground(true)
            stateListener?.invoke(false)
            stopSelf()
        }
    }

    private fun runOnMain(block: () -> Unit) {
        mainHandler.post(block)
    }

    /** Tears down tun2socks and the tun device; the service itself stays up. */
    fun stopTun() {
        starting = false
        if (!isRunning && tunFd == null) {
            return
        }
        isRunning = false
        Tun2Socks.stop()
        tunFd?.close()
        tunFd = null
        stopForeground(true)
    }

    /** Rebuilds the tunnel after an underlying network switch. */
    private fun restartTun() {
        stopTun()
        startTun()
    }

    private fun establishTun(): ParcelFileDescriptor? {
        val builder = Builder()
        builder.addAddress(InetAddress.getByName(IPV4_ADDRESS), IPV4_PREFIX)
        builder.addRoute(InetAddress.getByName("0.0.0.0"), 0)
        builder.addDnsServer(InetAddress.getByName(DNS_ADDRESS))
        builder.setMtu(MTU)
        builder.setSession("zhihu-proxy")
        builder.setBlocking(false)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            builder.setMetered(false)
        }
        // Bypass the tunnel for this app so DIRECT flows leave via the
        // physical interface (see class doc).
        builder.addDisallowedApplication(packageName)
        try {
            builder.addRoute(InetAddress.getByName("::"), 0)
        } catch (_: Exception) {
            // IPv6 routing unsupported by the device: fine, IPv4 still works.
        }
        return builder.establish()
    }

    private fun startForeground(connecting: Boolean) {
        createChannel()
        val stopIntent = Intent(this, VpnService::class.java).setAction(ACTION_STOP)
        val stopPi = PendingIntent.getService(
            this,
            0,
            stopIntent,
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )
        val contentIntent = PendingIntent.getActivity(
            this,
            1,
            Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )
        val notification = NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle("知乎代理")
            .setContentText(if (connecting) "正在连接…" else "代理运行中")
            .setSmallIcon(R.drawable.ic_stat_vpn)
            .setContentIntent(contentIntent)
            .setOngoing(true)
            .addAction(0, "停止", stopPi)
            .build()
        startForeground(NOTIFICATION_ID, notification)
    }

    private fun createChannel() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) {
            return
        }
        val manager = getSystemService(NotificationManager::class.java)
        val channel = NotificationChannel(
            CHANNEL_ID,
            "VPN 服务",
            NotificationManager.IMPORTANCE_LOW,
        )
        manager.createNotificationChannel(channel)
    }
}