package io.zproxy.zproxy_client.service

import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.VpnService as SystemVpnService
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.os.ParcelFileDescriptor
import android.util.Log
import androidx.core.app.NotificationCompat
import io.zproxy.zproxy_client.MainActivity
import io.zproxy.zproxy_client.R
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
        private const val TAG = "ZProxyVpn"

        const val ACTION_START = "io.zproxy.zproxy_client.action.VPN_START"
        const val ACTION_STOP = "io.zproxy.zproxy_client.action.VPN_STOP"
        const val EXTRA_SOCKS_PORT = "socks_port"
        const val EXTRA_DNS_SERVER = "dns_server"

        private const val CHANNEL_ID = "vpn_channel"
        private const val NOTIFICATION_ID = 1001

        const val IPV4_ADDRESS = "172.19.0.1"
        const val IPV4_PREFIX = 30
        const val DNS_ADDRESS = "172.19.0.2"
        // Standard Ethernet MTU: jumbo frames (9000) are unsupported by many
        // devices/emulators and cause dropped packets behind the tunnel.
        const val MTU = 1500

        /** Engine watchdog: probe interval and failures before teardown. */
        private const val WATCHDOG_INTERVAL_MS = 5000L
        private const val ENGINE_MAX_FAILURES = 3
        private const val WATCHDOG_CONNECT_TIMEOUT_MS = 2000

        @Volatile
        var isRunning = false
            private set

        @Volatile
        var socksPort = 0
            private set

        /** Real DNS server for the tunnel (defaults to [DNS_ADDRESS] fallback). */
        @Volatile
        var dnsServer: String = DNS_ADDRESS
            private set

        /** Fires state changes to the Flutter layer (AppPlugin registers it). */
        var stateListener: ((running: Boolean) -> Unit)? = null
    }

    private var tunFd: ParcelFileDescriptor? = null
    private var starting = false

    /**
     * Session generation: bumped by every [startTun] and [stopTun]. The
     * async start path captures its generation and aborts if it no longer
     * matches — otherwise a stop issued while the tun was still being
     * established would be overwritten when the start path completed
     * ("resurrected" tunnel after the user pressed stop).
     */
    @Volatile
    private var generation = 0

    /** Consecutive watchdog failures; guarded by the main handler. */
    private var engineFailures = 0
    private var watchdog: Runnable? = null

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
                    dnsServer = intent.getStringExtra(EXTRA_DNS_SERVER) ?: DNS_ADDRESS
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
        val gen = ++generation
        Log.i(TAG, "startTun: socksPort=$socksPort gen=$gen")
        startForeground(connecting = true)
        Thread {
            try {
                val fd = establishTun()
                if (fd == null) {
                    Log.e(TAG, "VPN establishment was rejected by the system")
                    postTunFailure("establish rejected", gen)
                    return@Thread
                }
                if (gen != generation) {
                    // stopTun()/restartTun() ran while the tun was being
                    // established: discard the session instead of letting it
                    // resurrect after the user pressed stop.
                    Log.i(TAG, "startTun aborted: generation changed ($gen != $generation)")
                    starting = false
                    fd.close()
                    return@Thread
                }
                tunFd = fd
                Log.i(TAG, "tun established fd=${fd.fd}")
                val started = Tun2Socks.start(fd = fd.fd, socksPort = socksPort, mtu = MTU)
                Log.i(TAG, "engine launched=$started")
                if (gen != generation) {
                    // Stopped (or restarted) while the engine was spinning up.
                    // The engine owns the fd once started, so only Tun2Socks
                    // may release it in that case (fdsan aborts on double-close).
                    if (started) Tun2Socks.stop() else fd.close()
                    tunFd = null
                    starting = false
                    Log.i(TAG, "startTun aborted after engine start: generation changed")
                    return@Thread
                }
                if (!started) {
                    fd.close()
                    tunFd = null
                    postTunFailure("engine start failed", gen)
                    return@Thread
                }
                // The engine now owns the tun fd: detach the Java handle so
                // nothing can double-close it (fdsan aborts the process).
                fd.detachFd()
                tunFd = null
                isRunning = true
                starting = false
                runOnMain {
                    if (gen != generation || !isRunning) return@runOnMain
                    startForeground(connecting = false)
                    Log.i(TAG, "vpn running")
                    stateListener?.invoke(true)
                    engineFailures = 0
                    scheduleEngineWatchdog(gen)
                }
            } catch (t: Throwable) {
                Log.e(TAG, "startTun failed", t)
                postTunFailure("exception: ${t.message}", gen)
            }
        }.apply { name = "vpn-tun"; start() }
    }

    private fun postTunFailure(reason: String, gen: Int) {
        if (gen != generation) return
        starting = false
        isRunning = false
        Log.e(TAG, "tunnel failed: $reason")
        runOnMain {
            if (gen != generation) return@runOnMain
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
        generation++ // invalidate any in-flight startTun
        watchdog?.let { mainHandler.removeCallbacks(it) }
        watchdog = null
        engineFailures = 0
        starting = false
        if (!isRunning && tunFd == null) {
            stopForeground(true)
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

    // ---- Engine watchdog ----

    /**
     * Periodically verifies the Dart-side SOCKS engine still accepts
     * connections. The engine lives in the Flutter isolate, so it can
     * disappear (activity destroyed, isolate crash) while this foreground
     * service keeps the tunnel up — traffic would silently blackhole.
     * After [ENGINE_MAX_FAILURES] consecutive probes fail the tunnel is
     * torn down and the state change reported.
     */
    private fun scheduleEngineWatchdog(gen: Int) {
        if (gen != generation || !isRunning) return
        watchdog?.let { mainHandler.removeCallbacks(it) }
        val next = Runnable { checkEngineAlive(gen) }
        watchdog = next
        mainHandler.postDelayed(next, WATCHDOG_INTERVAL_MS)
    }

    private fun checkEngineAlive(gen: Int) {
        if (gen != generation || !isRunning || socksPort <= 0) {
            return
        }
        val port = socksPort
        Thread {
            val alive = try {
                java.net.Socket().use {
                    it.connect(java.net.InetSocketAddress("127.0.0.1", port), WATCHDOG_CONNECT_TIMEOUT_MS)
                    true
                }
            } catch (_: Exception) {
                false
            }
            runOnMain {
                if (gen != generation || !isRunning) {
                    return@runOnMain
                }
                if (alive) {
                    engineFailures = 0
                    scheduleEngineWatchdog(gen)
                    return@runOnMain
                }
                engineFailures++
                Log.w(TAG, "watchdog: socks port $port unreachable (failures=$engineFailures)")
                if (engineFailures < ENGINE_MAX_FAILURES) {
                    scheduleEngineWatchdog(gen)
                    return@runOnMain
                }
                Log.e(TAG, "watchdog: engine dead, stopping tunnel")
                stopTun()
                stopSelf()
                stateListener?.invoke(false)
            }
        }.apply { name = "vpn-watchdog"; start() }
    }

    private fun establishTun(): ParcelFileDescriptor? {
        val builder = Builder()
        builder.addAddress(InetAddress.getByName(IPV4_ADDRESS), IPV4_PREFIX)
        builder.addRoute(InetAddress.getByName("0.0.0.0"), 0)
        builder.addDnsServer(InetAddress.getByName(dnsServer))
        builder.setMtu(MTU)
        builder.setSession("z-proxy")
        builder.setBlocking(false)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            builder.setMetered(false)
        }
        // Bypass the tunnel for this app so DIRECT flows leave via the
        // physical interface (see class doc).
        builder.addDisallowedApplication(packageName)
        // Bind the tunnel to the current physical network. Without an
        // underlying network the VPN may not become the default network on
        // Android 12+ (traffic keeps egressing over the physical interface).
        // TRANSPORT_VPN networks must be excluded: `allNetworks` contains
        // this VPN itself, and selecting it as underlying would loop traffic.
        val cm = getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager
        val underlying = cm?.allNetworks
            ?.firstOrNull {
                val caps = cm.getNetworkCapabilities(it)
                caps?.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED) == true &&
                    !caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)
            }
        if (underlying != null) {
            builder.setUnderlyingNetworks(arrayOf(underlying))
        }
        try {
            builder.addRoute(InetAddress.getByName("::"), 0)
        } catch (_: Exception) {
            // IPv6 routing unsupported by the device: fine, IPv4 still works.
        }
        Log.i(TAG, "establishTun: address=$IPV4_ADDRESS/$IPV4_PREFIX dns=$dnsServer mtu=$MTU packageName=$packageName")
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
            .setContentTitle("代理")
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
