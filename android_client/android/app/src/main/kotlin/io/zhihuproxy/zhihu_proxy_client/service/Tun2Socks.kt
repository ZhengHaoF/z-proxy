package io.zhihuproxy.zhihu_proxy_client.service

import android.util.Log

/**
 * In-process tun2socks engine (Go shared library `libtun2socks.so`, built
 * from xjasonlyu/tun2socks v2.7.0 with a thin JNI wrapper).
 *
 * The engine runs inside this process, so the TUN fd is passed as a plain
 * integer argument — Android close-inherited-fds child processes, which is
 * why a subprocess approach cannot work here.
 */
object Tun2Socks {
    private const val TAG = "Tun2Socks"

    init {
        System.loadLibrary("tun2socks")
    }

    @Volatile
    private var running = false

    val isRunning: Boolean
        get() = running

    private external fun nativeStart(
        fd: Int,
        proxy: String,
        mtu: Int,
        logLevel: String,
    ): Int

    private external fun nativeStop(): Int

    /** Starts the engine with the given tun [fd]; returns `false` on failure. */
    fun start(fd: Int, socksPort: Int, mtu: Int): Boolean {
        stop()
        Log.i(TAG, "engine start fd=$fd socksPort=$socksPort mtu=$mtu")
        val code = try {
            nativeStart(fd, "socks5://127.0.0.1:$socksPort", mtu, "info")
        } catch (t: Throwable) {
            Log.e(TAG, "engine start failed", t)
            return false
        }
        running = code == 0
        if (running) {
            Log.i(TAG, "engine started: socks5://127.0.0.1:$socksPort")
        } else {
            Log.e(TAG, "engine start returned code=$code")
        }
        return running
    }

    /** Stops the engine (idempotent). */
    fun stop() {
        if (!running) {
            return
        }
        running = false
        try {
            nativeStop()
        } catch (t: Throwable) {
            Log.e(TAG, "engine stop failed", t)
        }
    }
}