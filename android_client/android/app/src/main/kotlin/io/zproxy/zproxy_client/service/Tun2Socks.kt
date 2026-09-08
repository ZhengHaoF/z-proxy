package io.zproxy.zproxy_client.service

/**
 * Public facade for the in-process tun2socks engine.
 *
 * All native work is delegated to the legacy-named bridge
 * (`io.zhihuproxy.zhihu_proxy_client.service.Tun2Socks`) whose fully
 * qualified class name is baked into the prebuilt `libtun2socks.so` JNI
 * symbols. See the bridge class for details.
 */
object Tun2Socks {
    private val engine = io.zhihuproxy.zhihu_proxy_client.service.Tun2Socks

    val isRunning: Boolean
        get() = engine.isRunning

    /** Starts the engine with the given tun [fd]; returns `false` on failure. */
    fun start(fd: Int, socksPort: Int, mtu: Int): Boolean = engine.start(fd, socksPort, mtu)

    /** Stops the engine (idempotent). */
    fun stop() = engine.stop()
}
