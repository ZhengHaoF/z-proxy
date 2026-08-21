package io.zhihuproxy.zhihu_proxy_client.service

import android.content.Context
import android.os.Build
import android.util.Log
import java.io.File
import java.io.FileOutputStream

/**
 * tun2socks subprocess (xjasonlyu/tun2socks v2.7.0, gVisor stack).
 *
 * The binary ships inside Flutter assets (`assets/tun2socks-android-*`) and
 * is copied to the app-private dir at startup, then launched with
 * `--device fd://<fd> --proxy socks5://127.0.0.1:<port> --mtu <mtu>`.
 * The `fd://` device driver is confirmed against the v2.7.0 source
 * (`engine/parse.go` + `core/device/fdbased`); UDP packets are relayed by
 * the engine's SOCKS5 UDP support (DNS included), so no flag is needed here.
 */
object Tun2Socks {
    private const val TAG = "Tun2Socks"
    private const val DIR = "tun2socks"

    private var process: Process? = null
    private var outputThread: Thread? = null
    private var watcherThread: Thread? = null

    val isRunning: Boolean
        get() = process?.isAlive == true

    /**
     * Resolves the asset name for the current ABI and ensures an executable
     * copy exists in the app-private directory.
     */
    fun resolveBinary(context: Context): String {
        val assetName = when (Build.SUPPORTED_ABIS.firstOrNull()) {
            "arm64-v8a" -> "tun2socks-android-arm64"
            "armeabi-v7a" -> "tun2socks-android-armv7"
            "x86_64" -> "tun2socks-android-amd64"
            else -> throw IllegalStateException(
                "Unsupported ABI: ${Build.SUPPORTED_ABIS.firstOrNull()}",
            )
        }
        val dir = File(context.filesDir, DIR).apply { mkdirs() }
        val dst = File(dir, assetName)
        val expected = context.assets.open(assetName).use { it.available() }
        if (!dst.exists() || dst.length() != expected.toLong()) {
            context.assets.open(assetName).use { src ->
                FileOutputStream(dst).use { out -> src.copyTo(out) }
            }
        }
        dst.setExecutable(true)
        return dst.absolutePath
    }

    /**
     * Starts tun2socks with the given tun [fd]. Returns `false` on failure;
     * [onExit] fires when the process dies on its own.
     */
    fun start(
        context: Context,
        fd: Int,
        socksPort: Int,
        mtu: Int,
        onExit: () -> Unit,
    ): Boolean {
        stop()
        return try {
            val binary = resolveBinary(context)
            val cmd = listOf(
                binary,
                "--device", "fd://$fd",
                "--proxy", "socks5://127.0.0.1:$socksPort",
                "--mtu", mtu.toString(),
            )
            Log.i(TAG, "launch: ${cmd.joinToString(" ")}")
            val p = ProcessBuilder(cmd).redirectErrorStream(true).start()
            process = p
            outputThread = Thread {
                try {
                    p.inputStream.bufferedReader().forEachLine { line ->
                        Log.i(TAG, line)
                    }
                } catch (_: Exception) {
                }
            }.apply { name = "tun2socks-out"; start() }
            watcherThread = Thread {
                try {
                    p.waitFor()
                } catch (_: InterruptedException) {
                    return@Thread
                }
                if (process === p && !p.isAlive) {
                    process = null
                    onExit()
                }
            }.apply { name = "tun2socks-watch"; start() }
            true
        } catch (e: Exception) {
            Log.e(TAG, "failed to launch tun2socks", e)
            false
        }
    }

    /** Stops the subprocess if it is alive. */
    fun stop() {
        val p = process
        process = null
        if (p?.isAlive == true) {
            p.destroy()
        }
        outputThread = null
        watcherThread = null
    }
}