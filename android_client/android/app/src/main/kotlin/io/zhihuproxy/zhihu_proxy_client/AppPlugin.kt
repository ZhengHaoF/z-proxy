package io.zhihuproxy.zhihu_proxy_client

import android.Manifest
import android.app.Activity
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.os.PowerManager
import android.provider.Settings
import androidx.core.app.ActivityCompat
import androidx.core.content.ContextCompat
import androidx.core.content.getSystemService
import io.flutter.embedding.engine.plugins.FlutterPlugin
import io.flutter.embedding.engine.plugins.activity.ActivityAware
import io.flutter.embedding.engine.plugins.activity.ActivityPluginBinding
import io.flutter.plugin.common.EventChannel
import io.flutter.plugin.common.MethodCall
import io.flutter.plugin.common.MethodChannel
import io.flutter.plugin.common.MethodChannel.MethodCallHandler
import io.flutter.plugin.common.MethodChannel.Result
import io.zhihuproxy.zhihu_proxy_client.service.ServiceController
import io.zhihuproxy.zhihu_proxy_client.service.VpnService

/**
 * Bridges the Flutter UI and the VPN layer:
 *
 * MethodChannel `zhihu_proxy/vpn` — `prepare` / `start` / `stop` /
 * `syncState` / `requestNotificationPermission` /
 * `isBatteryOptimizationDisabled` / `openBatteryOptimizationSettings`
 *
 * EventChannel `zhihu_proxy/vpn_state` — pushes `{running: bool}` on every
 * tunnel state change (including revokes and always-on restarts).
 */
class AppPlugin :
    FlutterPlugin,
    MethodCallHandler,
    ActivityAware,
    EventChannel.StreamHandler {

    private var activity: Activity? = null
    private var application: Context? = null
    private lateinit var channel: MethodChannel
    private lateinit var stateChannel: EventChannel
    private var stateSink: EventChannel.EventSink? = null

    private var vpnPrepareCallback: ((Boolean) -> Unit)? = null
    private var notificationCallback: ((Boolean) -> Unit)? = null
    private var isRequestingNotificationPermission = false

    override fun onAttachedToEngine(binding: FlutterPlugin.FlutterPluginBinding) {
        application = binding.applicationContext
        channel = MethodChannel(binding.binaryMessenger, "zhihu_proxy/vpn")
        channel.setMethodCallHandler(this)
        stateChannel = EventChannel(binding.binaryMessenger, "zhihu_proxy/vpn_state")
        stateChannel.setStreamHandler(this)
        VpnService.stateListener = { running ->
            val sink = stateSink
            if (sink != null) {
                // Flutter's EventSink requires the main thread.
                Handler(Looper.getMainLooper()).post {
                    sink.success(mapOf("running" to running))
                }
            }
        }
    }

    override fun onDetachedFromEngine(binding: FlutterPlugin.FlutterPluginBinding) {
        channel.setMethodCallHandler(null)
        stateChannel.setStreamHandler(null)
        VpnService.stateListener = null
        stateSink = null
    }

    override fun onMethodCall(call: MethodCall, result: Result) {
        when (call.method) {
            "prepare" -> prepareVpn { granted ->
                result.success(mapOf("granted" to granted))
            }

            "start" -> {
                val port = call.argument<Int>("port") ?: 0
                result.success(mapOf("started" to startVpn(port)))
            }

            "stop" -> {
                stopVpn()
                result.success(true)
            }

            "syncState" -> result.success(
                mapOf(
                    "running" to VpnService.isRunning,
                    "port" to VpnService.socksPort,
                ),
            )

            "requestNotificationPermission" -> requestNotificationPermission { ok ->
                result.success(ok)
            }

            "isBatteryOptimizationDisabled" -> result.success(isBatteryOptimizationDisabled())

            "openBatteryOptimizationSettings" -> result.success(openBatteryOptimizationSettings())

            else -> result.notImplemented()
        }
    }

    private fun startVpn(port: Int): Boolean {
        val context = activity ?: return false
        val started = ServiceController.start(context, port)
        if (started) {
            // The service pushes the running state via the event channel.
        }
        return started
    }

    private fun stopVpn() {
        val context = activity ?: return
        ServiceController.stop(context)
    }

    fun prepareVpn(callback: (Boolean) -> Unit) {
        vpnPrepareCallback?.invoke(false)
        vpnPrepareCallback = callback
        val context = activity ?: run {
            invokeVpnPrepare(false)
            return
        }
        val intent = android.net.VpnService.prepare(context)
        if (intent != null) {
            @Suppress("DEPRECATION")
            context.startActivityForResult(intent, VPN_PERMISSION_REQUEST_CODE)
        } else {
            invokeVpnPrepare(true)
        }
    }

    private fun invokeVpnPrepare(granted: Boolean) {
        vpnPrepareCallback?.invoke(granted)
        vpnPrepareCallback = null
    }

    private fun requestNotificationPermission(callback: (Boolean) -> Unit) {
        notificationCallback?.invoke(false)
        notificationCallback = callback
        val context = activity ?: run {
            invokeNotificationResult(true)
            return
        }
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU) {
            invokeNotificationResult(true)
            return
        }
        if (ContextCompat.checkSelfPermission(
                context,
                Manifest.permission.POST_NOTIFICATIONS,
            ) == PackageManager.PERMISSION_GRANTED
        ) {
            invokeNotificationResult(true)
            return
        }
        if (isRequestingNotificationPermission) {
            return
        }
        isRequestingNotificationPermission = true
        ActivityCompat.requestPermissions(
            context,
            arrayOf(Manifest.permission.POST_NOTIFICATIONS),
            NOTIFICATION_PERMISSION_REQUEST_CODE,
        )
    }

    private fun invokeNotificationResult(allowed: Boolean) {
        isRequestingNotificationPermission = false
        notificationCallback?.invoke(allowed)
        notificationCallback = null
    }

    private fun isBatteryOptimizationDisabled(): Boolean {
        val powerManager = activity?.getSystemService<PowerManager>() ?: return false
        return powerManager.isIgnoringBatteryOptimizations(packageName())
    }

    private fun openBatteryOptimizationSettings(): Boolean {
        val context = activity ?: return false
        return try {
            val intent = Intent(Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS).apply {
                data = android.net.Uri.parse("package:${packageName()}")
            }
            context.startActivity(intent)
            true
        } catch (_: Exception) {
            false
        }
    }

    private fun packageName(): String = application?.packageName ?: activity?.packageName ?: ""

    // ---- ActivityAware ----

    override fun onAttachedToActivity(binding: ActivityPluginBinding) {
        activity = binding.activity
        binding.addActivityResultListener(::onActivityResult)
        binding.addRequestPermissionsResultListener(::onRequestPermissionsResult)
    }

    override fun onDetachedFromActivityForConfigChanges() {
        activity = null
    }

    override fun onReattachedToActivityForConfigChanges(binding: ActivityPluginBinding) {
        activity = binding.activity
        binding.addActivityResultListener(::onActivityResult)
        binding.addRequestPermissionsResultListener(::onRequestPermissionsResult)
    }

    override fun onDetachedFromActivity() {
        activity = null
        invokeVpnPrepare(false)
        invokeNotificationResult(true)
    }

    private fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?): Boolean {
        if (requestCode != VPN_PERMISSION_REQUEST_CODE) {
            return false
        }
        invokeVpnPrepare(resultCode == Activity.RESULT_OK)
        return true
    }

    private fun onRequestPermissionsResult(
        requestCode: Int,
        permissions: Array<out String>,
        grantResults: IntArray,
    ): Boolean {
        if (requestCode != NOTIFICATION_PERMISSION_REQUEST_CODE) {
            return false
        }
        invokeNotificationResult(grantResults.firstOrNull() == PackageManager.PERMISSION_GRANTED)
        return true
    }

    // ---- EventChannel ----

    override fun onListen(arguments: Any?, events: EventChannel.EventSink?) {
        stateSink = events
        events?.success(mapOf("running" to VpnService.isRunning))
    }

    override fun onCancel(arguments: Any?) {
        stateSink = null
    }

    private companion object {
        const val VPN_PERMISSION_REQUEST_CODE = 1001
        const val NOTIFICATION_PERMISSION_REQUEST_CODE = 1002
    }
}