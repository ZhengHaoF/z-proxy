import 'dart:async';

import 'package:flutter/services.dart';

/// MethodChannel/EventChannel wrapper for the native VPN bridge
/// (`AndroidManifest` service + `AppPlugin.kt`).
class VpnChannel {
  static const _channel = MethodChannel('zhihu_proxy/vpn');
  static const _state = EventChannel('zhihu_proxy/vpn_state');

  StreamSubscription<dynamic>? _sub;

  /// Fires at engine attach with the current state, then on every change
  /// (revokes, always-on restarts, manual start/stop).
  void listen(void Function(bool running) onState) {
    _sub ??= _state.receiveBroadcastStream().listen(
      (event) {
        if (event is Map) {
          onState(event['running'] == true);
        }
      },
      onError: (_) {}, // no native bridge (e.g. tests): stay idle
    );
  }

  Future<void> dispose() => _sub?.cancel() ?? Future.value();

  Future<bool> prepare() async {
    final r = await _channel.invokeMapMethod<String, dynamic>('prepare');
    return r?['granted'] == true;
  }

  Future<bool> start(int port) async {
    final r = await _channel.invokeMapMethod<String, dynamic>(
      'start',
      {'port': port},
    );
    return r?['started'] == true;
  }

  Future<void> stop() => _channel.invokeMethod('stop');

  Future<bool> requestNotificationPermission() async {
    final r = await _channel.invokeMethod('requestNotificationPermission');
    return r == true;
  }

  Future<bool> isBatteryOptimizationDisabled() async {
    final r = await _channel.invokeMethod('isBatteryOptimizationDisabled');
    return r == true;
  }

  Future<bool> openBatteryOptimizationSettings() async {
    final r = await _channel.invokeMethod('openBatteryOptimizationSettings');
    return r == true;
  }
}