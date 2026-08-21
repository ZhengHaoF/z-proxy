import 'dart:async';

import 'package:flutter/foundation.dart';
import 'package:zhihu_proxy_client/core/config.dart';
import 'package:zhihu_proxy_client/core/probe.dart';
import 'package:zhihu_proxy_client/core/proxy_engine.dart';
import 'package:zhihu_proxy_client/services/config_store.dart';
import 'package:zhihu_proxy_client/services/vpn_channel.dart';

/// App-wide state: config, rules, proxy engine lifecycle and the native VPN
/// bridge. A single instance is shared by all pages.
class AppServices extends ChangeNotifier {
  final VpnChannel vpn = VpnChannel();
  final _logs = <String>[];
  ProxyEngine? _engine;

  Config config = defaults;
  List<String> rules = [];
  bool vpnAuthorized = false;
  bool vpnRunning = false;
  String? lastError;
  int _startMillis = 0;

  List<String> get logs => List.unmodifiable(_logs);

  int get secondsRunning {
    if (!vpnRunning || _startMillis == 0) {
      return 0;
    }
    return DateTime.now().millisecondsSinceEpoch ~/ 1000 - _startMillis;
  }

  Future<void> init() async {
    try {
      config = await ConfigStore.loadConfig();
      rules = await ConfigStore.loadRules();
    } catch (_) {
      // keep defaults when storage is unavailable
    }
    vpn.listen((running) {
      vpnRunning = running;
      if (running) {
        _startMillis = DateTime.now().millisecondsSinceEpoch;
      } else {
        _startMillis = 0;
      }
      notifyListeners();
    });
    // Recover the VPN consent state when the app (re)starts: no dialog is
    // shown when consent already exists.
    try {
      vpnAuthorized = await vpn.prepare();
    } catch (_) {
      vpnAuthorized = false;
    }
    notifyListeners();
  }

  Future<void> applyConfig(Config c) async {
    config = c;
    await ConfigStore.saveConfig(c);
    notifyListeners();
  }

  Future<void> applyRules(List<String> r) async {
    rules = List.of(r);
    await ConfigStore.saveRules(rules);
    notifyListeners();
  }

  /// Asks for VPN consent (native system dialog when needed), boots the SOCKS
  /// engine and hands its port to the native VpnService.
  Future<void> start() async {
    lastError = null;
    notifyListeners();
    try {
      vpnAuthorized = await vpn.prepare();
    } catch (e) {
      lastError = '授权失败: $e';
      notifyListeners();
      return;
    }
    if (!vpnAuthorized) {
      notifyListeners();
      return;
    }
    try {
      final engine = ProxyEngine(
        serverHost: config.serverHost,
        serverPort: config.serverPort,
        token: config.token,
        rules: rules,
        mode: config.mode,
        bypass: config.bypass,
      );
      engine.setRequestLogger((tag, target) {
        _addLog('[$tag] $target');
      });
      final port = await engine.serveSocks();
      _engine = engine;
      final started = await vpn.start(port);
      if (!started) {
        lastError = 'VPN 启动失败(未授权或被系统拒绝)';
        await engine.close();
        _engine = null;
        notifyListeners();
        return;
      }
      notifyListeners();
    } catch (e) {
      lastError = '启动失败: $e';
      notifyListeners();
    }
  }

  Future<void> stop() async {
    await vpn.stop();
    await _engine?.close();
    _engine = null;
    vpnRunning = false;
    notifyListeners();
  }

  Future<ProbeResult> testConnection() => probe(
        serverHost: config.serverHost,
        serverPort: config.serverPort,
        token: config.token,
      );

  void clearLogs() {
    _logs.clear();
    notifyListeners();
  }

  void _addLog(String line) {
    _logs.add(line);
    if (_logs.length > 500) {
      _logs.removeRange(0, _logs.length - 500);
    }
    notifyListeners();
  }
}