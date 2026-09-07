import 'dart:async';

import 'package:flutter/material.dart';
import 'package:zproxy_client/services/app_services.dart';

class HomePage extends StatefulWidget {
  const HomePage({super.key, required this.services});

  final AppServices services;

  @override
  State<HomePage> createState() => _HomePageState();
}

class _HomePageState extends State<HomePage> {
  Timer? _ticker;

  @override
  void initState() {
    super.initState();
    _ticker = Timer.periodic(const Duration(seconds: 1), (_) => setState(() {}));
  }

  @override
  void dispose() {
    _ticker?.cancel();
    super.dispose();
  }

  String get _uptime {
    final s = widget.services.secondsRunning;
    final h = s ~/ 3600;
    final m = (s % 3600) ~/ 60;
    final sec = s % 60;
    String two(int v) => v.toString().padLeft(2, '0');
    return h > 0 ? '$h:${two(m)}:${two(sec)}' : '${two(m)}:${two(sec)}';
  }

  @override
  Widget build(BuildContext context) {
    final services = widget.services;
    return ListView(
      padding: const EdgeInsets.all(24),
      children: [
        const SizedBox(height: 8),
        _PowerButton(services: services),
        const SizedBox(height: 24),
        Card(
          child: Padding(
            padding: const EdgeInsets.symmetric(vertical: 16),
            child: Row(
              children: [
                _Stat(label: '服务端', value: '${services.config.serverHost}:${services.config.serverPort}'),
                _Stat(label: '规则数', value: '${services.rules.length}'),
                _Stat(label: '运行时长', value: services.vpnRunning ? _uptime : '--:--'),
              ],
            ),
          ),
        ),
        if (services.lastError != null)
          Card(
            color: Theme.of(context).colorScheme.errorContainer,
            child: Padding(
              padding: const EdgeInsets.all(16),
              child: Text(services.lastError!),
            ),
          ),
        const SizedBox(height: 16),
        OutlinedButton.icon(
          onPressed: _runConnectionTest,
          icon: const Icon(Icons.wifi_tethering),
          label: const Text('服务端连接测试'),
        ),
        const SizedBox(height: 8),
        OutlinedButton.icon(
          onPressed: _runSocksProxyTest,
          icon: const Icon(Icons.dns),
          label: const Text('SOCKS5 代理测试'),
        ),
        const SizedBox(height: 24),
        Text(
          'VPN 模式下仅转发匹配规则(或全部,视模式而定)的流量到加密隧道,'
          '其余流量本机直连,不会经过服务端。',
          style: Theme.of(context).textTheme.bodySmall,
        ),
      ],
    );
  }

  Future<void> _runConnectionTest() async {
    final services = widget.services;
    final result = await services.testConnection();
    if (!mounted) {
      return;
    }
    showDialog<void>(
      context: context,
      builder: (context) => AlertDialog(
        title: const Text('服务端连接测试'),
        content: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(result.ok ? '✓ 连接正常' : '✗ 连接失败',
                style: TextStyle(
                  color: result.ok
                      ? Colors.green.shade700
                      : Theme.of(context).colorScheme.error,
                )),
            const SizedBox(height: 12),
            Text(result.msg),
          ],
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.of(context).pop(),
            child: const Text('确定'),
          ),
        ],
      ),
    );
  }

  Future<void> _runSocksProxyTest() async {
    final services = widget.services;
    final result = await services.testSocksProxy();
    if (!mounted) {
      return;
    }
    showDialog<void>(
      context: context,
      builder: (context) => AlertDialog(
        title: const Text('SOCKS5 代理测试'),
        content: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(
              result.ok ? '✓ 代理正常' : '✗ 代理异常',
              style: TextStyle(
                color: result.ok
                    ? Colors.green.shade700
                    : Theme.of(context).colorScheme.error,
              ),
            ),
            const SizedBox(height: 8),
            Text('端口: ${services.socksPort}'),
            const SizedBox(height: 12),
            Text(result.msg),
            if (!result.ok) ...[
              const SizedBox(height: 8),
              const Text(
                '提示: 如果代理测试通过但 VPN 下无法上网,'
                ' 问题在 DNS 解析或 TUN 路由,请检查 DNS 配置和日志。',
                style: TextStyle(fontSize: 12),
              ),
            ],
          ],
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.of(context).pop(),
            child: const Text('确定'),
          ),
        ],
      ),
    );
  }
}

class _PowerButton extends StatelessWidget {
  const _PowerButton({required this.services});

  final AppServices services;

  @override
  Widget build(BuildContext context) {
    final running = services.vpnRunning;
    final color = running ? Colors.green : Theme.of(context).colorScheme.primary;
    return Center(
      child: Column(
        children: [
          SizedBox(
            width: 160,
            height: 160,
            child: Material(
              shape: const CircleBorder(),
              color: color.withValues(alpha: 0.12),
              child: InkWell(
                customBorder: const CircleBorder(),
                onTap: () => running ? services.stop() : services.start(),
                child: Center(
                  child: Icon(
                    running ? Icons.power_settings_new : Icons.power_settings_new,
                    size: 64,
                    color: color,
                  ),
                ),
              ),
            ),
          ),
          const SizedBox(height: 12),
          Text(
            running ? '代理运行中' : '点击启动代理',
            style: Theme.of(context).textTheme.titleMedium,
          ),
          if (!services.vpnAuthorized && !running)
            const Padding(
              padding: EdgeInsets.only(top: 4),
              child: Text(
                '首次启动需授权 VPN 权限',
                style: TextStyle(fontSize: 12),
              ),
            ),
        ],
      ),
    );
  }
}

class _Stat extends StatelessWidget {
  const _Stat({required this.label, required this.value});

  final String label;
  final String value;

  @override
  Widget build(BuildContext context) {
    return Expanded(
      child: Column(
        children: [
          Text(label, style: Theme.of(context).textTheme.bodySmall),
          const SizedBox(height: 4),
          Text(
            value,
            style: Theme.of(context).textTheme.titleSmall,
            overflow: TextOverflow.ellipsis,
          ),
        ],
      ),
    );
  }
}