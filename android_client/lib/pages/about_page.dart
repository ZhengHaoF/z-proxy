import 'package:flutter/material.dart';

class AboutPage extends StatelessWidget {
  const AboutPage({super.key});

  @override
  Widget build(BuildContext context) {
    return ListView(
      padding: const EdgeInsets.all(24),
      children: [
        const Icon(Icons.shield_outlined, size: 64),
        const SizedBox(height: 12),
        const Center(child: Text('代理', style: TextStyle(fontSize: 22))),
        const SizedBox(height: 4),
        Center(
          child: Text(
            '版本 $kVersion',
            style: Theme.of(context).textTheme.bodySmall,
          ),
        ),
        const SizedBox(height: 24),
        Card(
          child: Padding(
            padding: const EdgeInsets.all(16),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text('工作原理', style: Theme.of(context).textTheme.titleSmall),
                const SizedBox(height: 8),
                const Text(
                  '通过系统 VPN 接管设备流量,由本地代理按规则分流:\n'
                  '• 命中规则的域名 → 加密隧道转发到你的服务端\n'
                  '• 其余流量 → 本机直连,不经过服务端\n'
                  '• 所有数据均不会被第三方收集\n\n'
                  '系统级 VPN 形态,不依赖可关闭的调试模式。',
                ),
              ],
            ),
          ),
        ),
        const SizedBox(height: 16),
        Card(
          child: Padding(
            padding: const EdgeInsets.all(16),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text('注意', style: Theme.of(context).textTheme.titleSmall),
                const SizedBox(height: 8),
                const Text(
                  '• 启动需要授权系统 VPN 弹窗\n'
                  '• 建议在系统设置中允许本应用的电池优化豁免,避免后台中断\n'
                  '• 更换网络(Wi-Fi/流量)后会自动重建隧道',
                ),
              ],
            ),
          ),
        ),
      ],
    );
  }

  static const kVersion = '1.0.0';
}