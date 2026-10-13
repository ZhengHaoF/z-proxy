import 'package:flutter/material.dart';
import 'package:zproxy_client/core/config.dart';
import 'package:zproxy_client/pages/about_page.dart';
import 'package:zproxy_client/services/app_services.dart';

class SettingsPage extends StatefulWidget {
  const SettingsPage({super.key, required this.services});

  final AppServices services;

  @override
  State<SettingsPage> createState() => _SettingsPageState();
}

class _SettingsPageState extends State<SettingsPage> {
  final _formKey = GlobalKey<FormState>();
  late final TextEditingController _host;
  late final TextEditingController _port;
  late final TextEditingController _token;
  late final TextEditingController _bypass;
  late final TextEditingController _dns;
  late String _mode;
  bool _obscureKey = true;

  @override
  void initState() {
    super.initState();
    final c = widget.services.config;
    _host = TextEditingController(text: c.serverHost);
    _port = TextEditingController(text: '${c.serverPort}');
    _token = TextEditingController(text: c.token);
    _bypass = TextEditingController(text: c.bypass.join(', '));
    _dns = TextEditingController(text: c.dnsServer);
    _mode = c.mode;
  }

  @override
  void dispose() {
    _host.dispose();
    _port.dispose();
    _token.dispose();
    _bypass.dispose();
    _dns.dispose();
    super.dispose();
  }

  Future<void> _save() async {
    if (!_formKey.currentState!.validate()) {
      return;
    }
    final bypass = _bypass.text
        .split(',')
        .map((e) => e.trim())
        .where((e) => e.isNotEmpty)
        .toList();
    await widget.services.applyConfig(Config(
      clientPort: widget.services.config.clientPort,
      serverHost: _host.text.trim(),
      serverPort: int.parse(_port.text.trim()),
      token: _token.text.trim(),
      mode: _mode,
      bypass: bypass,
      dnsServer: _dns.text.trim(),
    ));
    if (!mounted) {
      return;
    }
    ScaffoldMessenger.of(context).showSnackBar(
      const SnackBar(content: Text('已保存;重新启动代理后生效')),
    );
  }

  @override
  Widget build(BuildContext context) {
    return ListView(
      padding: const EdgeInsets.all(16),
      children: [
        Form(
          key: _formKey,
          child: Column(
            children: [
              TextFormField(
                controller: _host,
                decoration: const InputDecoration(
                  labelText: '服务端地址',
                  helperText: '运行代理服务端的地址',
                ),
                validator: (v) => (v == null || v.trim().isEmpty)
                    ? '地址不能为空'
                    : null,
              ),
              TextFormField(
                controller: _port,
                keyboardType: TextInputType.number,
                decoration: const InputDecoration(labelText: '服务端端口'),
                validator: (v) {
                  final p = int.tryParse(v?.trim() ?? '');
                  return (p == null || p <= 0 || p > 65535) ? '端口无效' : null;
                },
              ),
              TextFormField(
                controller: _token,
                obscureText: _obscureKey,
                decoration: InputDecoration(
                  labelText: 'Key',
                  helperText: '与服务端 Key 保持一致',
                  suffixIcon: IconButton(
                    icon: Icon(
                      _obscureKey ? Icons.visibility_off : Icons.visibility,
                    ),
                    onPressed: () {
                      setState(() {
                        _obscureKey = !_obscureKey;
                      });
                    },
                  ),
                ),
                validator: (v) => (v == null || v.isEmpty) ? 'Key 不能为空' : null,
              ),
              const SizedBox(height: 8),
              SegmentedButton<String>(
                segments: const [
                  ButtonSegment(value: 'matched', label: Text('按规则匹配')),
                  ButtonSegment(value: 'all', label: Text('全部 TCP 代理')),
                ],
                selected: {_mode},
                onSelectionChanged: (v) => setState(() => _mode = v.first),
              ),
              TextFormField(
                controller: _bypass,
                decoration: const InputDecoration(
                  labelText: '直连白名单',
                  helperText: '逗号分隔;所有模式优先直连。DNS 直连，其他 UDP 不支持',
                ),
              ),
              TextFormField(
                controller: _dns,
                decoration: const InputDecoration(
                  labelText: 'VPN DNS 服务器',
                  helperText: '用于 TUN 内域名解析,默认为阿里 DNS(223.5.5.5)',
                ),
                validator: (v) => (v == null || v.trim().isEmpty)
                    ? 'DNS 不能为空'
                    : null,
              ),
              const SizedBox(height: 16),
              FilledButton.icon(
                onPressed: _save,
                icon: const Icon(Icons.save),
                label: const Text('保存设置'),
              ),
            ],
          ),
        ),
        const Divider(height: 32),
        const _SectionTitle('系统'),
        ListTile(
          leading: const Icon(Icons.notifications),
          title: const Text('通知权限'),
          subtitle: const Text('前台服务需要;拒绝后通知不显示但仍可运行'),
          trailing: const Icon(Icons.chevron_right),
          onTap: () async {
            await widget.services.vpn.requestNotificationPermission();
            if (context.mounted) {
              ScaffoldMessenger.of(context).showSnackBar(
                const SnackBar(content: Text('已处理通知权限请求')),
              );
            }
          },
        ),
        ListTile(
          leading: const Icon(Icons.battery_charging_full),
          title: const Text('电池优化豁免'),
          subtitle: const Text('避免后台被杀导致 VPN 中断'),
          trailing: _BatteryTile(services: widget.services),
          onTap: () async {
            final opened =
                await widget.services.vpn.openBatteryOptimizationSettings();
            if (!opened && context.mounted) {
              ScaffoldMessenger.of(context).showSnackBar(
                const SnackBar(content: Text('无法打开电池优化设置页')),
              );
            }
          },
        ),
        const Divider(height: 32),
        const _SectionTitle('其他'),
        ListTile(
          leading: const Icon(Icons.info_outline),
          title: const Text('关于'),
          trailing: const Icon(Icons.chevron_right),
          onTap: () {
            Navigator.of(context).push(
              MaterialPageRoute<void>(builder: (_) => const AboutPage()),
            );
          },
        ),
      ],
    );
  }
}

class _BatteryTile extends StatefulWidget {
  const _BatteryTile({required this.services});

  final AppServices services;

  @override
  State<_BatteryTile> createState() => _BatteryTileState();
}

class _BatteryTileState extends State<_BatteryTile> {
  bool? _ignored;

  @override
  void initState() {
    super.initState();
    _refresh();
  }

  Future<void> _refresh() async {
    final ignored = await widget.services.vpn.isBatteryOptimizationDisabled();
    if (mounted) {
      setState(() => _ignored = ignored);
    }
  }

  @override
  Widget build(BuildContext context) {
    return _ignored == null
        ? const SizedBox.shrink()
        : Icon(
            _ignored! ? Icons.check_circle : Icons.warning_amber,
            color: _ignored! ? Colors.green : Colors.orange,
          );
  }
}

class _SectionTitle extends StatelessWidget {
  const _SectionTitle(this.text);

  final String text;

  @override
  Widget build(BuildContext context) {
    return Padding(
      padding: const EdgeInsets.only(left: 16, bottom: 4),
      child: Text(
        text,
        style: Theme.of(context).textTheme.titleSmall,
      ),
    );
  }
}
