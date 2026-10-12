import 'package:flutter/material.dart';
import 'package:zproxy_client/services/app_services.dart';

class RulesPage extends StatefulWidget {
  const RulesPage({super.key, required this.services});

  final AppServices services;

  @override
  State<RulesPage> createState() => _RulesPageState();
}

class _RulesPageState extends State<RulesPage> {
  Future<void> _add() => _editRule(null);

  Future<void> _edit(String old) => _editRule(old);

  Future<void> _editRule(String? original) async {
    final controller = TextEditingController(text: original ?? '');
    final value = await showDialog<String>(
      context: context,
      builder: (context) => AlertDialog(
        title: Text(original == null ? '添加规则' : '编辑规则'),
        content: TextField(
          controller: controller,
          autofocus: true,
          decoration: const InputDecoration(
            hintText: 'example.com 或 *.example.com',
          ),
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.of(context).pop(),
            child: const Text('取消'),
          ),
          FilledButton(
            onPressed: () => Navigator.of(context).pop(controller.text.trim()),
            child: const Text('确定'),
          ),
        ],
      ),
    );
    if (value == null || value.isEmpty) {
      return;
    }
    final rules = List.of(widget.services.rules);
    if (original != null) {
      final i = rules.indexOf(original);
      if (i >= 0) {
        rules[i] = value;
      }
    } else if (!rules.contains(value)) {
      rules.add(value);
    }
    await widget.services.applyRules(rules);
  }

  Future<void> _delete(String rule) async {
    final rules = List.of(widget.services.rules)..remove(rule);
    await widget.services.applyRules(rules);
  }

  @override
  Widget build(BuildContext context) {
    final services = widget.services;
    return Column(
      children: [
        Padding(
          padding: const EdgeInsets.all(16),
          child: Text(
            services.config.mode == 'all'
                ? '当前为"全部 TCP 代理"模式:除白名单外 TCP 走服务端。DNS 直连，其他 UDP 不支持。'
                : '当前为"按规则匹配"模式:仅匹配目标域名走服务端。TUN 目标若已是 IP，域名规则可能不生效。',
            style: Theme.of(context).textTheme.bodySmall,
          ),
        ),
        Padding(
          padding: const EdgeInsets.fromLTRB(16, 0, 16, 8),
          child: FilledButton.icon(
            onPressed: _add,
            icon: const Icon(Icons.add),
            label: const Text('添加规则'),
          ),
        ),
        Expanded(
          child: services.rules.isEmpty
              ? const Center(child: Text('暂无规则,点击右下角添加'))
              : ListView.builder(
                  itemCount: services.rules.length,
                  itemBuilder: (context, i) {
                    final rule = services.rules[i];
                    return ListTile(
                      leading: const Icon(Icons.public),
                      title: Text(rule),
                      trailing: Row(
                        mainAxisSize: MainAxisSize.min,
                        children: [
                          IconButton(
                            icon: const Icon(Icons.edit_outlined),
                            onPressed: () => _edit(rule),
                          ),
                          IconButton(
                            icon: const Icon(Icons.delete_outline),
                            onPressed: () => _delete(rule),
                          ),
                        ],
                      ),
                      onTap: () => _edit(rule),
                    );
                  },
                ),
        ),
      ],
    );
  }
}
