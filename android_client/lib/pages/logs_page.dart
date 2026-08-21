import 'package:flutter/material.dart';
import 'package:zhihu_proxy_client/services/app_services.dart';

class LogsPage extends StatelessWidget {
  const LogsPage({super.key, required this.services});

  final AppServices services;

  @override
  Widget build(BuildContext context) {
    final logs = services.logs;
    return Column(
      children: [
        Padding(
          padding: const EdgeInsets.all(8),
          child: Align(
            alignment: Alignment.centerRight,
            child: TextButton.icon(
              onPressed: logs.isEmpty ? null : services.clearLogs,
              icon: const Icon(Icons.clear_all, size: 18),
              label: const Text('清空'),
            ),
          ),
        ),
        Expanded(
          child: logs.isEmpty
              ? const Center(child: Text('暂无日志'))
              : ListView.builder(
                  reverse: true,
                  itemCount: logs.length,
                  itemBuilder: (context, i) {
                    final line = logs[logs.length - 1 - i];
                    return Padding(
                      padding: const EdgeInsets.symmetric(
                        horizontal: 16,
                        vertical: 2,
                      ),
                      child: Text(
                        line,
                        style: const TextStyle(
                          fontFamily: 'monospace',
                          fontSize: 13,
                        ),
                      ),
                    );
                  },
                ),
        ),
      ],
    );
  }
}