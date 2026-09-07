import 'package:flutter/material.dart';
import 'package:zproxy_client/pages/home_page.dart';
import 'package:zproxy_client/pages/logs_page.dart';
import 'package:zproxy_client/pages/rules_page.dart';
import 'package:zproxy_client/pages/settings_page.dart';
import 'package:zproxy_client/services/app_services.dart';

void main() {
  runApp(const ZProxyApp());
}

class ZProxyApp extends StatefulWidget {
  const ZProxyApp({super.key});

  @override
  State<ZProxyApp> createState() => _ZProxyAppState();
}

class _ZProxyAppState extends State<ZProxyApp> {
  final services = AppServices();

  @override
  void initState() {
    super.initState();
    services.init();
  }

  @override
  void dispose() {
    services.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: '代理',
      theme: ThemeData(
        colorSchemeSeed: Colors.teal,
        useMaterial3: true,
      ),
      home: HomeShell(services: services),
    );
  }
}

class HomeShell extends StatefulWidget {
  const HomeShell({super.key, required this.services});

  final AppServices services;

  @override
  State<HomeShell> createState() => _HomeShellState();
}

class _HomeShellState extends State<HomeShell> {
  int _index = 0;

  @override
  Widget build(BuildContext context) {
    final services = widget.services;
    return ListenableBuilder(
      listenable: services,
      builder: (context, _) {
        final pages = [
          HomePage(services: services),
          RulesPage(services: services),
          LogsPage(services: services),
          SettingsPage(services: services),
        ];
        return Scaffold(
          appBar: AppBar(title: const Text('代理')),
          body: IndexedStack(index: _index, children: pages),
          bottomNavigationBar: NavigationBar(
            selectedIndex: _index,
            onDestinationSelected: (i) => setState(() => _index = i),
            destinations: const [
              NavigationDestination(
                icon: Icon(Icons.home_outlined),
                selectedIcon: Icon(Icons.home),
                label: '首页',
              ),
              NavigationDestination(
                icon: Icon(Icons.rule_outlined),
                selectedIcon: Icon(Icons.rule),
                label: '规则',
              ),
              NavigationDestination(
                icon: Icon(Icons.receipt_long_outlined),
                selectedIcon: Icon(Icons.receipt_long),
                label: '日志',
              ),
              NavigationDestination(
                icon: Icon(Icons.settings_outlined),
                selectedIcon: Icon(Icons.settings),
                label: '设置',
              ),
            ],
          ),
        );
      },
    );
  }
}