import 'dart:convert';
import 'dart:io';

const defaults = Config(
  clientPort: 8787,
  serverHost: '127.0.0.1',
  serverPort: 8443,
  token: 'zhihu-proxy-dev',
  mode: 'matched',
  bypass: ['localhost', '127.0.0.1', '::1'],
  dnsServer: '223.5.5.5',
);

/// Port of Python `DEFAULTS` / `load_config` (proxy_client.py L26-49).
class Config {
  final int clientPort;
  final String serverHost;
  final int serverPort;
  final String token;
  final String mode;
  final List<String> bypass;

  /// Android-only: DNS server handed to the VPN (the virtual TUN address is
  /// not routable, so the browser's DNS queries must reach a real server
  /// through the SOCKS5 UDP relay). Defaults to AliDNS for CN reachability.
  final String dnsServer;

  const Config({
    required this.clientPort,
    required this.serverHost,
    required this.serverPort,
    required this.token,
    required this.mode,
    required this.bypass,
    required this.dnsServer,
  });

  factory Config.fromJson(Map<String, dynamic> json) {
    return Config(
      clientPort: json['client_port'] is int ? json['client_port'] as int : defaults.clientPort,
      serverHost: json['server_host'] is String
          ? json['server_host'] as String
          : defaults.serverHost,
      serverPort: json['server_port'] is int ? json['server_port'] as int : defaults.serverPort,
      token: json['token'] is String ? json['token'] as String : defaults.token,
      mode: json['mode'] is String ? json['mode'] as String : defaults.mode,
      bypass: json['bypass'] is List
          ? (json['bypass'] as List).whereType<String>().toList()
          : defaults.bypass,
      dnsServer: json['dns_server'] is String
          ? json['dns_server'] as String
          : defaults.dnsServer,
    );
  }

  Map<String, dynamic> toJson() => {
        'client_port': clientPort,
        'server_host': serverHost,
        'server_port': serverPort,
        'token': token,
        'mode': mode,
        'bypass': bypass,
        'dns_server': dnsServer,
      };
}

/// Loads config from a JSON string; falls back to defaults on any error.
/// Missing keys keep their default values (JSON overrides defaults).
Config loadConfigFromJsonString(String json) {
  try {
    final data = jsonDecode(json);
    if (data is Map<String, dynamic>) {
      return Config.fromJson(data);
    }
  } catch (_) {
    // tolerate invalid json / wrong shapes like Python's load_config
  }
  return defaults;
}

/// Loads config from a file at [path]; missing or unreadable file -> defaults.
Config loadConfig({String? path}) {
  final file = File(path ?? 'config.json');
  try {
    if (file.existsSync()) {
      return loadConfigFromJsonString(file.readAsStringSync());
    }
  } catch (_) {
    // fall through to defaults
  }
  return defaults;
}