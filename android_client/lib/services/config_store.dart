import 'dart:convert';
import 'dart:io';

import 'package:path_provider/path_provider.dart';
import 'package:zproxy_client/core/config.dart';

/// Persistent storage for `config.json` (settings) and `rules.json`
/// (`{"rules":[...]}`, mirroring the Python client's layout).
class ConfigStore {
  static Directory? _dir;

  static Future<File> _file(String name) async {
    final d = _dir ??= await getApplicationDocumentsDirectory();
    return File('${d.path}${Platform.pathSeparator}$name');
  }

  static Future<Config> loadConfig() async {
    final f = await _file('config.json');
    try {
      return loadConfigFromJsonString(f.readAsStringSync());
    } catch (_) {
      return defaults;
    }
  }

  static Future<void> saveConfig(Config config) async {
    final f = await _file('config.json');
    await f.writeAsString(jsonEncode(config.toJson()));
  }

  static Future<List<String>> loadRules() async {
    final f = await _file('rules.json');
    try {
      final data = jsonDecode(f.readAsStringSync());
      if (data is Map && data['rules'] is List) {
        return (data['rules'] as List).whereType<String>().toList();
      }
    } catch (_) {
      // tolerate missing/corrupt file like Python load_rules
    }
    return [];
  }

  static Future<void> saveRules(List<String> rules) async {
    final f = await _file('rules.json');
    await f.writeAsString(jsonEncode({'rules': rules}));
  }
}