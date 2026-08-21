import 'dart:convert';

import 'package:flutter_test/flutter_test.dart';
import 'package:zhihu_proxy_client/core/config.dart';

void main() {
  group('loadConfigFromJsonString', () {
    test('invalid json falls back to defaults', () {
      final cfg = loadConfigFromJsonString('not json{{{');
      expect(cfg.clientPort, 8787);
      expect(cfg.serverHost, '127.0.0.1');
      expect(cfg.serverPort, 8443);
      expect(cfg.token, 'zhihu-proxy-dev');
      expect(cfg.mode, 'matched');
      expect(cfg.bypass, ['localhost', '127.0.0.1', '::1']);
    });

    test('partial json overrides only provided fields', () {
      final cfg = loadConfigFromJsonString('{"server_host": "example.com"}');
      expect(cfg.serverHost, 'example.com');
      expect(cfg.clientPort, 8787);
      expect(cfg.serverPort, 8443);
      expect(cfg.token, 'zhihu-proxy-dev');
    });

    test('full json matches input values', () {
      const json = '''
      {
        "client_port": 9999,
        "server_host": "82.156.168.149",
        "server_port": 8443,
        "token": "54ZhengHF",
        "mode": "all",
        "bypass": ["localhost", "127.0.0.1", "::1"]
      }
      ''';
      final cfg = loadConfigFromJsonString(json);
      expect(cfg.clientPort, 9999);
      expect(cfg.serverHost, '82.156.168.149');
      expect(cfg.serverPort, 8443);
      expect(cfg.token, '54ZhengHF');
      expect(cfg.mode, 'all');
      expect(cfg.bypass, ['localhost', '127.0.0.1', '::1']);
    });

    test('wrong-typed fields are tolerated (kept as defaults)', () {
      final cfg = loadConfigFromJsonString(
          '{"client_port": "not-a-number", "bypass": "localhost"}');
      expect(cfg.clientPort, 8787);
      expect(cfg.bypass, ['localhost', '127.0.0.1', '::1']);
    });

    test('empty mode/unknown fields do not break loading', () {
      final cfg = loadConfigFromJsonString(
          '{"mode": "weird", "extra_field": 42, "server_port": null}');
      expect(cfg.mode, 'weird');
      expect(cfg.serverPort, 8443);
    });
  });

  group('toJson', () {
    const expectedKeys = [
      'client_port',
      'server_host',
      'server_port',
      'token',
      'mode',
      'bypass',
      'dns_server',
    ];

    test('serializes fields matching client/config.json structure', () {
      final json =
          loadConfigFromJsonString('{"server_host": "82.156.168.149", "mode": "all"}').toJson();
      expect(json.keys.toList(), expectedKeys);
      expect(json['server_host'], '82.156.168.149');
      expect(json['client_port'], 8787);
      expect(json['mode'], 'all');
      expect(json['bypass'], ['localhost', '127.0.0.1', '::1']);
    });

    test('roundtrips through jsonEncode', () {
      final original =
          loadConfigFromJsonString('{"client_port": 9000, "server_host": "h"}');
      final decoded =
          loadConfigFromJsonString(jsonEncode(original.toJson()));
      expect(decoded.toJson(), original.toJson());
    });
  });
}