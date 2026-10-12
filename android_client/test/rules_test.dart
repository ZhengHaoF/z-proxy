import 'package:flutter_test/flutter_test.dart';
import 'package:zproxy_client/core/rules.dart';

void main() {
  group('domainMatches', () {
    test('bare domain matches itself and subdomains, not substrings', () {
      expect(domainMatches('example.com', const ['example.com']), isTrue);
      expect(domainMatches('www.example.com', const ['example.com']), isTrue);
      expect(domainMatches('anexample.com', const ['example.com']), isFalse);
      expect(domainMatches('xexample.com.evil.cn', const ['example.com']), isFalse);
    });

    test('*.example.com matches base and any depth, not lookalikes', () {
      const rules = ['*.example.com'];
      expect(domainMatches('example.com', rules), isTrue);
      expect(domainMatches('a.b.example.com', rules), isTrue);
      expect(domainMatches('notexample.com', rules), isFalse);
    });

    test('.example.com (leading dot) matches base and subdomains', () {
      const rules = ['.example.com'];
      expect(domainMatches('example.com', rules), isTrue);
      expect(domainMatches('www.example.com', rules), isTrue);
      expect(domainMatches('notexample.com', rules), isFalse);
    });

    test('case insensitive on both host and rule', () {
      expect(domainMatches('Example.COM', const ['example.com']), isTrue);
      expect(domainMatches('example.com', const ['EXAMPLE.com']), isTrue);
    });

    test('empty host or empty rules never match', () {
      expect(domainMatches('', const ['example.com']), isFalse);
      expect(domainMatches('example.com', const []), isFalse);
      expect(domainMatches('example.com', const ['', '  ']), isFalse);
    });

    test('rule whitespace is trimmed', () {
      expect(domainMatches('example.com', const [' example.com ']), isTrue);
    });
  });

  group('isBypass', () {
    const defaultBypass = ['localhost', '127.0.0.1', '::1'];

    test('private and loopback IPs are bypassed', () {
      expect(isBypass('192.168.1.1', defaultBypass), isTrue);
      expect(isBypass('127.0.0.1', defaultBypass), isTrue);
      expect(isBypass('10.0.0.5', defaultBypass), isTrue);
      expect(isBypass('172.16.9.9', defaultBypass), isTrue);
      expect(isBypass('172.31.255.255', defaultBypass), isTrue);
    });

    test('link-local and multicast are bypassed', () {
      expect(isBypass('169.254.1.1', defaultBypass), isTrue);
      expect(isBypass('224.0.0.1', defaultBypass), isTrue);
    });

    test('IPv6 loopback, ULA and link-local are bypassed', () {
      expect(isBypass('::1', defaultBypass), isTrue);
      expect(isBypass('fc00::1', defaultBypass), isTrue);
      expect(isBypass('fd12:3456::1', defaultBypass), isTrue);
      expect(isBypass('fe80::1', defaultBypass), isTrue);
    });

    test('public ip and hostnames are not bypassed', () {
      expect(isBypass('114.114.114.114', defaultBypass), isFalse);
      expect(isBypass('example.com', defaultBypass), isFalse);
      expect(isBypass('localhost', defaultBypass), isTrue);
      expect(isBypass('', defaultBypass), isFalse);
    });

    test('custom bypass entries support wildcard rules', () {
      const custom = ['*.internal'];
      expect(isBypass('a.internal', custom), isTrue);
      expect(isBypass('internal', custom), isTrue);
      expect(isBypass('internalx', custom), isFalse);
    });

    test('invalid ip strings fall through to list matching', () {
      expect(isBypass('999.1.1.1', defaultBypass), isFalse);
      expect(isBypass('123.456.789.0', defaultBypass), isFalse);
    });
  });

  group('useServer', () {
    test('bypass wins over matched rules', () {
      expect(
        useServer('example.com', rules: const ['example.com'],
            mode: 'matched', bypass: const ['example.com']),
        isFalse,
      );
      expect(
        useServer('127.0.0.1', rules: const ['127.0.0.1'], mode: 'matched'),
        isFalse,
      );
    });
    test('matched mode: only rule hits go to server', () {
      expect(useServer('example.com', rules: const ['example.com'], mode: 'matched'), isTrue);
      expect(useServer('www.example.com', rules: const ['example.com'], mode: 'matched'), isTrue);
      expect(useServer('other.com', rules: const ['example.com'], mode: 'matched'), isFalse);
    });

    test('all mode: everything non-bypass goes to server', () {
      expect(useServer('example.com', rules: const [], mode: 'all'), isTrue);
      expect(useServer('114.114.114.114', rules: const [], mode: 'all'), isTrue);
      expect(useServer('192.168.1.1', rules: const [], mode: 'all'), isFalse);
      expect(useServer('localhost', rules: const [], mode: 'all'), isFalse);
      expect(useServer('::1', rules: const [], mode: 'all'), isFalse);
    });

    test('empty host never goes to server', () {
      expect(useServer('', rules: const ['example.com'], mode: 'matched'), isFalse);
      expect(useServer('', rules: const [], mode: 'all'), isFalse);
    });
  });

  group('isPrivateIp', () {
    test('recognizes common private ranges', () {
      expect(isPrivateIp('10.1.2.3'), isTrue);
      expect(isPrivateIp('172.20.0.1'), isTrue);
      expect(isPrivateIp('192.168.0.1'), isTrue);
      expect(isPrivateIp('127.0.0.1'), isTrue);
      expect(isPrivateIp('169.254.0.1'), isTrue);
      expect(isPrivateIp('224.0.0.1'), isTrue);
      expect(isPrivateIp('8.8.8.8'), isFalse);
      expect(isPrivateIp('172.32.0.1'), isFalse);
      expect(isPrivateIp('192.169.0.1'), isFalse);
    });

    test('recognizes IPv6 special ranges', () {
      expect(isPrivateIp('::1'), isTrue);
      expect(isPrivateIp('::'), isTrue);
      expect(isPrivateIp('fc00::1'), isTrue);
      expect(isPrivateIp('fe80::1'), isTrue);
      // 2001:db8::/32 (documentation) counts as private in Python ipaddress
      expect(isPrivateIp('2001:db8::1'), isTrue);
      expect(isPrivateIp('2001:4860:4860::8888'), isFalse);
    });
  });
}
