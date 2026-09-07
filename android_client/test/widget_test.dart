import 'package:flutter_test/flutter_test.dart';

import 'package:zproxy_client/main.dart';

void main() {
  testWidgets('app builds and shows the home shell', (WidgetTester tester) async {
    await tester.pumpWidget(const ZProxyApp());
    await tester.pump(const Duration(seconds: 1));

    expect(find.text('代理'), findsOneWidget);
    expect(find.text('点击启动代理'), findsOneWidget);
    expect(find.text('规则'), findsOneWidget);
    expect(find.text('日志'), findsOneWidget);
    expect(find.text('设置'), findsOneWidget);
  });
}