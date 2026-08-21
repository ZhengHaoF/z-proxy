import 'package:flutter_test/flutter_test.dart';

import 'package:zhihu_proxy_client/main.dart';

void main() {
  testWidgets('app builds and shows the home shell', (WidgetTester tester) async {
    await tester.pumpWidget(const ZhihuProxyApp());
    await tester.pump(const Duration(seconds: 1));

    expect(find.text('知乎代理'), findsOneWidget);
    expect(find.text('点击启动代理'), findsOneWidget);
    expect(find.text('规则'), findsOneWidget);
    expect(find.text('日志'), findsOneWidget);
    expect(find.text('设置'), findsOneWidget);
  });
}