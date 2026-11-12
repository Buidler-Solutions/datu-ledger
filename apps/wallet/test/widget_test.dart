import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_test/flutter_test.dart';

import 'package:datu_wallet/main.dart';

void main() {
  testWidgets('wallet app boots into the sidebar shell', (WidgetTester tester) async {
    await tester.pumpWidget(const ProviderScope(child: DatuWalletApp()));
    await tester.pump();
    expect(find.text('DATU Signet'), findsWidgets);
    expect(find.text('My records'), findsOneWidget);
    expect(find.text('Explorer'), findsOneWidget);
    expect(find.text('Verifier'), findsOneWidget);
  });

  testWidgets('sidebar switches tabs', (WidgetTester tester) async {
    await tester.pumpWidget(const ProviderScope(child: DatuWalletApp()));
    await tester.pump();
    await tester.tap(find.text('Explorer'));
    await tester.pump();
    expect(find.text('Ledger explorer'), findsOneWidget);
    await tester.tap(find.text('Sign'));
    await tester.pump();
    expect(find.text('Holder consent'), findsOneWidget);
  });
}
