import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_test/flutter_test.dart';

import 'package:datu_wallet/main.dart';

void main() {
  testWidgets('wallet app boots', (WidgetTester tester) async {
    await tester.pumpWidget(const ProviderScope(child: DatuWalletApp()));
    await tester.pump();
    expect(find.text('DATU Wallet'), findsOneWidget);
  });
}
