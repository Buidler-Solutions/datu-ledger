import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_test/flutter_test.dart';

import 'package:datu_wallet/presentation/mobile/mobile_shell.dart';
import 'package:datu_wallet/providers/bridge_provider.dart';

/// A ready bridge with no identities, so the shell renders its first-run
/// state and never touches the network or the native core in tests.
class _EmptyBridgeController extends BridgeController {
  @override
  BridgeState build() =>
      const BridgeState(status: BridgeStatus.ready, identities: []);
}

void main() {
  testWidgets('mobile shell renders bottom navigation and first-run state', (tester) async {
    await tester.pumpWidget(
      ProviderScope(
        overrides: [bridgeControllerProvider.overrideWith(_EmptyBridgeController.new)],
        child: const MaterialApp(home: MobileShell()),
      ),
    );
    await tester.pump();

    expect(find.byType(NavigationBar), findsOneWidget);
    expect(find.text('Signet vault'), findsOneWidget);
    expect(find.text('Vault'), findsOneWidget);
    expect(find.text('Sign'), findsOneWidget);
    expect(find.text('Verify'), findsOneWidget);
    expect(find.text('Settings'), findsOneWidget);
    expect(find.text('No identity yet'), findsOneWidget);

    await tester.tap(find.text('Sign'));
    await tester.pumpAndSettle();
    expect(find.text('Document to sign'), findsOneWidget);
    expect(find.text('Review'), findsOneWidget);

    await tester.tap(find.text('Verify'));
    await tester.pumpAndSettle();
    expect(find.text('Entry JSON'), findsOneWidget);
    expect(find.text('Verify entry'), findsOneWidget);
  });
}
