import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:integration_test/integration_test.dart';
import 'package:path_provider/path_provider.dart';

import 'package:datu_wallet/core/bridge/native_wallet_bridge.dart';

/// On-device proof of the standalone mobile Signet: the Rust wallet core is
/// compiled into the app (iOS static lib / Android .so), so this test runs
/// the real crypto on the real device with no desktop bridge anywhere.
void main() {
  IntegrationTestWidgetsFlutterBinding.ensureInitialized();

  testWidgets('native core: create, list, sign an entry on device',
      (tester) async {
    final docs = await getApplicationDocumentsDirectory();
    final dir = Directory('${docs.path}/datu-wallet-it-${DateTime.now().millisecondsSinceEpoch}');
    addTearDown(() => dir.delete(recursive: true));

    final bridge = await NativeWalletBridge.open(dir.path);
    expect(await bridge.identities(), isEmpty);

    await bridge.create(name: 'phone', passphrase: 'phone-demo-pass');
    final ids = await bridge.identities();
    expect(ids.map((i) => i['name']), contains('phone'));

    final signed = await bridge.signEntry(
      name: 'phone',
      passphrase: 'phone-demo-pass',
      namespace: 'mobile.it',
      seq: 0,
      payloadJson: {'hello': 'mobile'},
    );
    expect(signed['entry'], isA<Map>());
    final entry = Map<String, dynamic>.from(signed['entry'] as Map);
    expect(entry['id'], isA<String>());

    final verdict = await bridge.verifyEntry(entry: entry);
    expect(verdict['ok'], isNot(false),
        reason: 'the core must verify its own signature: $verdict');
  });
}
