@Timeout(Duration(minutes: 2))
library;

import 'dart:io';

import 'package:flutter_test/flutter_test.dart';

import 'package:datu_wallet/core/bridge/native_wallet_bridge.dart';

/// End-to-end proof of the mobile path: Dart FFI → libdatu_wallet_ffi →
/// the same Rust wallet code the desktop bridge uses. Runs whenever the host
/// dylib exists (cargo build -p datu-wallet-ffi); set DATU_WALLET_FFI to
/// point somewhere else.
void main() {
  final dylib = Platform.environment['DATU_WALLET_FFI'] ??
      '${Directory.current.path}/../../target/debug/libdatu_wallet_ffi.dylib';

  setUpAll(() {
    if (!File(dylib).existsSync()) {
      throw StateError(
        'libdatu_wallet_ffi.dylib not found at $dylib - run: '
        'cargo build -p datu-wallet-ffi',
      );
    }
  });

  test('native core: create, list, party-sign, sign-entry', () async {
    final dir = await Directory.systemTemp.createTemp('datu-ffi-test');
    addTearDown(() => dir.delete(recursive: true));

    final bridge = await NativeWalletBridge.open(dir.path, libraryPath: dylib);

    expect(await bridge.identities(), isEmpty);

    final created = await bridge.create(
      name: 'amina',
      passphrase: 'correct horse battery',
    );
    expect(created['ok'], true, reason: '$created');
    final listed = await bridge.identities();
    expect(listed.single['name'], 'amina');
    expect(listed.single['pq_alg'], 'mldsa65');

    final signed = await bridge.partySign(
      name: 'amina',
      passphrase: 'correct horse battery',
      role: 'holder',
      kind: 'land.title.application',
      document: {'parcel': 'pk-7'},
    );
    expect(signed['ok'], true, reason: '$signed');
    final parties = (signed['document'] as Map)['parties'] as List;
    expect((parties.single as Map)['role'], 'holder');

    final entry = await bridge.signEntry(
      name: 'amina',
      passphrase: 'correct horse battery',
      namespace: 'test.dart.ffi',
      seq: 0,
      payloadJson: {'hello': 'from dart'},
    );
    expect(entry['ok'], true, reason: '$entry');
    expect((entry['entry'] as Map)['namespace'], 'test.dart.ffi');

    final wrong = await bridge.partySign(
      name: 'amina',
      passphrase: 'wrong passphrase',
      role: 'holder',
      kind: 'land.title.application',
      document: {'parcel': 'pk-7'},
    );
    expect(wrong['error'], isA<String>());
  });
}
