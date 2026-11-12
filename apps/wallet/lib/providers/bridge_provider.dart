import 'dart:io';

import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../core/bridge/bridge_launcher.dart';
import '../core/bridge/native_wallet_bridge.dart';
import '../core/bridge/wallet_bridge.dart';

enum BridgeStatus { starting, ready, error }

class BridgeState {
  const BridgeState({
    required this.status,
    this.error,
    this.bridge,
    this.identities = const [],
    this.native = false,
  });

  final BridgeStatus status;
  final String? error;
  final WalletBridge? bridge;
  final List<Map<String, dynamic>> identities;

  /// True when signing happens in the embedded Rust core (mobile / FFI
  /// demo) instead of the local bridge process.
  final bool native;
}

class BridgeController extends Notifier<BridgeState> {
  @override
  BridgeState build() {
    Future.microtask(start);
    return const BridgeState(status: BridgeStatus.starting);
  }

  Future<void> start() async {
    state = const BridgeState(status: BridgeStatus.starting);
    if (NativeWalletBridge.isSupported) {
      try {
        final dir = await NativeWalletBridge.defaultDataDir();
        final native = await NativeWalletBridge.open(dir);
        await _ready(native, identities: await native.identities(), native: true);
        return;
      } catch (e) {
        // Desktop: fall through to the bridge process. Mobile has no bridge
        // to fall back to - surface the failure.
        if (Platform.isAndroid || Platform.isIOS) {
          state = BridgeState(status: BridgeStatus.error, error: e.toString());
          return;
        }
      }
    }
    try {
      final conn = await BridgeLauncher.ensureRunning();
      await _use(conn.baseUrl, conn.token);
    } catch (e) {
      state = BridgeState(status: BridgeStatus.error, error: e.toString());
    }
  }

  Future<void> attach({required String baseUrl, required String token}) async {
    state = const BridgeState(status: BridgeStatus.starting);
    try {
      final conn = await BridgeLauncher.attach(baseUrl: baseUrl, token: token);
      await _use(conn.baseUrl, conn.token);
    } catch (e) {
      state = BridgeState(status: BridgeStatus.error, error: e.toString());
    }
  }

  Future<void> _use(String baseUrl, String token) async {
    final bridge = HttpWalletBridge(baseUrl: baseUrl, token: token);
    await _ready(bridge, identities: await bridge.identities());
  }

  Future<void> _ready(
    WalletBridge bridge, {
    required List<Map<String, dynamic>> identities,
    bool native = false,
  }) async {
    state = BridgeState(
      status: BridgeStatus.ready,
      bridge: bridge,
      identities: identities,
      native: native,
    );
  }

  Future<void> refresh() async {
    final bridge = state.bridge;
    if (bridge == null) return;
    try {
      final identities = await bridge.identities();
      state = BridgeState(
        status: BridgeStatus.ready,
        bridge: bridge,
        identities: identities,
        native: state.native,
      );
    } catch (e) {
      state = BridgeState(status: BridgeStatus.error, error: e.toString());
    }
  }

  /// Create an identity on the connected bridge, refresh the list and
  /// select the new identity (same flow as the extension's Settings tab).
  Future<Map<String, dynamic>> createIdentity({
    required String name,
    required String passphrase,
  }) async {
    final bridge = state.bridge;
    if (bridge == null) throw StateError('no wallet bridge connected');
    final created = await bridge.create(name: name, passphrase: passphrase);
    await refresh();
    return created;
  }
}

final bridgeControllerProvider =
    NotifierProvider<BridgeController, BridgeState>(BridgeController.new);

/// The identity every tab acts as - the extension's global selector.
/// Follows the identity list: keeps the selection while it exists, else
/// falls back to the first identity.
class SelectedIdentity extends Notifier<String?> {
  @override
  String? build() {
    final identities = ref.watch(bridgeControllerProvider).identities;
    if (identities.isEmpty) return null;
    final current = state;
    if (current != null && identities.any((id) => id['name'] == current)) {
      return current;
    }
    return identities.first['name'] as String?;
  }

  void select(String? name) => state = name;
}

final selectedIdentityProvider =
    NotifierProvider<SelectedIdentity, String?>(SelectedIdentity.new);

Map<String, dynamic>? identityByName(
  List<Map<String, dynamic>> identities,
  String? name,
) {
  if (name == null) return null;
  for (final id in identities) {
    if (id['name'] == name) return id;
  }
  return null;
}

/// Session passphrase, remembered until the window idles for 2 minutes
/// (mirrors the extension; cleared by the shell's idle lock).
class Passphrase extends Notifier<String> {
  @override
  String build() => '';

  void set(String value) => state = value;

  void clear() => state = '';
}

final passphraseProvider = NotifierProvider<Passphrase, String>(Passphrase.new);

/// The DATU node every ledger view reads from (explorer + my records).
class NodeUrl extends Notifier<String> {
  @override
  String build() => 'http://127.0.0.1:7474';

  void set(String value) => state = value;
}

final nodeUrlProvider = NotifierProvider<NodeUrl, String>(NodeUrl.new);

/// Node health chip: 'down' or `'<mode> · <entries> entries'`.
class NodeStatus extends Notifier<String> {
  @override
  String build() => 'down';

  void set(String value) => state = value;
}

final nodeStatusProvider = NotifierProvider<NodeStatus, String>(NodeStatus.new);

/// Hand-off from My records to My data: the last decrypted view.
class DecryptedView {
  const DecryptedView({required this.opened, required this.skipped, required this.document});

  final int opened;
  final int skipped;
  final Map<String, dynamic> document;
}

class Decrypted extends Notifier<DecryptedView?> {
  @override
  DecryptedView? build() => null;

  void set(DecryptedView? value) => state = value;

  void clear() => state = null;
}

final decryptedProvider = NotifierProvider<Decrypted, DecryptedView?>(Decrypted.new);

/// Which sidebar tab is showing.
enum WalletTab { records, sign, data, explorer, verify, settings }

class CurrentTab extends Notifier<WalletTab> {
  @override
  WalletTab build() => WalletTab.records;

  void go(WalletTab tab) => state = tab;
}

final tabProvider = NotifierProvider<CurrentTab, WalletTab>(CurrentTab.new);
