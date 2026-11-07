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
}

final bridgeControllerProvider =
    NotifierProvider<BridgeController, BridgeState>(BridgeController.new);
