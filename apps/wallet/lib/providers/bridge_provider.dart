import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../core/bridge/bridge_launcher.dart';
import '../core/bridge/wallet_bridge.dart';

enum BridgeStatus { starting, ready, error }

class BridgeState {
  const BridgeState({
    required this.status,
    this.error,
    this.bridge,
    this.identities = const [],
  });

  final BridgeStatus status;
  final String? error;
  final WalletBridge? bridge;
  final List<Map<String, dynamic>> identities;
}

class BridgeController extends Notifier<BridgeState> {
  @override
  BridgeState build() {
    Future.microtask(start);
    return const BridgeState(status: BridgeStatus.starting);
  }

  Future<void> start() async {
    state = const BridgeState(status: BridgeStatus.starting);
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
    final bridge = WalletBridge(baseUrl: baseUrl, token: token);
    final identities = await bridge.identities();
    state = BridgeState(
      status: BridgeStatus.ready,
      bridge: bridge,
      identities: identities,
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
      );
    } catch (e) {
      state = BridgeState(status: BridgeStatus.error, error: e.toString());
    }
  }
}

final bridgeControllerProvider =
    NotifierProvider<BridgeController, BridgeState>(BridgeController.new);
