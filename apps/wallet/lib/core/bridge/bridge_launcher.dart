import 'dart:io';

import 'package:dio/dio.dart';

/// Desktop bridge lifecycle: find or start the local wallet service and hand
/// back a usable client. Mobile builds will replace this with Rust FFI - the
/// screens only ever see [WalletBridge], never the process.
class BridgeLauncher {
  static const defaultPort = 7488;

  static Future<Directory> dataDir() async {
    final home = Platform.environment['HOME'] ?? '.';
    if (Platform.isMacOS) {
      return Directory('$home/Library/Application Support/DATU');
    }
    if (Platform.isWindows) {
      final appData = Platform.environment['APPDATA'] ?? '.';
      return Directory('$appData\\DATU');
    }
    return Directory('$home/.local/share/datu');
  }

  static Future<String?> _findBinary() async {
    final env = Platform.environment['DATU_BIN'];
    if (env != null && env.isNotEmpty && File(env).existsSync()) return env;

    // Inside a macOS .app bundle: <App>/Contents/MacOS/<exe> -> Resources/datu
    final exe = File(Platform.resolvedExecutable).parent;
    for (final candidate in [
      '${exe.parent.path}/Resources/datu',
      '${exe.path}/datu',
    ]) {
      if (File(candidate).existsSync()) return candidate;
    }

    for (final dir in (Platform.environment['PATH'] ?? '').split(':')) {
      final candidate = File('$dir/datu');
      if (candidate.existsSync()) return candidate.path;
    }
    return null;
  }

  static Future<String?> _readToken(Directory dir) async {
    final file = File('${dir.path}/wallet/bridge.token');
    if (!file.existsSync()) return null;
    final token = (await file.readAsString()).trim();
    return token.isEmpty ? null : token;
  }

  static Future<bool> _healthy(String baseUrl, String token) async {
    try {
      final dio = Dio(
        BaseOptions(
          connectTimeout: const Duration(seconds: 2),
          receiveTimeout: const Duration(seconds: 3),
          headers: {'Authorization': 'Bearer $token'},
        ),
      );
      final res = await dio.get('$baseUrl/v1/wallet/identities');
      return res.statusCode == 200;
    } catch (_) {
      return false;
    }
  }

  /// Attach to a running service on [port] (e.g. the installed DATU Wallet
  /// LaunchAgent) or start one from [binaryPath] with our data dir.
  static Future<({String baseUrl, String token})> ensureRunning({
    int port = defaultPort,
  }) async {
    final dir = await dataDir();
    await dir.create(recursive: true);
    final baseUrl = 'http://127.0.0.1:$port';

    final existing = await _readToken(dir);
    if (existing != null && await _healthy(baseUrl, existing)) {
      return (baseUrl: baseUrl, token: existing);
    }

    final binary = await _findBinary();
    if (binary == null) {
      throw StateError(
        'wallet binary not found - set DATU_BIN or bundle `datu` in Resources',
      );
    }
    final process = await Process.start(binary, [
      '--data-dir',
      dir.path,
      'wallet',
      'serve',
      '--addr',
      '127.0.0.1:$port',
    ]);
    // Keep draining so the OS pipe buffers never block the child.
    process.stdout.transform(const SystemEncoding().decoder).listen((_) {});
    process.stderr.transform(const SystemEncoding().decoder).listen((_) {});
    process.exitCode.then((_) {});

    for (var i = 0; i < 50; i++) {
      await Future<void>.delayed(const Duration(milliseconds: 200));
      final token = await _readToken(dir);
      if (token != null && await _healthy(baseUrl, token)) {
        return (baseUrl: baseUrl, token: token);
      }
    }
    process.kill();
    throw StateError('wallet service did not come up on $baseUrl');
  }

  /// Manual attach: the user pastes a URL + token (demo bridges, remote hosts).
  static Future<({String baseUrl, String token})> attach({
    required String baseUrl,
    required String token,
  }) async {
    final clean = baseUrl.trim().replaceAll(RegExp(r'/+$'), '');
    if (!await _healthy(clean, token.trim())) {
      throw StateError('bridge refused the token at $clean');
    }
    return (baseUrl: clean, token: token.trim());
  }
}
