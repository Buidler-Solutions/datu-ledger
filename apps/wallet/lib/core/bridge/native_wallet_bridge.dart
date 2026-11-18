import 'dart:convert';
import 'dart:ffi' as ffi;
import 'dart:io';
import 'dart:isolate';

import 'package:ffi/ffi.dart' as pffi;
import 'package:path_provider/path_provider.dart';

import 'wallet_bridge.dart';

/// The embedded Rust wallet core (`crates/wallet-ffi`), linked into the app.
///
/// Phones cannot spawn the desktop bridge as a sidecar, so the same wallet
/// code is compiled into the binary and called through a four-function C ABI
/// (`datu_wallet_open` / `datu_wallet_request` / `datu_wallet_close` /
/// `datu_string_free`). The request grammar and response shapes mirror the
/// HTTP bridge routes, so screens cannot tell the difference.
///
/// Every request runs on a background isolate (open → request → close), so
/// Argon2id passphrase stretching never freezes the UI and no raw pointer
/// ever outlives one call.
class NativeWalletBridge implements WalletBridge {
  NativeWalletBridge._(this.dataDir, this._libraryPath);

  /// Keystore directory the core is bound to.
  final String dataDir;

  /// Explicit dylib path (desktop demo / tests); null = platform rules
  /// (process symbols on iOS, libdatu_wallet_ffi.so on Android).
  final String? _libraryPath;

  @override
  String get baseUrl => 'datu-wallet-ffi · in-process native core';

  @override
  String get token => '';

  /// Desktop override: when DATU_WALLET_FFI points at the cdylib, the app
  /// demonstrates the native path on macOS before mobile exists.
  static String? get _envLibraryPath {
    final path = Platform.environment['DATU_WALLET_FFI'];
    return (path == null || path.isEmpty) ? null : path;
  }

  /// Mobile always uses the native core; desktop only when asked via env.
  static bool get isSupported =>
      Platform.isAndroid || Platform.isIOS || _envLibraryPath != null;

  /// Keystore location: app documents on mobile, the shared DATU data dir on
  /// desktop (so the FFI demo signs with the same identities as the bridge).
  static Future<String> defaultDataDir() async {
    if (Platform.isAndroid || Platform.isIOS) {
      final docs = await getApplicationDocumentsDirectory();
      return '${docs.path}/datu-wallet';
    }
    final env = Platform.environment['DATU_WALLET_FFI_DIR'];
    if (env != null && env.isNotEmpty) return env;
    final home = Platform.environment['HOME'] ?? '.';
    if (Platform.isMacOS) return '$home/Library/Application Support/DATU';
    if (Platform.isWindows) {
      final appData = Platform.environment['APPDATA'] ?? '.';
      return '$appData\\DATU';
    }
    return '$home/.local/share/datu';
  }

  /// Try to bring up the native core; returns null on desktop when the
  /// library is not available (caller falls back to the HTTP bridge).
  /// On mobile the failure is fatal - there is no bridge to fall back to.
  /// [libraryPath] overrides DATU_WALLET_FFI (used by the FFI test).
  static Future<NativeWalletBridge> open(
    String dataDir, {
    String? libraryPath,
  }) async {
    final lib = libraryPath ?? _envLibraryPath;
    if (lib != null && !File(lib).existsSync()) {
      throw StateError(
        'native wallet library not found at $lib - '
        'build it: cargo build -p datu-wallet-ffi',
      );
    }
    final bridge = NativeWalletBridge._(dataDir, lib);
    await Directory(dataDir).create(recursive: true);
    await bridge.identities(); // smoke test: library loads and answers JSON
    return bridge;
  }

  Future<Map<String, dynamic>> _call(Map<String, dynamic> request) async {
    // Capture plain locals only: the closure crosses an isolate boundary.
    final dir = dataDir;
    final requestJson = jsonEncode(request);
    final libPath = _libraryPath ?? _envLibraryPath;
    final answer = await Isolate.run(
      () => _nativeRequest(dir, requestJson, libPath),
    );
    final decoded = jsonDecode(answer);
    if (decoded is! Map<String, dynamic>) {
      throw StateError('native core returned ${decoded.runtimeType}');
    }
    return decoded;
  }

  @override
  Future<List<Map<String, dynamic>>> identities() async {
    final res = await _call({'action': 'identities'});
    _throwIfError(res);
    final list = (res['identities'] as List?) ?? const [];
    return list.cast<Map<String, dynamic>>();
  }

  @override
  Future<Map<String, dynamic>> create({
    required String name,
    required String passphrase,
  }) =>
      _call({
        'action': 'create',
        'name': name,
        'passphrase': passphrase,
      });

  @override
  Future<Map<String, dynamic>> partySign({
    required String name,
    required String passphrase,
    required String role,
    required String kind,
    required Map<String, dynamic> document,
  }) =>
      _call({
        'action': 'party-sign',
        'name': name,
        'passphrase': passphrase,
        'role': role,
        'kind': kind,
        'document': document,
      });

  @override
  Future<Map<String, dynamic>> seal({
    required String name,
    required String passphrase,
    required Map<String, dynamic> document,
    required List<String> fields,
    required List<String> to,
    List<String> toFields = const [],
  }) =>
      _call({
        'action': 'seal',
        'name': name,
        'passphrase': passphrase,
        'document': document,
        'fields': fields,
        'to': to,
        'to_fields': toFields,
      });

  @override
  Future<Map<String, dynamic>> signEntry({
    required String name,
    required String passphrase,
    required String namespace,
    required int seq,
    String? prev,
    required Map<String, dynamic> payloadJson,
  }) =>
      _call({
        'action': 'sign-entry',
        'name': name,
        'passphrase': passphrase,
        'request': {
          'namespace': namespace,
          'seq': seq,
          'prev': prev,
          'payload_json': payloadJson,
        },
      });

  @override
  Future<Map<String, dynamic>> authAssert({
    required String name,
    required String passphrase,
    required String rpId,
    required String origin,
    required String nonce,
    required int expiresAtMs,
  }) =>
      _call({
        'action': 'auth-assert',
        'name': name,
        'passphrase': passphrase,
        'rp_id': rpId,
        'origin': origin,
        'nonce': nonce,
        'expires_at_ms': expiresAtMs,
      });

  @override
  Future<Map<String, dynamic>> verifyEntry({
    required Map<String, dynamic> entry,
  }) =>
      _call({
        'action': 'verify-entry',
        'entry': entry,
      });

  @override
  Future<Map<String, dynamic>> openFields({
    required String name,
    required String passphrase,
    required Map<String, dynamic> document,
  }) =>
      _call({
        'action': 'open',
        'name': name,
        'passphrase': passphrase,
        'document': document,
      });

  @override
  Future<Map<String, dynamic>> exportIdentity({
    required String name,
    required String passphrase,
    required String backupPassphrase,
  }) =>
      _call({
        'action': 'export',
        'name': name,
        'passphrase': passphrase,
        'backup_passphrase': backupPassphrase,
      });

  @override
  Future<Map<String, dynamic>> importIdentity({
    required Map<String, dynamic> backup,
    required String passphrase,
    String? rename,
  }) =>
      _call({
        'action': 'import',
        'backup': backup,
        'passphrase': passphrase,
        'rename': ?rename,
      });
}

void _throwIfError(Map<String, dynamic> res) {
  final error = res['error'];
  if (error is String && error.isNotEmpty) throw StateError(error);
}

// ---- FFI plumbing (top-level: run inside the request isolate) ----

typedef _OpenC = ffi.Pointer<ffi.Void> Function(ffi.Pointer<pffi.Utf8>);
typedef _OpenDart = ffi.Pointer<ffi.Void> Function(ffi.Pointer<pffi.Utf8>);
typedef _RequestC = ffi.Pointer<pffi.Utf8> Function(
    ffi.Pointer<ffi.Void>, ffi.Pointer<pffi.Utf8>);
typedef _RequestDart = ffi.Pointer<pffi.Utf8> Function(
    ffi.Pointer<ffi.Void>, ffi.Pointer<pffi.Utf8>);
typedef _CloseC = ffi.Void Function(ffi.Pointer<ffi.Void>);
typedef _CloseDart = void Function(ffi.Pointer<ffi.Void>);
typedef _FreeC = ffi.Void Function(ffi.Pointer<pffi.Utf8>);
typedef _FreeDart = void Function(ffi.Pointer<pffi.Utf8>);

/// One full native round trip, entirely inside one isolate: load the
/// library, open a core, process the request, close, free.
String _nativeRequest(String dataDir, String requestJson, String? libPath) {
  final lib = _openLibrary(libPath);
  final open = lib.lookupFunction<_OpenC, _OpenDart>('datu_wallet_open');
  final request =
      lib.lookupFunction<_RequestC, _RequestDart>('datu_wallet_request');
  final close = lib.lookupFunction<_CloseC, _CloseDart>('datu_wallet_close');
  final free = lib.lookupFunction<_FreeC, _FreeDart>('datu_string_free');

  final cDir = dataDir.toNativeUtf8(allocator: pffi.calloc);
  final core = open(cDir);
  pffi.calloc.free(cDir);
  if (core == ffi.nullptr) {
    throw StateError('native core refused to open $dataDir');
  }

  final cRequest = requestJson.toNativeUtf8(allocator: pffi.calloc);
  final cAnswer = request(core, cRequest);
  pffi.calloc.free(cRequest);
  close(core);

  if (cAnswer == ffi.nullptr) throw StateError('native core returned null');
  final answer = cAnswer.toDartString();
  free(cAnswer);
  return answer;
}

ffi.DynamicLibrary _openLibrary(String? explicitPath) {
  if (Platform.isIOS) {
    // Static library: the symbols are already in this process.
    return ffi.DynamicLibrary.process();
  }
  if (Platform.isAndroid) {
    return ffi.DynamicLibrary.open('libdatu_wallet_ffi.so');
  }
  if (explicitPath != null) {
    return ffi.DynamicLibrary.open(explicitPath);
  }
  throw StateError(
    'native wallet core not configured - set DATU_WALLET_FFI to the '
    'libdatu_wallet_ffi dylib path (cargo build -p datu-wallet-ffi)',
  );
}
