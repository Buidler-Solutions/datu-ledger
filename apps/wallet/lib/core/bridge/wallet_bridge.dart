import 'dart:convert';

import 'package:dio/dio.dart';

/// The wallet surface every screen talks to. Two implementations:
/// - [HttpWalletBridge] - desktop, talks to the local bridge process
///   (`datu wallet serve`);
/// - `NativeWalletBridge` - mobile / FFI demo, links the Rust core into the
///   app process (crates/wallet-ffi).
///
/// The keys never live in this app either way: both implementations only
/// accept passphrase-gated sign/seal requests and hand back results.
abstract class WalletBridge {
  String get baseUrl;
  String get token;

  Future<List<Map<String, dynamic>>> identities();

  Future<Map<String, dynamic>> create({
    required String name,
    required String passphrase,
  });

  Future<Map<String, dynamic>> partySign({
    required String name,
    required String passphrase,
    required String role,
    required String kind,
    required Map<String, dynamic> document,
  });

  Future<Map<String, dynamic>> seal({
    required String name,
    required String passphrase,
    required Map<String, dynamic> document,
    required List<String> fields,
    required List<String> to,
    List<String> toFields,
  });

  Future<Map<String, dynamic>> signEntry({
    required String name,
    required String passphrase,
    required String namespace,
    required int seq,
    String? prev,
    required Map<String, dynamic> payloadJson,
  });

  /// Verify a ledger entry fetched from ANY node - locally, without trusting
  /// the node that served it (Ed25519 + ML-DSA-65 + party signatures).
  Future<Map<String, dynamic>> verifyEntry({
    required Map<String, dynamic> entry,
  });

  /// SignetAuth: sign a relying party's login challenge with [name].
  /// The response is the assertion a dApp verifies locally:
  /// {domain, rp_id, origin, nonce, expires_at_ms, pubkey, signature}.
  Future<Map<String, dynamic>> authAssert({
    required String name,
    required String passphrase,
    required String rpId,
    required String origin,
    required String nonce,
    required int expiresAtMs,
  });

  /// Decrypt the fields of [document] that are sealed to this identity
  /// (`open_fields` in the core; named `openFields` here because `open` is
  /// taken by the native bridge's static constructor).
  Future<Map<String, dynamic>> openFields({
    required String name,
    required String passphrase,
    required Map<String, dynamic> document,
  });

  /// Export an identity as a portable backup encrypted with a separate
  /// backup passphrase.
  Future<Map<String, dynamic>> exportIdentity({
    required String name,
    required String passphrase,
    required String backupPassphrase,
  });

  /// Restore a backup produced by [exportIdentity].
  Future<Map<String, dynamic>> importIdentity({
    required Map<String, dynamic> backup,
    required String passphrase,
    String? rename,
  });

  static String pretty(Object? value) =>
      const JsonEncoder.withIndent('  ').convert(value);
}

/// Thin client over the local DATU wallet bridge (`datu wallet serve`).
/// The bridge holds the keys; this app only asks it to sign and read.
class HttpWalletBridge implements WalletBridge {
  HttpWalletBridge({required String baseUrl, required this.token})
      : baseUrl = baseUrl.replaceAll(RegExp(r'/+$'), '') {
    _dio = Dio(
      BaseOptions(
        connectTimeout: const Duration(seconds: 5),
        receiveTimeout: const Duration(seconds: 120),
      ),
    );
    _dio.interceptors.add(
      InterceptorsWrapper(
        onRequest: (options, handler) {
          options.headers['Authorization'] = 'Bearer $token';
          handler.next(options);
        },
      ),
    );
  }

  @override
  final String baseUrl;
  @override
  final String token;
  late final Dio _dio;

  @override
  Future<List<Map<String, dynamic>>> identities() async {
    final res = await _dio.get('$baseUrl/v1/wallet/identities');
    final list = (res.data['identities'] as List?) ?? const [];
    return list.cast<Map<String, dynamic>>();
  }

  @override
  Future<Map<String, dynamic>> create({
    required String name,
    required String passphrase,
  }) async {
    final res = await _dio.post('$baseUrl/v1/wallet/create', data: {
      'name': name,
      'passphrase': passphrase,
    });
    return (res.data as Map).cast<String, dynamic>();
  }

  @override
  Future<Map<String, dynamic>> partySign({
    required String name,
    required String passphrase,
    required String role,
    required String kind,
    required Map<String, dynamic> document,
  }) async {
    final res = await _dio.post('$baseUrl/v1/wallet/party-sign', data: {
      'name': name,
      'passphrase': passphrase,
      'role': role,
      'kind': kind,
      'document': document,
    });
    return (res.data as Map).cast<String, dynamic>();
  }

  @override
  Future<Map<String, dynamic>> seal({
    required String name,
    required String passphrase,
    required Map<String, dynamic> document,
    required List<String> fields,
    required List<String> to,
    List<String> toFields = const [],
  }) async {
    final res = await _dio.post('$baseUrl/v1/wallet/seal', data: {
      'name': name,
      'passphrase': passphrase,
      'document': document,
      'fields': fields,
      'to': to,
      'to_fields': toFields,
    });
    return (res.data as Map).cast<String, dynamic>();
  }

  @override
  Future<Map<String, dynamic>> signEntry({
    required String name,
    required String passphrase,
    required String namespace,
    required int seq,
    String? prev,
    required Map<String, dynamic> payloadJson,
  }) async {
    final res = await _dio.post('$baseUrl/v1/wallet/sign-entry', data: {
      'name': name,
      'passphrase': passphrase,
      'request': {
        'namespace': namespace,
        'seq': seq,
        'prev': prev,
        'payload_json': payloadJson,
      },
    });
    return (res.data as Map).cast<String, dynamic>();
  }

  @override
  Future<Map<String, dynamic>> verifyEntry({
    required Map<String, dynamic> entry,
  }) async {
    final res = await _dio.post('$baseUrl/v1/wallet/verify-entry', data: {
      'entry': entry,
    });
    return (res.data as Map).cast<String, dynamic>();
  }

  @override
  Future<Map<String, dynamic>> authAssert({
    required String name,
    required String passphrase,
    required String rpId,
    required String origin,
    required String nonce,
    required int expiresAtMs,
  }) async {
    final res = await _dio.post('$baseUrl/v1/wallet/auth-assert', data: {
      'name': name,
      'passphrase': passphrase,
      'rp_id': rpId,
      'origin': origin,
      'nonce': nonce,
      'expires_at_ms': expiresAtMs,
    });
    return (res.data as Map).cast<String, dynamic>();
  }

  @override
  Future<Map<String, dynamic>> openFields({
    required String name,
    required String passphrase,
    required Map<String, dynamic> document,
  }) async {
    final res = await _dio.post('$baseUrl/v1/wallet/open', data: {
      'name': name,
      'passphrase': passphrase,
      'document': document,
    });
    return (res.data as Map).cast<String, dynamic>();
  }

  @override
  Future<Map<String, dynamic>> exportIdentity({
    required String name,
    required String passphrase,
    required String backupPassphrase,
  }) async {
    final res = await _dio.post('$baseUrl/v1/wallet/export', data: {
      'name': name,
      'passphrase': passphrase,
      'backup_passphrase': backupPassphrase,
    });
    return (res.data as Map).cast<String, dynamic>();
  }

  @override
  Future<Map<String, dynamic>> importIdentity({
    required Map<String, dynamic> backup,
    required String passphrase,
    String? rename,
  }) async {
    final res = await _dio.post('$baseUrl/v1/wallet/import', data: {
      'backup': backup,
      'passphrase': passphrase,
      'rename': ?rename,
    });
    return (res.data as Map).cast<String, dynamic>();
  }
}
