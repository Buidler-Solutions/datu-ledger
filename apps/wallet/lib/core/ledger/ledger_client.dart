import 'dart:convert';

import 'package:dio/dio.dart';

/// Read-only client for a DATU node's HTTP API (validator or free observer -
/// the wallet never trusts it, it only fetches; verification is local).
class LedgerClient {
  LedgerClient({required this.baseUrl})
      : _dio = Dio(
          BaseOptions(
            connectTimeout: const Duration(seconds: 4),
            receiveTimeout: const Duration(seconds: 20),
          ),
        );

  final String baseUrl;
  final Dio _dio;

  String get base => baseUrl.trim().replaceAll(RegExp(r'/+$'), '');

  /// Node summary: entries, checkpoints, policy mode, governance freshness.
  Future<Map<String, dynamic>> status() async =>
      (await _dio.get('$base/v1/status').then((r) => r.data as Map))
          .cast<String, dynamic>();

  /// Identity chain for a key: attestations naming it, their cosigners,
  /// revocations. Plain ledger statements; the wallet renders who vouches,
  /// never a bare "verified".
  Future<Map<String, dynamic>> identityChain(String key) async =>
      (await _dio.get('$base/v1/identity/$key').then((r) => r.data as Map))
          .cast<String, dynamic>();

  /// Recent entries. `author`/`ns` optional filters.
  Future<List<Map<String, dynamic>>> entries({
    String? ns,
    String? author,
    int limit = 50,
  }) async {
    final res = await _dio.get('$base/v1/entries', queryParameters: {
      if (ns != null && ns.isNotEmpty) 'ns': ns,
      if (author != null && author.isNotEmpty) 'author': author,
      'limit': limit,
    });
    final list = (res.data['entries'] as List?) ?? const [];
    return list.cast<Map<String, dynamic>>();
  }

  /// One full signed entry, JSON.
  Future<Map<String, dynamic>> entry(String id) async =>
      (await _dio.get('$base/v1/entry/$id').then((r) => r.data as Map))
          .cast<String, dynamic>();

  /// One author's feed + head.
  Future<Map<String, dynamic>> feed(String author) async =>
      (await _dio.get('$base/v1/feed/$author').then((r) => r.data as Map))
          .cast<String, dynamic>();

  /// Every signer's latest witness root.
  Future<List<Map<String, dynamic>>> checkpoints() async {
    final res = await _dio.get('$base/v1/checkpoints');
    final list = (res.data['checkpoints'] as List?) ?? const [];
    return list.cast<Map<String, dynamic>>();
  }

  /// Recorded feed disputes (preserved evidence + resolutions).
  Future<List<Map<String, dynamic>>> conflicts() async {
    final res = await _dio.get('$base/v1/conflicts');
    final list = (res.data['conflicts'] as List?) ?? const [];
    return list.cast<Map<String, dynamic>>();
  }

  /// Decode an entry's base64 payload into a JSON object, or null when the
  /// payload is not a JSON object (still a valid entry, just not a document).
  static Map<String, dynamic>? decodePayload(String? payloadBase64) {
    if (payloadBase64 == null || payloadBase64.isEmpty) return null;
    try {
      final decoded = jsonDecode(utf8.decode(base64Decode(payloadBase64)));
      if (decoded is Map<String, dynamic>) return decoded;
      return null;
    } catch (_) {
      return null;
    }
  }
}
