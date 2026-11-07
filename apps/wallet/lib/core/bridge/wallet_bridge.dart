import 'dart:convert';

import 'package:dio/dio.dart';

/// Thin client over the local DATU wallet bridge (`datu wallet serve`).
/// The bridge holds the keys; this app only asks it to sign and read.
class WalletBridge {
  WalletBridge({required String baseUrl, required this.token})
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

  final String baseUrl;
  final String token;
  late final Dio _dio;

  Future<List<Map<String, dynamic>>> identities() async {
    final res = await _dio.get('$baseUrl/v1/wallet/identities');
    final list = (res.data['identities'] as List?) ?? const [];
    return list.cast<Map<String, dynamic>>();
  }

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

  static String pretty(Object? value) =>
      const JsonEncoder.withIndent('  ').convert(value);
}
