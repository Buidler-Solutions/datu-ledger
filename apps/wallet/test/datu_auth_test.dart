import 'dart:convert';

import 'package:flutter_test/flutter_test.dart';

import 'package:datu_wallet/core/auth/datu_auth.dart';

/// The standalone sign-in handoff, tested without a device: parsing a dApp
/// link, the canonical bytes a signature covers, and the return URL the dApp
/// gets back. The crypto itself is the embedded core's job (see
/// crates/wallet-ffi auth_assert_action_signs_verifiable_login_challenge).

void main() {
  final nonce = 'ab' * 16;
  final expires =
      DateTime.now().add(const Duration(minutes: 2)).millisecondsSinceEpoch;

  String link({Map<String, String>? override}) {
    final q = {
      'rp_id': 'app.example.com',
      'origin': 'https://app.example.com',
      'nonce': nonce,
      'expires_at_ms': '$expires',
      'redirect': 'https://app.example.com/auth/callback',
      ...?override,
    };
    return Uri(scheme: 'datu-auth', host: 'sign', queryParameters: q).toString();
  }

  test('parses a valid datu-auth link', () {
    final r = SignInRequest.parse(link());
    expect(r.rpId, 'app.example.com');
    expect(r.origin, 'https://app.example.com');
    expect(r.nonce, nonce);
    expect(r.expiresAtMs, expires);
    expect(r.redirect.toString(), 'https://app.example.com/auth/callback');
    expect(r.expired, isFalse);
    expect(r.remainingSeconds, greaterThan(0));
  });

  test('parses the https form used by QR codes', () {
    final r = SignInRequest.parse(
      'https://app.example.com/datu-auth?rp_id=app.example.com&origin=https%3A%2F%2Fapp.example.com'
      '&nonce=$nonce&expires_at_ms=$expires&redirect=https%3A%2F%2Fapp.example.com%2Fin',
    );
    expect(r.rpId, 'app.example.com');
  });

  test('canonical bytes match the core format', () {
    final r = SignInRequest.parse(link());
    expect(
      r.canonicalBytes,
      'datu-auth-v1\napp.example.com\nhttps://app.example.com\n$nonce\n$expires\n',
    );
  });

  test('refuses wrong scheme, bad nonce, bad origin and short redirect', () {
    expect(() => SignInRequest.parse('https://app.example.com/other?rp_id=x'),
        throwsA(isA<DatuAuthException>()));
    expect(() => SignInRequest.parse(link(override: {'nonce': 'zz'})),
        throwsA(isA<DatuAuthException>()));
    expect(() => SignInRequest.parse(link(override: {'origin': 'javascript:alert(1)'})),
        throwsA(isA<DatuAuthException>()));
    expect(
      () => SignInRequest.parse(link(override: {'redirect': 'ftp://app.example.com'})),
      throwsA(isA<DatuAuthException>()),
    );
  });

  test('refuses an expiry beyond the accepted lifetime', () {
    final far = DateTime.now()
        .add(const Duration(minutes: 30))
        .millisecondsSinceEpoch;
    expect(() => SignInRequest.parse(link(override: {'expires_at_ms': '$far'})),
        throwsA(isA<DatuAuthException>()));
  });

  test('return URL carries the assertion in the fragment and round-trips', () {
    final assertion = {
      'domain': 'datu-auth-v1',
      'rp_id': 'app.example.com',
      'origin': 'https://app.example.com',
      'nonce': nonce,
      'expires_at_ms': expires,
      'pubkey': 'a' * 64,
      'signature': 'b' * 128,
    };
    final redirect = Uri.parse('https://app.example.com/auth/callback?lang=en');
    final back = buildReturnUri(redirect, assertion);

    expect(back.path, '/auth/callback');
    expect(back.queryParameters['lang'], 'en');
    expect(back.fragment, startsWith('datu-assertion='));
    // Payloads are base64url so the fragment stays URL-safe.
    final payload = back.fragment.substring('datu-assertion='.length);
    expect(payload.contains('+'), isFalse);
    expect(payload.contains('/'), isFalse);
    expect(payload.contains('='), isFalse);

    final decoded = readAssertionFromUrl(back.toString());
    expect(decoded, assertion);
  });

  test('readAssertionFromUrl rejects a missing or malformed fragment', () {
    expect(() => readAssertionFromUrl('https://app.example.com/cb'),
        throwsA(isA<DatuAuthException>()));
    expect(() => readAssertionFromUrl('https://app.example.com/cb#datu-assertion=%%%'),
        throwsA(isA<DatuAuthException>()));
  });

  test('sample links are valid and round-trip through the parser', () {
    final sample = sampleSignInLink(nonce: nonce);
    final parsed = SignInRequest.parse(sample);
    expect(parsed.nonce, nonce);
    expect(parsed.rpId, 'app.example.com');
    // And the payload decodes as JSON once signed.
    final round = buildReturnUri(parsed.redirect, jsonDecode('{"ok":true}') as Map<String, dynamic>);
    expect(readAssertionFromUrl(round.toString()), {'ok': true});
  });
}
