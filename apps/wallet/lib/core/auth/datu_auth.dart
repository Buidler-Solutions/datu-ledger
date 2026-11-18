/// Standalone SignetAuth handoff for phones.
///
/// A dApp cannot hold keys and a phone app must not need a desktop bridge, so
/// the login request travels as a link: the dApp shows a `datu-auth://sign`
/// URI (as a QR or a button), the phone app parses it, signs the challenge
/// with the embedded Rust core, and returns the assertion in the fragment of
/// the dApp's redirect URL. Nothing here touches a network or a bridge token.
///
/// Request (query parameters):
///   rp_id          relying party id, e.g. app.example.com
///   origin         exact origin the request came from, e.g. https://app.example.com
///   nonce          32 lowercase hex characters, single use
///   expires_at_ms  challenge expiry, milliseconds since Unix epoch
///   redirect       https URL the assertion is returned to
///
/// Response: `redirect#datu-assertion=<base64url(no padding) of the assertion JSON>`
library;

import 'dart:convert';

class DatuAuthException implements Exception {
  DatuAuthException(this.message);

  final String message;

  @override
  String toString() => message;
}

class SignInRequest {
  SignInRequest({
    required this.rpId,
    required this.origin,
    required this.nonce,
    required this.expiresAtMs,
    required this.redirect,
  });

  final String rpId;
  final String origin;
  final String nonce;
  final int expiresAtMs;
  final Uri redirect;

  static const scheme = 'datu-auth';
  static final _nonceRe = RegExp(r'^[0-9a-f]{32}$');
  static final _originRe = RegExp(r'^https?://');
  static const maxLifetimeMs = 5 * 60 * 1000;

  bool get expired => DateTime.now().millisecondsSinceEpoch > expiresAtMs;

  /// Remaining seconds, clamped at zero (for the review screen).
  int get remainingSeconds {
    final left = expiresAtMs - DateTime.now().millisecondsSinceEpoch;
    return left <= 0 ? 0 : (left / 1000).ceil();
  }

  /// Accepts `datu-auth://sign?...` and the web form
  /// `https://<rp>/datu-auth?...` (same parameters, convenient for QR codes
  /// that must open a browser first).
  static SignInRequest parse(String raw) {
    final uri = Uri.tryParse(raw.trim());
    if (uri == null) {
      throw DatuAuthException('This is not a link.');
    }
    final isScheme = uri.scheme == scheme &&
        (uri.host == 'sign' || uri.path == '/sign' || uri.path == 'sign');
    final isWeb = uri.scheme == 'https' &&
        (uri.path == '/datu-auth' || uri.path.endsWith('/datu-auth'));
    if (!isScheme && !isWeb) {
      throw DatuAuthException('Not a DATU sign-in link (expected datu-auth://sign?…)');
    }
    final q = uri.queryParameters;
    final rpId = (q['rp_id'] ?? '').trim();
    final origin = (q['origin'] ?? '').trim();
    final nonce = (q['nonce'] ?? '').trim().toLowerCase();
    final expiresRaw = (q['expires_at_ms'] ?? '').trim();
    final redirectRaw = (q['redirect'] ?? '').trim();

    if (rpId.isEmpty || rpId.contains('/')) {
      throw DatuAuthException('The link is missing a valid rp_id.');
    }
    if (!_originRe.hasMatch(origin)) {
      throw DatuAuthException('The link is missing a valid origin.');
    }
    if (!_nonceRe.hasMatch(nonce)) {
      throw DatuAuthException('The nonce must be 32 lowercase hex characters.');
    }
    final expires = int.tryParse(expiresRaw);
    if (expires == null || expires <= 0) {
      throw DatuAuthException('The link is missing a valid expires_at_ms.');
    }
    if (expires - DateTime.now().millisecondsSinceEpoch > maxLifetimeMs) {
      throw DatuAuthException('The challenge expiry is too far in the future; refuse it.');
    }
    final redirect = Uri.tryParse(redirectRaw);
    if (redirect == null || !_originRe.hasMatch(redirectRaw) || redirect.host.isEmpty) {
      throw DatuAuthException('The link is missing a valid https redirect.');
    }
    return SignInRequest(
      rpId: rpId,
      origin: origin,
      nonce: nonce,
      expiresAtMs: expires,
      redirect: redirect,
    );
  }

  /// The canonical bytes the signature covers, for display and for tests.
  /// Must match crates/core/src/auth.rs exactly.
  String get canonicalBytes =>
      'datu-auth-v1\n$rpId\n$origin\n$nonce\n$expiresAtMs\n';
}

/// Build the redirect the dApp verifies. The assertion rides in the URL
/// fragment so it never appears in server logs or referrer headers.
Uri buildReturnUri(Uri redirect, Map<String, dynamic> assertion) {
  final payload = base64Url
      .encode(utf8.encode(jsonEncode(assertion)))
      .replaceAll('=', '');
  return redirect.replace(fragment: 'datu-assertion=$payload');
}

/// Read the assertion back out of a return URL (used by dApps and tests).
Map<String, dynamic> readAssertionFromUrl(String raw) {
  final uri = Uri.tryParse(raw);
  if (uri == null) {
    throw DatuAuthException('Not a URL.');
  }
  final fragment = uri.fragment;
  const prefix = 'datu-assertion=';
  if (!fragment.startsWith(prefix)) {
    throw DatuAuthException('No datu-assertion in the fragment.');
  }
  final payload = fragment.substring(prefix.length);
  final padded = payload.padRight((payload.length + 3) & ~3, '=');
  final Object? json;
  try {
    json = jsonDecode(utf8.decode(base64Url.decode(padded)));
  } on FormatException {
    throw DatuAuthException('The assertion payload is not valid base64url JSON.');
  }
  if (json is! Map<String, dynamic>) {
    throw DatuAuthException('The assertion is not a JSON object.');
  }
  return json;
}

/// Sample link for the review screen and manual testing.
String sampleSignInLink({String rpId = 'app.example.com', String? nonce}) {
  final n = nonce ?? 'ab' * 16;
  final expires =
      DateTime.now().add(const Duration(minutes: 2)).millisecondsSinceEpoch;
  final q = {
    'rp_id': rpId,
    'origin': 'https://$rpId',
    'nonce': n,
    'expires_at_ms': '$expires',
    'redirect': 'https://$rpId/auth/callback',
  };
  return Uri(
    scheme: signetScheme,
    host: 'sign',
    queryParameters: q,
  ).toString();
}

const signetScheme = 'datu-auth';
