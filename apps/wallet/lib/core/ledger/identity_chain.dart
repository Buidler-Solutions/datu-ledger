/// Rendering rules for the identity chain, kept pure so the wording is
/// testable and identical to what the explorer prints.
library;

String _short(String? key) {
  if (key == null || key.length < 12) return key ?? '?';
  return '${key.substring(0, 8)}...${key.substring(key.length - 4)}';
}

/// One line per attestation, plus revocation notes. Empty when nothing on
/// this ledger names the key; the caller shows the "unattested" sentence.
List<String> describeIdentityChain(Map<String, dynamic> chain) {
  final lines = <String>[];
  final attestations = (chain['attestations'] as List?) ?? const [];
  for (final raw in attestations) {
    final a = (raw as Map).cast<String, dynamic>();
    final claims = (a['claims'] as Map?)?.entries
            .map((e) => '${e.key}=${e.value}')
            .join(', ') ??
        'no claims';
    final cosigners = ((a['cosigners'] as List?) ?? const []).cast<String>();
    final cosigned = cosigners.isEmpty
        ? ''
        : ' | cosigned by ${cosigners.length}: ${cosigners.map(_short).join(', ')}';
    lines.add('attested by ${_short(a['by'] as String?)} - $claims$cosigned');
    final revoked = a['revoked_by'];
    if (a['revoked'] == true && revoked is Map && revoked['by'] != null) {
      final reason = revoked['reason'];
      lines.add(
          'REVOKED by ${_short(revoked['by'] as String?)}${reason == null ? '' : ' - $reason'}');
    }
  }
  final keyRevoke = chain['revoked_by_key'];
  if (keyRevoke is Map && keyRevoke['by'] != null) {
    final reason = keyRevoke['reason'];
    lines.add(
        'key revoked directly by ${_short(keyRevoke['by'] as String?)}${reason == null ? '' : ' - $reason'}');
  }
  return lines;
}
