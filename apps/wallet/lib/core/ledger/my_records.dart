/// "Is this record about me?" - the same rule the browser extension uses:
/// a record concerns an identity when a party signature key is theirs, or
/// the document names their key in any field (holder_key, bidder_key,
/// licensee_key, …). Any namespace, any transaction kind.
library;

bool concernsMe(Map<String, dynamic>? payload, String edPublic) {
  if (payload == null) return false;
  final parties = payload['parties'];
  if (parties is List && parties.any((p) => p is Map && p['key'] == edPublic)) {
    return true;
  }
  final doc = payload['doc'] is Map ? payload['doc'] as Map : payload;
  return doc.values.any((v) => v == edPublic);
}

bool nsMatches(String pattern, String ns) {
  final trimmed = pattern.trim();
  if (trimmed.isEmpty) return true;
  return trimmed.endsWith('*')
      ? ns.startsWith(trimmed.substring(0, trimmed.length - 1))
      : ns == trimmed;
}

const _labelCandidates = [
  'parcel', 'title_no', 'license_id', 'license_no', 'licence_no',
  'lot', 'bid_id', 'permit_no', 'reference', 'ref', 'object', 'subject', 'id',
  'name',
];

/// Human label for a record: the most meaningful document field, else the
/// first string field, else the entry id prefix.
String recordLabel(Map<String, dynamic>? payload, String id) {
  final doc = _innerDoc(payload);
  for (final key in _labelCandidates) {
    final value = doc[key];
    if (value is String && value.isNotEmpty) {
      return '${key.replaceAll('_', ' ')} · $value';
    }
  }
  final first = doc.entries.where((e) => e.value is String && (e.value as String).isNotEmpty);
  if (first.isNotEmpty) {
    final e = first.first;
    return '${e.key.replaceAll('_', ' ')} · ${e.value}';
  }
  return '${id.substring(0, id.length < 12 ? id.length : 12)}…';
}

Map<String, dynamic> _innerDoc(Map<String, dynamic>? payload) {
  if (payload == null) return const {};
  final doc = payload['doc'];
  if (doc is Map<String, dynamic>) return doc;
  return payload;
}
