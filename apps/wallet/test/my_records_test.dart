import 'package:flutter_test/flutter_test.dart';

import 'package:datu_wallet/core/ledger/my_records.dart';

void main() {
  final me = 'a'.padRight(64, 'a');
  final other = 'b'.padRight(64, 'b');

  test('a record is mine when a party key is mine', () {
    final payload = {
      'kind': 'land.title.application',
      'parties': [
        {'role': 'holder', 'key': other},
        {'role': 'officer', 'key': me},
      ],
      'doc': {'parcel': 'LOT-42'},
    };
    expect(concernsMe(payload, me), isTrue);
    expect(concernsMe(payload, other), isTrue);
    expect(concernsMe(payload, 'c'.padRight(64, 'c')), isFalse);
  });

  test('a record is mine when the document names my key in any field', () {
    final payload = {
      'doc': {'bidder_key': me, 'bid_id': 'BID-7'},
      'parties': [],
    };
    expect(concernsMe(payload, me), isTrue);
    expect(concernsMe(payload, other), isFalse);
  });

  test('null payload concerns nobody', () {
    expect(concernsMe(null, me), isFalse);
  });

  test('namespace patterns: exact, prefix, blank', () {
    expect(nsMatches('', 'gov.records'), isTrue);
    expect(nsMatches('gov.*', 'gov.records'), isTrue);
    expect(nsMatches('gov.*', 'identity.attest'), isFalse);
    expect(nsMatches('gov.records', 'gov.records'), isTrue);
    expect(nsMatches('gov.records', 'gov.records.extra'), isFalse);
  });

  test('record labels pick the most meaningful field, else the first string, else the id', () {
    expect(recordLabel({'doc': {'parcel': 'LOT-42'}}, 'deadbeef'), 'parcel · LOT-42');
    expect(recordLabel({'doc': {'mystery': 'x'}}, 'deadbeef'), 'mystery · x');
    expect(recordLabel({'doc': {}}, 'deadbeef'), 'deadbeef…');
    expect(recordLabel(null, 'deadbeef'), 'deadbeef…');
  });
}
