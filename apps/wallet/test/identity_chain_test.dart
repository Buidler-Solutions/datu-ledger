import 'package:flutter_test/flutter_test.dart';

import 'package:datu_wallet/core/ledger/identity_chain.dart';

/// The wording of the chain lives here, once; the explorer prints the same
/// sentences from the same JSON. Fixtures keep them from drifting.

void main() {
  Map<String, dynamic> chain({List<Map<String, dynamic>> attestations = const [], Map<String, dynamic>? keyRevoke}) => {
        'counts': {'attestations': attestations.length},
        'attestations': attestations,
        'revoked_by_key': keyRevoke,
      };

  test('an attested key reads as who vouches, with claims and cosigners', () {
    final lines = describeIdentityChain(chain(attestations: [
      {
        'by': 'd53ad911aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
        'claims': {'role': 'clerk', 'legal_name': 'Acme Registry'},
        'cosigners': ['6a14f870bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb'],
        'revoked': false,
      }
    ]));
    expect(lines, hasLength(1));
    expect(lines.first, contains('attested by d53ad911...aaaa'));
    expect(lines.first, contains('role=clerk'));
    expect(lines.first, contains('legal_name=Acme Registry'));
    expect(lines.first, contains('cosigned by 1'));
  });

  test('revocation stays attached to the attestation that was killed', () {
    final lines = describeIdentityChain(chain(attestations: [
      {
        'by': 'd53ad911aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
        'claims': {'role': 'clerk'},
        'cosigners': const [],
        'revoked': true,
        'revoked_by': {
          'by': 'd53ad911aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
          'reason': 'left the registry',
        },
      }
    ]));
    expect(lines.last, 'REVOKED by d53ad911...aaaa - left the registry');
  });

  test('key-level ejection and empty chains behave', () {
    expect(describeIdentityChain(chain()), isEmpty);
    final lines = describeIdentityChain(chain(keyRevoke: {
      'by': 'd53ad911aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
      'reason': 'key compromised',
    }));
    expect(lines.single, 'key revoked directly by d53ad911...aaaa - key compromised');
  });
}
