// Identity chains: the policy layer above /v1/identity. The SDK must name
// vouchers and filter by roots/roles/claims/cosigners - never emit a bare
// "verified" - and it must fail closed on transport problems and malformed
// chains.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  DatuError,
  ErrorCode,
  checkAttestation,
  fetchIdentityChain,
  requireAttestation,
} from '../src/index.js';

const ROOT = 'd53ad911aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
const OTHER = '6a14f870bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb';
const KEY = '8163bf896300b625cd180f094c7b08b6fb41556c5c678da50bc2f9c577bf6073';

const chain = (attestations = [], extra = {}) => ({
  key: KEY,
  attestations,
  revocations: [],
  revoked_by_key: null,
  counts: { attestations: attestations.length, distinct_cosigners: 0, revoked: 0 },
  verified: true,
  note: 'Attestations are signed statements, not a verdict. Which roots count is your policy.',
  ...extra,
});

const attestation = (over = {}) => ({
  id: '17c0c54f' + '0'.repeat(56),
  by: ROOT,
  label: 'Acme Ltd',
  claims: { role: 'bidder', legal_name: 'Acme Ltd' },
  cosigners: [OTHER],
  enroll: null,
  revoked: false,
  revoked_by: null,
  ...over,
});

test('any live attestation vouches, and the voucher is named', () => {
  const verdict = requireAttestation(chain([attestation()]));
  assert.equal(verdict.ok, true);
  assert.equal(verdict.reason, null);
  assert.equal(verdict.vouchers.length, 1);
  assert.equal(verdict.vouchers[0].by, ROOT);
  assert.equal(verdict.vouchers[0].cosigners, 1);
  assert.equal(verdict.vouchers[0].claims.role, 'bidder');
});

test('roots filter: only configured trust roots count', () => {
  const trusted = requireAttestation(chain([attestation()]), { roots: [ROOT] });
  assert.equal(trusted.ok, true);
  const stranger = requireAttestation(chain([attestation()]), { roots: [OTHER] });
  assert.equal(stranger.ok, false);
  assert.match(stranger.reason, /no attestation .* satisfies the requirement/);
  assert.deepEqual(stranger.vouchers, []);
});

test('roles, claims and cosigners are ANDed', () => {
  const byRole = requireAttestation(chain([attestation()]), { roles: ['clerk'] });
  assert.equal(byRole.ok, false);
  const byClaim = requireAttestation(chain([attestation()]), { claims: { legal_name: 'Other Ltd' } });
  assert.equal(byClaim.ok, false);
  const byQuorum = requireAttestation(chain([attestation({ cosigners: [] })]), { minCosigners: 1 });
  assert.equal(byQuorum.ok, false);
  const all = requireAttestation(chain([attestation()]), {
    roots: [ROOT],
    roles: ['bidder'],
    claims: { legal_name: 'Acme Ltd' },
    minCosigners: 1,
  });
  assert.equal(all.ok, true);
});

test('revoked attestations never vouch; direct key revocation vetoes everything', () => {
  const revoked = requireAttestation(chain([attestation({ revoked: true })]));
  assert.equal(revoked.ok, false);
  assert.match(revoked.reason, /every attestation .* is revoked/);

  const keyRevoke = requireAttestation(
    chain([attestation()], {
      revoked_by_key: { by: ROOT, reason: 'key compromised' },
    }),
  );
  assert.equal(keyRevoke.ok, false);
  assert.match(keyRevoke.reason, /key revoked directly by d53ad911/);
});

test('an empty chain reads as unattested, never as an error', () => {
  const verdict = requireAttestation(chain([]));
  assert.equal(verdict.ok, false);
  assert.match(verdict.reason, /signed in, unattested/);
  assert.equal(requireAttestation(null).ok, false);
});

test('fetchIdentityChain validates input and fails closed on bad answers', async () => {
  await assert.rejects(
    fetchIdentityChain('http://127.0.0.1:7474', 'not-hex'),
    (e) => e instanceof DatuError && e.code === ErrorCode.BAD_ARGUMENT,
  );
  await assert.rejects(
    fetchIdentityChain('', KEY),
    (e) => e instanceof DatuError && e.code === ErrorCode.BAD_ARGUMENT,
  );

  const ok = await fetchIdentityChain('http://127.0.0.1:7474/', KEY, {
    fetchImpl: async (url) => {
      assert.equal(url, `http://127.0.0.1:7474/v1/identity/${KEY}`);
      return { ok: true, status: 200, json: async () => chain([attestation()]) };
    },
  });
  assert.equal(ok.attestations.length, 1);

  await assert.rejects(
    fetchIdentityChain('http://127.0.0.1:7474', KEY, {
      fetchImpl: async () => ({ ok: false, status: 503, json: async () => ({}) }),
    }),
    (e) => e instanceof DatuError && e.code === ErrorCode.NODE_ERROR,
  );

  await assert.rejects(
    fetchIdentityChain('http://127.0.0.1:7474', KEY, {
      fetchImpl: async () => ({ ok: true, status: 200, json: async () => ({ key: OTHER, attestations: [] }) }),
    }),
    (e) => e instanceof DatuError && e.code === ErrorCode.NODE_ERROR,
  );
});

test('checkAttestation composes fetch and policy; transport throws, policy returns', async () => {
  const verdict = await checkAttestation('http://127.0.0.1:7474', KEY, {
    fetchImpl: async () => ({ ok: true, status: 200, json: async () => chain([attestation()]) }),
    roots: [ROOT],
    minCosigners: 1,
  });
  assert.equal(verdict.ok, true);
  assert.equal(verdict.vouchers[0].by, ROOT);

  const unattested = await checkAttestation('http://127.0.0.1:7474', KEY, {
    fetchImpl: async () => ({ ok: true, status: 200, json: async () => chain([]) }),
  });
  assert.equal(unattested.ok, false);
  await assert.rejects(checkAttestation('http://127.0.0.1:1', KEY), Error);
});
