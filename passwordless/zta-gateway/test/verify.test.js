import { test } from 'node:test';
import assert from 'node:assert/strict';
import { decodeJwt, verifyEntraToken } from '../src/verify.js';
import { TokenError } from '../src/errors.js';
import { makeSigner, userClaims, TENANT, AUDIENCE } from './helpers.js';

const signer = makeSigner();
const base = { tenantId: TENANT, audience: AUDIENCE, keyStore: signer.keyStore };

async function rejects(token, code, options = {}) {
  await assert.rejects(
    verifyEntraToken(token, { ...base, ...options }),
    (err) => err instanceof TokenError && err.code === code,
    `expected rejection with code ${code}`,
  );
}

test('accepts a well-formed RS256 token from the tenant', async () => {
  const { claims } = await verifyEntraToken(signer.sign(userClaims()), base);
  assert.equal(claims.oid, 'oid-1');
  assert.deepEqual(claims.amr, ['fido', 'mfa']);
});

test('accepts v1.0 issuer and audience given as an array', async () => {
  const token = signer.sign(userClaims({ iss: `https://sts.windows.net/${TENANT}/`, aud: ['other', AUDIENCE] }));
  const { claims } = await verifyEntraToken(token, base);
  assert.equal(claims.tid, TENANT);
});

test('rejects tampered payload', async () => {
  const token = signer.sign(userClaims());
  const [h, , s] = token.split('.');
  const forged = Buffer.from(JSON.stringify(userClaims({ oid: 'attacker' }))).toString('base64url');
  await rejects(`${h}.${forged}.${s}`, 'bad_signature');
});

test('rejects alg none and unexpected algorithms', async () => {
  await rejects(signer.sign(userClaims(), { alg: 'none' }), 'alg_not_allowed');
  await rejects(signer.sign(userClaims(), { alg: 'PS256' }), 'alg_not_allowed');
  const hs = `${Buffer.from(JSON.stringify({ alg: 'HS256', kid: signer.kid })).toString('base64url')}.${Buffer.from(JSON.stringify(userClaims())).toString('base64url')}.AAAA`;
  await rejects(hs, 'alg_not_allowed');
});

test('PS256 works only when explicitly allowed', async () => {
  const token = signer.sign(userClaims(), { alg: 'PS256' });
  const { claims } = await verifyEntraToken(token, { ...base, allowedAlgorithms: ['RS256', 'PS256'] });
  assert.equal(claims.sub, 'sub-1');
});

test('rejects unknown kid and missing kid', async () => {
  await rejects(signer.sign(userClaims(), { header: { kid: 'nope' } }), 'unknown_kid');
  await rejects(signer.sign(userClaims(), { header: { kid: '' } }), 'missing_kid');
});

test('rejects wrong issuer, audience and tenant', async () => {
  await rejects(signer.sign(userClaims({ iss: 'https://login.microsoftonline.com/other-tenant/v2.0' })), 'bad_issuer');
  await rejects(signer.sign(userClaims({ aud: 'api://someone-else' })), 'bad_audience');
  await rejects(signer.sign(userClaims({ tid: 'other-tenant' })), 'bad_tenant');
});

test('enforces exp and nbf with clock skew', async () => {
  const now = 1_800_000_000;
  const opts = { now: () => now };
  await rejects(signer.sign(userClaims({ exp: now - 200 }, now)), 'expired', opts);
  await rejects(signer.sign(userClaims({ nbf: now + 500, exp: now + 900 }, now)), 'not_yet_valid', opts);
  const ok = await verifyEntraToken(signer.sign(userClaims({ exp: now + 60, nbf: now + 30 }, now)), { ...base, ...opts });
  assert.equal(ok.claims.sub, 'sub-1');
  await rejects(signer.sign(userClaims({ exp: 'never' }, now)), 'expired', opts);
});

test('rejects malformed tokens', async () => {
  await rejects('', 'malformed');
  await rejects('a.b', 'malformed');
  await rejects('a.b.c', 'malformed');
  await rejects(`${Buffer.from('[]').toString('base64url')}.${Buffer.from('{}').toString('base64url')}.x`, 'malformed');
  assert.throws(() => decodeJwt(42), TokenError);
});

test('requires configuration', async () => {
  await assert.rejects(verifyEntraToken('x.y.z', { audience: AUDIENCE, keyStore: signer.keyStore }), TypeError);
  await assert.rejects(verifyEntraToken('x.y.z', { tenantId: TENANT, keyStore: signer.keyStore }), TypeError);
  await assert.rejects(verifyEntraToken('x.y.z', { tenantId: TENANT, audience: AUDIENCE }), TypeError);
});
