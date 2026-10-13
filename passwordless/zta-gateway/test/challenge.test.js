import { test } from 'node:test';
import assert from 'node:assert/strict';
import { buildClaimsChallengeHeader, buildClaimsRequest, buildInvalidTokenHeader, parseClaimsChallenge } from '../src/challenge.js';

test('claims challenge header matches the documented format', () => {
  const header = buildClaimsChallengeHeader({ authContext: 'c1' });
  assert.match(header, /^Bearer realm="", authorization_uri="https:\/\/login\.microsoftonline\.com\/common\/oauth2\/authorize", error="insufficient_claims", claims="[A-Za-z0-9+/=]+"$/);
  const parsed = parseClaimsChallenge(header);
  assert.equal(parsed.error, 'insufficient_claims');
  assert.deepEqual(parsed.claims, { access_token: { acrs: { essential: true, value: 'c1' } } });
});

test('tenant-scoped challenge sets realm and v2.0 authorize endpoint, CAE prepends xms_cc', () => {
  const header = buildClaimsChallengeHeader({ authContext: 'c25', tenantId: 'contoso.onmicrosoft.com', caeCapable: true });
  const parsed = parseClaimsChallenge(header);
  assert.equal(parsed.realm, 'contoso.onmicrosoft.com');
  assert.equal(parsed.authorizationUri, 'https://login.microsoftonline.com/contoso.onmicrosoft.com/oauth2/v2.0/authorize');
  assert.deepEqual(parsed.claims, { access_token: { xms_cc: { values: ['cp1'] }, acrs: { essential: true, value: 'c25' } } });
  assert.deepEqual(Object.keys(buildClaimsRequest({ authContext: 'c1', caeCapable: true }).access_token), ['xms_cc', 'acrs']);
});

test('rejects invalid auth context ids', () => {
  assert.throws(() => buildClaimsRequest({ authContext: 'cp1' }), TypeError);
  assert.throws(() => buildClaimsRequest({ authContext: 'c100' }), TypeError);
});

test('invalid_token header escapes quotes and parses', () => {
  const header = buildInvalidTokenHeader('expired', 'token "has" expired');
  assert.equal(header, 'Bearer error="invalid_token", error_description="expired: token has expired"');
  assert.equal(parseClaimsChallenge(header).error, 'invalid_token');
  assert.equal(parseClaimsChallenge('Basic realm=x'), null);
  assert.equal(parseClaimsChallenge(undefined), null);
});
