import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { constants, createHash, createPublicKey, verify as cryptoVerify, X509Certificate } from 'node:crypto';
import { acquireTokenWithCertificate, certificateThumbprints, createClientAssertion, CLIENT_ASSERTION_TYPE } from '../src/client-assertion.js';
import { decodeJwt } from '../src/verify.js';
import { fakeFetch } from './helpers.js';

/** Generate a throwaway self-signed certificate with openssl; skip if unavailable. */
function makeCert() {
  const dir = mkdtempSync(join(tmpdir(), 'zta-cert-'));
  try {
    execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', join(dir, 'key.pem'), '-out', join(dir, 'cert.pem'), '-days', '1', '-subj', '/CN=zta-gateway-test'], { stdio: 'ignore' });
  } catch {
    rmSync(dir, { recursive: true, force: true });
    return null;
  }
  const out = { keyPem: readFileSync(join(dir, 'key.pem'), 'utf8'), certPem: readFileSync(join(dir, 'cert.pem'), 'utf8') };
  rmSync(dir, { recursive: true, force: true });
  return out;
}

const cert = makeCert();
const CLIENT = '00000000-aaaa-bbbb-cccc-000000000001';
const TENANT = 'contoso.onmicrosoft.com';

test('thumbprints are base64url SHA-1 and SHA-256 of the DER certificate', { skip: !cert && 'openssl not available' }, () => {
  const tp = certificateThumbprints(cert.certPem);
  const der = new X509Certificate(cert.certPem).raw;
  assert.equal(tp.sha256, createHash('sha256').update(der).digest('base64url'));
  assert.equal(tp.sha1, createHash('sha1').update(der).digest('base64url'));
  assert.match(tp.subject, /CN=zta-gateway-test/);
});

test('client assertion is a PS256 JWT with the claims Entra requires', { skip: !cert && 'openssl not available' }, () => {
  const now = 1_800_000_000;
  const jwt = createClientAssertion({ clientId: CLIENT, tenantId: TENANT, privateKey: cert.keyPem, certificate: cert.certPem, now: () => now });
  const { header, payload, signingInput, signature } = decodeJwt(jwt);
  assert.equal(header.alg, 'PS256');
  assert.equal(header.typ, 'JWT');
  assert.equal(header['x5t#S256'], certificateThumbprints(cert.certPem).sha256);
  assert.equal(payload.aud, `https://login.microsoftonline.com/${TENANT}/oauth2/v2.0/token`);
  assert.equal(payload.iss, CLIENT);
  assert.equal(payload.sub, CLIENT);
  assert.equal(payload.nbf, now);
  assert.equal(payload.exp, now + 300);
  assert.match(payload.jti, /^[0-9a-f-]{36}$/);
  const pub = createPublicKey(cert.certPem);
  assert.equal(cryptoVerify('sha256', Buffer.from(signingInput), { key: pub, padding: constants.RSA_PKCS1_PSS_PADDING, saltLength: constants.RSA_PSS_SALTLEN_DIGEST }, signature), true);
});

test('RS256 assertion and explicit thumbprints are supported; long lifetimes are not', { skip: !cert && 'openssl not available' }, () => {
  const jwt = createClientAssertion({ clientId: CLIENT, tenantId: TENANT, privateKey: cert.keyPem, thumbprints: { sha256: 'abc' }, algorithm: 'RS256' });
  const { header, signingInput, signature } = decodeJwt(jwt);
  assert.equal(header.alg, 'RS256');
  assert.equal(header['x5t#S256'], 'abc');
  assert.equal(header.x5t, undefined);
  assert.equal(cryptoVerify('sha256', Buffer.from(signingInput), createPublicKey(cert.certPem), signature), true);
  assert.throws(() => createClientAssertion({ clientId: CLIENT, tenantId: TENANT, privateKey: cert.keyPem, thumbprints: { sha256: 'abc' }, lifetimeSeconds: 3600 }), RangeError);
  assert.throws(() => createClientAssertion({ clientId: CLIENT, tenantId: TENANT, privateKey: cert.keyPem }), TypeError);
});

test('acquireTokenWithCertificate posts a client_credentials grant with CAE capability', { skip: !cert && 'openssl not available' }, async () => {
  const fetch = fakeFetch(() => ({ body: { access_token: 'AT', token_type: 'Bearer', expires_in: 3599 } }));
  const result = await acquireTokenWithCertificate({ clientId: CLIENT, tenantId: TENANT, scope: 'https://graph.microsoft.com/.default', privateKey: cert.keyPem, certificate: cert.certPem, fetch });
  assert.equal(result.accessToken, 'AT');
  const call = fetch.calls[0];
  assert.equal(call.url, `https://login.microsoftonline.com/${TENANT}/oauth2/v2.0/token`);
  const body = call.init.body;
  assert.equal(body.get('grant_type'), 'client_credentials');
  assert.equal(body.get('client_assertion_type'), CLIENT_ASSERTION_TYPE);
  assert.equal(body.get('client_secret'), null, 'no secret is ever sent');
  assert.deepEqual(JSON.parse(body.get('claims')), { access_token: { xms_cc: { values: ['cp1'] } } });
  assert.equal(decodeJwt(body.get('client_assertion')).payload.iss, CLIENT);

  const failing = fakeFetch(() => ({ status: 401, body: { error: 'invalid_client', error_description: 'AADSTS700027' } }));
  await assert.rejects(
    acquireTokenWithCertificate({ clientId: CLIENT, tenantId: TENANT, scope: 'x/.default', privateKey: cert.keyPem, certificate: cert.certPem, fetch: failing }),
    /invalid_client AADSTS700027/,
  );
});
