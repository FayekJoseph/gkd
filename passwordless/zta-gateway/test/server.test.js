import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { createRequestHandler, loadConfigFromEnv } from '../src/server.js';
import { makeSigner, userClaims, appClaims, TENANT, AUDIENCE } from './helpers.js';

const signer = makeSigner();
const config = loadConfigFromEnv({ ZTA_TENANT_ID: TENANT, ZTA_AUDIENCE: AUDIENCE, ZTA_AUTH_CONTEXT_ID: 'c1' });
const quiet = { info() {}, warn() {} };
const handler = createRequestHandler({ config, keyStore: signer.keyStore, logger: quiet });
const server = createServer((req, res) => handler(req, res));
await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
const base = `http://127.0.0.1:${server.address().port}`;
after(() => server.close());

const get = (path, token) => fetch(`${base}${path}`, { headers: token ? { authorization: `Bearer ${token}` } : {} });

test('healthz is open', async () => {
  const res = await get('/healthz');
  assert.equal(res.status, 200);
  assert.deepEqual(await res.json(), { status: 'ok' });
});

test('missing or invalid token gives 401 with WWW-Authenticate', async () => {
  const none = await get('/api/me');
  assert.equal(none.status, 401);
  assert.equal(none.headers.get('www-authenticate'), 'Bearer');
  const bad = await get('/api/me', signer.sign(userClaims({ aud: 'nope' })));
  assert.equal(bad.status, 401);
  assert.match(bad.headers.get('www-authenticate'), /error="invalid_token", error_description="bad_audience/);
  assert.equal((await bad.json()).error_code, 'bad_audience');
  assert.equal(bad.headers.get('cache-control'), 'no-store');
});

test('phishing-resistant user token is accepted; MFA-by-push is not', async () => {
  const ok = await get('/api/me', signer.sign(userClaims()));
  assert.equal(ok.status, 200);
  const body = await ok.json();
  assert.equal(body.subject, 'oid-1');
  assert.deepEqual(body.amr, ['fido', 'mfa']);

  const weak = await get('/api/me', signer.sign(userClaims({ amr: ['pwd', 'rsa', 'mfa'] })));
  assert.equal(weak.status, 403);
  assert.deepEqual((await weak.json()).reasons, ['strength_insufficient:mfa']);
});

test('app token needs certificate auth', async () => {
  assert.equal((await get('/api/me', signer.sign(appClaims()))).status, 200);
  const secret = await get('/api/me', signer.sign(appClaims({ azpacr: '1' })));
  assert.equal(secret.status, 403);
});

test('privileged route issues a claims challenge until acrs c1 is present', async () => {
  const challenge = await get('/api/privileged', signer.sign(userClaims()));
  assert.equal(challenge.status, 401);
  const header = challenge.headers.get('www-authenticate');
  assert.match(header, /error="insufficient_claims"/);
  assert.match(header, new RegExp(`realm="${TENANT}"`));
  const claims = /claims="([^"]+)"/.exec(header)[1];
  assert.deepEqual(JSON.parse(Buffer.from(claims, 'base64').toString()), { access_token: { xms_cc: { values: ['cp1'] }, acrs: { essential: true, value: 'c1' } } });

  const stepped = await get('/api/privileged', signer.sign(userClaims({ acrs: ['c1'] })));
  assert.equal(stepped.status, 200);
  assert.equal((await stepped.json()).satisfied_auth_context, 'c1');

  const weakWithCtx = await get('/api/privileged', signer.sign(userClaims({ amr: ['swk', 'mfa'], acrs: ['c1'] })));
  assert.equal(weakWithCtx.status, 403, 'auth context never lowers the strength bar');
});

test('unknown routes and methods', async () => {
  assert.equal((await get('/nope')).status, 404);
  const post = await fetch(`${base}/api/me`, { method: 'POST' });
  assert.equal(post.status, 405);
});

test('loadConfigFromEnv validates input', () => {
  assert.throws(() => loadConfigFromEnv({}), /ZTA_TENANT_ID/);
  assert.throws(() => loadConfigFromEnv({ ZTA_TENANT_ID: 't' }), /ZTA_AUDIENCE/);
  assert.throws(() => loadConfigFromEnv({ ZTA_TENANT_ID: 't', ZTA_AUDIENCE: 'a', ZTA_MIN_STRENGTH: 'max' }), /ZTA_MIN_STRENGTH/);
  const c = loadConfigFromEnv({ ZTA_TENANT_ID: 't', ZTA_AUDIENCE: 'a, b', ZTA_ALLOWED_CLIENT_IDS: 'x,y' });
  assert.deepEqual(c.audience, ['a', 'b']);
  assert.deepEqual(c.allowedClientIds, ['x', 'y']);
  assert.equal(c.minimumStrength, 'phishingResistant');
});
