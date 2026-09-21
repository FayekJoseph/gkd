import { test } from 'node:test';
import assert from 'node:assert/strict';
import { JwksKeyStore } from '../src/jwks.js';
import { makeSigner, fakeFetch } from './helpers.js';

test('loads keys from JWKS, caches, and refreshes once on unknown kid', async () => {
  const a = makeSigner({ kid: 'kid-a' });
  const b = makeSigner({ kid: 'kid-b' });
  let published = [a.jwk];
  let clock = 1_000_000;
  const fetch = fakeFetch(() => ({ body: { keys: published } }));
  const store = new JwksKeyStore({ jwksUri: 'https://login.microsoftonline.com/t/discovery/v2.0/keys', fetch, now: () => clock, minRefreshIntervalMs: 60_000 });

  const keyA = await store.getKey('kid-a');
  assert.ok(keyA);
  assert.equal(keyA.asymmetricKeyType, 'rsa');
  assert.equal(fetch.calls.length, 1);

  await store.getKey('kid-a');
  assert.equal(fetch.calls.length, 1, 'cached lookup should not refetch');

  assert.equal(await store.getKey('kid-b'), null, 'unknown kid before rotation');
  assert.equal(fetch.calls.length, 1, 'refresh is rate-limited right after a fetch');

  clock += 61_000;
  published = [a.jwk, b.jwk];
  assert.ok(await store.getKey('kid-b'), 'kid miss after the interval triggers a refresh');
  assert.equal(fetch.calls.length, 2);
});

test('forTenant builds the login.microsoftonline.com discovery URL', () => {
  const store = JwksKeyStore.forTenant('contoso.onmicrosoft.com', { fetch: fakeFetch(() => ({ body: { keys: [] } })) });
  assert.equal(store.jwksUri, 'https://login.microsoftonline.com/contoso.onmicrosoft.com/discovery/v2.0/keys');
});

test('rejects non-https endpoints, HTTP errors and empty key sets', async () => {
  assert.throws(() => new JwksKeyStore({ jwksUri: 'http://evil/keys' }), TypeError);
  const failing = new JwksKeyStore({ jwksUri: 'https://x/keys', fetch: fakeFetch(() => ({ status: 500, body: {} })) });
  await assert.rejects(failing.getKey('k'), /HTTP 500/);
  const empty = new JwksKeyStore({ jwksUri: 'https://x/keys', fetch: fakeFetch(() => ({ body: { keys: [{ kty: 'EC', kid: 'e' }] } })) });
  await assert.rejects(empty.getKey('k'), /no usable RSA/);
});
