import { test } from 'node:test';
import assert from 'node:assert/strict';
import { acquireManagedIdentityToken } from '../src/managed-identity.js';
import { fakeFetch } from './helpers.js';

const ok = { body: { access_token: 'MI', expires_on: '1800000000', resource: 'https://graph.microsoft.com', client_id: 'mi-client' } };

test('IMDS path on Azure VMs', async () => {
  const fetch = fakeFetch(() => ok);
  const r = await acquireManagedIdentityToken({ resource: 'https://graph.microsoft.com', env: {}, fetch });
  assert.equal(r.source, 'imds');
  assert.equal(r.accessToken, 'MI');
  assert.equal(r.expiresOn, 1800000000);
  const u = new URL(fetch.calls[0].url);
  assert.equal(u.origin, 'http://169.254.169.254');
  assert.equal(u.searchParams.get('api-version'), '2018-02-01');
  assert.equal(u.searchParams.get('resource'), 'https://graph.microsoft.com');
  assert.equal(fetch.calls[0].init.headers.Metadata, 'true');
});

test('App Service path uses IDENTITY_ENDPOINT and X-IDENTITY-HEADER, forwards client_id', async () => {
  const fetch = fakeFetch(() => ok);
  const env = { IDENTITY_ENDPOINT: 'http://127.0.0.1:41000/msi/token', IDENTITY_HEADER: 'hdr' };
  const r = await acquireManagedIdentityToken({ resource: 'https://vault.azure.net', clientId: 'uami', env, fetch });
  assert.equal(r.source, 'app-service');
  const u = new URL(fetch.calls[0].url);
  assert.equal(u.pathname, '/msi/token');
  assert.equal(u.searchParams.get('api-version'), '2019-08-01');
  assert.equal(u.searchParams.get('client_id'), 'uami');
  assert.equal(fetch.calls[0].init.headers['X-IDENTITY-HEADER'], 'hdr');
});

test('Azure Arc path completes the Basic realm challenge from the local secret file', async () => {
  const fetch = fakeFetch((url, init, n) => (n === 1
    ? { status: 401, headers: { 'www-authenticate': 'Basic realm=/var/opt/azcmagent/tokens/abc.key' } }
    : ok));
  const env = { IDENTITY_ENDPOINT: 'http://localhost:40342/metadata/identity/oauth2/token' };
  const r = await acquireManagedIdentityToken({ resource: 'https://management.azure.com/', env, fetch, readFile: async (p) => (p === '/var/opt/azcmagent/tokens/abc.key' ? 'SECRET\n' : '') });
  assert.equal(r.source, 'arc');
  assert.equal(fetch.calls.length, 2);
  assert.equal(fetch.calls[1].init.headers.Authorization, 'Basic SECRET');
});

test('surfaces endpoint errors', async () => {
  const fetch = fakeFetch(() => ({ status: 400, body: { error: 'invalid_request', error_description: 'Identity not found' } }));
  await assert.rejects(acquireManagedIdentityToken({ resource: 'r', env: {}, fetch }), /HTTP 400 Identity not found/);
  await assert.rejects(acquireManagedIdentityToken({ env: {}, fetch }), TypeError);
});
