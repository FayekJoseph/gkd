import { constants, generateKeyPairSync, sign as cryptoSign } from 'node:crypto';
import { StaticKeyStore } from '../src/jwks.js';
import { encodeJsonSegment, toBase64Url } from '../src/base64url.js';

export const TENANT = '11111111-2222-3333-4444-555555555555';
export const AUDIENCE = 'api://zta-gateway-test';
export const KID = 'test-kid-2026';

/** A throwaway RSA signer standing in for Entra's token signing key. */
export function makeSigner({ kid = KID } = {}) {
  const { publicKey, privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
  const jwk = { ...publicKey.export({ format: 'jwk' }), kid, use: 'sig', alg: 'RS256' };
  const keyStore = new StaticKeyStore({ [kid]: publicKey });

  /**
   * @param {Record<string, unknown>} claims
   * @param {{ alg?: 'RS256' | 'PS256' | 'none', header?: Record<string, unknown> }} [opts]
   */
  function sign(claims, opts = {}) {
    const alg = opts.alg ?? 'RS256';
    const header = { alg, typ: 'JWT', kid, ...(opts.header ?? {}) };
    const input = `${encodeJsonSegment(header)}.${encodeJsonSegment(claims)}`;
    if (alg === 'none') return `${input}.`;
    const params = alg === 'PS256'
      ? { key: privateKey, padding: constants.RSA_PKCS1_PSS_PADDING, saltLength: constants.RSA_PSS_SALTLEN_DIGEST }
      : { key: privateKey, padding: constants.RSA_PKCS1_PADDING };
    return `${input}.${toBase64Url(cryptoSign('sha256', Buffer.from(input, 'ascii'), params))}`;
  }

  return { kid, publicKey, privateKey, jwk, keyStore, sign };
}

/** Claims of a typical v2.0 delegated token from a passkey sign-in. */
export function userClaims(overrides = {}, nowSeconds = Math.floor(Date.now() / 1000)) {
  return {
    iss: `https://login.microsoftonline.com/${TENANT}/v2.0`,
    aud: AUDIENCE,
    tid: TENANT,
    sub: 'sub-1',
    oid: 'oid-1',
    azp: 'client-app-1',
    azpacr: '0',
    idtyp: 'user',
    scp: 'access_as_user',
    preferred_username: 'someone@example.com',
    name: 'Someone',
    amr: ['fido', 'mfa'],
    ver: '2.0',
    iat: nowSeconds - 10,
    nbf: nowSeconds - 10,
    exp: nowSeconds + 3600,
    ...overrides,
  };
}

/** Claims of an app-only token acquired with a certificate credential. */
export function appClaims(overrides = {}, nowSeconds = Math.floor(Date.now() / 1000)) {
  return {
    iss: `https://login.microsoftonline.com/${TENANT}/v2.0`,
    aud: AUDIENCE,
    tid: TENANT,
    sub: 'sp-oid-1',
    oid: 'sp-oid-1',
    azp: 'daemon-app-1',
    azpacr: '2',
    idtyp: 'app',
    roles: ['Data.Read.All'],
    ver: '2.0',
    iat: nowSeconds - 10,
    nbf: nowSeconds - 10,
    exp: nowSeconds + 3600,
    ...overrides,
  };
}

/** Minimal fetch double that records calls and replays canned responses. */
export function fakeFetch(responder) {
  const calls = [];
  const fn = async (input, init = {}) => {
    const url = input instanceof URL ? input.toString() : String(input);
    calls.push({ url, init });
    const r = await responder(url, init, calls.length);
    const headers = new Headers(r.headers ?? {});
    const body = r.body === undefined ? '' : typeof r.body === 'string' ? r.body : JSON.stringify(r.body);
    return new Response(body, { status: r.status ?? 200, headers });
  };
  fn.calls = calls;
  return fn;
}
