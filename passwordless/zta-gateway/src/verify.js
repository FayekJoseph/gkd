import { constants, verify as cryptoVerify } from 'node:crypto';
import { decodeJsonSegment, fromBase64Url } from './base64url.js';
import { TokenError } from './errors.js';

const SIGNATURE_PARAMS = {
  RS256: (key) => ({ key, padding: constants.RSA_PKCS1_PADDING }),
  PS256: (key) => ({ key, padding: constants.RSA_PKCS1_PSS_PADDING, saltLength: constants.RSA_PSS_SALTLEN_DIGEST }),
};

/**
 * Split a compact JWS into its parts without trusting anything in it.
 * @param {string} token
 */
export function decodeJwt(token) {
  if (typeof token !== 'string' || token.length === 0) {
    throw new TokenError('malformed', 'token must be a non-empty string');
  }
  const parts = token.split('.');
  if (parts.length !== 3) {
    throw new TokenError('malformed', 'token must have exactly three segments');
  }
  const [h, p, s] = parts;
  let header;
  let payload;
  let signature;
  try {
    header = decodeJsonSegment(h);
    payload = decodeJsonSegment(p);
    signature = fromBase64Url(s);
  } catch (err) {
    throw new TokenError('malformed', `token segments could not be decoded: ${err.message}`);
  }
  return { header, payload, signingInput: `${h}.${p}`, signature };
}

/**
 * Issuer values Entra uses for a tenant. v2.0 tokens use login.microsoftonline.com,
 * v1.0 tokens use sts.windows.net.
 * @param {string} tenantId
 */
export function issuersForTenant(tenantId) {
  return [
    `https://login.microsoftonline.com/${tenantId}/v2.0`,
    `https://sts.windows.net/${tenantId}/`,
  ];
}

/**
 * Verify an Entra-issued access token: signature, algorithm allow-list,
 * issuer, audience, lifetime and tenant. Returns the decoded header and claims.
 *
 * @param {string} token
 * @param {object} options
 * @param {string} options.tenantId
 * @param {string | string[]} options.audience  application ID URI(s) or client id(s) of this API
 * @param {{ getKey(kid: string): Promise<import('node:crypto').KeyObject | null> }} options.keyStore
 * @param {() => number} [options.now] seconds since epoch
 * @param {number} [options.clockSkewSeconds] default 120
 * @param {string[]} [options.allowedAlgorithms] default ['RS256']
 * @param {string[]} [options.issuers] override the accepted issuer list
 */
export async function verifyEntraToken(token, options) {
  const {
    tenantId,
    audience,
    keyStore,
    now = () => Math.floor(Date.now() / 1000),
    clockSkewSeconds = 120,
    allowedAlgorithms = ['RS256'],
    issuers,
  } = options ?? {};

  if (!tenantId || typeof tenantId !== 'string') throw new TypeError('options.tenantId is required');
  if (!audience) throw new TypeError('options.audience is required');
  if (!keyStore || typeof keyStore.getKey !== 'function') throw new TypeError('options.keyStore is required');

  const { header, payload, signingInput, signature } = decodeJwt(token);

  if (typeof header.alg !== 'string' || !allowedAlgorithms.includes(header.alg) || !SIGNATURE_PARAMS[header.alg]) {
    throw new TokenError('alg_not_allowed', `algorithm ${String(header.alg)} is not allowed`);
  }
  if (typeof header.kid !== 'string' || header.kid.length === 0) {
    throw new TokenError('missing_kid', 'token header has no kid');
  }

  const key = await keyStore.getKey(header.kid);
  if (!key) {
    throw new TokenError('unknown_kid', `no signing key for kid ${header.kid}`);
  }
  const ok = cryptoVerify('sha256', Buffer.from(signingInput, 'ascii'), SIGNATURE_PARAMS[header.alg](key), signature);
  if (!ok) {
    throw new TokenError('bad_signature', 'signature verification failed');
  }

  const acceptedIssuers = issuers ?? issuersForTenant(tenantId);
  if (typeof payload.iss !== 'string' || !acceptedIssuers.includes(payload.iss)) {
    throw new TokenError('bad_issuer', `issuer ${String(payload.iss)} is not trusted`);
  }

  const expectedAudiences = Array.isArray(audience) ? audience : [audience];
  const tokenAudiences = Array.isArray(payload.aud) ? payload.aud : [payload.aud];
  if (!tokenAudiences.some((aud) => typeof aud === 'string' && expectedAudiences.includes(aud))) {
    throw new TokenError('bad_audience', 'token was not issued for this API');
  }

  const t = now();
  if (typeof payload.exp !== 'number' || t >= payload.exp + clockSkewSeconds) {
    throw new TokenError('expired', 'token has expired');
  }
  if (typeof payload.nbf === 'number' && t + clockSkewSeconds < payload.nbf) {
    throw new TokenError('not_yet_valid', 'token is not valid yet');
  }
  if (payload.tid !== tenantId) {
    throw new TokenError('bad_tenant', 'token was issued by a different tenant');
  }

  return { header, claims: payload };
}
