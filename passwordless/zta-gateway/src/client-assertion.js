import { constants, createHash, createPrivateKey, randomUUID, sign as cryptoSign, X509Certificate } from 'node:crypto';
import { encodeJsonSegment, toBase64Url } from './base64url.js';

export const CLIENT_ASSERTION_TYPE = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer';

/**
 * SHA-1 and SHA-256 thumbprints of a certificate, base64url-encoded, as
 * Entra expects them in the `x5t` and `x5t#S256` JWT headers.
 * @param {string | Buffer | X509Certificate} certificate PEM, DER or parsed
 */
export function certificateThumbprints(certificate) {
  const x509 = certificate instanceof X509Certificate ? certificate : new X509Certificate(certificate);
  const der = x509.raw;
  return {
    sha1: toBase64Url(createHash('sha1').update(der).digest()),
    sha256: toBase64Url(createHash('sha256').update(der).digest()),
    subject: x509.subject,
    notAfter: x509.validTo,
  };
}

/**
 * Build the signed JWT that replaces a client secret in the client-credentials
 * grant (OIDC `private_key_jwt`). Format per
 * learn.microsoft.com/entra/identity-platform/certificate-credentials.
 *
 * @param {object} options
 * @param {string} options.clientId application (client) id
 * @param {string} options.tenantId
 * @param {string | Buffer | import('node:crypto').KeyObject} options.privateKey PEM/DER or KeyObject
 * @param {string | Buffer | X509Certificate} [options.certificate] used for the thumbprint headers
 * @param {{ sha1?: string, sha256: string }} [options.thumbprints] alternative to certificate
 * @param {'PS256' | 'RS256'} [options.algorithm] default PS256 (Microsoft's current recommendation)
 * @param {number} [options.lifetimeSeconds] default 300, keep it short
 * @param {() => number} [options.now] seconds since epoch
 * @param {string} [options.tokenEndpoint] override the audience (e.g. sovereign clouds)
 */
export function createClientAssertion(options) {
  const {
    clientId,
    tenantId,
    privateKey,
    certificate,
    thumbprints,
    algorithm = 'PS256',
    lifetimeSeconds = 300,
    now = () => Math.floor(Date.now() / 1000),
    tokenEndpoint,
  } = options;

  if (!clientId || !tenantId) throw new TypeError('clientId and tenantId are required');
  if (!privateKey) throw new TypeError('privateKey is required');
  if (!['PS256', 'RS256'].includes(algorithm)) throw new TypeError('algorithm must be PS256 or RS256');
  if (lifetimeSeconds > 600) throw new RangeError('assertion lifetime must be at most 10 minutes');

  const tp = certificate ? certificateThumbprints(certificate) : thumbprints;
  if (!tp || !tp.sha256) throw new TypeError('certificate or thumbprints.sha256 is required');

  const header = { alg: algorithm, typ: 'JWT', 'x5t#S256': tp.sha256 };
  if (tp.sha1) header.x5t = tp.sha1;

  const t = now();
  const payload = {
    aud: tokenEndpoint ?? `https://login.microsoftonline.com/${tenantId}/oauth2/v2.0/token`,
    iss: clientId,
    sub: clientId,
    jti: randomUUID(),
    nbf: t,
    iat: t,
    exp: t + lifetimeSeconds,
  };

  const signingInput = `${encodeJsonSegment(header)}.${encodeJsonSegment(payload)}`;
  const key = typeof privateKey === 'object' && 'type' in privateKey ? privateKey : createPrivateKey(privateKey);
  const signParams = algorithm === 'PS256'
    ? { key, padding: constants.RSA_PKCS1_PSS_PADDING, saltLength: constants.RSA_PSS_SALTLEN_DIGEST }
    : { key, padding: constants.RSA_PKCS1_PADDING };
  const signature = cryptoSign('sha256', Buffer.from(signingInput, 'ascii'), signParams);
  return `${signingInput}.${toBase64Url(signature)}`;
}

/**
 * Client-credentials token request authenticated with a certificate instead of
 * a secret. Declares CAE capability (cp1) by default so Graph can revoke tokens
 * in near-real time.
 *
 * @param {object} options
 * @param {string} options.clientId
 * @param {string} options.tenantId
 * @param {string} options.scope e.g. 'https://graph.microsoft.com/.default'
 * @param {string | Buffer | import('node:crypto').KeyObject} options.privateKey
 * @param {string | Buffer | X509Certificate} options.certificate
 * @param {typeof fetch} [options.fetch]
 * @param {boolean} [options.caeCapable] default true
 * @param {string} [options.claims] raw claims-request JSON from a claims challenge to replay
 * @param {string} [options.authority] default https://login.microsoftonline.com
 */
export async function acquireTokenWithCertificate(options) {
  const {
    clientId,
    tenantId,
    scope,
    privateKey,
    certificate,
    fetch = globalThis.fetch,
    caeCapable = true,
    claims,
    authority = 'https://login.microsoftonline.com',
  } = options;
  if (!scope) throw new TypeError('scope is required');

  const tokenEndpoint = `${authority}/${encodeURIComponent(tenantId)}/oauth2/v2.0/token`;
  const assertion = createClientAssertion({ clientId, tenantId, privateKey, certificate, tokenEndpoint });

  const body = new URLSearchParams({
    client_id: clientId,
    scope,
    grant_type: 'client_credentials',
    client_assertion_type: CLIENT_ASSERTION_TYPE,
    client_assertion: assertion,
  });
  if (claims) {
    body.set('claims', claims);
  } else if (caeCapable) {
    body.set('claims', JSON.stringify({ access_token: { xms_cc: { values: ['cp1'] } } }));
  }

  const res = await fetch(tokenEndpoint, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body,
  });
  const json = await res.json().catch(() => ({}));
  if (!res.ok) {
    const err = new Error(`token request failed: ${json.error ?? res.status} ${json.error_description ?? ''}`.trim());
    err.status = res.status;
    err.body = json;
    throw err;
  }
  return {
    accessToken: json.access_token,
    tokenType: json.token_type,
    expiresIn: json.expires_in,
    expiresOn: Math.floor(Date.now() / 1000) + Number(json.expires_in ?? 0),
  };
}
