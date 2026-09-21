/**
 * Build and parse the `WWW-Authenticate` headers used by the Microsoft identity
 * platform for claims challenges (Conditional Access authentication context and
 * Continuous Access Evaluation). Format per learn.microsoft.com/entra/identity-platform/claims-challenge.
 */

const COMMON_AUTHORIZE = 'https://login.microsoftonline.com/common/oauth2/authorize';

/** @param {string} value */
function quote(value) {
  return `"${String(value).replace(/["\\]/g, '')}"`;
}

/**
 * The JSON claims request a client must send back to Entra (minified).
 * @param {object} options
 * @param {string} options.authContext e.g. 'c1'
 * @param {boolean} [options.caeCapable] prepend xms_cc cp1 so the new token is CAE-enabled
 */
export function buildClaimsRequest({ authContext, caeCapable = false }) {
  if (!/^c[1-9][0-9]?$/.test(authContext)) {
    throw new TypeError('authContext must look like c1..c99');
  }
  const accessToken = {};
  if (caeCapable) accessToken.xms_cc = { values: ['cp1'] };
  accessToken.acrs = { essential: true, value: authContext };
  return { access_token: accessToken };
}

/**
 * 401 challenge telling the client which authentication context it must satisfy.
 * @param {object} options
 * @param {string} options.authContext
 * @param {string} [options.tenantId] when omitted the common endpoint is used and realm is empty
 * @param {boolean} [options.caeCapable]
 */
export function buildClaimsChallengeHeader({ authContext, tenantId, caeCapable = false }) {
  const claims = Buffer.from(JSON.stringify(buildClaimsRequest({ authContext, caeCapable })), 'utf8').toString('base64');
  const authorizationUri = tenantId
    ? `https://login.microsoftonline.com/${encodeURIComponent(tenantId)}/oauth2/v2.0/authorize`
    : COMMON_AUTHORIZE;
  const realm = tenantId ?? '';
  return `Bearer realm=${quote(realm)}, authorization_uri=${quote(authorizationUri)}, error="insufficient_claims", claims=${quote(claims)}`;
}

/**
 * Standard RFC 6750 rejection for a token that failed validation.
 * @param {string} code
 * @param {string} description
 */
export function buildInvalidTokenHeader(code, description) {
  return `Bearer error="invalid_token", error_description=${quote(`${code}: ${description}`)}`;
}

/**
 * Client-side helper: pull the claims request out of a 401 so it can be passed
 * to MSAL (`claims` parameter) or a raw /authorize request.
 * @param {string | null | undefined} headerValue
 */
export function parseClaimsChallenge(headerValue) {
  if (!headerValue || !/^Bearer\b/i.test(headerValue)) return null;
  const params = {};
  const re = /([a-zA-Z_]+)=(?:"([^"]*)"|([^,\s]+))/g;
  let m;
  while ((m = re.exec(headerValue)) !== null) {
    params[m[1]] = m[2] ?? m[3];
  }
  let claims = null;
  if (params.claims) {
    try {
      claims = JSON.parse(Buffer.from(params.claims, 'base64').toString('utf8'));
    } catch {
      claims = null;
    }
  }
  return { error: params.error ?? null, authorizationUri: params.authorization_uri ?? null, realm: params.realm ?? null, claims };
}
