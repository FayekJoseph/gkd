/**
 * Authentication-strength policy evaluated on top of a verified token.
 *
 * `amr` values are documented in the Entra optional-claims reference:
 *   fido  -> passkey / FIDO2 security key           (phishing-resistant)
 *   hwk   -> Windows Hello for Business, MF CBA     (phishing-resistant)
 *   swk   -> Authenticator phone sign-in            (passwordless, not phishing-resistant)
 *   mfa   -> some second factor completed
 *   pwd   -> password (or app client secret)
 *   x509  -> single-factor CBA or device cert       (NOT phishing-resistant on its own)
 *
 * `amr` is only emitted in v2.0 access tokens when the API app registration
 * requests it as an optional claim, so a missing claim fails closed.
 * `acrs` carries Conditional Access authentication-context IDs (c1..c99).
 * `azpacr` / `appidacr` is '2' when an app authenticated with a certificate.
 */

export const STRENGTH = Object.freeze({
  NONE: 'none',
  MFA: 'mfa',
  PASSWORDLESS: 'passwordless',
  PHISHING_RESISTANT: 'phishingResistant',
});

const RANK = Object.freeze({
  unknown: -1,
  singleFactor: 0,
  [STRENGTH.MFA]: 1,
  [STRENGTH.PASSWORDLESS]: 2,
  [STRENGTH.PHISHING_RESISTANT]: 3,
});

const REQUIRED_RANK = Object.freeze({
  [STRENGTH.NONE]: 0,
  [STRENGTH.MFA]: 1,
  [STRENGTH.PASSWORDLESS]: 2,
  [STRENGTH.PHISHING_RESISTANT]: 3,
});

export const PHISHING_RESISTANT_AMR = Object.freeze(['fido', 'hwk']);
export const PASSWORDLESS_AMR = Object.freeze(['swk']);

/**
 * Classify how the subject authenticated.
 * @param {unknown} amr
 * @returns {'phishingResistant' | 'passwordless' | 'mfa' | 'singleFactor' | 'unknown'}
 */
export function classifyAmr(amr) {
  if (!Array.isArray(amr) || amr.some((v) => typeof v !== 'string')) return 'unknown';
  if (amr.some((v) => PHISHING_RESISTANT_AMR.includes(v))) return STRENGTH.PHISHING_RESISTANT;
  if (amr.some((v) => PASSWORDLESS_AMR.includes(v))) return STRENGTH.PASSWORDLESS;
  if (amr.includes('mfa') || amr.includes('multipleauthn')) return STRENGTH.MFA;
  return 'singleFactor';
}

/** @param {Record<string, unknown>} claims */
export function isAppOnlyToken(claims) {
  if (claims.idtyp === 'app') return true;
  if (claims.idtyp === 'user') return false;
  return claims.scp === undefined && Array.isArray(claims.roles);
}

/** @param {Record<string, unknown>} claims */
export function usedCertificateClientAuth(claims) {
  return claims.azpacr === '2' || claims.appidacr === '2';
}

/**
 * @typedef {object} Requirement
 * @property {'none'|'mfa'|'passwordless'|'phishingResistant'} [minimumStrength] default phishingResistant
 * @property {string} [authContext] Conditional Access authentication context id (e.g. 'c1') the token must carry
 * @property {boolean} [allowUsers] default true
 * @property {boolean} [allowAppOnly] default true
 * @property {boolean} [requireCertificateForApps] default true: app-only tokens must come from certificate auth
 * @property {boolean} [requireCaeCapable] default false: client must have declared xms_cc cp1
 * @property {string[]} [allowedClientIds] if set, azp/appid must be in this list
 */

/**
 * @param {Record<string, unknown>} claims verified claims
 * @param {Requirement} [requirement]
 */
export function evaluateAccess(claims, requirement = {}) {
  const req = {
    minimumStrength: STRENGTH.PHISHING_RESISTANT,
    authContext: undefined,
    allowUsers: true,
    allowAppOnly: true,
    requireCertificateForApps: true,
    requireCaeCapable: false,
    allowedClientIds: undefined,
    ...requirement,
  };
  if (!(req.minimumStrength in REQUIRED_RANK)) {
    throw new TypeError(`unknown minimumStrength ${req.minimumStrength}`);
  }

  /** @type {string[]} */
  const reasons = [];
  const isApp = isAppOnlyToken(claims);
  let strength = 'n/a';

  if (isApp) {
    if (!req.allowAppOnly) reasons.push('app_only_not_allowed');
    if (req.requireCertificateForApps && !usedCertificateClientAuth(claims)) {
      reasons.push('app_client_auth_not_certificate');
    }
  } else {
    if (!req.allowUsers) reasons.push('user_tokens_not_allowed');
    strength = classifyAmr(claims.amr);
    if (RANK[strength] < REQUIRED_RANK[req.minimumStrength]) {
      reasons.push(`strength_insufficient:${strength}`);
    }
  }

  const clientId = typeof claims.azp === 'string' ? claims.azp : claims.appid;
  if (Array.isArray(req.allowedClientIds) && !req.allowedClientIds.includes(clientId)) {
    reasons.push('client_not_allowed');
  }

  let stepUpAuthContext;
  if (req.authContext) {
    const acrs = claims.acrs;
    if (!Array.isArray(acrs) || !acrs.includes(req.authContext)) {
      reasons.push('auth_context_missing');
      stepUpAuthContext = req.authContext;
    }
  }

  if (req.requireCaeCapable) {
    const cc = claims.xms_cc;
    if (!Array.isArray(cc) || !cc.map((v) => String(v).toLowerCase()).includes('cp1')) {
      reasons.push('client_not_cae_capable');
    }
  }

  return { allowed: reasons.length === 0, reasons, isApp, strength, stepUpAuthContext };
}
