import { createServer } from 'node:http';
import { buildClaimsChallengeHeader, buildInvalidTokenHeader } from './challenge.js';
import { TokenError } from './errors.js';
import { JwksKeyStore } from './jwks.js';
import { evaluateAccess, STRENGTH } from './policy.js';
import { verifyEntraToken } from './verify.js';

/**
 * Minimal resource server that shows the full pattern:
 *   GET /healthz          no auth
 *   GET /api/me           valid Entra token + minimum authentication strength
 *   GET /api/privileged   additionally requires the Conditional Access authentication
 *                         context (default c1); otherwise answers 401 with a claims challenge
 *
 * Run it behind a TLS terminator (Front Door, App Gateway, nginx, Cloudflare); it
 * speaks plain HTTP on purpose so certificates stay out of the process.
 */

/** @param {NodeJS.ProcessEnv} env */
export function loadConfigFromEnv(env = process.env) {
  const tenantId = env.ZTA_TENANT_ID;
  const audience = env.ZTA_AUDIENCE;
  if (!tenantId) throw new Error('ZTA_TENANT_ID is required');
  if (!audience) throw new Error('ZTA_AUDIENCE is required (client id or api:// URI of this API)');
  const minimumStrength = env.ZTA_MIN_STRENGTH ?? STRENGTH.PHISHING_RESISTANT;
  if (!Object.values(STRENGTH).includes(minimumStrength)) {
    throw new Error(`ZTA_MIN_STRENGTH must be one of ${Object.values(STRENGTH).join(', ')}`);
  }
  return {
    tenantId,
    audience: audience.split(',').map((s) => s.trim()).filter(Boolean),
    minimumStrength,
    privilegedAuthContext: env.ZTA_AUTH_CONTEXT_ID ?? 'c1',
    requireCaeCapable: env.ZTA_REQUIRE_CAE === 'true',
    allowedClientIds: env.ZTA_ALLOWED_CLIENT_IDS ? env.ZTA_ALLOWED_CLIENT_IDS.split(',').map((s) => s.trim()).filter(Boolean) : undefined,
    port: Number(env.ZTA_PORT ?? 8080),
    host: env.ZTA_HOST ?? '127.0.0.1',
    jwksUri: env.ZTA_JWKS_URI,
  };
}

/** @param {import('node:http').ServerResponse} res */
function sendJson(res, status, body, headers = {}) {
  res.writeHead(status, {
    'content-type': 'application/json; charset=utf-8',
    'cache-control': 'no-store',
    'x-content-type-options': 'nosniff',
    ...headers,
  });
  res.end(JSON.stringify(body));
}

/** @param {string | undefined} header */
function extractBearer(header) {
  if (!header) return null;
  const m = /^Bearer\s+([A-Za-z0-9\-_.]+)\s*$/i.exec(header);
  return m ? m[1] : null;
}

/**
 * @param {object} deps
 * @param {ReturnType<typeof loadConfigFromEnv>} deps.config
 * @param {{ getKey(kid: string): Promise<import('node:crypto').KeyObject | null> }} deps.keyStore
 * @param {Pick<Console, 'info' | 'warn'>} [deps.logger]
 * @param {() => number} [deps.now]
 */
export function createRequestHandler({ config, keyStore, logger = console, now }) {
  const baseRequirement = {
    minimumStrength: config.minimumStrength,
    requireCaeCapable: config.requireCaeCapable,
    allowedClientIds: config.allowedClientIds,
  };

  /**
   * @param {import('node:http').IncomingMessage} req
   * @param {import('node:http').ServerResponse} res
   * @param {import('./policy.js').Requirement} requirement
   */
  async function authorize(req, res, requirement) {
    const token = extractBearer(req.headers.authorization);
    if (!token) {
      sendJson(res, 401, { error: 'unauthorized', error_description: 'bearer token required' }, { 'www-authenticate': 'Bearer' });
      return null;
    }
    let verified;
    try {
      verified = await verifyEntraToken(token, { tenantId: config.tenantId, audience: config.audience, keyStore, now });
    } catch (err) {
      if (err instanceof TokenError) {
        logger.warn(`token rejected: ${err.code}`);
        sendJson(res, 401, { error: 'invalid_token', error_code: err.code }, { 'www-authenticate': buildInvalidTokenHeader(err.code, err.message) });
        return null;
      }
      logger.warn(`token verification error: ${err.message}`);
      sendJson(res, 503, { error: 'verification_unavailable' });
      return null;
    }

    const decision = evaluateAccess(verified.claims, requirement);
    if (decision.allowed) return verified.claims;

    if (decision.stepUpAuthContext && decision.reasons.every((r) => r === 'auth_context_missing')) {
      sendJson(res, 401, { error: 'insufficient_claims', auth_context: decision.stepUpAuthContext }, {
        'www-authenticate': buildClaimsChallengeHeader({ authContext: decision.stepUpAuthContext, tenantId: config.tenantId, caeCapable: true }),
      });
      return null;
    }

    logger.warn(`access denied: ${decision.reasons.join(',')}`);
    sendJson(res, 403, { error: 'insufficient_authentication_strength', reasons: decision.reasons, strength: decision.strength });
    return null;
  }

  return async function handler(req, res) {
    const url = new URL(req.url ?? '/', 'http://localhost');
    if (req.method !== 'GET') {
      sendJson(res, 405, { error: 'method_not_allowed' }, { allow: 'GET' });
      return;
    }
    switch (url.pathname) {
      case '/healthz':
        sendJson(res, 200, { status: 'ok' });
        return;
      case '/api/me': {
        const claims = await authorize(req, res, baseRequirement);
        if (!claims) return;
        sendJson(res, 200, {
          subject: claims.oid ?? claims.sub,
          name: claims.name ?? null,
          upn: claims.preferred_username ?? claims.upn ?? null,
          app: claims.azp ?? claims.appid ?? null,
          amr: claims.amr ?? null,
          acrs: claims.acrs ?? null,
          cae: Array.isArray(claims.xms_cc) ? claims.xms_cc : null,
        });
        return;
      }
      case '/api/privileged': {
        const claims = await authorize(req, res, { ...baseRequirement, minimumStrength: STRENGTH.PHISHING_RESISTANT, authContext: config.privilegedAuthContext });
        if (!claims) return;
        sendJson(res, 200, { ok: true, subject: claims.oid ?? claims.sub, satisfied_auth_context: config.privilegedAuthContext });
        return;
      }
      default:
        sendJson(res, 404, { error: 'not_found' });
    }
  };
}

/**
 * @param {object} [options]
 * @param {ReturnType<typeof loadConfigFromEnv>} [options.config]
 * @param {{ getKey(kid: string): Promise<import('node:crypto').KeyObject | null> }} [options.keyStore]
 */
export function startServer(options = {}) {
  const config = options.config ?? loadConfigFromEnv();
  const keyStore = options.keyStore ?? (config.jwksUri ? new JwksKeyStore({ jwksUri: config.jwksUri }) : JwksKeyStore.forTenant(config.tenantId));
  const handler = createRequestHandler({ config, keyStore, logger: options.logger });
  const server = createServer((req, res) => {
    handler(req, res).catch((err) => {
      (options.logger ?? console).warn(`unhandled error: ${err.message}`);
      if (!res.headersSent) sendJson(res, 500, { error: 'internal_error' });
    });
  });
  return new Promise((resolve) => {
    server.listen(config.port, config.host, () => resolve(server));
  });
}

if (process.argv[1] && import.meta.url === new URL(`file://${process.argv[1]}`).href) {
  startServer().then((server) => {
    const addr = server.address();
    console.info(`zta-gateway listening on ${typeof addr === 'string' ? addr : `${addr.address}:${addr.port}`}`);
  }).catch((err) => {
    console.error(err.message);
    process.exit(1);
  });
}
