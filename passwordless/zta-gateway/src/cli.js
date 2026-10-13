#!/usr/bin/env node
import { decodeJwt } from './verify.js';
import { classifyAmr, evaluateAccess, isAppOnlyToken, usedCertificateClientAuth } from './policy.js';
import { parseClaimsChallenge } from './challenge.js';

/**
 * Offline helpers for debugging tokens during rollout. Nothing here verifies
 * a signature; it only tells you what Entra put in the token.
 *
 *   zta-token inspect <jwt> [--min-strength phishingResistant] [--auth-context c1]
 *   zta-token challenge '<WWW-Authenticate header>'
 */

function usage() {
  console.error('usage: zta-token inspect <jwt> [--min-strength <none|mfa|passwordless|phishingResistant>] [--auth-context <cN>]');
  console.error('       zta-token challenge "<WWW-Authenticate header value>"');
  process.exit(2);
}

const [, , command, ...rest] = process.argv;

if (command === 'inspect') {
  const token = rest.find((a) => !a.startsWith('--'));
  if (!token) usage();
  const opt = (name) => {
    const i = rest.indexOf(name);
    return i >= 0 ? rest[i + 1] : undefined;
  };
  const { header, payload } = decodeJwt(token);
  const decision = evaluateAccess(payload, {
    minimumStrength: opt('--min-strength') ?? 'phishingResistant',
    authContext: opt('--auth-context'),
  });
  const out = {
    warning: 'signature NOT verified; use verifyEntraToken for that',
    header,
    identity: {
      type: isAppOnlyToken(payload) ? 'app' : 'user',
      tenant: payload.tid,
      subject: payload.oid ?? payload.sub,
      upn: payload.preferred_username ?? payload.upn ?? null,
      client: payload.azp ?? payload.appid ?? null,
      clientAuth: usedCertificateClientAuth(payload) ? 'certificate' : (payload.azpacr ?? payload.appidacr ?? 'n/a'),
    },
    authentication: {
      amr: payload.amr ?? '(missing: request amr as an optional claim on the API app registration)',
      strength: classifyAmr(payload.amr),
      acrs: payload.acrs ?? null,
      caeCapable: Array.isArray(payload.xms_cc) && payload.xms_cc.includes('cp1'),
    },
    lifetime: {
      issuedAt: payload.iat ? new Date(payload.iat * 1000).toISOString() : null,
      expires: payload.exp ? new Date(payload.exp * 1000).toISOString() : null,
    },
    decision,
  };
  console.log(JSON.stringify(out, null, 2));
} else if (command === 'challenge') {
  const value = rest[0];
  if (!value) usage();
  console.log(JSON.stringify(parseClaimsChallenge(value), null, 2));
} else {
  usage();
}
