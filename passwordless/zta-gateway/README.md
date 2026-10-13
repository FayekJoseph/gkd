# zta-gateway

Zero-dependency (Node 22 built-ins only) building blocks for phishing-resistant, passwordless API access with Microsoft Entra ID. Every piece is exported from `src/index.js` and covered by `npm test` (38 tests, `node --test`).

| Module | What it does |
| --- | --- |
| `verify.js` | `verifyEntraToken(token, { tenantId, audience, keyStore })`: RS256 (PS256 opt-in) signature via JWKS, issuer (v1 and v2), audience, `exp`/`nbf` with skew, `tid`. Rejects `alg: none`, HS*, unknown `kid`, malformed input |
| `jwks.js` | `JwksKeyStore.forTenant(tenantId)`: caches the tenant's signing keys, refreshes on rotation with rate limiting. `StaticKeyStore` for tests/offline |
| `policy.js` | `evaluateAccess(claims, requirement)`: maps `amr` to `phishingResistant` (`fido`, `hwk`), `passwordless` (`swk`), `mfa`, `singleFactor`; requires `azpacr == 2` (certificate) for app-only tokens; checks `acrs` authentication context, `xms_cc` CAE capability and a client allow-list |
| `challenge.js` | `buildClaimsChallengeHeader({ authContext, tenantId })` produces the `WWW-Authenticate: Bearer ... error="insufficient_claims", claims="..."` header MSAL understands; `parseClaimsChallenge` for clients |
| `client-assertion.js` | `createClientAssertion` (PS256, `x5t#S256`, 5-minute lifetime) and `acquireTokenWithCertificate` for secretless client-credentials, CAE-capable by default |
| `managed-identity.js` | `acquireManagedIdentityToken({ resource })` for IMDS (VM/AKS), App Service/Functions/Container Apps and Azure Arc |
| `server.js` | Reference API: `/healthz`, `/api/me` (phishing-resistant user or certificate app), `/api/privileged` (needs `acrs c1`, else claims challenge) |
| `cli.js` | `node src/cli.js inspect <jwt>` shows identity type, `amr` strength, `acrs`, CAE and the policy decision without verifying the signature (debugging aid) |

## Run the reference API
```bash
export ZTA_TENANT_ID=<tenant guid>
export ZTA_AUDIENCE=api://<your-api-app-id-uri>     # comma-separate several
export ZTA_AUTH_CONTEXT_ID=c1                         # default
export ZTA_MIN_STRENGTH=phishingResistant             # none | mfa | passwordless | phishingResistant
export ZTA_REQUIRE_CAE=false
export ZTA_ALLOWED_CLIENT_IDS=<client id>,<client id> # optional
export ZTA_PORT=8080
node src/server.js
```
Put it behind a TLS terminator. The API app registration needs the optional claims `amr`, `acrs` and `xms_cc` on access tokens.

## Use it in your own API
```js
import { JwksKeyStore, verifyEntraToken, evaluateAccess, buildClaimsChallengeHeader } from './src/index.js';

const keyStore = JwksKeyStore.forTenant(process.env.ZTA_TENANT_ID);

async function guard(req, res, requirement) {
  const token = req.headers.authorization?.replace(/^Bearer\s+/i, '');
  const { claims } = await verifyEntraToken(token, { tenantId: process.env.ZTA_TENANT_ID, audience: 'api://my-api', keyStore });
  const decision = evaluateAccess(claims, requirement);
  if (decision.stepUpAuthContext) {
    res.writeHead(401, { 'www-authenticate': buildClaimsChallengeHeader({ authContext: decision.stepUpAuthContext, tenantId: process.env.ZTA_TENANT_ID, caeCapable: true }) }).end();
    return null;
  }
  if (!decision.allowed) { res.writeHead(403).end(JSON.stringify(decision.reasons)); return null; }
  return claims;
}
```

## Daemon without a secret
```js
import { readFileSync } from 'node:fs';
import { acquireTokenWithCertificate } from './src/index.js';

const { accessToken } = await acquireTokenWithCertificate({
  clientId: process.env.APP_ID,
  tenantId: process.env.TENANT_ID,
  scope: 'https://graph.microsoft.com/.default',
  privateKey: readFileSync('/etc/svc/key.pem'),      // or a KeyObject from a TPM/HSM provider
  certificate: readFileSync('/etc/svc/cert.pem'),
});
```
On Azure or an Arc-enabled server, replace the whole thing with `acquireManagedIdentityToken({ resource: 'https://graph.microsoft.com' })`.
