import { createPublicKey } from 'node:crypto';

/**
 * Key stores resolve a JWT `kid` header to a Node KeyObject.
 * Both implementations expose `getKey(kid): Promise<KeyObject | null>`.
 */

/** In-memory key store, mainly for tests and air-gapped verification. */
export class StaticKeyStore {
  /** @param {Record<string, import('node:crypto').KeyObject>} keysByKid */
  constructor(keysByKid) {
    this.keys = new Map(Object.entries(keysByKid));
  }

  /** @param {string} kid */
  async getKey(kid) {
    return this.keys.get(kid) ?? null;
  }
}

/**
 * Fetches and caches the tenant's signing keys from the OIDC JWKS endpoint.
 * Keys rotate roughly every six weeks; on an unknown `kid` the store refreshes
 * once, rate-limited so a flood of bogus tokens cannot hammer the endpoint.
 */
export class JwksKeyStore {
  /**
   * @param {object} options
   * @param {string} options.jwksUri
   * @param {typeof fetch} [options.fetch]
   * @param {number} [options.ttlMs] cache lifetime, default 6 hours
   * @param {number} [options.minRefreshIntervalMs] floor between refreshes on kid miss, default 60 s
   * @param {() => number} [options.now]
   */
  constructor({ jwksUri, fetch = globalThis.fetch, ttlMs = 6 * 60 * 60 * 1000, minRefreshIntervalMs = 60_000, now = Date.now }) {
    if (!jwksUri || !/^https:\/\//.test(jwksUri)) {
      throw new TypeError('jwksUri must be an https URL');
    }
    this.jwksUri = jwksUri;
    this.fetch = fetch;
    this.ttlMs = ttlMs;
    this.minRefreshIntervalMs = minRefreshIntervalMs;
    this.now = now;
    /** @type {Map<string, import('node:crypto').KeyObject>} */
    this.keys = new Map();
    this.fetchedAt = 0;
    this.lastRefreshAttempt = 0;
    /** @type {Promise<void> | null} */
    this.inflight = null;
  }

  /** @param {string} tenantId */
  static forTenant(tenantId, options = {}) {
    return new JwksKeyStore({
      jwksUri: `https://login.microsoftonline.com/${encodeURIComponent(tenantId)}/discovery/v2.0/keys`,
      ...options,
    });
  }

  /** @param {string} kid */
  async getKey(kid) {
    const stale = this.now() - this.fetchedAt > this.ttlMs;
    if (this.keys.size === 0 || stale) {
      await this.refresh();
    }
    if (!this.keys.has(kid) && this.now() - this.lastRefreshAttempt >= this.minRefreshIntervalMs) {
      await this.refresh();
    }
    return this.keys.get(kid) ?? null;
  }

  async refresh() {
    if (this.inflight) return this.inflight;
    this.lastRefreshAttempt = this.now();
    this.inflight = (async () => {
      const res = await this.fetch(this.jwksUri, { headers: { accept: 'application/json' } });
      if (!res.ok) {
        throw new Error(`JWKS fetch failed: HTTP ${res.status}`);
      }
      const body = await res.json();
      const next = new Map();
      for (const jwk of body.keys ?? []) {
        if (jwk.kty !== 'RSA' || typeof jwk.kid !== 'string') continue;
        if (jwk.use && jwk.use !== 'sig') continue;
        try {
          next.set(jwk.kid, createPublicKey({ key: { kty: 'RSA', n: jwk.n, e: jwk.e }, format: 'jwk' }));
        } catch {
          // Skip malformed entries rather than failing the whole set.
        }
      }
      if (next.size === 0) {
        throw new Error('JWKS document contained no usable RSA signing keys');
      }
      this.keys = next;
      this.fetchedAt = this.now();
    })();
    try {
      await this.inflight;
    } finally {
      this.inflight = null;
    }
  }
}
