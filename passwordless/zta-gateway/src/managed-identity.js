import { readFile as fsReadFile } from 'node:fs/promises';

/**
 * Acquire a token from the platform-managed identity endpoint, so the workload
 * never holds a credential. Detects the environment from the variables Azure
 * injects:
 *   IDENTITY_ENDPOINT + IDENTITY_HEADER  -> App Service, Functions, Container Apps, ACI (Windows)
 *   IDENTITY_ENDPOINT only               -> Azure Arc-enabled server (challenge/response)
 *   neither                              -> Azure VM / VMSS / AKS via IMDS 169.254.169.254
 *
 * @param {object} options
 * @param {string} options.resource e.g. 'https://graph.microsoft.com' or 'https://vault.azure.net'
 * @param {string} [options.clientId] required when the host has several user-assigned identities
 * @param {NodeJS.ProcessEnv} [options.env]
 * @param {typeof fetch} [options.fetch]
 * @param {(path: string) => Promise<string>} [options.readFile] used for the Arc challenge file
 */
export async function acquireManagedIdentityToken(options) {
  const { resource, clientId, env = process.env, fetch = globalThis.fetch, readFile = (p) => fsReadFile(p, 'utf8') } = options;
  if (!resource) throw new TypeError('resource is required');

  if (env.IDENTITY_ENDPOINT && env.IDENTITY_HEADER) {
    const url = new URL(env.IDENTITY_ENDPOINT);
    url.searchParams.set('resource', resource);
    url.searchParams.set('api-version', '2019-08-01');
    if (clientId) url.searchParams.set('client_id', clientId);
    const res = await fetch(url, { headers: { 'X-IDENTITY-HEADER': env.IDENTITY_HEADER } });
    return finish(res, 'app-service');
  }

  if (env.IDENTITY_ENDPOINT) {
    const url = new URL(env.IDENTITY_ENDPOINT);
    url.searchParams.set('resource', resource);
    url.searchParams.set('api-version', '2020-06-01');
    if (clientId) url.searchParams.set('client_id', clientId);
    const first = await fetch(url, { headers: { Metadata: 'true' } });
    if (first.status !== 401) return finish(first, 'arc');
    const challenge = first.headers.get('www-authenticate') ?? '';
    const m = /Basic realm=(\S+)/i.exec(challenge);
    if (!m) throw new Error('Arc identity endpoint did not return a Basic realm challenge');
    const secret = (await readFile(m[1])).trim();
    const second = await fetch(url, { headers: { Metadata: 'true', Authorization: `Basic ${secret}` } });
    return finish(second, 'arc');
  }

  const url = new URL('http://169.254.169.254/metadata/identity/oauth2/token');
  url.searchParams.set('api-version', '2018-02-01');
  url.searchParams.set('resource', resource);
  if (clientId) url.searchParams.set('client_id', clientId);
  const res = await fetch(url, { headers: { Metadata: 'true' } });
  return finish(res, 'imds');
}

/**
 * @param {Response} res
 * @param {'app-service' | 'arc' | 'imds'} source
 */
async function finish(res, source) {
  const json = await res.json().catch(() => ({}));
  if (!res.ok || !json.access_token) {
    const err = new Error(`managed identity token request failed (${source}): HTTP ${res.status} ${json.error_description ?? json.error ?? ''}`.trim());
    err.status = res.status;
    err.body = json;
    throw err;
  }
  return {
    accessToken: json.access_token,
    expiresOn: Number(json.expires_on),
    resource: json.resource,
    clientId: json.client_id,
    source,
  };
}
