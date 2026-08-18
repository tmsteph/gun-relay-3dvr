'use strict';

const crypto = require('crypto');

const MAX_TOKEN_BYTES = 16 * 1024;
const DEFAULT_CACHE_MS = 10 * 60 * 1000;
const CLOCK_TOLERANCE_SECONDS = 60;

function decodeBase64UrlJson(value) {
  const decoded = Buffer.from(value, 'base64url').toString('utf8');
  return JSON.parse(decoded);
}

function audienceMatches(value, expected) {
  if (typeof value === 'string') return value === expected;
  return Array.isArray(value) && value.includes(expected);
}

function createVercelOidcAuthorizer(options = {}) {
  const {
    issuer = 'https://oidc.vercel.com/tmstephs-projects',
    audience = 'https://vercel.com/tmstephs-projects',
    subject = 'owner:tmstephs-projects:project:3dvr-portal:environment:production',
    owner = 'tmstephs-projects',
    ownerId = 'team_xxJGO7S7h1ZP4BHidYV0CX9Z',
    project = '3dvr-portal',
    projectId = 'prj_rAhxzdSdrK9MwKjUMeAXGxk8z8Ch',
    environment = 'production',
    fetchImpl = globalThis.fetch,
    now = () => Date.now(),
    cacheMs = DEFAULT_CACHE_MS,
  } = options;

  if (typeof fetchImpl !== 'function') throw new TypeError('fetch implementation is required');

  let discoveryCache = null;
  let jwksCache = null;

  async function fetchJson(url) {
    const response = await fetchImpl(url, {
      headers: { accept: 'application/json' },
      signal: AbortSignal.timeout(5000),
    });
    if (!response.ok) throw new Error(`identity metadata HTTP ${response.status}`);
    return response.json();
  }

  async function discovery(force = false) {
    const t = now();
    if (!force && discoveryCache && discoveryCache.expiresAt > t) return discoveryCache.value;
    const value = await fetchJson(`${issuer}/.well-known/openid-configuration`);
    if (!value || value.issuer !== issuer || typeof value.jwks_uri !== 'string') {
      throw new Error('invalid identity metadata');
    }
    discoveryCache = { value, expiresAt: t + cacheMs };
    return value;
  }

  async function jwks(force = false) {
    const t = now();
    if (!force && jwksCache && jwksCache.expiresAt > t) return jwksCache.value;
    const metadata = await discovery(force);
    const value = await fetchJson(metadata.jwks_uri);
    if (!value || !Array.isArray(value.keys)) throw new Error('invalid identity keys');
    jwksCache = { value, expiresAt: t + cacheMs };
    return value;
  }

  async function signingKey(kid) {
    let keys = await jwks(false);
    let jwk = keys.keys.find((key) => key && key.kid === kid);
    if (!jwk) {
      keys = await jwks(true);
      jwk = keys.keys.find((key) => key && key.kid === kid);
    }
    if (!jwk || jwk.kty !== 'RSA' || (jwk.use && jwk.use !== 'sig') || (jwk.alg && jwk.alg !== 'RS256')) {
      throw new Error('identity signing key unavailable');
    }
    return crypto.createPublicKey({ key: jwk, format: 'jwk' });
  }

  async function verify(token) {
    if (typeof token !== 'string' || token.length < 64 || Buffer.byteLength(token, 'utf8') > MAX_TOKEN_BYTES) {
      throw new Error('invalid identity token');
    }
    const parts = token.split('.');
    if (parts.length !== 3 || parts.some((part) => !part)) throw new Error('invalid identity token');

    let header;
    let claims;
    try {
      header = decodeBase64UrlJson(parts[0]);
      claims = decodeBase64UrlJson(parts[1]);
    } catch (_error) {
      throw new Error('invalid identity token');
    }
    if (!header || header.typ !== 'JWT' || header.alg !== 'RS256' || typeof header.kid !== 'string') {
      throw new Error('unsupported identity token');
    }

    const key = await signingKey(header.kid);
    const verified = crypto.verify(
      'RSA-SHA256',
      Buffer.from(`${parts[0]}.${parts[1]}`, 'utf8'),
      key,
      Buffer.from(parts[2], 'base64url'),
    );
    if (!verified) throw new Error('invalid identity signature');

    const seconds = Math.floor(now() / 1000);
    if (claims.iss !== issuer) throw new Error('unexpected identity issuer');
    if (!audienceMatches(claims.aud, audience)) throw new Error('unexpected identity audience');
    if (claims.sub !== subject) throw new Error('unexpected identity subject');
    if (claims.owner !== owner || claims.owner_id !== ownerId) throw new Error('unexpected identity owner');
    if (claims.project !== project || claims.project_id !== projectId) throw new Error('unexpected identity project');
    if (claims.environment !== environment) throw new Error('unexpected identity environment');
    if (!Number.isFinite(claims.exp) || claims.exp < seconds - CLOCK_TOLERANCE_SECONDS) {
      throw new Error('expired identity token');
    }
    if (Number.isFinite(claims.nbf) && claims.nbf > seconds + CLOCK_TOLERANCE_SECONDS) {
      throw new Error('identity token not active');
    }
    if (Number.isFinite(claims.iat) && claims.iat > seconds + CLOCK_TOLERANCE_SECONDS) {
      throw new Error('identity token issued in the future');
    }

    return {
      owner: claims.owner,
      project: claims.project,
      environment: claims.environment,
      subject: claims.sub,
    };
  }

  async function authorizeRequest(req) {
    const header = req.get('authorization') || '';
    const match = /^Bearer\s+([^\s]+)$/.exec(header);
    if (!match) throw new Error('missing workload identity');
    return verify(match[1]);
  }

  return { verify, authorizeRequest };
}

module.exports = { createVercelOidcAuthorizer };
