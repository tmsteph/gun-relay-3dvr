'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('crypto');
const { createVercelOidcAuthorizer } = require('../vercel-oidc');

const ISSUER = 'https://oidc.vercel.com/3dvr';
const AUDIENCE = 'https://vercel.com/3dvr';
const SUBJECT = 'owner:3dvr:project:3dvr-portal:environment:production';
const NOW_MS = Date.UTC(2026, 7, 17, 18, 10, 0);
const NOW_SECONDS = Math.floor(NOW_MS / 1000);

function baseClaims(overrides = {}) {
  return {
    iss: ISSUER,
    aud: AUDIENCE,
    sub: SUBJECT,
    iat: NOW_SECONDS - 30,
    nbf: NOW_SECONDS - 30,
    exp: NOW_SECONDS + 600,
    owner: '3dvr',
    owner_id: 'team_KXuVUd00RMnDsjoqwdREcZ7J',
    project: '3dvr-portal',
    project_id: 'prj_V49UqQXH0kmkYcL0NZFBkklzsbuy',
    environment: 'production',
    ...overrides,
  };
}

function encode(value) {
  return Buffer.from(JSON.stringify(value), 'utf8').toString('base64url');
}

function signToken(privateKey, claims, kid = 'test-key') {
  const header = encode({ typ: 'JWT', alg: 'RS256', kid });
  const payload = encode(claims);
  const signingInput = `${header}.${payload}`;
  const signature = crypto.sign('RSA-SHA256', Buffer.from(signingInput, 'utf8'), privateKey).toString('base64url');
  return `${signingInput}.${signature}`;
}

function fixture() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
  const jwk = publicKey.export({ format: 'jwk' });
  Object.assign(jwk, { kid: 'test-key', use: 'sig', alg: 'RS256' });
  const calls = [];
  const fetchImpl = async (url) => {
    calls.push(String(url));
    if (String(url) === `${ISSUER}/.well-known/openid-configuration`) {
      return { ok: true, json: async () => ({ issuer: ISSUER, jwks_uri: `${ISSUER}/jwks` }) };
    }
    if (String(url) === `${ISSUER}/jwks`) {
      return { ok: true, json: async () => ({ keys: [jwk] }) };
    }
    return { ok: false, status: 404, json: async () => ({}) };
  };
  const authorizer = createVercelOidcAuthorizer({ fetchImpl, now: () => NOW_MS });
  return { authorizer, privateKey, calls };
}

test('accepts the exact production 3dvr-portal workload identity', async () => {
  const { authorizer, privateKey } = fixture();
  const identity = await authorizer.verify(signToken(privateKey, baseClaims()));
  assert.deepEqual(identity, {
    owner: '3dvr',
    project: '3dvr-portal',
    environment: 'production',
    subject: SUBJECT,
  });
});

test('rejects preview deployments even when signed by Vercel', async () => {
  const { authorizer, privateKey } = fixture();
  const token = signToken(privateKey, baseClaims({
    sub: 'owner:3dvr:project:3dvr-portal:environment:preview',
    environment: 'preview',
  }));
  await assert.rejects(() => authorizer.verify(token), /unexpected identity subject|unexpected identity environment/);
});

test('rejects another Vercel project', async () => {
  const { authorizer, privateKey } = fixture();
  const token = signToken(privateKey, baseClaims({
    sub: 'owner:3dvr:project:donovan-lighting:environment:production',
    project: 'donovan-lighting',
    project_id: 'prj_other',
  }));
  await assert.rejects(() => authorizer.verify(token), /unexpected identity subject|unexpected identity project/);
});

test('rejects a tampered token signature', async () => {
  const { authorizer, privateKey } = fixture();
  const token = signToken(privateKey, baseClaims());
  const parts = token.split('.');
  const tampered = `${parts[0]}.${encode(baseClaims({ environment: 'preview' }))}.${parts[2]}`;
  await assert.rejects(() => authorizer.verify(tampered), /invalid identity signature/);
});

test('rejects expired production tokens', async () => {
  const { authorizer, privateKey } = fixture();
  const token = signToken(privateKey, baseClaims({ exp: NOW_SECONDS - 120 }));
  await assert.rejects(() => authorizer.verify(token), /expired identity token/);
});

test('caches discovery and JWKS metadata across successful verifications', async () => {
  const { authorizer, privateKey, calls } = fixture();
  const token = signToken(privateKey, baseClaims());
  await authorizer.verify(token);
  await authorizer.verify(token);
  assert.equal(calls.filter((url) => url.includes('openid-configuration')).length, 1);
  assert.equal(calls.filter((url) => url.endsWith('/jwks')).length, 1);
});
