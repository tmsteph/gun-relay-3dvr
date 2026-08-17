const express = require('express');
const http = require('http');
const crypto = require('crypto');
const Gun = require('gun');
require('gun/axe');
const { createCompanionCommandRelay } = require('./companion-command-relay');

const app = express();
app.disable('x-powered-by');

const RELAY_TTL_MS = Math.min(5 * 60 * 1000, Math.max(30 * 1000, Number.parseInt(process.env.RELAY_TTL_MS || '120000', 10) || 120000));
const DEVICE_TTL_MS = Math.min(24 * 60 * 60 * 1000, Math.max(5 * 60 * 1000, Number.parseInt(process.env.RELAY_DEVICE_TTL_MS || '3600000', 10) || 3600000));
const MAX_ENVELOPES = 128;
const MAX_PAYLOAD_BYTES = 24 * 1024;
const REF_RE = /^[A-Za-z0-9_-]{22,86}$/;

const envelopes = new Map();
const devices = new Map();
const rateBuckets = new Map();

const { publicKey: relayPublicKey, privateKey: relayPrivateKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 3072, publicExponent: 0x10001 });
const relayPublicPem = relayPublicKey.export({ type: 'spki', format: 'pem' });
const relayKeyId = crypto.createHash('sha256').update(relayPublicKey.export({ type: 'spki', format: 'der' })).digest('hex').slice(0, 24);

function now() { return Date.now(); }
function randomToken(bytes = 32) { return crypto.randomBytes(bytes).toString('base64url'); }
function sha256(value) { return crypto.createHash('sha256').update(String(value)).digest(); }
function safeEqual(left, right) {
  if (!Buffer.isBuffer(left) || !Buffer.isBuffer(right) || left.length !== right.length) return false;
  return crypto.timingSafeEqual(left, right);
}
function privateHeaders(res) {
  res.setHeader('Cache-Control', 'no-store, max-age=0');
  res.setHeader('Pragma', 'no-cache');
  res.setHeader('X-Robots-Tag', 'noindex, nofollow, noarchive');
  res.setHeader('Referrer-Policy', 'no-referrer');
}
function clientIp(req) {
  const fly = req.get('fly-client-ip');
  if (fly) return fly;
  const forwarded = req.get('x-forwarded-for');
  if (forwarded) return forwarded.split(',')[0].trim();
  return req.socket?.remoteAddress || 'unknown';
}
function allowRate(req, namespace, limit, windowMs) {
  const key = `${namespace}:${clientIp(req)}`;
  const t = now();
  let bucket = rateBuckets.get(key);
  if (!bucket || bucket.resetAt <= t) { bucket = { count: 0, resetAt: t + windowMs }; rateBuckets.set(key, bucket); }
  bucket.count += 1;
  return bucket.count <= limit;
}
function cleanup() {
  const t = now();
  for (const [ref, item] of envelopes) if (item.expiresAt <= t) envelopes.delete(ref);
  for (const [id, item] of devices) if (item.expiresAt <= t) devices.delete(id);
  for (const [key, item] of rateBuckets) if (item.resetAt <= t) rateBuckets.delete(key);
}
const cleanupTimer = setInterval(cleanup, 30 * 1000); cleanupTimer.unref?.();
function createEnvelope(kind, payload, direction) {
  cleanup();
  if (envelopes.size >= MAX_ENVELOPES) {
    const oldest = [...envelopes.entries()].sort((a, b) => a[1].createdAt - b[1].createdAt)[0];
    if (oldest) envelopes.delete(oldest[0]);
  }
  const ref = randomToken(32); const createdAt = now(); const expiresAt = createdAt + RELAY_TTL_MS;
  envelopes.set(ref, { kind, payload, direction, createdAt, expiresAt });
  return { ref, createdAt, expiresAt };
}
function readBearer(req) {
  const header = req.get('authorization') || '';
  const match = /^Bearer\s+([A-Za-z0-9_-]{32,128})$/.exec(header);
  return match ? match[1] : '';
}
function authorizedDevice(req) {
  const id = req.get('x-3dvr-device') || ''; const token = readBearer(req);
  if (!REF_RE.test(id) || !token) return null;
  const record = devices.get(id);
  if (!record || record.expiresAt <= now()) { devices.delete(id); return null; }
  return safeEqual(record.tokenHash, sha256(token)) ? { id, record } : null;
}
function parseHybridEnvelope(encoded) {
  if (typeof encoded !== 'string' || encoded.length < 40 || encoded.length > 12000) throw new Error('invalid encrypted envelope');
  const outer = JSON.parse(Buffer.from(encoded, 'base64url').toString('utf8'));
  if (!outer || typeof outer !== 'object' || outer.v !== 1 || outer.kid !== relayKeyId) throw new Error('invalid encrypted envelope');
  const wrappedKey = Buffer.from(String(outer.k || ''), 'base64url'); const iv = Buffer.from(String(outer.iv || ''), 'base64url');
  const tag = Buffer.from(String(outer.tag || ''), 'base64url'); const ciphertext = Buffer.from(String(outer.ct || ''), 'base64url');
  if (wrappedKey.length < 256 || iv.length !== 12 || tag.length !== 16 || ciphertext.length < 1) throw new Error('invalid encrypted envelope');
  const aesKey = crypto.privateDecrypt({ key: relayPrivateKey, oaepHash: 'sha256', padding: crypto.constants.RSA_PKCS1_OAEP_PADDING }, wrappedKey);
  if (aesKey.length !== 32) throw new Error('invalid encrypted key');
  const decipher = crypto.createDecipheriv('aes-256-gcm', aesKey, iv); decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
}
function validateReplyEnvelope(value) {
  if (!value || typeof value !== 'object' || value.kind !== 'message.reply') return null;
  const payload = value.payload; if (!payload || typeof payload !== 'object') return null;
  const key = typeof payload.key === 'string' ? payload.key.trim() : ''; const text = typeof payload.text === 'string' ? payload.text : '';
  if (!key || !text.trim() || Buffer.byteLength(key, 'utf8') > 1024 || Buffer.byteLength(text, 'utf8') > 4000) return null;
  return { key, text };
}

const relayJson = express.json({ limit: '32kb', type: 'application/json' });
const companionCommands = createCompanionCommandRelay({
  hasDevice: (deviceId) => { cleanup(); return devices.has(deviceId); },
  listDevices: () => { cleanup(); return [...devices.entries()].map(([deviceId, record]) => ({ deviceId, expiresAt: record.expiresAt })); },
  authorizeDevice: authorizedDevice,
});
companionCommands.mount(app, { json: relayJson, privateHeaders, allowRate });

app.use(Gun.serve);
app.get('/', (_req, res) => res.status(200).send('OK'));
app.get('/relay/v1/health', (req, res) => {
  privateHeaders(res); cleanup();
  res.status(200).json({ ok: true, service: '3dvr-private-relay', storage: 'memory-only', oneTimeReads: true, ttlMs: RELAY_TTL_MS, keyId: relayKeyId, companionCommands: ['health', 'device.status'] });
});
app.get('/relay/v1/public-key', (req, res) => {
  privateHeaders(res); if (!allowRate(req, 'public-key', 60, 60 * 1000)) return res.status(429).json({ ok: false, error: 'rate limited' });
  return res.status(200).json({ ok: true, version: 1, keyId: relayKeyId, algorithm: 'RSA-OAEP-SHA256+A256GCM', publicKeyPem: relayPublicPem });
});
app.post('/relay/v1/devices', relayJson, (req, res) => {
  privateHeaders(res); if (!allowRate(req, 'device-bootstrap', 12, 60 * 60 * 1000)) return res.status(429).json({ ok: false, error: 'rate limited' });
  cleanup(); const id = randomToken(18); const token = randomToken(32); const expiresAt = now() + DEVICE_TTL_MS;
  devices.set(id, { tokenHash: sha256(token), expiresAt }); return res.status(201).json({ ok: true, deviceId: id, deviceToken: token, expiresAt });
});
app.post('/relay/v1/envelopes', relayJson, (req, res) => {
  privateHeaders(res); if (!allowRate(req, 'device-upload', 60, 60 * 1000)) return res.status(429).json({ ok: false, error: 'rate limited' });
  if (!authorizedDevice(req)) return res.status(401).json({ ok: false, error: 'device authorization required' });
  const body = req.body || {}; if (body.kind !== 'messages.snapshot' || !body.payload || typeof body.payload !== 'object') return res.status(400).json({ ok: false, error: 'unsupported envelope' });
  if (Buffer.byteLength(JSON.stringify(body.payload), 'utf8') > MAX_PAYLOAD_BYTES) return res.status(413).json({ ok: false, error: 'payload too large' });
  const envelope = createEnvelope('messages.snapshot', body.payload, 'device-to-agent'); return res.status(201).json({ ok: true, ...envelope });
});
app.get('/relay/v1/encrypted/:blob', (req, res) => {
  privateHeaders(res); if (!allowRate(req, 'encrypted-upload', 30, 60 * 1000)) return res.status(429).json({ ok: false, error: 'rate limited' });
  try {
    const plaintext = parseHybridEnvelope(req.params.blob); if (plaintext.length > 8 * 1024) return res.status(413).json({ ok: false, error: 'payload too large' });
    const payload = validateReplyEnvelope(JSON.parse(plaintext.toString('utf8'))); if (!payload) return res.status(400).json({ ok: false, error: 'unsupported envelope' });
    const envelope = createEnvelope('message.reply', payload, 'agent-to-device'); return res.status(201).json({ ok: true, ...envelope });
  } catch (_error) { return res.status(400).json({ ok: false, error: 'invalid encrypted envelope' }); }
});
app.get('/relay/v1/envelopes/:ref', (req, res) => {
  privateHeaders(res); if (!allowRate(req, 'envelope-read', 120, 60 * 1000)) return res.status(429).json({ ok: false, error: 'rate limited' });
  const ref = req.params.ref || ''; if (!REF_RE.test(ref)) return res.status(404).json({ ok: false, error: 'not found' });
  const envelope = envelopes.get(ref); envelopes.delete(ref); if (!envelope) return res.status(404).json({ ok: false, error: 'not found' });
  if (envelope.expiresAt <= now()) return res.status(410).json({ ok: false, error: 'expired' });
  return res.status(200).json({ ok: true, kind: envelope.kind, payload: envelope.payload, direction: envelope.direction, createdAt: envelope.createdAt, expiresAt: envelope.expiresAt, consumed: true });
});
app.use((req, res, next) => (req.path.startsWith('/gun') || req.path.startsWith('/relay/') ? next() : res.status(404).end()));

const server = http.createServer(app);
const gun = Gun({ web: server, radisk: true, file: 'data', axe: true });
const PORT = process.env.PORT || 8080;
server.listen(PORT, () => { console.log(`GUN relay listening on :${PORT}`); });
module.exports = { app, server, gun };
