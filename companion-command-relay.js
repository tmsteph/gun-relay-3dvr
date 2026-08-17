'use strict';

const crypto = require('crypto');

const DEVICE_ID_RE = /^[A-Za-z0-9_-]{22,86}$/;
const REQUEST_ID_RE = /^[A-Za-z0-9_-]{16,86}$/;
const ALLOWED_CAPABILITIES = new Set(['health', 'device.status']);
const MAX_COMMAND_TTL_MS = 60 * 1000;
const DEFAULT_COMMAND_TTL_MS = 15 * 1000;
const RESULT_TTL_MS = 2 * 60 * 1000;
const MAX_QUEUE_PER_DEVICE = 32;
const MAX_ARGUMENT_BYTES = 8 * 1024;
const MAX_RESULT_BYTES = 24 * 1024;

function tokenDigest(value) {
  return crypto.createHash('sha256').update(String(value)).digest();
}

function safeTokenEqual(left, right) {
  if (!left || !right) return false;
  return crypto.timingSafeEqual(tokenDigest(left), tokenDigest(right));
}

function readBearer(req) {
  const header = req.get('authorization') || '';
  const match = /^Bearer\s+([^\s]{32,256})$/.exec(header);
  return match ? match[1] : '';
}

function createCompanionCommandRelay(options = {}) {
  const {
    now = () => Date.now(),
    randomToken = (bytes = 18) => crypto.randomBytes(bytes).toString('base64url'),
    agentToken = process.env.COMPANION_AGENT_TOKEN || '',
    hasDevice,
    listDevices = () => [],
    authorizeDevice,
  } = options;

  if (typeof hasDevice !== 'function') throw new TypeError('hasDevice is required');
  if (typeof listDevices !== 'function') throw new TypeError('listDevices must be a function');
  if (typeof authorizeDevice !== 'function') throw new TypeError('authorizeDevice is required');

  const queues = new Map();
  const knownRequests = new Map();
  const results = new Map();

  function cleanup() {
    const t = now();
    for (const [deviceId, queue] of queues) {
      const live = queue.filter((command) => command.expiresAt > t);
      if (live.length) queues.set(deviceId, live);
      else queues.delete(deviceId);
    }
    for (const [requestId, record] of knownRequests) {
      if (record.expiresAt <= t) knownRequests.delete(requestId);
    }
    for (const [requestId, record] of results) {
      if (record.expiresAt <= t) results.delete(requestId);
    }
  }

  function authorizeAgent(req) {
    if (!agentToken) return { ok: false, status: 503, error: 'agent relay unavailable' };
    const supplied = readBearer(req);
    if (!supplied || !safeTokenEqual(supplied, agentToken)) {
      return { ok: false, status: 401, error: 'agent authorization required' };
    }
    return { ok: true };
  }

  function normalizeCommand(body = {}) {
    const deviceId = typeof body.deviceId === 'string' ? body.deviceId.trim() : '';
    const capabilityId = typeof body.capabilityId === 'string' ? body.capabilityId.trim() : '';
    const requestedId = typeof body.requestId === 'string' ? body.requestId.trim() : '';
    const requestId = requestedId || randomToken(18);
    const argumentsValue = body.arguments == null ? {} : body.arguments;

    if (!DEVICE_ID_RE.test(deviceId)) throw new Error('invalid device id');
    if (!REQUEST_ID_RE.test(requestId)) throw new Error('invalid request id');
    if (!ALLOWED_CAPABILITIES.has(capabilityId)) throw new Error('unsupported capability');
    if (!argumentsValue || typeof argumentsValue !== 'object' || Array.isArray(argumentsValue)) {
      throw new Error('arguments must be an object');
    }
    if (Buffer.byteLength(JSON.stringify(argumentsValue), 'utf8') > MAX_ARGUMENT_BYTES) {
      throw new Error('arguments too large');
    }

    const ttlRaw = Number(body.ttlMs);
    const ttlMs = Number.isFinite(ttlRaw)
      ? Math.min(MAX_COMMAND_TTL_MS, Math.max(1000, Math.round(ttlRaw)))
      : DEFAULT_COMMAND_TTL_MS;
    const createdAt = now();
    return {
      requestId,
      deviceId,
      capabilityId,
      arguments: argumentsValue,
      createdAt,
      expiresAt: createdAt + ttlMs,
    };
  }

  function enqueue(command) {
    cleanup();
    if (knownRequests.has(command.requestId)) throw new Error('duplicate request id');
    const queue = queues.get(command.deviceId) || [];
    if (queue.length >= MAX_QUEUE_PER_DEVICE) throw new Error('device queue full');
    queue.push(command);
    queues.set(command.deviceId, queue);
    knownRequests.set(command.requestId, {
      deviceId: command.deviceId,
      state: 'queued',
      expiresAt: command.expiresAt,
    });
  }

  function takeNext(deviceId) {
    cleanup();
    const queue = queues.get(deviceId) || [];
    while (queue.length) {
      const command = queue.shift();
      if (command.expiresAt <= now()) continue;
      if (queue.length) queues.set(deviceId, queue);
      else queues.delete(deviceId);
      knownRequests.set(command.requestId, {
        deviceId,
        state: 'inflight',
        expiresAt: command.expiresAt,
      });
      return command;
    }
    queues.delete(deviceId);
    return null;
  }

  function acceptResult(deviceId, body = {}) {
    cleanup();
    const requestId = typeof body.requestId === 'string' ? body.requestId.trim() : '';
    if (!REQUEST_ID_RE.test(requestId)) throw new Error('invalid request id');
    if (typeof body.ok !== 'boolean') throw new Error('ok must be boolean');
    const known = knownRequests.get(requestId);
    if (!known || known.deviceId !== deviceId || known.state !== 'inflight') {
      throw new Error('request is not inflight for this device');
    }
    const code = typeof body.code === 'string' ? body.code.slice(0, 120) : null;
    const data = body.data == null ? {} : body.data;
    if (!data || typeof data !== 'object' || Array.isArray(data)) {
      throw new Error('data must be an object');
    }
    if (Buffer.byteLength(JSON.stringify(data), 'utf8') > MAX_RESULT_BYTES) {
      throw new Error('result too large');
    }
    const completedAt = now();
    results.set(requestId, {
      response: {
        ok: true,
        requestId,
        commandOk: body.ok,
        code,
        data,
        completedAt,
      },
      expiresAt: completedAt + RESULT_TTL_MS,
    });
    knownRequests.set(requestId, {
      deviceId,
      state: 'completed',
      expiresAt: completedAt + RESULT_TTL_MS,
    });
  }

  function resultStatus(requestId) {
    cleanup();
    const result = results.get(requestId);
    if (result) {
      results.delete(requestId);
      knownRequests.delete(requestId);
      return { status: 200, body: result.response };
    }
    const known = knownRequests.get(requestId);
    if (known) {
      return { status: 202, body: { ok: true, requestId, state: known.state } };
    }
    return { status: 404, body: { ok: false, error: 'request not found' } };
  }

  function mount(app, { json, privateHeaders, allowRate }) {
    app.get('/relay/v1/devices', (req, res) => {
      privateHeaders(res);
      if (!allowRate(req, 'companion-agent-devices', 120, 60 * 1000)) {
        return res.status(429).json({ ok: false, error: 'rate limited' });
      }
      const auth = authorizeAgent(req);
      if (!auth.ok) return res.status(auth.status).json({ ok: false, error: auth.error });
      cleanup();
      return res.status(200).json({ ok: true, devices: listDevices() });
    });

    app.post('/relay/v1/commands', json, (req, res) => {
      privateHeaders(res);
      if (!allowRate(req, 'companion-agent-command', 120, 60 * 1000)) {
        return res.status(429).json({ ok: false, error: 'rate limited' });
      }
      const auth = authorizeAgent(req);
      if (!auth.ok) return res.status(auth.status).json({ ok: false, error: auth.error });

      try {
        const command = normalizeCommand(req.body || {});
        if (!hasDevice(command.deviceId)) {
          return res.status(404).json({ ok: false, error: 'device not available' });
        }
        enqueue(command);
        return res.status(201).json({
          ok: true,
          requestId: command.requestId,
          deviceId: command.deviceId,
          capabilityId: command.capabilityId,
          createdAt: command.createdAt,
          expiresAt: command.expiresAt,
        });
      } catch (error) {
        const message = error instanceof Error ? error.message : 'invalid command';
        const status = message === 'device queue full' ? 429 : 400;
        return res.status(status).json({ ok: false, error: message });
      }
    });

    app.get('/relay/v1/devices/:deviceId/commands/next', (req, res) => {
      privateHeaders(res);
      if (!allowRate(req, 'companion-device-poll', 600, 60 * 1000)) {
        return res.status(429).json({ ok: false, error: 'rate limited' });
      }
      const auth = authorizeDevice(req);
      if (!auth || auth.id !== req.params.deviceId) {
        return res.status(401).json({ ok: false, error: 'device authorization required' });
      }
      const command = takeNext(auth.id);
      return res.status(200).json({
        ok: true,
        command: command
          ? {
              requestId: command.requestId,
              capabilityId: command.capabilityId,
              arguments: command.arguments,
              issuedAt: command.createdAt,
              expiresAt: command.expiresAt,
            }
          : null,
      });
    });

    app.post('/relay/v1/devices/:deviceId/results', json, (req, res) => {
      privateHeaders(res);
      if (!allowRate(req, 'companion-device-result', 240, 60 * 1000)) {
        return res.status(429).json({ ok: false, error: 'rate limited' });
      }
      const auth = authorizeDevice(req);
      if (!auth || auth.id !== req.params.deviceId) {
        return res.status(401).json({ ok: false, error: 'device authorization required' });
      }
      try {
        acceptResult(auth.id, req.body || {});
        return res.status(202).json({ ok: true, requestId: req.body.requestId });
      } catch (error) {
        const message = error instanceof Error ? error.message : 'invalid result';
        return res.status(400).json({ ok: false, error: message });
      }
    });

    app.get('/relay/v1/results/:requestId', (req, res) => {
      privateHeaders(res);
      if (!allowRate(req, 'companion-agent-result', 240, 60 * 1000)) {
        return res.status(429).json({ ok: false, error: 'rate limited' });
      }
      const auth = authorizeAgent(req);
      if (!auth.ok) return res.status(auth.status).json({ ok: false, error: auth.error });
      if (!REQUEST_ID_RE.test(req.params.requestId || '')) {
        return res.status(404).json({ ok: false, error: 'request not found' });
      }
      const result = resultStatus(req.params.requestId);
      return res.status(result.status).json(result.body);
    });
  }

  return {
    mount,
    cleanup,
    normalizeCommand,
    enqueue,
    takeNext,
    acceptResult,
    resultStatus,
    authorizeAgent,
  };
}

module.exports = {
  ALLOWED_CAPABILITIES,
  createCompanionCommandRelay,
};
