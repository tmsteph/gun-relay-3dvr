'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { createCompanionCommandRelay } = require('../companion-command-relay');

function createRelay({ agentToken = 'agent-token-abcdefghijklmnopqrstuvwxyz123456', start = 1_000_000 } = {}) {
  let clock = start;
  const devices = new Set(['device_abcdefghijklmnopqrstuv', 'device_zyxwvutsrqponmlkjihgfe']);
  const relay = createCompanionCommandRelay({
    now: () => clock,
    randomToken: () => 'request_abcdefghijklmnopqrstuv',
    agentToken,
    hasDevice: (deviceId) => devices.has(deviceId),
    authorizeDevice: () => null,
  });
  return {
    relay,
    devices,
    advance(milliseconds) { clock += milliseconds; },
  };
}

function fakeRequest(authorization) {
  return {
    get(name) { return name.toLowerCase() === 'authorization' ? authorization || '' : ''; },
  };
}

test('agent API is unavailable without a configured agent token', () => {
  const { relay } = createRelay({ agentToken: '' });
  assert.deepEqual(relay.authorizeAgent(fakeRequest()), { ok: false, status: 503, error: 'agent relay unavailable' });
});

test('agent API rejects an incorrect bearer token', () => {
  const { relay } = createRelay();
  assert.deepEqual(relay.authorizeAgent(fakeRequest('Bearer wrong-token-wrong-token-wrong-token-wrong-token')), { ok: false, status: 401, error: 'agent authorization required' });
});

test('agent API accepts the configured bearer token', () => {
  const token = 'agent-token-abcdefghijklmnopqrstuvwxyz123456';
  const { relay } = createRelay({ agentToken: token });
  assert.deepEqual(relay.authorizeAgent(fakeRequest(`Bearer ${token}`)), { ok: true });
});

test('high-risk capabilities remain blocked', () => {
  const { relay } = createRelay();
  assert.throws(() => relay.normalizeCommand({
    deviceId: 'device_abcdefghijklmnopqrstuv',
    requestId: 'request_abcdefghijklmnopqrstuv',
    capabilityId: 'ui.perform',
  }), /unsupported capability/);
});

test('known app opening is admitted only for the bounded alias list', () => {
  const { relay } = createRelay();
  const command = relay.normalizeCommand({
    deviceId: 'device_abcdefghijklmnopqrstuv',
    requestId: 'request_abcdefghijklmnopqrstuv',
    capabilityId: 'app.open_known',
    arguments: { alias: 'maps' },
  });
  assert.deepEqual(command.arguments, { alias: 'maps' });

  assert.throws(() => relay.normalizeCommand({
    deviceId: 'device_abcdefghijklmnopqrstuv',
    requestId: 'request_zyxwvutsrqponmlkjihgfe',
    capabilityId: 'app.open_known',
    arguments: { alias: 'termux' },
  }), /unsupported app alias/);
});

test('remote URL opening requires clean HTTPS', () => {
  const { relay } = createRelay();
  const command = relay.normalizeCommand({
    deviceId: 'device_abcdefghijklmnopqrstuv',
    requestId: 'request_abcdefghijklmnopqrstuv',
    capabilityId: 'url.open',
    arguments: { url: 'https://example.com/path' },
  });
  assert.equal(command.arguments.url, 'https://example.com/path');

  for (const url of ['http://example.com', 'https://user:pass@example.com/', 'not-a-url']) {
    assert.throws(() => relay.normalizeCommand({
      deviceId: 'device_abcdefghijklmnopqrstuv',
      requestId: `request_${Buffer.from(url).toString('hex').slice(0, 22).padEnd(22, 'a')}`,
      capabilityId: 'url.open',
      arguments: { url },
    }), /valid https url required/);
  }
});

test('voice authorization requires a bounded opaque nonce', () => {
  const { relay } = createRelay();
  const nonce = 'voice_nonce_abcdefghijklmnopqrstuv';
  const command = relay.normalizeCommand({
    deviceId: 'device_abcdefghijklmnopqrstuv',
    requestId: 'request_voiceabcdefghijklmnop',
    capabilityId: 'voice.authorize',
    arguments: { nonce },
    ttlMs: 10_000,
  });
  assert.deepEqual(command.arguments, { nonce });

  for (const invalid of ['', 'short', 'contains spaces contains spaces']) {
    assert.throws(() => relay.normalizeCommand({
      deviceId: 'device_abcdefghijklmnopqrstuv',
      requestId: 'request_voiceinvalidabcdefgh',
      capabilityId: 'voice.authorize',
      arguments: { nonce: invalid },
    }), /invalid voice nonce/);
  }
});

test('read-only capabilities reject unexpected arguments', () => {
  const { relay } = createRelay();
  assert.throws(() => relay.normalizeCommand({
    deviceId: 'device_abcdefghijklmnopqrstuv',
    requestId: 'request_abcdefghijklmnopqrstuv',
    capabilityId: 'device.status',
    arguments: { surprise: true },
  }), /does not accept arguments/);
});

test('command moves from queue to inflight to one-time result', () => {
  const { relay } = createRelay();
  const command = relay.normalizeCommand({
    deviceId: 'device_abcdefghijklmnopqrstuv',
    requestId: 'request_abcdefghijklmnopqrstuv',
    capabilityId: 'device.status',
    arguments: {},
    ttlMs: 10_000,
  });

  relay.enqueue(command);
  const delivered = relay.takeNext(command.deviceId);
  assert.equal(delivered.requestId, command.requestId);
  assert.equal(delivered.capabilityId, 'device.status');
  assert.deepEqual(relay.resultStatus(command.requestId), { status: 202, body: { ok: true, requestId: command.requestId, state: 'inflight' } });

  relay.acceptResult(command.deviceId, { requestId: command.requestId, ok: true, data: { batteryPercent: 67 } });
  const completed = relay.resultStatus(command.requestId);
  assert.equal(completed.status, 200);
  assert.equal(completed.body.ok, true);
  assert.equal(completed.body.commandOk, true);
  assert.deepEqual(completed.body.data, { batteryPercent: 67 });
  assert.deepEqual(relay.resultStatus(command.requestId), { status: 404, body: { ok: false, error: 'request not found' } });
});

test('duplicate request ids are rejected', () => {
  const { relay } = createRelay();
  const command = relay.normalizeCommand({
    deviceId: 'device_abcdefghijklmnopqrstuv',
    requestId: 'request_abcdefghijklmnopqrstuv',
    capabilityId: 'health',
  });
  relay.enqueue(command);
  assert.throws(() => relay.enqueue(command), /duplicate request id/);
});

test('expired queued commands are never delivered', () => {
  const context = createRelay();
  const command = context.relay.normalizeCommand({
    deviceId: 'device_abcdefghijklmnopqrstuv',
    requestId: 'request_abcdefghijklmnopqrstuv',
    capabilityId: 'health',
    ttlMs: 1_000,
  });
  context.relay.enqueue(command);
  context.advance(1_001);
  assert.equal(context.relay.takeNext(command.deviceId), null);
});

test('a different device cannot submit a result for an inflight request', () => {
  const { relay } = createRelay();
  const command = relay.normalizeCommand({
    deviceId: 'device_abcdefghijklmnopqrstuv',
    requestId: 'request_abcdefghijklmnopqrstuv',
    capabilityId: 'health',
  });
  relay.enqueue(command);
  relay.takeNext(command.deviceId);
  assert.throws(() => relay.acceptResult('device_zyxwvutsrqponmlkjihgfe', {
    requestId: command.requestId,
    ok: true,
    data: {},
  }), /request is not inflight for this device/);
});
