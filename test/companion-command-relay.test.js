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
    advance(milliseconds) {
      clock += milliseconds;
    },
  };
}

function fakeRequest(authorization) {
  return {
    get(name) {
      return name.toLowerCase() === 'authorization' ? authorization || '' : '';
    },
  };
}

test('agent API is unavailable without a configured agent token', () => {
  const { relay } = createRelay({ agentToken: '' });
  assert.deepEqual(relay.authorizeAgent(fakeRequest()), {
    ok: false,
    status: 503,
    error: 'agent relay unavailable',
  });
});

test('agent API rejects an incorrect bearer token', () => {
  const { relay } = createRelay();
  assert.deepEqual(relay.authorizeAgent(fakeRequest('Bearer wrong-token-wrong-token-wrong-token-wrong-token')), {
    ok: false,
    status: 401,
    error: 'agent authorization required',
  });
});

test('agent API accepts the configured bearer token', () => {
  const token = 'agent-token-abcdefghijklmnopqrstuvwxyz123456';
  const { relay } = createRelay({ agentToken: token });
  assert.deepEqual(relay.authorizeAgent(fakeRequest(`Bearer ${token}`)), { ok: true });
});

test('only read-only capabilities are admitted initially', () => {
  const { relay } = createRelay();
  assert.throws(
    () => relay.normalizeCommand({
      deviceId: 'device_abcdefghijklmnopqrstuv',
      requestId: 'request_abcdefghijklmnopqrstuv',
      capabilityId: 'ui.perform',
    }),
    /unsupported capability/,
  );
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

  assert.deepEqual(relay.resultStatus(command.requestId), {
    status: 202,
    body: { ok: true, requestId: command.requestId, state: 'inflight' },
  });

  relay.acceptResult(command.deviceId, {
    requestId: command.requestId,
    ok: true,
    data: { batteryPercent: 67 },
  });

  const completed = relay.resultStatus(command.requestId);
  assert.equal(completed.status, 200);
  assert.equal(completed.body.ok, true);
  assert.equal(completed.body.commandOk, true);
  assert.deepEqual(completed.body.data, { batteryPercent: 67 });

  assert.deepEqual(relay.resultStatus(command.requestId), {
    status: 404,
    body: { ok: false, error: 'request not found' },
  });
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

  assert.throws(
    () => relay.acceptResult('device_zyxwvutsrqponmlkjihgfe', {
      requestId: command.requestId,
      ok: true,
      data: {},
    }),
    /request is not inflight for this device/,
  );
});
