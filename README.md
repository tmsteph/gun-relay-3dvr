# gun-relay-3dvr

Private 3DVR relay used by the portal and 3DVR Companion. It provides the Gun sync endpoint plus short-lived, memory-only relay primitives for encrypted messages and permissioned device commands.

## Configuration

- `PORT`: Express listen port (defaults to `8080`).
- `CORS_ALLOW_ORIGINS`: Optional comma-separated list of allowed origins.
- `RELAY_TTL_MS`: Lifetime for one-time encrypted envelopes.
- `RELAY_DEVICE_TTL_MS`: Lifetime for ephemeral Companion device credentials.
- `COMPANION_AGENT_TOKEN`: Private server-side bearer token required to enqueue Companion commands and read their results. Never commit this value or expose it to the Android app.

## Companion command relay

The first direct-control slice deliberately permits only read-only capabilities:

- `health`
- `device.status`

Flow:

1. Companion bootstraps an ephemeral device id/token with `POST /relay/v1/devices`.
2. The authorized agent queues a short-lived command with `POST /relay/v1/commands`.
3. Companion polls `GET /relay/v1/devices/:deviceId/commands/next` using its device id and bearer credential.
4. Companion posts the result to `POST /relay/v1/devices/:deviceId/results`.
5. The agent reads the result once from `GET /relay/v1/results/:requestId`.

Commands expire quickly, request ids are deduplicated, queues are bounded, results are device-bound, and all state is memory-only. The server refuses agent command access entirely when `COMPANION_AGENT_TOKEN` is not configured.

This is intentionally not a remote shell. Additional Companion capabilities should be admitted one named capability at a time after the read-only round trip and device ownership/pairing are proven.

## Development

```bash
npm install
npm test
npm start
```
