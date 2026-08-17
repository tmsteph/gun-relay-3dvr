# gun-relay-3dvr

Private 3DVR relay used by the portal and 3DVR Companion. It provides the Gun sync endpoint plus short-lived, memory-only relay primitives for encrypted messages and permissioned device commands.

## Configuration

- `PORT`: Express listen port (defaults to `8080`).
- `CORS_ALLOW_ORIGINS`: Optional comma-separated list of allowed origins.
- `RELAY_TTL_MS`: Lifetime for one-time encrypted envelopes.
- `RELAY_DEVICE_TTL_MS`: Lifetime for ephemeral Companion device credentials.

No shared Companion agent password is required in production. Agent command routes verify Vercel's signed OIDC workload identity and accept only the production `3dvr/3dvr-portal` workload. The relay discovers Vercel's signing keys through the issuer's OpenID metadata/JWKS endpoints and caches public metadata briefly in memory.

## Companion command relay

The first direct-control slice deliberately permits only read-only capabilities:

- `health`
- `device.status`

Flow:

1. Companion bootstraps an ephemeral device id/token with `POST /relay/v1/devices`.
2. The production 3DVR Portal presents its Vercel OIDC token and queues a short-lived command with `POST /relay/v1/commands`.
3. Companion polls `GET /relay/v1/devices/:deviceId/commands/next` using its device id and bearer credential.
4. Companion posts the result to `POST /relay/v1/devices/:deviceId/results`.
5. The Portal reads the result once from `GET /relay/v1/results/:requestId`.

The OIDC trust policy pins the team slug/id, project name/id, production environment, issuer, audience, subject, expiry, and RS256 signature. Preview deployments and other Vercel projects are rejected.

Commands expire quickly, request ids are deduplicated, queues are bounded, results are device-bound, and all command/result state is memory-only.

This is intentionally not a remote shell. Additional Companion capabilities should be admitted one named capability at a time after the read-only round trip and device ownership/pairing are proven.

## Development

```bash
npm install
npm test
npm start
```
