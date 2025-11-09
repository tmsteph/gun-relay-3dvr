# gun-relay-3dvr

Gun relay server used by the 3dvr portal. The server now applies a Brave-friendly CORS policy that exposes Gun-specific headers
and supports credentialed requests by reflecting the caller's origin.

## Configuration

- `PORT`: Port the Express server listens on (defaults to `8080`).
- `CORS_ALLOW_ORIGINS`: Optional comma-separated list of allowed origins. Include `*` to mirror any origin. When unset, the
  server reflects any provided origin.

## Development

```bash
npm install
npm start
```
