const express = require('express');
const http = require('http');
const Gun = require('gun');
require('gun/axe');

const app = express();
app.disable('x-powered-by');

const configuredOrigins = (process.env.CORS_ALLOW_ORIGINS || '')
  .split(',')
  .map((origin) => origin.trim())
  .filter(Boolean);
const allowAnyOrigin = configuredOrigins.length === 0 || configuredOrigins.includes('*');

const isAllowedOrigin = (origin) => {
  if (!origin) {
    return false;
  }

  if (allowAnyOrigin) {
    return true;
  }

  return configuredOrigins.includes(origin);
};

app.use((req, res, next) => {
  const origin = req.headers.origin;

  if (isAllowedOrigin(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Vary', 'Origin');
  }

  res.setHeader('Access-Control-Allow-Credentials', 'true');
  res.setHeader(
    'Access-Control-Allow-Headers',
    'Origin, X-Requested-With, Content-Type, Accept, Authorization, gun-sid'
  );
  res.setHeader('Access-Control-Expose-Headers', 'gun-sid');
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,PUT,PATCH,DELETE,OPTIONS');

  if (req.method === 'OPTIONS') {
    res.status(204).end();
    return;
  }

  next();
});

// Serve Gun assets only (no public dir to avoid tracker heuristics)
app.use(Gun.serve);

// Health check endpoint
app.get('/', (_req, res) => res.status(200).send('OK'));

// Limit path surface area to Gun endpoints
app.use((req, res, next) => (req.path.startsWith('/gun') ? next() : res.status(404).end()));

const server = http.createServer(app);

const gun = Gun({
  web: server,
  radisk: true,
  file: 'data',
  axe: true,
});

const PORT = process.env.PORT || 8080;
server.listen(PORT, () => {
  console.log(`GUN relay listening on :${PORT}`);
});

module.exports = { app, server, gun };
