const express = require('express');
const http = require('http');
const Gun = require('gun');
require('gun/axe');

const app = express();
app.disable('x-powered-by');

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
