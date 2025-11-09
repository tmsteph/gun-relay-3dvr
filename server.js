const express = require('express');
const Gun = require('gun');

const app = express();
const port = process.env.PORT || 8080;

const corsOrigins = process.env.CORS_ALLOW_ORIGINS
  ? process.env.CORS_ALLOW_ORIGINS.split(',').map((entry) => entry.trim()).filter(Boolean)
  : null;

app.use((req, res, next) => {
  const origin = req.headers.origin;
  const originAllowed = !corsOrigins || corsOrigins.includes('*') || (origin && corsOrigins.includes(origin));
  const allowOrigin = originAllowed && origin ? origin : '*';

  const originalSetHeader = res.setHeader.bind(res);
  res.setHeader = (key, value) => {
    if (typeof key === 'string' && key.toLowerCase() === 'access-control-allow-origin') {
      return originalSetHeader(key, allowOrigin);
    }
    return originalSetHeader(key, value);
  };

  res.header('Access-Control-Allow-Origin', allowOrigin);

  const existingVary = res.getHeader('Vary');
  if (existingVary) {
    const varyValues = new Set(
      existingVary
        .toString()
        .split(',')
        .map((value) => value.trim())
        .filter(Boolean)
    );
    varyValues.add('Origin');
    res.header('Vary', Array.from(varyValues).join(', '));
  } else {
    res.header('Vary', 'Origin');
  }
  res.header('Access-Control-Allow-Credentials', 'true');
  res.header(
    'Access-Control-Allow-Headers',
    'Origin, X-Requested-With, Content-Type, Accept, Authorization, gun-sid, gun-msg, gun-peer'
  );
  res.header('Access-Control-Expose-Headers', 'gun-sid, gun-msg, gun-peer');
  res.header('Access-Control-Allow-Methods', 'GET,POST,PUT,PATCH,DELETE,OPTIONS');

  if (req.method === 'OPTIONS') {
    return res.sendStatus(204);
  }

  next();
});

// Health check or homepage
app.get('/', (req, res) => res.send('🟢 Gun relay is running'));

// Serve Gun's static files + WebSocket handler
app.use(Gun.serve);

const server = app.listen(port, '0.0.0.0', () => {
  console.log(`Gun relay listening on http://0.0.0.0:${port}`);
});

Gun({ web: server, radisk: true });
