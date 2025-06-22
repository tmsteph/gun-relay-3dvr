const express = require('express');
const Gun = require('gun');
const cors = require('cors');

const app = express();
const port = process.env.PORT || 8765;

app.use(cors());
app.use(Gun.serve);

const server = app.listen(port, () => {
  console.log(`Gun relay listening on port ${port}`);
});

// ✅ Enable persistence and real-time relay sync
Gun({
  web: server,
  radisk: true,   // stores data to disk (needed for multi-client sync)
  peers: []       // no external peers needed unless you want to join other relays
});
