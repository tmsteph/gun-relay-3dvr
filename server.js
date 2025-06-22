const express = require('express');
const Gun = require('gun');
const cors = require('cors');

const app = express();
const port = process.env.PORT || 8765;

app.use(cors());
app.use(Gun.serve); // serves static + WebSocket handler at /gun

const server = app.listen(port, '0.0.0.0', () => {
  console.log(`Gun relay listening on http://0.0.0.0:${port}`);
});

// Gun relay with file persistence
Gun({ web: server, radisk: true });
