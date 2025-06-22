const express = require('express');
const Gun = require('gun');
const cors = require('cors');

const app = express();
const port = process.env.PORT || 8080;

app.use(cors());

// Health check or homepage
app.get('/', (req, res) => res.send('🟢 Gun relay is running'));

// Serve Gun's static files + WebSocket handler
app.use(Gun.serve);

const server = app.listen(port, '0.0.0.0', () => {
  console.log(`Gun relay listening on http://0.0.0.0:${port}`);
});

Gun({ web: server, radisk: true });
