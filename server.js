const express = require('express');
const Gun = require('gun');
const cors = require('cors');

const app = express();
const port = process.env.PORT || 8765;

app.use(cors()); // ✅ Allow cross-origin
app.use(Gun.serve);

const server = app.listen(port, () => {
  console.log(`Gun relay listening on port ${port}`);
});

Gun({ web: server });
