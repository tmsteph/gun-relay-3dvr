// server.js
const Gun = require('gun');
const express = require('express');
const app = express();

const server = app.listen(process.env.PORT || 8765, () => {
  console.log('Gun relay running on port', process.env.PORT || 8765);
});

Gun({ web: server });
