// api/index.js
const app = require('../server');   // loads your Express app
module.exports = (req, res) => app(req, res);

