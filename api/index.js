// Vercel Serverless entrypoint that mounts your existing Express app.
// Place this file at: api/index.js (sibling to your server.js in the project root).

const app = require('../server'); // server.js must export the Express app (module.exports = app)

module.exports = (req, res) => {
  // Let Express handle the request
  return app(req, res);
};
