// api/ping.js
module.exports = (_req, res) => {
  res.setHeader('Content-Type', 'application/json');
  res.status(200).end(JSON.stringify({ ok: true, hello: 'from serverless' }));
};
