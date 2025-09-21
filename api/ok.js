// api/ok.js
module.exports = (req, res) => {
  res.setHeader('Cache-Control', 'no-store');
  res.status(200).json({
    ok: true,
    at: '/api/ok',
    method: req.method,
    url: req.url
  });
};
