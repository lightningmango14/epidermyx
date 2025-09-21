// api/ok.js
export default async function handler(req, res) {
  res.setHeader('Cache-Control', 'no-store');
  res.status(200).json({
    method: req.method,
    path: req.url,
    headers: req.headers,
  });
}
