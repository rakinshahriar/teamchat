const express = require('express');

const app = express();
const port = process.env.PORT || 3000;
const googleClientId = process.env.GOOGLE_CLIENT_ID || '';
const publicApiBase = process.env.PUBLIC_API_BASE_URL || '';

app.use((req, res, next) => {
  if (req.path === '/' || req.path === '/config.js' || /\.(html|js|css)$/.test(req.path)) {
    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
    res.setHeader('Pragma', 'no-cache');
    res.setHeader('Expires', '0');
  }
  next();
});

app.use(express.static('public'));

app.get('/config.js', (_req, res) => {
  const safeClientId = JSON.stringify(googleClientId);
  const safeApiBase = JSON.stringify(publicApiBase);
  res.type('application/javascript');
  res.send(`window.APP_CONFIG = { googleClientId: ${safeClientId}, apiBase: ${safeApiBase} };`);
});

app.get('/health', (_req, res) => {
  res.json({ status: 'ok', service: 'web' });
});

app.get('/', (_req, res) => {
  res.sendFile('index.html', { root: 'public' });
});

app.listen(port, () => {
  console.log(`web listening on ${port}`);
});
