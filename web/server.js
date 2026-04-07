const express = require('express');

const app = express();
const port = process.env.PORT || 3000;
const googleClientId = process.env.GOOGLE_CLIENT_ID || '';
const oidcProvidersJson = process.env.OIDC_PROVIDERS_JSON || '';
const publicApiBase = process.env.PUBLIC_API_BASE_URL || '';

app.set('trust proxy', true);

function isLocalHost(host) {
  const hostOnly = (host || '').split(':', 1)[0].trim().toLowerCase();
  return hostOnly === 'localhost' || hostOnly === '127.0.0.1' || hostOnly === '::1' || hostOnly === 'web' || hostOnly === 'api' || hostOnly === 'db';
}

app.use((req, res, next) => {
  const forwardedProto = String(req.headers['x-forwarded-proto'] || '').split(',', 1)[0].trim().toLowerCase();
  const forwardedHost = String(req.headers['x-forwarded-host'] || '').split(',', 1)[0].trim();
  const host = forwardedHost || String(req.headers.host || '').split(',', 1)[0].trim();

  if (forwardedProto === 'http' && host && !isLocalHost(host)) {
    return res.redirect(308, `https://${host}${req.originalUrl}`);
  }

  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
  if (forwardedProto === 'https') {
    res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  }

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
  const safeOidcEnabled = JSON.stringify(Boolean(oidcProvidersJson.trim()));
  const safeApiBase = JSON.stringify(publicApiBase);
  res.type('application/javascript');
  res.send(`window.APP_CONFIG = { googleClientId: ${safeClientId}, oidcSsoEnabled: ${safeOidcEnabled}, apiBase: ${safeApiBase} };`);
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
