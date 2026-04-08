const express = require('express');

const app = express();
const port = process.env.PORT || 3000;
const googleClientId = process.env.GOOGLE_CLIENT_ID || '';
const oidcProvidersJson = process.env.OIDC_PROVIDERS_JSON || '';
const publicApiBase = process.env.PUBLIC_API_BASE_URL || '';
const internalApiBase = process.env.INTERNAL_API_BASE_URL || 'http://api:8000';
const resolvedPublicApiBase = publicApiBase.trim().startsWith('/') ? publicApiBase.trim() : '/api';

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
  // Allow same-origin framing so the Terms dialog iframe can render /terms.html.
  res.setHeader('X-Frame-Options', 'SAMEORIGIN');
  res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self' https://accounts.google.com; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; frame-src 'self' https://accounts.google.com; connect-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'self'; form-action 'self'");
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

async function readRequestBody(req) {
  return await new Promise((resolve, reject) => {
    const chunks = [];
    req.on('data', (chunk) => chunks.push(chunk));
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

app.use('/api', async (req, res) => {
  const upstreamPath = req.originalUrl.replace(/^\/api/, '') || '/';
  const targetUrl = `${internalApiBase}${upstreamPath}`;
  const method = String(req.method || 'GET').toUpperCase();

  const headers = { ...req.headers };
  delete headers.host;
  delete headers['content-length'];

  let body;
  if (method !== 'GET' && method !== 'HEAD') {
    const raw = await readRequestBody(req);
    if (raw.length > 0) {
      body = raw;
    }
  }

  try {
    const upstream = await fetch(targetUrl, {
      method,
      headers,
      body,
      redirect: 'manual',
    });

    res.status(upstream.status);
    upstream.headers.forEach((value, key) => {
      if (key.toLowerCase() === 'transfer-encoding') {
        return;
      }
      res.setHeader(key, value);
    });

    const data = Buffer.from(await upstream.arrayBuffer());
    res.send(data);
  } catch (err) {
    console.error('API proxy error:', err && err.message ? err.message : err);
    res.status(502).json({ detail: 'API upstream unreachable' });
  }
});

app.use(express.static('public'));

app.get('/config.js', (_req, res) => {
  const safeClientId = JSON.stringify(googleClientId);
  const safeOidcEnabled = JSON.stringify(Boolean(oidcProvidersJson.trim()));
  const safeApiBase = JSON.stringify(resolvedPublicApiBase);
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
