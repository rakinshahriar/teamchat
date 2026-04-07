const computedApiBase = `${window.location.protocol}//${window.location.hostname}:8000`;
const apiBase = window.APP_CONFIG?.apiBase || computedApiBase;

const verifyForm = document.getElementById('verifyForm');
const verifyToken = document.getElementById('verifyToken');
const verifyStatus = document.getElementById('verifyStatus');

const queryToken = new URLSearchParams(window.location.search).get('token');
if (queryToken) {
  verifyToken.value = queryToken;
}

async function api(path, options = {}) {
  const res = await fetch(`${apiBase}${path}`, {
    ...options,
    headers: {
      'Content-Type': 'application/json',
      ...(options.headers || {}),
    },
    credentials: 'include',
  });
  const text = await res.text();
  const payload = text ? JSON.parse(text) : {};
  if (!res.ok) {
    throw new Error(payload.detail || `Request failed (${res.status})`);
  }
  return payload;
}

verifyForm.addEventListener('submit', async (event) => {
  event.preventDefault();
  try {
    verifyStatus.textContent = '';
    await api('/auth/verify-email', {
      method: 'POST',
      body: JSON.stringify({ token: verifyToken.value.trim() }),
    });
    verifyStatus.style.color = '#027a48';
    verifyStatus.textContent = 'Email verified. You can now log in.';
  } catch (err) {
    verifyStatus.style.color = '#b42318';
    verifyStatus.textContent = String(err.message || err);
  }
});
