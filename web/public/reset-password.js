const apiBase = window.APP_CONFIG?.apiBase || '/api';

const requestForm = document.getElementById('requestForm');
const requestEmail = document.getElementById('requestEmail');
const confirmForm = document.getElementById('confirmForm');
const newPassword = document.getElementById('newPassword');
const resetStatus = document.getElementById('resetStatus');

const queryToken = new URLSearchParams(window.location.search).get('token');
if (queryToken) {
  requestForm.classList.add('hidden');
  confirmForm.classList.remove('hidden');
  resetStatus.style.color = '#027a48';
  resetStatus.textContent = 'Reset link detected. Set your new password below.';
} else {
  requestForm.classList.remove('hidden');
  confirmForm.classList.add('hidden');
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

requestForm.addEventListener('submit', async (event) => {
  event.preventDefault();
  try {
    const data = await api('/auth/password-reset/request', {
      method: 'POST',
      body: JSON.stringify({ email: requestEmail.value.trim() }),
    });
    resetStatus.style.color = '#027a48';
    resetStatus.textContent = 'If the account exists, a 5-minute reset link has been sent to that email.';
  } catch (err) {
    resetStatus.style.color = '#b42318';
    resetStatus.textContent = String(err.message || err);
  }
});

confirmForm.addEventListener('submit', async (event) => {
  event.preventDefault();
  if (!queryToken) {
    resetStatus.style.color = '#b42318';
    resetStatus.textContent = 'Invalid or missing reset link token.';
    return;
  }
  try {
    await api('/auth/password-reset/confirm', {
      method: 'POST',
      body: JSON.stringify({
        token: queryToken,
        new_password: newPassword.value,
      }),
    });
    resetStatus.style.color = '#027a48';
    resetStatus.textContent = 'Password reset complete. Redirecting to login...';
    setTimeout(() => {
      window.location.href = '/';
    }, 2200);
  } catch (err) {
    resetStatus.style.color = '#b42318';
    resetStatus.textContent = String(err.message || err);
  }
});
