const registerForm = document.getElementById('registerForm');
const registerNotice = document.getElementById('registerNotice');
const registerName = document.getElementById('registerName');
const registerEmail = document.getElementById('registerEmail');
const registerPassword = document.getElementById('registerPassword');
const registerTerms = document.getElementById('registerTerms');
const termsDialog = document.getElementById('termsDialog');
const termsOpenBtn = document.getElementById('termsOpenBtn');
const termsCloseBtn = document.getElementById('termsCloseBtn');

const computedApiBase = `${window.location.protocol}//${window.location.hostname}:8000`;
const apiBase = window.APP_CONFIG?.apiBase || computedApiBase;

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
  let payload;
  try {
    payload = text ? JSON.parse(text) : {};
  } catch {
    payload = {};
  }

  if (!res.ok) {
    const detail = payload.detail || payload.error || `Request failed (${res.status})`;
    throw new Error(detail);
  }
  return payload;
}

async function registerManual(event) {
  event.preventDefault();
  try {
    if (registerTerms && !registerTerms.checked) {
      registerNotice.style.color = '#b42318';
      registerNotice.textContent = 'Please accept the Terms of Service before creating an account.';
      return;
    }
    registerNotice.style.color = '#027a48';
    registerNotice.textContent = '';
    const data = await api('/auth/register', {
      method: 'POST',
      body: JSON.stringify({
        display_name: registerName.value.trim(),
        email: registerEmail.value.trim(),
        password: registerPassword.value,
      }),
    });

    registerForm.reset();
    if (data.verification_required) {
      registerNotice.innerHTML = 'Registered. Check your email for verification. If needed, <a href="/verify.html">verify token here</a>.';
    } else {
      registerNotice.textContent = 'Registered successfully. You can now log in.';
    }
  } catch (err) {
    registerNotice.style.color = '#b42318';
    registerNotice.textContent = String(err.message || err);
  }
}

if (termsOpenBtn && termsDialog) {
  termsOpenBtn.addEventListener('click', () => {
    termsDialog.showModal();
  });
}

if (termsCloseBtn && termsDialog) {
  termsCloseBtn.addEventListener('click', () => {
    termsDialog.close();
  });
}

registerForm.addEventListener('submit', registerManual);
