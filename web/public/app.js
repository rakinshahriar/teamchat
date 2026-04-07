const authCard = document.getElementById('authCard');
const appCard = document.getElementById('appCard');
const loginNotice = document.getElementById('loginNotice');
const displayNameEl = document.getElementById('displayName');
const emailEl = document.getElementById('email');
const avatarEl = document.getElementById('avatar');
const logoutBtn = document.getElementById('logoutBtn');
const messageForm = document.getElementById('messageForm');
const messageInput = document.getElementById('messageInput');
const messageList = document.getElementById('messageList');
const registerForm = document.getElementById('registerForm');
const manualLoginForm = document.getElementById('manualLoginForm');
const registerName = document.getElementById('registerName');
const registerEmail = document.getElementById('registerEmail');
const registerPassword = document.getElementById('registerPassword');
const loginEmail = document.getElementById('loginEmail');
const loginPassword = document.getElementById('loginPassword');
const authStack = document.getElementById('authStack');
const adminLinkWrap = document.getElementById('adminLinkWrap');

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

function renderMessages(messages) {
  messageList.innerHTML = '';
  if (!messages || messages.length === 0) {
    const empty = document.createElement('li');
    empty.textContent = 'No messages yet.';
    messageList.appendChild(empty);
    return;
  }

  messages.forEach((msg) => {
    const li = document.createElement('li');
    const ts = document.createElement('span');
    ts.className = 'message-time';
    ts.textContent = new Date(msg.created_at).toLocaleString();
    const text = document.createElement('div');
    text.textContent = msg.content;
    li.appendChild(ts);
    li.appendChild(text);
    messageList.appendChild(li);
  });
}

async function loadMessages() {
  const data = await api('/messages', { method: 'GET' });
  renderMessages(data.messages || []);
}

async function onGoogleCredential(response) {
  try {
    loginNotice.textContent = '';
    await api('/auth/google', {
      method: 'POST',
      body: JSON.stringify({ credential: response.credential }),
    });
    await initSession();
  } catch (err) {
    loginNotice.textContent = String(err.message || err);
  }
}

async function registerManual(event) {
  event.preventDefault();
  try {
    loginNotice.textContent = '';
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
      loginNotice.style.color = '#027a48';
      loginNotice.innerHTML = 'Registered. Verify your email before login. <a href="/verify.html">Open verification</a>';
      return;
    }
    await initSession();
  } catch (err) {
    loginNotice.style.color = '#b42318';
    loginNotice.textContent = String(err.message || err);
  }
}

async function loginManual(event) {
  event.preventDefault();
  try {
    loginNotice.textContent = '';
    await api('/auth/login', {
      method: 'POST',
      body: JSON.stringify({
        email: loginEmail.value.trim(),
        password: loginPassword.value,
      }),
    });
    manualLoginForm.reset();
    await initSession();
  } catch (err) {
    loginNotice.style.color = '#b42318';
    loginNotice.textContent = String(err.message || err);
  }
}

async function initSession() {
  try {
    const me = await api('/me', { method: 'GET' });
    displayNameEl.textContent = me.display_name;
    emailEl.textContent = me.email;
    avatarEl.src = me.picture_url || 'https://www.gravatar.com/avatar/?d=mp';
    const isAdmin = Boolean(me.is_admin || Number(me.rank) >= 2 || me.role === 'admin' || me.role === 'super_admin');
    if (isAdmin) {
      adminLinkWrap.classList.remove('hidden');
    } else {
      adminLinkWrap.classList.add('hidden');
    }
    authCard.classList.add('hidden');
    appCard.classList.remove('hidden');
    await loadMessages();
  } catch {
    adminLinkWrap.classList.add('hidden');
    authCard.classList.remove('hidden');
    appCard.classList.add('hidden');
  }
}

function showRegisterMode() {
  if (!authStack) {
    return;
  }
  authStack.classList.add('mode-register');
  authStack.classList.remove('mode-login');
}

function showLoginMode() {
  if (!authStack) {
    return;
  }
  authStack.classList.add('mode-login');
  authStack.classList.remove('mode-register');
}

messageForm.addEventListener('submit', async (event) => {
  event.preventDefault();
  const content = messageInput.value.trim();
  if (!content) {
    return;
  }

  try {
    await api('/messages', {
      method: 'POST',
      body: JSON.stringify({ content }),
    });
    messageInput.value = '';
    await loadMessages();
  } catch (err) {
    alert(String(err.message || err));
  }
});

logoutBtn.addEventListener('click', async () => {
  try {
    await api('/logout', { method: 'POST' });
  } finally {
    adminLinkWrap.classList.add('hidden');
    authCard.classList.remove('hidden');
    appCard.classList.add('hidden');
  }
});

if (registerForm) {
  registerForm.addEventListener('submit', registerManual);
}
if (manualLoginForm) {
  manualLoginForm.addEventListener('submit', loginManual);
}
if (authStack) {
  authStack.addEventListener('click', (event) => {
    const target = event.target;
    if (!(target instanceof HTMLElement)) {
      return;
    }
    const mode = target.getAttribute('data-auth-switch');
    if (mode === 'register') {
      showRegisterMode();
    } else if (mode === 'login') {
      showLoginMode();
    }
  });
}

window.addEventListener('load', async () => {
  const clientId = window.APP_CONFIG?.googleClientId || '';
  if (!clientId) {
    loginNotice.textContent = 'Google login is not configured. Add GOOGLE_CLIENT_ID in .env.';
  } else if (window.google?.accounts?.id) {
    window.google.accounts.id.initialize({
      client_id: clientId,
      callback: onGoogleCredential,
    });
    window.google.accounts.id.renderButton(document.getElementById('googleButton'), {
      type: 'standard',
      theme: 'outline',
      size: 'large',
      text: 'signin_with',
      shape: 'pill',
    });
  }

  await initSession();
});
