const authCard = document.getElementById('authCard');
const appCard = document.getElementById('appCard');
const loginNotice = document.getElementById('loginNotice');
const displayNameEl = document.getElementById('displayName');
const emailEl = document.getElementById('email');
const avatarEl = document.getElementById('avatar');
const logoutBtn = document.getElementById('logoutBtn');
const registerForm = document.getElementById('registerForm');
const manualLoginForm = document.getElementById('manualLoginForm');
const registerName = document.getElementById('registerName');
const registerEmail = document.getElementById('registerEmail');
const registerPassword = document.getElementById('registerPassword');
const registerTerms = document.getElementById('registerTerms');
const termsDialog = document.getElementById('termsDialog');
const termsOpenBtn = document.getElementById('termsOpenBtn');
const termsCloseBtn = document.getElementById('termsCloseBtn');
const companySsoDialog = document.getElementById('companySsoDialog');
const companySsoForm = document.getElementById('companySsoForm');
const companySsoDomainInput = document.getElementById('companySsoDomainInput');
const companySsoCancelBtn = document.getElementById('companySsoCancelBtn');
const googleDisplayNameDialog = document.getElementById('googleDisplayNameDialog');
const googleDisplayNameForm = document.getElementById('googleDisplayNameForm');
const googleDisplayNameInput = document.getElementById('googleDisplayNameInput');
const googleDisplayNameTerms = document.getElementById('googleDisplayNameTerms');
const googleDisplayNameNotice = document.getElementById('googleDisplayNameNotice');
const googleDisplayNameCancelBtn = document.getElementById('googleDisplayNameCancelBtn');
const loginEmail = document.getElementById('loginEmail');
const loginPassword = document.getElementById('loginPassword');
const authStack = document.getElementById('authStack');
const portraitWelcomeText = document.getElementById('portraitWelcomeText');
const authEyebrow = document.getElementById('authEyebrow');
const authTitle = document.getElementById('authTitle');
const authSubtitle = document.getElementById('authSubtitle');
const adminLinkWrap = document.getElementById('adminLinkWrap');
const connectionSearchForm = document.getElementById('connectionSearchForm');
const connectionSearchInput = document.getElementById('connectionSearchInput');
const connectionSearchResults = document.getElementById('connectionSearchResults');
const incomingRequests = document.getElementById('incomingRequests');
const outgoingRequests = document.getElementById('outgoingRequests');
const connectionsList = document.getElementById('connectionsList');
const groupCreateForm = document.getElementById('groupCreateForm');
const groupNameInput = document.getElementById('groupNameInput');
const groupsList = document.getElementById('groupsList');
const activeConnectionName = document.getElementById('activeConnectionName');
const dmList = document.getElementById('dmList');
const dmForm = document.getElementById('dmForm');
const dmInput = document.getElementById('dmInput');
const charCount = document.getElementById('charCount');
const chatHint = document.getElementById('chatHint');
const groupMemberSearchForm = document.getElementById('groupMemberSearchForm');
const groupMemberSearchInput = document.getElementById('groupMemberSearchInput');
const groupMemberSearchResults = document.getElementById('groupMemberSearchResults');
const companySsoBtn = document.getElementById('companySsoBtn');
const bodyEl = document.body;

const computedApiBase = `${window.location.protocol}//${window.location.hostname}:8000`;
const apiBase = window.APP_CONFIG?.apiBase || computedApiBase;

let currentUser = null;
let allConnections = [];
let incoming = [];
let outgoing = [];
let allGroups = [];
let selectedConnectionId = null;
let selectedGroupId = null;
let selectedChatType = null;
let pendingSsoIntent = 'login';
let pendingSsoDisplayName = '';
let pendingSsoTosAccepted = false;
const AUTH_MODE_STORAGE_KEY = 'teamchat_auth_mode';

function setViewMode(isAuthView) {
  if (!bodyEl) {
    return;
  }
  bodyEl.classList.toggle('auth-view', isAuthView);
  bodyEl.classList.toggle('app-view', !isAuthView);
}

function saveAuthMode(mode) {
  try {
    localStorage.setItem(AUTH_MODE_STORAGE_KEY, mode);
  } catch {
    // Ignore storage errors (private mode, restricted storage, etc.)
  }
}

function getSavedAuthMode() {
  try {
    const mode = localStorage.getItem(AUTH_MODE_STORAGE_KEY);
    return mode === 'register' ? 'register' : 'login';
  } catch {
    return 'login';
  }
}

function isRegisterMode() {
  return Boolean(authStack?.classList.contains('mode-register'));
}

function getSignupDisplayName() {
  return (registerName?.value || '').trim();
}

function renderGoogleButtonForMode() {
  if (!window.google?.accounts?.id) {
    return;
  }
  const googleMount = document.getElementById('googleButton');
  if (!googleMount) {
    return;
  }
  googleMount.innerHTML = '';
  const googleBtnWidth = Math.max(280, Math.floor(googleMount.clientWidth || 320));
  window.google.accounts.id.renderButton(googleMount, {
    type: 'standard',
    theme: 'outline',
    size: 'large',
    text: isRegisterMode() ? 'continue_with' : 'signin_with',
    shape: 'rectangular',
    width: googleBtnWidth,
  });
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
  let payload;
  try {
    payload = text ? JSON.parse(text) : {};
  } catch {
    payload = {};
  }

  if (!res.ok) {
    const detail = payload.detail || payload.error || `Request failed (${res.status})`;
    const err = new Error(detail);
    err.status = res.status;
    err.payload = payload;
    throw err;
  }
  return payload;
}

function renderSimpleList(container, rows, emptyText) {
  container.innerHTML = '';
  if (!rows || rows.length === 0) {
    const empty = document.createElement('li');
    empty.className = 'empty-line';
    empty.textContent = emptyText;
    container.appendChild(empty);
    return;
  }
  rows.forEach((row) => container.appendChild(row));
}

function userLabel(user) {
  return `${user.display_name || 'User'} (${user.email || ''})`;
}

async function loadConnectionsAndRequests() {
  const [connData, reqData] = await Promise.all([
    api('/connections', { method: 'GET' }),
    api('/connections/requests', { method: 'GET' }),
  ]);
  allConnections = connData.connections || [];
  incoming = reqData.incoming || [];
  outgoing = reqData.outgoing || [];
  renderRequests();
  renderConnections();
}

async function loadGroups() {
  const data = await api('/groups', { method: 'GET' });
  allGroups = data.groups || [];
  renderGroups();
}

async function refreshSidebarData() {
  await Promise.all([loadConnectionsAndRequests(), loadGroups()]);
}

function renderRequests() {
  const incomingRows = incoming.map((req) => {
    const item = document.createElement('li');
    item.className = 'compact-item';
    const text = document.createElement('div');
    text.textContent = userLabel(req);
    const actions = document.createElement('div');
    actions.className = 'row';
    const acceptBtn = document.createElement('button');
    acceptBtn.type = 'button';
    acceptBtn.textContent = 'Accept';
    acceptBtn.addEventListener('click', async () => {
      try {
        await api('/connections/requests/accept', {
          method: 'POST',
          body: JSON.stringify({ requester_user_id: req.user_id }),
        });
        await loadConnectionsAndRequests();
      } catch (err) {
        alert(String(err.message || err));
      }
    });
    const declineBtn = document.createElement('button');
    declineBtn.type = 'button';
    declineBtn.className = 'ghost';
    declineBtn.textContent = 'Decline';
    declineBtn.addEventListener('click', async () => {
      try {
        await api('/connections/requests/decline', {
          method: 'POST',
          body: JSON.stringify({ requester_user_id: req.user_id }),
        });
        await loadConnectionsAndRequests();
      } catch (err) {
        alert(String(err.message || err));
      }
    });
    actions.appendChild(acceptBtn);
    actions.appendChild(declineBtn);
    item.appendChild(text);
    item.appendChild(actions);
    return item;
  });
  renderSimpleList(incomingRequests, incomingRows, 'No incoming requests.');

  const outgoingRows = outgoing.map((req) => {
    const item = document.createElement('li');
    item.className = 'compact-item';
    item.textContent = `${userLabel(req)} - pending`;
    return item;
  });
  renderSimpleList(outgoingRequests, outgoingRows, 'No outgoing requests.');
}

function renderConnections() {
  const rows = allConnections.map((conn) => {
    const item = document.createElement('li');
    item.className = 'compact-item';
    const btn = document.createElement('button');
    btn.type = 'button';
    btn.className = selectedChatType === 'connection' && selectedConnectionId === conn.user_id ? 'active-connection' : 'ghost';
    btn.textContent = userLabel(conn);
    btn.addEventListener('click', async () => {
      selectedChatType = 'connection';
      selectedConnectionId = conn.user_id;
      selectedGroupId = null;
      activeConnectionName.textContent = `Chat with ${conn.display_name || conn.email}`;
      chatHint.textContent = `Connected with ${conn.email}`;
      if (groupMemberSearchForm) {
        groupMemberSearchForm.classList.add('hidden');
      }
      if (groupMemberSearchResults) {
        groupMemberSearchResults.classList.add('hidden');
        groupMemberSearchResults.innerHTML = '';
      }
      renderGroups();
      renderConnections();
      await loadDirectMessages();
    });
    item.appendChild(btn);
    return item;
  });
  renderSimpleList(connectionsList, rows, 'No connections yet.');

  const stillExists = allConnections.some((c) => c.user_id === selectedConnectionId);
  if (selectedChatType === 'connection' && !stillExists) {
    selectedConnectionId = null;
    selectedChatType = null;
    activeConnectionName.textContent = 'Select a connection or group';
    chatHint.textContent = 'You can only chat with accepted connections or group members.';
    renderSimpleList(dmList, [], 'Choose a connection or group to start chatting.');
  }
}

function renderGroups() {
  const rows = allGroups.map((group) => {
    const item = document.createElement('li');
    item.className = 'compact-item';
    const controls = document.createElement('div');
    controls.className = 'row';

    const btn = document.createElement('button');
    btn.type = 'button';
    btn.className = selectedChatType === 'group' && selectedGroupId === group.id ? 'active-connection' : 'ghost';
    const companyLabel = group.group_type === 'company' ? ' (Company)' : '';
    btn.textContent = `${group.name}${companyLabel}`;
    btn.addEventListener('click', async () => {
      selectedChatType = 'group';
      selectedGroupId = group.id;
      selectedConnectionId = null;
      activeConnectionName.textContent = `Group: ${group.name}`;
      chatHint.textContent = 'Only group members can see and send messages.';
      if (groupMemberSearchForm) {
        groupMemberSearchForm.classList.remove('hidden');
      }
      if (groupMemberSearchResults) {
        groupMemberSearchResults.classList.add('hidden');
        groupMemberSearchResults.innerHTML = '';
      }
      renderConnections();
      renderGroups();
      await loadGroupMessages();
    });

    const leaveBtn = document.createElement('button');
    leaveBtn.type = 'button';
    leaveBtn.className = 'ghost';
    leaveBtn.textContent = 'Leave';
    leaveBtn.addEventListener('click', async () => {
      const confirmed = window.confirm(`Leave group "${group.name}"?`);
      if (!confirmed) {
        return;
      }
      try {
        await api(`/groups/${group.id}/members/me`, { method: 'DELETE' });
        if (selectedChatType === 'group' && selectedGroupId === group.id) {
          selectedGroupId = null;
          selectedChatType = null;
          activeConnectionName.textContent = 'Select a connection or group';
          chatHint.textContent = 'You can only chat with accepted connections or group members.';
          renderSimpleList(dmList, [], 'Choose a connection or group to start chatting.');
          if (groupMemberSearchForm) {
            groupMemberSearchForm.classList.add('hidden');
          }
          if (groupMemberSearchResults) {
            groupMemberSearchResults.classList.add('hidden');
            groupMemberSearchResults.innerHTML = '';
          }
        }
        await loadGroups();
      } catch (err) {
        alert(String(err.message || err));
      }
    });

    controls.appendChild(btn);
    controls.appendChild(leaveBtn);
    item.appendChild(controls);
    return item;
  });
  renderSimpleList(groupsList, rows, 'No groups yet.');

  const stillExists = allGroups.some((g) => g.id === selectedGroupId);
  if (selectedChatType === 'group' && !stillExists) {
    selectedGroupId = null;
    selectedChatType = null;
    if (groupMemberSearchForm) {
      groupMemberSearchForm.classList.add('hidden');
    }
    activeConnectionName.textContent = 'Select a connection or group';
    chatHint.textContent = 'You can only chat with accepted connections or group members.';
    renderSimpleList(dmList, [], 'Choose a connection or group to start chatting.');
  }
}

function renderDirectMessages(messages) {
  dmList.innerHTML = '';
  if (!messages || messages.length === 0) {
    const empty = document.createElement('li');
    empty.className = 'empty-line';
    empty.textContent = 'No messages yet. Say hello!';
    dmList.appendChild(empty);
    return;
  }
  messages.forEach((msg) => {
    const isMine = String(msg.sender_user_id) === String(currentUser?.id);
    const li = document.createElement('li');
    li.className = isMine ? 'msg-out' : 'msg-in';
    const ts = document.createElement('span');
    ts.className = 'message-time';
    ts.textContent = new Date(msg.created_at).toLocaleString();
    if (!isMine && msg.sender_display_name) {
      const sender = document.createElement('strong');
      sender.textContent = msg.sender_display_name;
      li.appendChild(sender);
    }
    const text = document.createElement('div');
    text.textContent = msg.content;
    li.appendChild(ts);
    li.appendChild(text);
    dmList.appendChild(li);
  });
}

async function loadDirectMessages() {
  if (!selectedConnectionId) {
    renderSimpleList(dmList, [], 'Choose a connection or group to start chatting.');
    return;
  }
  const data = await api(`/connections/messages/${selectedConnectionId}`, { method: 'GET' });
  renderDirectMessages(data.messages || []);
}

async function loadGroupMessages() {
  if (!selectedGroupId) {
    renderSimpleList(dmList, [], 'Choose a connection or group to start chatting.');
    return;
  }
  const data = await api(`/groups/${selectedGroupId}/messages`, { method: 'GET' });
  renderDirectMessages(data.messages || []);
}

async function runUserSearch(event) {
  event.preventDefault();
  const query = connectionSearchInput.value.trim();
  if (query.length < 2) {
    return;
  }
  const data = await api(`/users/search?q=${encodeURIComponent(query)}`, { method: 'GET' });
  const rows = (data.users || []).map((candidate) => {
    const item = document.createElement('li');
    item.className = 'compact-item';
    const text = document.createElement('div');
    text.textContent = userLabel(candidate);
    const btn = document.createElement('button');
    btn.type = 'button';
    btn.textContent = 'Connect';
    const alreadyConnected = allConnections.some((c) => c.user_id === candidate.id);
    const outgoingPending = outgoing.some((r) => r.user_id === candidate.id);
    const incomingPending = incoming.some((r) => r.user_id === candidate.id);
    if (alreadyConnected || outgoingPending || incomingPending) {
      btn.disabled = true;
      btn.textContent = alreadyConnected ? 'Connected' : 'Pending';
    }
    btn.addEventListener('click', async () => {
      try {
        await api('/connections/request', {
          method: 'POST',
          body: JSON.stringify({ target_user_id: candidate.id }),
        });
        await loadConnectionsAndRequests();
        await runUserSearch(new Event('submit'));
      } catch (err) {
        alert(String(err.message || err));
      }
    });
    item.appendChild(text);
    item.appendChild(btn);
    return item;
  });
  renderSimpleList(connectionSearchResults, rows, 'No users found.');
}

async function runGroupMemberSearch(event) {
  event.preventDefault();
  if (!selectedGroupId) {
    return;
  }
  const query = groupMemberSearchInput.value.trim();
  if (query.length < 2) {
    return;
  }
  const data = await api(`/users/search?q=${encodeURIComponent(query)}`, { method: 'GET' });
  const rows = (data.users || []).map((candidate) => {
    const item = document.createElement('li');
    item.className = 'compact-item';
    const text = document.createElement('div');
    text.textContent = userLabel(candidate);
    const btn = document.createElement('button');
    btn.type = 'button';
    btn.textContent = 'Add to Group';
    btn.addEventListener('click', async () => {
      try {
        await api(`/groups/${selectedGroupId}/members`, {
          method: 'POST',
          body: JSON.stringify({ user_id: candidate.id }),
        });
        btn.disabled = true;
        btn.textContent = 'Added';
      } catch (err) {
        alert(String(err.message || err));
      }
    });
    item.appendChild(text);
    item.appendChild(btn);
    return item;
  });
  groupMemberSearchResults.classList.remove('hidden');
  renderSimpleList(groupMemberSearchResults, rows, 'No users found.');
}

function requestSignupDetails(initialValue = '') {
  return new Promise((resolve) => {
    if (!googleDisplayNameDialog || !googleDisplayNameForm || !googleDisplayNameInput) {
      resolve(null);
      return;
    }

    let completed = false;
    googleDisplayNameInput.value = initialValue;
    if (googleDisplayNameTerms) {
      googleDisplayNameTerms.checked = false;
    }
    if (googleDisplayNameNotice) {
      googleDisplayNameNotice.textContent = '';
    }

    const cleanup = () => {
      googleDisplayNameForm.removeEventListener('submit', handleSubmit);
      if (googleDisplayNameCancelBtn) {
        googleDisplayNameCancelBtn.removeEventListener('click', handleCancel);
      }
      googleDisplayNameDialog.removeEventListener('close', handleClose);
    };

    const finish = (value) => {
      if (completed) {
        return;
      }
      completed = true;
      cleanup();
      resolve(value);
    };

    const handleSubmit = (event) => {
      event.preventDefault();
      const value = (googleDisplayNameInput.value || '').trim();
      if (!value) {
        if (googleDisplayNameNotice) {
          googleDisplayNameNotice.style.color = '#b42318';
          googleDisplayNameNotice.textContent = 'Display name is required to continue.';
        }
        googleDisplayNameInput.focus();
        return;
      }
      if (googleDisplayNameTerms && !googleDisplayNameTerms.checked) {
        if (googleDisplayNameNotice) {
          googleDisplayNameNotice.style.color = '#b42318';
          googleDisplayNameNotice.textContent = 'Please accept the Terms of Service to continue.';
        }
        googleDisplayNameTerms.focus();
        return;
      }
      googleDisplayNameDialog.close('continue');
      finish({ displayName: value, tosAccepted: true });
    };

    const handleCancel = () => {
      googleDisplayNameDialog.close('cancel');
      finish(null);
    };

    const handleClose = () => {
      if (completed) {
        return;
      }
      finish(null);
    };

    googleDisplayNameForm.addEventListener('submit', handleSubmit);
    if (googleDisplayNameCancelBtn) {
      googleDisplayNameCancelBtn.addEventListener('click', handleCancel);
    }
    googleDisplayNameDialog.addEventListener('close', handleClose);
    googleDisplayNameDialog.showModal();
    googleDisplayNameInput.focus();
    googleDisplayNameInput.select();
  });
}

async function onGoogleCredential(response) {
  try {
    const registerIntent = isRegisterMode();
    let signupDisplayName = '';
    if (registerIntent) {
      const signupDetails = await requestSignupDetails(getSignupDisplayName());
      if (!signupDetails?.displayName || !signupDetails.tosAccepted) {
        loginNotice.style.color = '#b42318';
        loginNotice.textContent = 'Signup cancelled. Preferred name and ToS are required to create your account.';
        return;
      }
      signupDisplayName = signupDetails.displayName;
      if (registerName) {
        registerName.value = signupDisplayName;
      }
    }
    loginNotice.textContent = '';
    await api('/auth/google', {
      method: 'POST',
      body: JSON.stringify({
        credential: response.credential,
        intent: registerIntent ? 'register' : 'login',
        display_name: registerIntent ? signupDisplayName : undefined,
        tos_accepted: registerIntent,
      }),
    });
    await initSession();
  } catch (err) {
    loginNotice.textContent = String(err.message || err);
  }
}

async function registerManual(event) {
  event.preventDefault();
  try {
    if (registerTerms && !registerTerms.checked) {
      loginNotice.style.color = '#b42318';
      loginNotice.textContent = 'Please accept the Terms of Service before creating an account.';
      return;
    }
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

if (termsOpenBtn && termsDialog) {
  termsOpenBtn.addEventListener('click', () => {
    const isPortraitTermsMode = window.matchMedia('(max-width: 1080px) and (orientation: portrait)').matches;
    if (isPortraitTermsMode) {
      window.open('/terms.html', '_blank', 'noopener');
      return;
    }
    termsDialog.showModal();
  });
}

if (termsCloseBtn && termsDialog) {
  termsCloseBtn.addEventListener('click', () => {
    termsDialog.close();
  });
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
    const msg = String(err.message || err);
    if (msg.toLowerCase().includes('email not verified') || msg.toLowerCase().includes('not verified')) {
      loginNotice.style.color = '';
      loginNotice.innerHTML = '';
      const text = document.createElement('span');
      text.style.color = '#b42318';
      text.style.fontWeight = '600';
      text.textContent = 'Your email address has not been verified. ';
      const resendBtn = document.createElement('button');
      resendBtn.type = 'button';
      resendBtn.className = 'toggle-link';
      resendBtn.style.display = 'inline';
      resendBtn.style.fontSize = 'inherit';
      resendBtn.textContent = 'Resend verification email';
      resendBtn.addEventListener('click', async () => {
        resendBtn.disabled = true;
        resendBtn.textContent = 'Sending…';
        try {
          await api('/auth/resend-verification', {
            method: 'POST',
            body: JSON.stringify({ email: loginEmail.value.trim() }),
          });
          loginNotice.style.color = '';
          loginNotice.innerHTML = '';
          const ok = document.createElement('span');
          ok.style.color = '#027a48';
          ok.style.fontWeight = '600';
          ok.textContent = 'Verification email sent — check your inbox.';
          loginNotice.appendChild(ok);
        } catch (resendErr) {
          const retryAfter = resendErr?.payload?.retry_after;
          if (resendErr?.status === 429 && retryAfter && Number.isFinite(retryAfter)) {
            // Cooldown in effect — count down and re-enable when ready
            let remaining = Math.ceil(retryAfter);
            function tick() {
              if (remaining <= 0) {
                text.textContent = 'Your email address has not been verified. ';
                resendBtn.disabled = false;
                resendBtn.textContent = 'Resend verification email';
                return;
              }
              const m = Math.floor(remaining / 60);
              const s = remaining % 60;
              text.textContent = m > 0
                ? `Please wait ${m}m ${String(s).padStart(2, '0')}s before requesting again. `
                : `Please wait ${s}s before requesting again. `;
              remaining--;
              setTimeout(tick, 1000);
            }
            tick();
          } else if (resendErr?.status === 429) {
            // Daily limit reached — no retry today
            text.textContent = 'Daily limit of 3 verification emails reached. Try again tomorrow. ';
            resendBtn.disabled = true;
            resendBtn.textContent = 'Limit reached';
          } else {
            resendBtn.disabled = false;
            resendBtn.textContent = 'Resend verification email';
            text.textContent = 'Could not send verification email. Please try again. ';
          }
        }
      });
      loginNotice.appendChild(text);
      loginNotice.appendChild(resendBtn);
    } else {
      loginNotice.style.color = '#b42318';
      loginNotice.textContent = msg;
    }
  }
}

async function initSession() {
  try {
    const me = await api('/me', { method: 'GET' });
    currentUser = me;
    displayNameEl.textContent = me.display_name;
    emailEl.textContent = me.email;
    avatarEl.src = me.picture_url || 'https://www.gravatar.com/avatar/?d=mp';
    const isAdmin = Boolean(me.is_admin || Number(me.rank) >= 2 || me.role === 'admin' || me.role === 'super_admin');
    if (isAdmin) {
      adminLinkWrap.classList.remove('hidden');
    } else {
      adminLinkWrap.classList.add('hidden');
    }
    setViewMode(false);
    authCard.classList.add('hidden');
    appCard.classList.remove('hidden');
    selectedChatType = null;
    selectedConnectionId = null;
    selectedGroupId = null;
    activeConnectionName.textContent = 'Select a connection or group';
    chatHint.textContent = 'You can only chat with accepted connections or group members.';
    renderSimpleList(dmList, [], 'Choose a connection or group to start chatting.');
    await refreshSidebarData();
  } catch {
    currentUser = null;
    adminLinkWrap.classList.add('hidden');
    setViewMode(true);
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
  saveAuthMode('register');
  if (portraitWelcomeText) {
    portraitWelcomeText.textContent = "Welcome to TeamChat, let's get you started.";
  }
  if (authEyebrow) {
    authEyebrow.textContent = 'Create Account';
  }
  if (authTitle) {
    authTitle.textContent = '';
  }
  if (authSubtitle) {
    authSubtitle.textContent = 'Get started to experience search and connect, accept requests, private messaging, group chat.';
  }
  if (companySsoBtn) {
    companySsoBtn.textContent = 'Continue with SSO';
  }
  renderGoogleButtonForMode();
}

function showLoginMode() {
  if (!authStack) {
    return;
  }
  authStack.classList.add('mode-login');
  authStack.classList.remove('mode-register');
  saveAuthMode('login');
  if (portraitWelcomeText) {
    portraitWelcomeText.textContent = 'Welcome back to TeamChat';
  }
  if (authEyebrow) {
    authEyebrow.textContent = 'Sign In';
  }
  if (authTitle) {
    authTitle.textContent = '';
  }
  if (authSubtitle) {
    authSubtitle.textContent = '';
  }
  if (companySsoBtn) {
    companySsoBtn.textContent = 'Sign in with SSO';
  }
  renderGoogleButtonForMode();
}

if (dmForm) {
  dmForm.addEventListener('submit', async (event) => {
    event.preventDefault();
    const content = dmInput.value.trim();
    if (!content) {
      return;
    }
    try {
      if (selectedChatType === 'connection' && selectedConnectionId) {
        await api('/connections/messages', {
          method: 'POST',
          body: JSON.stringify({ recipient_user_id: selectedConnectionId, content }),
        });
      } else if (selectedChatType === 'group' && selectedGroupId) {
        await api(`/groups/${selectedGroupId}/messages`, {
          method: 'POST',
          body: JSON.stringify({ content }),
        });
      } else {
        return;
      }
      dmInput.value = '';
      if (charCount) {
        charCount.textContent = '0 / 2000';
      }
      if (selectedChatType === 'group') {
        await loadGroupMessages();
      } else {
        await loadDirectMessages();
      }
    } catch (err) {
      alert(String(err.message || err));
    }
  });
}

if (dmInput && charCount) {
  dmInput.addEventListener('input', () => {
    charCount.textContent = `${dmInput.value.length} / 2000`;
  });
}

logoutBtn.addEventListener('click', async () => {
  try {
    await api('/logout', { method: 'POST' });
  } finally {
    adminLinkWrap.classList.add('hidden');
    setViewMode(true);
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
if (connectionSearchForm) {
  connectionSearchForm.addEventListener('submit', async (event) => {
    try {
      await runUserSearch(event);
    } catch (err) {
      alert(String(err.message || err));
    }
  });
}
if (groupCreateForm) {
  groupCreateForm.addEventListener('submit', async (event) => {
    event.preventDefault();
    const name = groupNameInput.value.trim();
    if (name.length < 2) {
      return;
    }
    try {
      await api('/groups', {
        method: 'POST',
        body: JSON.stringify({ name }),
      });
      groupNameInput.value = '';
      await loadGroups();
    } catch (err) {
      alert(String(err.message || err));
    }
  });
}
if (groupMemberSearchForm) {
  groupMemberSearchForm.addEventListener('submit', async (event) => {
    try {
      await runGroupMemberSearch(event);
    } catch (err) {
      alert(String(err.message || err));
    }
  });
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

if (companySsoBtn) {
  companySsoBtn.addEventListener('click', async () => {
    const registerIntent = isRegisterMode();
    let signupDisplayName = '';
    if (registerIntent) {
      const signupDetails = await requestSignupDetails(getSignupDisplayName());
      if (!signupDetails?.displayName || !signupDetails.tosAccepted) {
        loginNotice.style.color = '#b42318';
        loginNotice.textContent = 'Signup cancelled. Preferred name and ToS are required to create your account.';
        return;
      }
      signupDisplayName = signupDetails.displayName;
      if (registerName) {
        registerName.value = signupDisplayName;
      }
    }

    pendingSsoIntent = registerIntent ? 'register' : 'login';
    pendingSsoDisplayName = registerIntent ? signupDisplayName : '';
    pendingSsoTosAccepted = registerIntent;
    if (!companySsoDialog || !companySsoDomainInput) {
      return;
    }

    companySsoDomainInput.value = 'acme.com';
    companySsoDialog.showModal();
    companySsoDomainInput.focus();
  });
}

if (companySsoCancelBtn && companySsoDialog) {
  companySsoCancelBtn.addEventListener('click', () => {
    companySsoDialog.close();
  });
}

if (companySsoForm) {
  companySsoForm.addEventListener('submit', (event) => {
    event.preventDefault();
    const company = (companySsoDomainInput?.value || '').trim();
    if (!company) {
      loginNotice.style.color = '#b42318';
      loginNotice.textContent = 'Company domain or name is required for Company SSO.';
      return;
    }

    companySsoDialog?.close();
    const params = new URLSearchParams({
      company,
      intent: pendingSsoIntent,
    });
    if (pendingSsoIntent === 'register' && pendingSsoDisplayName) {
      params.set('display_name', pendingSsoDisplayName);
      params.set('tos_accepted', pendingSsoTosAccepted ? '1' : '0');
    }
    const startUrl = `${apiBase}/auth/sso/oidc/start?${params.toString()}`;
    window.location.assign(startUrl);
  });
}

window.addEventListener('load', async () => {
  setViewMode(true);
  if (getSavedAuthMode() === 'register') {
    showRegisterMode();
  } else {
    showLoginMode();
  }
  const clientId = window.APP_CONFIG?.googleClientId || '';
  if (!clientId) {
    loginNotice.textContent = 'Google login is not configured. Add GOOGLE_CLIENT_ID in .env.';
  } else if (window.google?.accounts?.id) {
    window.google.accounts.id.initialize({
      client_id: clientId,
      callback: onGoogleCredential,
    });
    renderGoogleButtonForMode();
  }

  await initSession();
});
