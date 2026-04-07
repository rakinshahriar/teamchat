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
const loginEmail = document.getElementById('loginEmail');
const loginPassword = document.getElementById('loginPassword');
const authStack = document.getElementById('authStack');
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
    const btn = document.createElement('button');
    btn.type = 'button';
    btn.className = selectedChatType === 'group' && selectedGroupId === group.id ? 'active-connection' : 'ghost';
    btn.textContent = group.name;
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
    item.appendChild(btn);
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
