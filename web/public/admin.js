const computedApiBase = `${window.location.protocol}//${window.location.hostname}:8000`;
const apiBase = window.APP_CONFIG?.apiBase || computedApiBase;

const refreshBtn = document.getElementById('refreshBtn');
const adminStatus = document.getElementById('adminStatus');
const rankTree = document.getElementById('rankTree');
const bannedList = document.getElementById('bannedList');
const eventsDump = document.getElementById('eventsDump');
const actionStatus = document.getElementById('actionStatus');
const userSearch = document.getElementById('userSearch');
const bannedPanelTile = document.getElementById('bannedPanelTile');
const securityPanelTile = document.getElementById('securityPanelTile');

let currentUser = null;
let allUsers = [];

async function api(path, options = {}) {
  const res = await fetch(`${apiBase}${path}`, {
    ...options,
    headers: {
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
    throw new Error(payload.detail || `Request failed (${res.status})`);
  }
  return payload;
}

function rankLabel(value) {
  return `Rank ${value}`;
}

function makeActionButton(text, action, userId) {
  const btn = document.createElement('button');
  btn.type = 'button';
  btn.textContent = text;
  btn.addEventListener('click', async () => {
    try {
      actionStatus.textContent = '';
      let requestBody = { user_id: userId };
      if (action === 'ban') {
        const reason = prompt('Ban reason (required):')?.trim() || '';
        if (!reason) {
          actionStatus.style.color = '#b42318';
          actionStatus.textContent = 'Ban reason is required.';
          return;
        }
        requestBody = { user_id: userId, reason };
      }
      await api(`/admin/users/${action}`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(requestBody),
      });
      actionStatus.style.color = '#027a48';
      actionStatus.textContent = `${text} completed.`;
      await refresh();
    } catch (err) {
      actionStatus.style.color = '#b42318';
      actionStatus.textContent = String(err.message || err);
    }
  });
  return btn;
}

function renderRankTree(users) {
  rankTree.innerHTML = '';
  const byRank = new Map();
  for (let rank = 7; rank >= 1; rank -= 1) {
    byRank.set(rank, []);
  }
  users.forEach((u) => {
    const rank = Number(u.rank || 1);
    if (!byRank.has(rank)) {
      byRank.set(rank, []);
    }
    byRank.get(rank).push(u);
  });

  for (let rank = 7; rank >= 1; rank -= 1) {
    const usersAtRank = byRank.get(rank) || [];
    if (usersAtRank.length === 0) {
      continue;
    }

    const rankBox = document.createElement('details');
    rankBox.className = 'rank-box';
    rankBox.open = rank >= 5;

    const summary = document.createElement('summary');
    summary.textContent = `${rankLabel(rank)} (${usersAtRank.length})`;
    rankBox.appendChild(summary);

    const usersWrap = document.createElement('div');
    usersWrap.className = 'rank-users';

    usersAtRank.forEach((u) => {
      const card = document.createElement('details');
      card.className = 'user-box';

      const head = document.createElement('summary');
      head.textContent = `${u.display_name || 'User'} - ${u.email} - ${rankLabel(u.rank)}`;
      card.appendChild(head);

      const body = document.createElement('div');
      body.className = 'user-box-body';

      const meta = document.createElement('p');
      meta.className = 'sub';
      meta.textContent = `Verified: ${u.email_verified ? 'yes' : 'no'}`;
      body.appendChild(meta);

      const actions = document.createElement('div');
      actions.className = 'row';

      const isSelf = currentUser && currentUser.id === u.id;
      const actorRank = Number(currentUser?.rank || 1);
      const targetRank = Number(u.rank || 1);
      const diff = actorRank - targetRank;

      if (!isSelf && !u.is_banned && actorRank > 2 && diff >= 1 && targetRank > 1) {
        actions.appendChild(makeActionButton('Demote', 'demote', u.id));
      }
      if (!isSelf && !u.is_banned && diff >= 2) {
        actions.appendChild(makeActionButton('Promote', 'promote', u.id));
        actions.appendChild(makeActionButton('Ban', 'ban', u.id));
      }
      if (!isSelf && u.is_banned && diff >= 2) {
        actions.appendChild(makeActionButton('Unban', 'unban', u.id));
      }

      if (actions.childElementCount === 0) {
        const noAction = document.createElement('small');
        noAction.textContent = 'No direct actions available for this user from your current rank.';
        actions.appendChild(noAction);
      }

      body.appendChild(actions);
      card.appendChild(body);
      usersWrap.appendChild(card);
    });

    rankBox.appendChild(usersWrap);
    rankTree.appendChild(rankBox);
  }

  if (rankTree.childElementCount === 0) {
    const empty = document.createElement('p');
    empty.className = 'sub';
    empty.textContent = 'No active users match this view.';
    rankTree.appendChild(empty);
  }
}

function renderBannedPanel(users) {
  bannedList.innerHTML = '';
  if (!users.length) {
    const empty = document.createElement('p');
    empty.className = 'sub';
    empty.textContent = 'No banned users.';
    bannedList.appendChild(empty);
    return;
  }

  users.forEach((u) => {
    const card = document.createElement('div');
    card.className = 'banned-user';

    const title = document.createElement('div');
    title.textContent = `${u.display_name || 'User'} - ${u.email}`;
    card.appendChild(title);

    const meta = document.createElement('small');
    const byRank = u.banned_by_rank ? ` by rank ${u.banned_by_rank}` : '';
    const reason = u.banned_reason ? ` | Reason: ${u.banned_reason}` : '';
    meta.textContent = `Stored at Rank ${u.rank}${byRank}${reason}`;
    card.appendChild(meta);

    const actorRank = Number(currentUser?.rank || 1);
    const targetRank = Number(u.rank || 1);
    const bannedByRank = Number(u.banned_by_rank || 0);
    const canUnban =
      currentUser &&
      currentUser.id !== u.id &&
      actorRank >= targetRank + 2 &&
      (!bannedByRank || actorRank > bannedByRank || actorRank >= 7);

    if (canUnban) {
      card.appendChild(makeActionButton('Unban', 'unban', u.id));
    }

    bannedList.appendChild(card);
  });
}

function renderAll(filteredUsers) {
  const active = filteredUsers.filter((u) => !u.is_banned);
  const banned = filteredUsers.filter((u) => u.is_banned);
  renderRankTree(active);
  renderBannedPanel(banned);
}

async function refresh() {
  try {
    adminStatus.textContent = '';
    actionStatus.textContent = '';
    currentUser = await api('/me');
    const users = await api('/admin/users');
    const events = await api('/admin/security-events?limit=50');
    allUsers = users.users || [];
    renderAll(allUsers);
    eventsDump.textContent = JSON.stringify(events.events, null, 2);
  } catch (err) {
    adminStatus.textContent = String(err.message || err);
  }
}

refreshBtn.addEventListener('click', refresh);
if (userSearch) {
  userSearch.addEventListener('input', () => {
    const q = userSearch.value.trim().toLowerCase();
    if (!q) {
      renderAll(allUsers);
      return;
    }
    const filtered = allUsers.filter((u) => {
      const hay = `${u.email || ''} ${u.display_name || ''}`.toLowerCase();
      return hay.includes(q);
    });
    renderAll(filtered);
  });
}
window.addEventListener('load', refresh);
window.addEventListener('load', () => {
  if (bannedPanelTile) {
    bannedPanelTile.open = false;
  }
  if (securityPanelTile) {
    securityPanelTile.open = false;
  }
});
