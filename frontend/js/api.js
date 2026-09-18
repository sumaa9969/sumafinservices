// Point this at your deployed backend URL. Defaults to relative '/api',
// which works when this frontend is served BY the backend itself
// (http://localhost:5000/login.html) — the recommended way to run this
// locally. If you open these HTML files directly from disk (file://) or
// host the frontend separately, set window.API_BASE before this script
// loads, e.g. <script>window.API_BASE = 'http://localhost:5000/api';</script>
const API_BASE = window.API_BASE || (location.protocol === 'file:' ? 'http://localhost:5000/api' : '/api');

function getToken() {
  return localStorage.getItem('token');
}

function getUser() {
  try {
    return JSON.parse(localStorage.getItem('user') || 'null');
  } catch {
    return null;
  }
}

function saveSession(token, user) {
  localStorage.setItem('token', token);
  localStorage.setItem('user', JSON.stringify(user));
}

function clearSession() {
  localStorage.removeItem('token');
  localStorage.removeItem('user');
}

function logout() {
  clearSession();
  window.location.href = 'login.html';
}

// Redirect helpers used at the top of protected pages
function requireAuth() {
  const token = getToken();
  if (!token) {
    window.location.href = 'login.html';
    return null;
  }
  return getUser();
}

function requireAdmin() {
  const user = requireAuth();
  if (user && user.role !== 'admin') {
    window.location.href = 'dashboard.html';
    return null;
  }
  return user;
}

function requireUser() {
  const user = requireAuth();
  if (user && user.role === 'admin') {
    window.location.href = 'admin-dashboard.html';
    return null;
  }
  return user;
}

async function apiFetch(path, options = {}) {
  const headers = Object.assign(
    { 'Content-Type': 'application/json' },
    options.headers || {}
  );
  const token = getToken();
  if (token) headers['Authorization'] = 'Bearer ' + token;

  const res = await fetch(API_BASE + path, Object.assign({}, options, { headers }));

  let data = null;
  try {
    data = await res.json();
  } catch {
    data = null;
  }

  if (res.status === 401 || res.status === 403) {
    if (data && data.error === 'Admin access only') {
      throw new Error(data.error);
    }
    // Expired/invalid token -> force re-login
    clearSession();
    window.location.href = 'login.html';
    throw new Error((data && data.error) || 'Session expired');
  }

  if (!res.ok) {
    throw new Error((data && data.error) || 'Something went wrong');
  }

  return data;
}

function formatMoney(n) {
  const num = Number(n || 0);
  return '$' + num.toLocaleString(undefined, { minimumFractionDigits: 2, maximumFractionDigits: 2 });
}

function formatDate(d) {
  if (!d) return '-';
  const dt = new Date(d.replace(' ', 'T') + 'Z');
  if (isNaN(dt.getTime())) return d;
  return dt.toLocaleString();
}

// Adds/refreshes a small unread-count badge on the topbar notification bell
// so users are alerted to new notifications on every page, not just after
// they open the Notifications page. Safe to call on any authenticated page.
async function initNotifBadge() {
  const link = document.getElementById('notifBellBtn')
    || document.querySelector('.sidebar nav a[href="notifications.html"], .sidebar nav a[href="admin-notifications.html"]');
  if (!link) return;

  let badge = link.querySelector('.nav-badge');
  if (!badge) {
    badge = document.createElement('span');
    badge.className = 'nav-badge';
    link.appendChild(badge);
  }

  try {
    const data = await apiFetch('/user/notifications/unread-count');
    const count = data.unread_count || 0;
    if (count > 0) {
      badge.textContent = count > 9 ? '9+' : String(count);
      badge.style.display = 'inline-block';
    } else {
      badge.style.display = 'none';
    }
  } catch {
    badge.style.display = 'none';
  }
}

// Wires up the topbar logout icon on every page automatically. Safe no-op
// on pages that don't have this element (e.g. login/register).
// Note: the mobile hamburger drawer has been removed — this app now always
// renders the laptop/desktop layout, so the sidebar is permanently visible
// and .hamburger-btn / .sidebar-overlay are unused.
document.addEventListener('DOMContentLoaded', () => {
  const logoutEl = document.getElementById('logoutLink');
  if (logoutEl && !logoutEl.dataset.boundLogout) {
    logoutEl.dataset.boundLogout = '1';
    logoutEl.addEventListener('click', (e) => {
      e.preventDefault();
      logout();
    });
  }
});

function showBox(el, message, isError = true) {
  el.textContent = message;
  el.style.display = message ? 'block' : 'none';
  el.className = isError ? 'error-box' : 'success-box';
  el.style.display = 'block';
}
