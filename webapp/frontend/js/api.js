/**
 * api.js — Centralized API client for OSINT Agent
 *
 * Security rules:
 *  - Never logs response bodies that might contain sensitive data
 *  - Automatically redirects to /login on 401
 *  - All requests send credentials (cookies) — JWT in httpOnly cookies
 *  - Never stores tokens in localStorage or sessionStorage
 */

const API_BASE = '/api';

class ApiError extends Error {
  constructor(message, status, data) {
    super(message);
    this.status = status;
    this.data = data;
    this.name = 'ApiError';
  }
}

/**
 * Core fetch wrapper.
 * - Attaches credentials for cookie-based JWT
 * - Returns parsed JSON or throws ApiError
 * - Handles 401 → redirect to login
 */
async function apiFetch(path, options = {}) {
  const url = `${API_BASE}${path}`;
  const config = {
    credentials: 'include',          // Always send httpOnly cookies
    headers: {
      'Content-Type': 'application/json',
      'Accept': 'application/json',
      ...(options.headers || {}),
    },
    ...options,
  };

  // Remove Content-Type for FormData (browser sets boundary automatically)
  if (options.body instanceof FormData) {
    delete config.headers['Content-Type'];
  }

  let response;
  try {
    response = await fetch(url, config);
  } catch (networkErr) {
    throw new ApiError('Network error — server may be offline', 0, null);
  }

  // Auto-refresh: try token refresh on 401 (token_expired), then retry once
  if (response.status === 401) {
    const data = await response.json().catch(() => ({}));
    if (data.code === 'token_expired') {
      const refreshed = await _tryRefreshToken();
      if (refreshed) {
        // Retry original request once
        return apiFetch(path, options);
      }
    }
    // Not refreshable — redirect to login
    if (!path.startsWith('/auth/')) {
      window.location.href = '/login';
    }
    throw new ApiError(data.error || 'Unauthorized', 401, data);
  }

  // Parse response body
  let body;
  const contentType = response.headers.get('Content-Type') || '';
  if (contentType.includes('application/json')) {
    body = await response.json();
  } else {
    body = await response.text();
  }

  if (!response.ok) {
    const message = (typeof body === 'object' && body.error) ? body.error : `HTTP ${response.status}`;
    throw new ApiError(message, response.status, body);
  }

  return body;
}

async function _tryRefreshToken() {
  try {
    await fetch(`${API_BASE}/auth/refresh`, {
      method: 'POST',
      credentials: 'include',
      headers: { 'Content-Type': 'application/json' },
    });
    return true;
  } catch {
    return false;
  }
}

// ── Auth API ──────────────────────────────────────────────────────────────────

const Auth = {
  async register(email, password) {
    return apiFetch('/auth/register', {
      method: 'POST',
      body: JSON.stringify({ email, password }),
    });
  },

  async login(email, password) {
    return apiFetch('/auth/login', {
      method: 'POST',
      body: JSON.stringify({ email, password }),
    });
  },

  async logout() {
    return apiFetch('/auth/logout', { method: 'POST' });
  },

  async me() {
    return apiFetch('/auth/me');
  },
};

// ── Scan API ──────────────────────────────────────────────────────────────────

const Scans = {
  async run(module, target, extras = {}) {
    return apiFetch('/scan/run', {
      method: 'POST',
      body: JSON.stringify({ module, target, ...extras }),
    });
  },

  async list(page = 1, perPage = 20) {
    return apiFetch(`/scan/list?page=${page}&per_page=${perPage}`);
  },

  async getReport(scanId) {
    return apiFetch(`/scan/report/${scanId}`);
  },

  async deleteScan(scanId) {
    return apiFetch(`/scan/${scanId}`, { method: 'DELETE' });
  },

  /**
   * Open a Server-Sent Events stream for live scan progress.
   * Returns an EventSource instance (caller must call .close() when done).
   *
   * @param {number} scanId
   * @param {object} callbacks - { onLog, onDone, onError }
   */
  streamStatus(scanId, { onLog, onDone, onError } = {}) {
    // EventSource always sends cookies (for httpOnly JWT)
    const es = new EventSource(`/api/scan/status/${scanId}`, { withCredentials: true });

    es.onmessage = (event) => {
      let msg;
      try {
        msg = JSON.parse(event.data);
      } catch {
        return;
      }

      if (msg.type === 'log' && onLog) {
        onLog(msg.message, msg.level || 'info');
      } else if (msg.type === 'done') {
        if (onDone) onDone(msg.status, msg.error);
        es.close();
      }
    };

    es.onerror = () => {
      if (onError) onError('Connection lost');
      es.close();
    };

    return es;
  },
};

// ── Toast Notifications ───────────────────────────────────────────────────────

const Toast = (() => {
  let container = null;

  function _getContainer() {
    if (!container) {
      container = document.createElement('div');
      container.className = 'toast-container';
      document.body.appendChild(container);
    }
    return container;
  }

  function show(message, type = 'info', duration = 4000) {
    const c = _getContainer();
    const toast = document.createElement('div');
    toast.className = `toast toast-${type}`;

    const icon = type === 'success' ? '✓' : type === 'error' ? '✕' : 'ℹ';
    const iconEl = document.createElement('span');
    iconEl.textContent = icon;

    const msgEl = document.createElement('span');
    msgEl.textContent = message; // textContent — XSS safe

    toast.appendChild(iconEl);
    toast.appendChild(msgEl);
    c.appendChild(toast);

    setTimeout(() => {
      toast.classList.add('toast-exit');
      setTimeout(() => toast.remove(), 300);
    }, duration);
  }

  return {
    success: (msg, d) => show(msg, 'success', d),
    error:   (msg, d) => show(msg, 'error', d),
    info:    (msg, d) => show(msg, 'info', d),
  };
})();

// ── Safe DOM Utilities ────────────────────────────────────────────────────────

/**
 * Safely set text content of an element (XSS-safe, no innerHTML)
 */
function setText(selector, text) {
  const el = typeof selector === 'string' ? document.querySelector(selector) : selector;
  if (el) el.textContent = String(text ?? '');
}

/**
 * Safely create an element with text content
 */
function createElement(tag, className, text) {
  const el = document.createElement(tag);
  if (className) el.className = className;
  if (text !== undefined) el.textContent = String(text);
  return el;
}

/**
 * Format relative time (e.g. "2 minutes ago")
 */
function timeAgo(isoString) {
  if (!isoString) return '—';
  const date = new Date(isoString);
  const seconds = Math.floor((Date.now() - date.getTime()) / 1000);
  if (seconds < 60) return 'just now';
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`;
  return `${Math.floor(seconds / 86400)}d ago`;
}

/**
 * Format a date for display
 */
function formatDate(isoString) {
  if (!isoString) return '—';
  return new Date(isoString).toLocaleString(undefined, {
    year: 'numeric', month: 'short', day: 'numeric',
    hour: '2-digit', minute: '2-digit',
  });
}

// ── Exports (module-style without bundler) ────────────────────────────────────
window.OSINT = window.OSINT || {};
Object.assign(window.OSINT, { Auth, Scans, Toast, ApiError, setText, createElement, timeAgo, formatDate });
