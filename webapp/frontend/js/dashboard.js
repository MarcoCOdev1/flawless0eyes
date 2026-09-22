/**
 * dashboard.js — Main dashboard logic
 * Scan runner, SSE progress, history table, pagination
 */

document.addEventListener('DOMContentLoaded', async () => {
  const { Auth, Scans, Toast, ApiError, createElement, timeAgo, formatDate } = window.OSINT;

  // ── Auth guard ──────────────────────────────────────────────────────────────
  let currentUser = null;
  try {
    const res = await Auth.me();
    currentUser = res.user;
    // Display email
    const userEmailEl = document.getElementById('user-email');
    if (userEmailEl) userEmailEl.textContent = currentUser.email;
    const userAvatarEl = document.getElementById('user-avatar');
    if (userAvatarEl) userAvatarEl.textContent = currentUser.email[0].toUpperCase();
  } catch {
    window.location.href = '/login';
    return;
  }

  // ── Logout ──────────────────────────────────────────────────────────────────
  document.getElementById('logout-btn')?.addEventListener('click', async () => {
    try {
      await Auth.logout();
    } finally {
      window.location.href = '/login';
    }
  });

  // ── Sidebar navigation ──────────────────────────────────────────────────────
  const views = { 'new-scan': true, 'history': false };
  const navItems = document.querySelectorAll('.nav-item[data-view]');

  function showView(viewName) {
    document.querySelectorAll('.view-panel').forEach(p => {
      p.classList.toggle('hidden', p.dataset.view !== viewName);
    });
    navItems.forEach(item => {
      item.classList.toggle('active', item.dataset.view === viewName);
    });
    if (viewName === 'history') loadHistory(1);
  }

  navItems.forEach(item => {
    item.addEventListener('click', () => showView(item.dataset.view));
  });

  // ── Module Tabs ─────────────────────────────────────────────────────────────
  const MODULE_CONFIGS = {
    domain:   { icon: '🌐', label: 'Domain',    hint: 'e.g. example.com',          desc: 'WHOIS, DNS records, subdomain enumeration via crt.sh' },
    username: { icon: '👤', label: 'Username',  hint: 'e.g. john_doe',             desc: 'Check handle existence across 58+ platforms' },
    breach:   { icon: '🔓', label: 'Breach',    hint: 'e.g. user@example.com',     desc: 'Email breach exposure via Have I Been Pwned' },
    search:   { icon: '🔍', label: 'Search',    hint: 'e.g. acme corp fraud',      desc: 'Web search via Google CSE / Bing / DuckDuckGo' },
    entity:   { icon: '🏢', label: 'Entity',    hint: 'e.g. Jane Smith Acme Corp', desc: '24 Google-dork queries: news, filings, court records, leaks' },
    dork:     { icon: '🎯', label: 'Dork',      hint: 'e.g. site:acme.com filetype:pdf', desc: 'Hand-crafted search query with full operator support' },
    metadata: { icon: '📄', label: 'Metadata',  hint: 'file path or URL',          desc: 'Extract embedded metadata from PDFs and images' },
    full:     { icon: '⚡', label: 'Full Scan', hint: 'e.g. example.com',          desc: 'Domain + username + breach + search + entity in one pass' },
  };

  let activeModule = 'domain';
  const moduleTabsEl = document.getElementById('module-tabs');
  const targetInput  = document.getElementById('scan-target');
  const targetHint   = document.getElementById('scan-target-hint');
  const moduleDesc   = document.getElementById('module-desc');
  const extraFields  = document.getElementById('extra-fields');

  // Build tabs
  Object.entries(MODULE_CONFIGS).forEach(([key, cfg]) => {
    const tab = createElement('button', `module-tab${key === activeModule ? ' active' : ''}`);
    tab.dataset.module = key;
    tab.setAttribute('type', 'button');

    const icon  = createElement('span', 'module-tab-icon', cfg.icon);
    const label = createElement('span', 'module-tab-label', cfg.label);
    tab.appendChild(icon);
    tab.appendChild(label);

    tab.addEventListener('click', () => selectModule(key));
    moduleTabsEl?.appendChild(tab);
  });

  function selectModule(key) {
    activeModule = key;
    document.querySelectorAll('.module-tab').forEach(t => {
      t.classList.toggle('active', t.dataset.module === key);
    });
    const cfg = MODULE_CONFIGS[key];
    if (targetHint)  targetHint.textContent  = cfg.hint;
    if (moduleDesc)  moduleDesc.textContent   = cfg.desc;
    if (targetInput) targetInput.placeholder  = cfg.hint;
    // Show/hide extra fields for full scan
    if (extraFields) extraFields.classList.toggle('hidden', key !== 'full');
    // Reset input
    if (targetInput) targetInput.value = '';
  }
  selectModule('domain');

  // ── Scan Form Submission ────────────────────────────────────────────────────
  const scanForm      = document.getElementById('scan-form');
  const scanSubmitBtn = document.getElementById('scan-submit-btn');
  const terminalEl    = document.getElementById('terminal-panel');
  const terminalBody  = document.getElementById('terminal-body');
  const terminalTitle = document.getElementById('terminal-title');
  let currentEventSource = null;

  scanForm?.addEventListener('submit', async (e) => {
    e.preventDefault();

    const target = targetInput?.value.trim();
    if (!target) {
      Toast.error('Please enter a target');
      targetInput?.focus();
      return;
    }

    // Gather extras for full scan
    const extras = {};
    if (activeModule === 'full') {
      const u  = document.getElementById('extra-username')?.value.trim();
      const em = document.getElementById('extra-email')?.value.trim();
      const en = document.getElementById('extra-entity')?.value.trim();
      if (u)  extras.username    = u;
      if (em) extras.email       = em;
      if (en) extras.entity_name = en;
    }

    // Close any existing stream
    currentEventSource?.close();
    clearTerminal();
    showTerminal();

    setSubmitLoading(true);
    addTerminalLine(`> Starting ${activeModule} scan on: ${target}`, 'info');

    let scanId;
    try {
      const res = await Scans.run(activeModule, target, extras);
      scanId = res.scan_id;
      addTerminalLine(`Scan ID: ${scanId} — streaming live output...`, 'info');
    } catch (err) {
      const msg = err instanceof ApiError ? err.data?.error || err.message : 'Failed to start scan';
      addTerminalLine(`Error: ${msg}`, 'error');
      setSubmitLoading(false);
      Toast.error(msg);
      return;
    }

    // Stream SSE progress
    currentEventSource = Scans.streamStatus(scanId, {
      onLog: (message, level) => addTerminalLine(message, level),
      onDone: (status, error) => {
        setSubmitLoading(false);
        if (status === 'done') {
          addTerminalLine('✅ Scan complete! View in History.', 'success');
          Toast.success('Scan completed successfully!');
          // Update history badge
          updateHistoryBadge();
        } else {
          addTerminalLine(`❌ Scan failed: ${error || 'Unknown error'}`, 'error');
          Toast.error('Scan failed — see terminal for details');
        }
        // Show "View Report" button
        showViewReportBtn(scanId, status === 'done');
      },
      onError: (msg) => {
        addTerminalLine(`Connection error: ${msg}`, 'error');
        setSubmitLoading(false);
      },
    });
  });

  function setSubmitLoading(loading) {
    if (!scanSubmitBtn) return;
    scanSubmitBtn.disabled = loading;
    const textEl = scanSubmitBtn.querySelector('.btn-text');
    const spinEl = scanSubmitBtn.querySelector('.btn-spinner');
    if (textEl)  textEl.textContent = loading ? 'Scanning...' : 'Run Scan';
    if (spinEl)  spinEl.classList.toggle('hidden', !loading);
  }

  function showTerminal() {
    terminalEl?.classList.remove('hidden');
    if (terminalTitle) terminalTitle.textContent = `osint-agent • ${activeModule} scan`;
  }

  function clearTerminal() {
    if (terminalBody) terminalBody.innerHTML = '';
  }

  function addTerminalLine(message, level = 'info') {
    if (!terminalBody) return;
    const line = createElement('div', `terminal-line level-${level}`);
    const prompt = createElement('span', 'terminal-line-prompt', '>');
    const text   = createElement('span', 'terminal-line-text', message);
    line.appendChild(prompt);
    line.appendChild(text);
    terminalBody.appendChild(line);
    // Auto-scroll
    terminalBody.scrollTop = terminalBody.scrollHeight;
  }

  function showViewReportBtn(scanId, success) {
    const existingBtn = document.getElementById('view-report-btn');
    if (existingBtn) existingBtn.remove();
    if (!success) return;

    const btn = createElement('a', 'btn btn-ghost btn-sm', '📋 View Full Report');
    btn.id = 'view-report-btn';
    btn.href = `/report?id=${scanId}`;
    btn.style.marginTop = '8px';

    const actionsEl = document.getElementById('scan-actions');
    actionsEl?.appendChild(btn);
  }

  function updateHistoryBadge() {
    const badge = document.getElementById('history-badge');
    if (badge) {
      const count = parseInt(badge.textContent || '0', 10) + 1;
      badge.textContent = String(count);
    }
  }

  // ── Scan History ────────────────────────────────────────────────────────────
  let historyCurrentPage = 1;
  const historyTbody = document.getElementById('history-tbody');
  const historyEmpty = document.getElementById('history-empty');
  const paginationEl = document.getElementById('pagination');

  async function loadHistory(page = 1) {
    historyCurrentPage = page;
    if (historyTbody) historyTbody.innerHTML = '';
    if (historyEmpty) historyEmpty.classList.add('hidden');

    // Show skeleton loading
    for (let i = 0; i < 5; i++) {
      const row = historyTbody?.insertRow();
      if (row) {
        row.innerHTML = '<td colspan="6" style="padding:14px 20px;"><div style="height:14px;background:rgba(255,255,255,0.04);border-radius:6px;width:100%;"></div></td>';
      }
    }

    try {
      const res = await Scans.list(page, 20);
      if (historyTbody) historyTbody.innerHTML = '';

      if (!res.scans || res.scans.length === 0) {
        historyEmpty?.classList.remove('hidden');
        if (paginationEl) paginationEl.innerHTML = '';
        return;
      }

      res.scans.forEach(scan => renderHistoryRow(scan));
      renderPagination(res.page, res.pages, res.total);

      // Update badge
      const badge = document.getElementById('history-badge');
      if (badge) badge.textContent = res.total;

    } catch (err) {
      if (historyTbody) historyTbody.innerHTML = '';
      Toast.error('Failed to load scan history');
    }
  }

  function renderHistoryRow(scan) {
    if (!historyTbody) return;
    const row = historyTbody.insertRow();

    // Module chip
    const moduleTd = row.insertCell();
    const chip = createElement('span', 'history-module-chip', scan.module);
    moduleTd.appendChild(chip);

    // Target
    const targetTd = row.insertCell();
    const targetSpan = createElement('span', 'history-target', scan.target);
    targetSpan.title = scan.target;
    targetTd.appendChild(targetSpan);

    // Status badge
    const statusTd = row.insertCell();
    const badge = createElement('span', `badge badge-${scan.status}`, scan.status);
    // Add pulse dot for running
    if (scan.status === 'running') {
      const dot = createElement('span', '');
      dot.style.cssText = 'width:6px;height:6px;background:currentColor;border-radius:50%;display:inline-block;';
      badge.prepend(dot);
    }
    statusTd.appendChild(badge);

    // Time
    const timeTd = row.insertCell();
    const timeSpan = createElement('span', 'history-time', timeAgo(scan.created_at));
    timeSpan.title = formatDate(scan.created_at);
    timeTd.appendChild(timeSpan);

    // Duration
    const durTd = row.insertCell();
    if (scan.completed_at && scan.created_at) {
      const ms = new Date(scan.completed_at) - new Date(scan.created_at);
      const s = Math.round(ms / 1000);
      durTd.textContent = s < 60 ? `${s}s` : `${Math.floor(s/60)}m ${s%60}s`;
      durTd.style.color = 'var(--color-text-muted)';
      durTd.style.fontSize = '12px';
    } else {
      durTd.textContent = '—';
    }

    // Actions
    const actionsTd = row.insertCell();
    const actionsDiv = createElement('div', 'history-actions');

    if (scan.status === 'done') {
      const viewBtn = createElement('a', 'btn btn-ghost btn-sm', '📋 Report');
      viewBtn.href = `/report?id=${scan.id}`;
      actionsDiv.appendChild(viewBtn);
    }

    const deleteBtn = createElement('button', 'btn btn-danger btn-sm', '🗑');
    deleteBtn.title = 'Delete scan';
    deleteBtn.setAttribute('type', 'button');
    deleteBtn.addEventListener('click', () => deleteScan(scan.id, row));
    actionsDiv.appendChild(deleteBtn);

    actionsTd.appendChild(actionsDiv);
  }

  async function deleteScan(scanId, rowEl) {
    if (!confirm('Delete this scan and its report?')) return;
    try {
      await Scans.deleteScan(scanId);
      rowEl.style.transition = 'opacity 0.2s ease, transform 0.2s ease';
      rowEl.style.opacity = '0';
      rowEl.style.transform = 'translateX(-10px)';
      setTimeout(() => rowEl.remove(), 200);
      Toast.success('Scan deleted');
    } catch (err) {
      Toast.error(err instanceof ApiError ? err.message : 'Delete failed');
    }
  }

  function renderPagination(page, pages, total) {
    if (!paginationEl) return;
    paginationEl.innerHTML = '';
    if (pages <= 1) return;

    const prevBtn = createElement('button', 'page-btn', '‹');
    prevBtn.disabled = page <= 1;
    prevBtn.addEventListener('click', () => loadHistory(page - 1));
    paginationEl.appendChild(prevBtn);

    for (let i = 1; i <= pages; i++) {
      if (pages > 7 && Math.abs(i - page) > 2 && i !== 1 && i !== pages) {
        if (i === page - 3 || i === page + 3) {
          paginationEl.appendChild(createElement('span', 'page-btn text-muted', '…'));
        }
        continue;
      }
      const btn = createElement('button', `page-btn${i === page ? ' active' : ''}`, String(i));
      btn.addEventListener('click', () => loadHistory(i));
      paginationEl.appendChild(btn);
    }

    const nextBtn = createElement('button', 'page-btn', '›');
    nextBtn.disabled = page >= pages;
    nextBtn.addEventListener('click', () => loadHistory(page + 1));
    paginationEl.appendChild(nextBtn);
  }

  // ── Initial load ────────────────────────────────────────────────────────────
  showView('new-scan');
  // Preload history count
  Scans.list(1, 1).then(res => {
    const badge = document.getElementById('history-badge');
    if (badge && res.total > 0) badge.textContent = res.total;
  }).catch(() => {});
});
