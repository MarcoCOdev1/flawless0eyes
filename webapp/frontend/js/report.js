/**
 * report.js — Report detail page
 * Loads and renders a saved scan report with XSS-safe templating
 */

document.addEventListener('DOMContentLoaded', async () => {
  const { Auth, Scans, Toast, ApiError, createElement, formatDate, timeAgo } = window.OSINT;

  // ── Auth guard ──────────────────────────────────────────────────────────────
  try {
    await Auth.me();
  } catch {
    window.location.href = '/login';
    return;
  }

  // ── Get scan ID from URL ────────────────────────────────────────────────────
  const params = new URLSearchParams(window.location.search);
  const scanId = parseInt(params.get('id'), 10);
  if (!scanId) {
    showError('No scan ID provided');
    return;
  }

  // ── Load report ─────────────────────────────────────────────────────────────
  const loadingEl = document.getElementById('report-loading');
  const contentEl = document.getElementById('report-content');

  try {
    const data = await Scans.getReport(scanId);
    const { scan, report } = data;
    const findings = report?.findings || {};

    if (loadingEl) loadingEl.classList.add('hidden');
    if (contentEl) contentEl.classList.remove('hidden');

    // Update page title (safe — textContent only)
    document.title = `Report: ${scan.module} — ${scan.target} | OSINT Agent`;

    // Set header info
    safeSetText('report-module', scan.module.toUpperCase());
    safeSetText('report-target', scan.target);
    safeSetText('report-date', formatDate(scan.created_at));
    safeSetText('report-scan-id', `#${scan.id}`);

    // Render sections based on module
    renderReport(scan, findings);

    // Download buttons
    document.getElementById('download-json-btn')?.addEventListener('click', () => {
      downloadJson(findings, `osint_${scan.module}_${scan.target}_${scan.id}.json`);
    });
    document.getElementById('download-md-btn')?.addEventListener('click', () => {
      downloadText(report.markdown || '', `osint_${scan.module}_${scan.target}_${scan.id}.md`);
    });

  } catch (err) {
    if (loadingEl) loadingEl.classList.add('hidden');
    const msg = err instanceof ApiError ? err.message : 'Failed to load report';
    showError(msg);
  }

  // ── Report Renderer ─────────────────────────────────────────────────────────
  function renderReport(scan, findings) {
    const container = document.getElementById('report-sections');
    if (!container) return;
    container.innerHTML = '';

    const { module } = scan;

    if (findings.domain || module === 'domain') {
      container.appendChild(renderDomainSection(findings.domain));
    }
    if (findings.username || module === 'username') {
      container.appendChild(renderUsernameSection(findings.username));
    }
    if (findings.breach || module === 'breach') {
      container.appendChild(renderBreachSection(findings.breach));
    }
    if (findings.search || module === 'search' || module === 'dork') {
      container.appendChild(renderSearchSection(findings.search));
    }
    if (findings.entity || module === 'entity') {
      container.appendChild(renderSearchSection(findings.entity, 'Entity Intelligence'));
    }
    if (findings.metadata || module === 'metadata') {
      container.appendChild(renderMetadataSection(findings.metadata));
    }
  }

  // ── Domain Section ──────────────────────────────────────────────────────────
  function renderDomainSection(data) {
    const section = makeSection('🌐 Domain Reconnaissance');
    if (!data) { section.appendChild(makeEmpty('No domain data')); return section; }

    // WHOIS card
    if (data.whois) {
      const card = makeCard('WHOIS Information');
      const grid = createElement('div', 'info-grid');
      const w = data.whois;
      const rows = [
        ['Registrar',    w.registrar],
        ['Created',      w.creation_date],
        ['Expires',      w.expiration_date],
        ['Updated',      w.updated_date],
        ['Organisation', w.org],
        ['Country',      w.country],
        ['Emails',       Array.isArray(w.emails) ? w.emails.join(', ') : w.emails],
        ['Name Servers', Array.isArray(w.name_servers) ? w.name_servers.join(', ') : w.name_servers],
      ];
      rows.forEach(([label, value]) => {
        if (!value) return;
        const row = createElement('div', 'info-row');
        row.appendChild(createElement('span', 'info-label', label));
        row.appendChild(createElement('span', 'info-value text-mono', String(value)));
        grid.appendChild(row);
      });
      card.appendChild(grid);
      section.appendChild(card);
    }

    // DNS Records
    if (data.dns) {
      const card = makeCard('DNS Records');
      const table = makeTable(['Type', 'Records']);
      Object.entries(data.dns).forEach(([type, values]) => {
        if (type.startsWith('_') || !values || !values.length) return;
        const row = table.querySelector('tbody').insertRow();
        row.insertCell().appendChild(createElement('code', 'dns-type', type));
        const valCell = row.insertCell();
        (Array.isArray(values) ? values : [values]).forEach(v => {
          const span = createElement('div', 'dns-value text-mono', v);
          valCell.appendChild(span);
        });
      });
      card.appendChild(table);
      section.appendChild(card);
    }

    // Subdomains
    if (data.subdomains && data.subdomains.length > 0) {
      const card = makeCard(`Subdomains (${data.subdomain_count || data.subdomains.length} found)`);
      const chipContainer = createElement('div', 'chip-container');
      data.subdomains.slice(0, 200).forEach(sub => {
        const chip = createElement('span', 'subdomain-chip text-mono', sub);
        chipContainer.appendChild(chip);
      });
      card.appendChild(chipContainer);
      section.appendChild(card);
    }

    return section;
  }

  // ── Username Section ─────────────────────────────────────────────────────────
  function renderUsernameSection(data) {
    const section = makeSection('👤 Username Footprint');
    if (!data) { section.appendChild(makeEmpty('No username data')); return section; }

    const found = data.found || [];
    const summary = createElement('div', 'username-summary');
    summary.appendChild(createElement('div', 'stat-chip stat-found', `✓ ${found.length} Found`));
    summary.appendChild(createElement('div', 'stat-chip stat-notfound', `✕ ${data.not_found_count || 0} Not Found`));
    if (data.errors?.length) {
      summary.appendChild(createElement('div', 'stat-chip stat-error', `⚠ ${data.errors.length} Errors`));
    }
    section.appendChild(summary);

    if (found.length > 0) {
      const card = makeCard('Found Profiles');
      const grid = createElement('div', 'platform-grid');
      found.forEach(result => {
        const item = createElement('a', 'platform-item');
        item.href = result.url;
        item.target = '_blank';
        item.rel = 'noopener noreferrer';
        // Only set URL via href attribute, textContent for labels
        const name = createElement('span', 'platform-name', result.platform);
        const badge = createElement('span', 'badge badge-found', '✓ Found');
        const url = createElement('span', 'platform-url text-mono', result.url);
        item.appendChild(name);
        item.appendChild(badge);
        item.appendChild(url);
        grid.appendChild(item);
      });
      card.appendChild(grid);
      section.appendChild(card);
    }

    return section;
  }

  // ── Breach Section ───────────────────────────────────────────────────────────
  function renderBreachSection(data) {
    const section = makeSection('🔓 Breach Exposure');
    if (!data) { section.appendChild(makeEmpty('No breach data')); return section; }

    if (data.error) {
      section.appendChild(makeError(data.error));
      return section;
    }

    const breaches = data.breaches || [];
    if (breaches.length === 0) {
      const okBanner = createElement('div', 'breach-safe-banner');
      okBanner.appendChild(createElement('span', '', '✅'));
      okBanner.appendChild(createElement('span', '', 'No breaches found — email appears clean'));
      section.appendChild(okBanner);
    } else {
      const warnBanner = createElement('div', 'breach-warn-banner');
      warnBanner.appendChild(createElement('span', '', `⚠️ Found in ${breaches.length} breach${breaches.length !== 1 ? 'es' : ''}`));
      section.appendChild(warnBanner);

      const card = makeCard('Breach Details');
      const list = createElement('div', 'breach-list');
      breaches.forEach(b => {
        const item = createElement('div', 'breach-item');
        const header = createElement('div', 'breach-item-header');
        header.appendChild(createElement('strong', 'breach-name', b.Name || b.name || 'Unknown'));
        if (b.BreachDate || b.breach_date) {
          header.appendChild(createElement('span', 'breach-date', b.BreachDate || b.breach_date));
        }
        item.appendChild(header);
        if (b.DataClasses || b.data_classes) {
          const classes = b.DataClasses || b.data_classes || [];
          const chipWrap = createElement('div', 'breach-classes');
          (Array.isArray(classes) ? classes : [classes]).forEach(c => {
            chipWrap.appendChild(createElement('span', 'breach-class-chip', c));
          });
          item.appendChild(chipWrap);
        }
        list.appendChild(item);
      });
      card.appendChild(list);
      section.appendChild(card);
    }
    return section;
  }

  // ── Search / Entity Section ──────────────────────────────────────────────────
  function renderSearchSection(data, title = '🔍 Search Results') {
    const section = makeSection(title);
    if (!data) { section.appendChild(makeEmpty('No search data')); return section; }

    const results = data.results || (Array.isArray(data) ? data : []);
    if (results.length === 0) {
      section.appendChild(makeEmpty('No results found'));
      return section;
    }

    const backendBadge = createElement('div', 'search-meta');
    if (data.backend) {
      backendBadge.appendChild(createElement('span', 'search-backend-badge', `via ${data.backend}`));
    }
    section.appendChild(backendBadge);

    const list = createElement('div', 'search-results-list');
    results.forEach(r => {
      const item = createElement('div', 'search-result-item');
      if (r.title) item.appendChild(createElement('div', 'search-result-title', r.title));
      if (r.url) {
        const link = createElement('a', 'search-result-url text-mono', r.url);
        link.href = r.url;
        link.target = '_blank';
        link.rel = 'noopener noreferrer';
        item.appendChild(link);
      }
      if (r.snippet) item.appendChild(createElement('div', 'search-result-snippet', r.snippet));
      list.appendChild(item);
    });
    section.appendChild(list);
    return section;
  }

  // ── Metadata Section ─────────────────────────────────────────────────────────
  function renderMetadataSection(data) {
    const section = makeSection('📄 Document Metadata');
    if (!data) { section.appendChild(makeEmpty('No metadata')); return section; }

    const card = makeCard('Extracted Metadata');
    const grid = createElement('div', 'info-grid');

    function addRows(obj, prefix = '') {
      Object.entries(obj || {}).forEach(([key, value]) => {
        if (value === null || value === undefined || value === '') return;
        if (typeof value === 'object' && !Array.isArray(value)) {
          addRows(value, `${prefix}${key} › `);
          return;
        }
        const row = createElement('div', 'info-row');
        row.appendChild(createElement('span', 'info-label', prefix + key));
        row.appendChild(createElement('span', 'info-value text-mono', Array.isArray(value) ? value.join(', ') : String(value)));
        grid.appendChild(row);
      });
    }
    addRows(data);

    if (!grid.children.length) {
      grid.appendChild(createElement('p', 'text-muted', 'No metadata fields extracted'));
    }
    card.appendChild(grid);
    section.appendChild(card);
    return section;
  }

  // ── DOM Helpers ──────────────────────────────────────────────────────────────
  function makeSection(title) {
    const section = createElement('div', 'report-section');
    const h3 = createElement('h3', 'report-section-title', title);
    section.appendChild(h3);
    return section;
  }

  function makeCard(title) {
    const card = createElement('div', 'report-card glass-card');
    if (title) {
      const h4 = createElement('h4', 'report-card-title', title);
      card.appendChild(h4);
    }
    return card;
  }

  function makeTable(headers) {
    const table = createElement('table', 'data-table');
    const thead = createElement('thead', '');
    const headerRow = createElement('tr', '');
    headers.forEach(h => headerRow.appendChild(createElement('th', '', h)));
    thead.appendChild(headerRow);
    table.appendChild(thead);
    table.appendChild(createElement('tbody', ''));
    return table;
  }

  function makeEmpty(msg) {
    const el = createElement('div', 'section-empty', `ℹ️ ${msg}`);
    return el;
  }

  function makeError(msg) {
    return createElement('div', 'section-error', `⚠️ ${msg}`);
  }

  function safeSetText(id, text) {
    const el = document.getElementById(id);
    if (el) el.textContent = String(text ?? '—');
  }

  function showError(message) {
    const errorEl = document.getElementById('report-error');
    if (errorEl) {
      errorEl.classList.remove('hidden');
      const msgEl = errorEl.querySelector('.error-message');
      if (msgEl) msgEl.textContent = message;
    }
  }

  // ── Download helpers ──────────────────────────────────────────────────────────
  function downloadJson(data, filename) {
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
    triggerDownload(blob, filename);
  }

  function downloadText(text, filename) {
    const blob = new Blob([text], { type: 'text/markdown' });
    triggerDownload(blob, filename);
  }

  function triggerDownload(blob, filename) {
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  }
});
