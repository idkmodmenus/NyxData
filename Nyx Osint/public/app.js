/* ═══════════════════════════════════════════════════════════════
   Nyx OSINT — Frontend v2
   ═══════════════════════════════════════════════════════════════ */
'use strict';

// ── State ─────────────────────────────────────────────────────
const state = {
  mode:        'email',
  loading:     false,
  lastResults: null,
  lastQuery:   '',
  breachDB:    null,   // loaded once
};

// ── DOM ───────────────────────────────────────────────────────
const $ = id => document.getElementById(id);
const searchForm    = $('search-form');
const searchInput   = $('search-input');
const searchBtn     = $('search-btn');
const modeLabel     = $('mode-label');
const modeDesc      = $('mode-desc');
const inputIcon     = $('input-icon');
const privacyNote   = $('privacy-note');
const emptyState    = $('empty-state');
const loadingState  = $('loading-state');
const loadingText   = $('loading-text');
const progressBar   = $('progress-bar');
const resultsOutput = $('results-output');
const historyList   = $('history-list');
const clearHistBtn  = $('clear-history-btn');
const exportModal   = $('export-modal');
const modalClose    = $('modal-close');
const dbBrowser     = $('db-browser');
const dbGrid        = $('db-grid');
const dbSearch      = $('db-search');
const dbCategory    = $('db-category');
const dbSeverity    = $('db-severity');
const dbSub         = $('db-sub');
const dbPagination  = $('db-pagination');
const breachModal   = $('breach-modal');
const breachModalTitle = $('breach-modal-title');
const breachModalBody  = $('breach-modal-body');
const searchCard    = $('search-card');
const historySec    = $('history-section');

// ── Mode config ───────────────────────────────────────────────
const MODES = {
  email: {
    label: 'Email Intelligence',
    desc:  'Analyze an email against the Nyx Data breach database (30B+ records), infostealer logs, domain intel, Gravatar, and MX records.',
    placeholder: 'Enter an email address…',
    icon: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><rect x="2" y="4" width="20" height="16" rx="2"/><polyline points="2,4 12,13 22,4"/></svg>`,
  },
  breach: {
    label: 'Breach Lookup',
    desc:  'Check an email against the Nyx Data breach intelligence database — 30B+ records searched instantly.',
    placeholder: 'Enter an email address…',
    icon: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M12 2L3 7v5c0 5.25 3.75 10.15 9 11.35C17.25 22.15 21 17.25 21 12V7z"/><line x1="12" y1="9" x2="12" y2="13"/><circle cx="12" cy="16" r="1" fill="currentColor"/></svg>`,
  },
  password: {
    label: 'Password Exposure Check',
    desc:  'Check if a password has appeared in known data breaches. Uses k-anonymity — your password never leaves your browser.',
    placeholder: 'Enter a password to check…',
    icon: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0110 0v4"/></svg>`,
  },
  username: {
    label: 'Username Search',
    desc:  'Scan 55+ platforms for a username — social media, dev tools, gaming, creative, and more.',
    placeholder: 'Enter a username…',
    icon: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><circle cx="12" cy="8" r="4"/><path d="M4 20c0-4 3.6-7 8-7s8 3 8 7"/></svg>`,
  },
  phone: {
    label: 'Phone Number Lookup',
    desc:  'Look up carrier, country, line type, and validation info for any phone number.',
    placeholder: 'Enter a phone number (e.g. +1 555 000 1234)…',
    icon: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M22 16.92v3a2 2 0 01-2.18 2 19.79 19.79 0 01-8.63-3.07A19.5 19.5 0 013.12 12 19.79 19.79 0 01.1 3.39 2 2 0 012.07 1h3a2 2 0 012 1.72c.127.96.361 1.903.7 2.81a2 2 0 01-.45 2.11L6.91 8.09a16 16 0 006 6l.91-.91a2 2 0 012.11-.45c.907.339 1.85.573 2.81.7A2 2 0 0122 16.92z"/></svg>`,
  },
  ip: {
    label: 'IP / Domain Lookup',
    desc:  'Geolocate an IP address or look up domain DNS records, ASN, and threat intelligence.',
    placeholder: 'Enter an IP address or domain…',
    icon: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 010 20M12 2a15.3 15.3 0 000 20"/></svg>`,
  },
  db: {
    label: 'Browse Breach Database',
    desc:  'Explore our index of 100+ major company data breaches with full details.',
    placeholder: 'Search breaches by company name…',
    icon: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><ellipse cx="12" cy="5" rx="9" ry="3"/><path d="M3 5v4c0 1.66 4.03 3 9 3s9-1.34 9-3V5"/><path d="M3 9v4c0 1.66 4.03 3 9 3s9-1.34 9-3V9"/><path d="M3 13v4c0 1.66 4.03 3 9 3s9-1.34 9-3v-4"/></svg>`,
  },
};

// ── Load breach DB ─────────────────────────────────────────────
async function loadBreachDB() {
  if (state.breachDB) return state.breachDB;
  try {
    const res = await fetch('/breachdb.json');
    state.breachDB = await res.json();
    return state.breachDB;
  } catch { return []; }
}
loadBreachDB();

// ── Mode switching ─────────────────────────────────────────────
document.querySelectorAll('.pill').forEach(btn => {
  btn.addEventListener('click', () => {
    const mode = btn.dataset.mode;
    state.mode = mode;
    document.querySelectorAll('.pill').forEach(p => {
      p.classList.toggle('active', p.dataset.mode === mode);
      p.setAttribute('aria-pressed', p.dataset.mode === mode ? 'true' : 'false');
    });

    const cfg = MODES[mode];
    modeLabel.textContent      = cfg.label;
    modeDesc.textContent       = cfg.desc;
    searchInput.placeholder    = cfg.placeholder;
    inputIcon.innerHTML        = cfg.icon;
    privacyNote.classList.toggle('hidden', mode !== 'password');

    // Toggle password input type
    searchInput.type = mode === 'password' ? 'password' : 'text';

    // DB mode: show browser, hide search results
    const isDB = mode === 'db';
    searchCard.classList.toggle('hidden', isDB);
    dbBrowser.classList.toggle('hidden', !isDB);
    historySec.classList.toggle('hidden', isDB);
    if (isDB) {
      showEmpty();
      initDBBrowser();
    } else {
      dbBrowser.classList.add('hidden');
      historySec.classList.remove('hidden');
      searchInput.value = '';
      showEmpty();
    }
  });
});

// ── Form submit ───────────────────────────────────────────────
searchForm.addEventListener('submit', async e => {
  e.preventDefault();
  const query = searchInput.value.trim();
  if (!query || state.loading) return;
  await runSearch(query);
});

async function runSearch(query) {
  state.loading   = true;
  state.lastQuery = query;
  searchBtn.disabled = true;
  showLoading('Initializing…');

  try {
    let results;
    if      (state.mode === 'email')    results = await searchEmail(query);
    else if (state.mode === 'breach')   results = await searchBreach(query);
    else if (state.mode === 'password') results = await searchPassword(query);
    else if (state.mode === 'username') results = await searchUsername(query);
    else if (state.mode === 'phone')    results = await searchPhone(query);
    else if (state.mode === 'ip')       results = await searchIP(query);

    state.lastResults = results;
    addToHistory(query, state.mode);
    renderResults(results, state.mode, query);
  } catch (err) {
    showError(`Search failed: ${err.message}`);
  } finally {
    state.loading = false;
    searchBtn.disabled = false;
  }
}

// ── API wrappers ──────────────────────────────────────────────

async function searchEmail(email) {
  setProgress(10);
  loadingText.textContent = 'Checking breach databases…';
  const [breachRes, emailRes] = await Promise.all([
    apiFetch('/api/breach', { email }),
    apiFetch('/api/email',  { email }),
  ]);
  setProgress(100);
  return { breach: breachRes, email: emailRes };
}

async function searchBreach(email) {
  loadingText.textContent = 'Querying breach intelligence sources…';
  setProgress(15);
  const res = await apiFetch('/api/breach', { email });
  setProgress(100);
  return { breach: res };
}

async function searchPassword(password) {
  loadingText.textContent = 'Hashing locally…';
  setProgress(20);

  // Hash in the browser — only prefix goes to server
  const prefix = await sha1Prefix(password);
  setProgress(50);
  loadingText.textContent = 'Checking against 800M+ leaked passwords…';

  const res = await apiFetch('/api/password', { prefix: prefix.slice(0, 5) });
  setProgress(100);

  const suffix    = prefix.slice(5).toUpperCase();
  const matchLine = (res.entries || []).find(e => e.suffix.toUpperCase() === suffix);
  const count     = matchLine ? matchLine.count : 0;

  return { password: { count, prefix, pwned: count > 0, totalEntries: res.entries?.length || 0 } };
}

async function searchUsername(username) {
  loadingText.textContent = 'Scanning platforms…';
  setProgress(5);
  const res = await apiFetch('/api/username', { username }, { timeout: 60000 });
  setProgress(100);
  return { username: res };
}

async function searchPhone(phone) {
  loadingText.textContent = 'Looking up phone number…';
  setProgress(20);
  const res = await apiFetch('/api/phone', { phone });
  setProgress(100);
  return { phone: res };
}

async function searchIP(target) {
  loadingText.textContent = 'Geolocating target…';
  setProgress(20);
  const res = await apiFetch('/api/ip', { target });
  setProgress(100);
  return { ip: res };
}

async function apiFetch(path, body, opts = {}) {
  const controller = new AbortController();
  const timeout    = setTimeout(() => controller.abort(), opts.timeout || 30000);
  try {
    const res = await fetch(path, {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify(body),
      signal:  controller.signal,
    });
    clearTimeout(timeout);
    if (!res.ok) {
      const err = await res.json().catch(() => ({ error: `HTTP ${res.status}` }));
      throw new Error(err.error || `HTTP ${res.status}`);
    }
    return res.json();
  } catch (err) {
    clearTimeout(timeout);
    if (err.name === 'AbortError') throw new Error('Request timed out');
    throw err;
  }
}

// ── SHA-1 (browser WebCrypto) ─────────────────────────────────
async function sha1Prefix(str) {
  const enc  = new TextEncoder();
  const buf  = await crypto.subtle.digest('SHA-1', enc.encode(str));
  return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('').toUpperCase();
}

// ── Render dispatcher ─────────────────────────────────────────
function renderResults(data, mode, query) {
  hideLoading();
  resultsOutput.innerHTML = '';
  resultsOutput.classList.remove('hidden');
  emptyState.classList.add('hidden');

  if      (mode === 'email')    renderEmailResults(data, query);
  else if (mode === 'breach')   renderBreachResults(data, query);
  else if (mode === 'password') renderPasswordResults(data, query);
  else if (mode === 'username') renderUsernameResults(data, query);
  else if (mode === 'phone')    renderPhoneResults(data, query);
  else if (mode === 'ip')       renderIPResults(data, query);

  // Export bar
  const bar = el('div', 'export-bar');
  bar.innerHTML = `<span class="export-bar-label">Results for <strong class="mono">${esc(query)}</strong></span><button class="export-bar-btn" id="open-export-btn">⬇ Export</button>`;
  resultsOutput.appendChild(bar);
  bar.querySelector('#open-export-btn').addEventListener('click', openExportModal);
}

// ─── Email ────────────────────────────────────────────────────
function renderEmailResults(data, query) {
  const { breach, email } = data;
  const breaches    = breach?.breaches || [];
  const dbMatches   = breach?.dbMatches || [];
  const infostealers = breaches.filter(b => b.isInfostealer);
  const apiBreaches  = breaches.filter(b => !b.isInfostealer);
  const hasAny       = breaches.length > 0 || dbMatches.length > 0;

  // Summary
  const summary = el('div', `summary-banner ${hasAny ? 'danger' : 'safe'}`);
  summary.innerHTML = hasAny
    ? `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg><span><strong>${breaches.length} record${breaches.length !== 1 ? 's' : ''} found in Nyx Data</strong> for ${esc(query)}</span>`
    : `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M22 11.08V12a10 10 0 11-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg><span><strong>Not found in Nyx Data</strong> for ${esc(query)}</span>`;
  resultsOutput.appendChild(summary);

  // Stats
  const stats = el('div', 'stats-row');
  stats.innerHTML = `
    <div class="stat-box"><div class="stat-num ${apiBreaches.length > 0 ? 'red' : 'green'}">${apiBreaches.length}</div><div class="stat-label">Breach Records</div></div>
    <div class="stat-box"><div class="stat-num ${infostealers.length > 0 ? 'orange' : 'green'}">${infostealers.length}</div><div class="stat-label">Infostealer Hits</div></div>
    <div class="stat-box"><div class="stat-num ${dbMatches.length > 0 ? 'yellow' : 'green'}">${dbMatches.length}</div><div class="stat-label">DB Matches</div></div>
    <div class="stat-box"><div class="stat-num ${email?.isDisposable ? 'red' : 'green'}">${email?.isDisposable ? 'YES' : 'NO'}</div><div class="stat-label">Disposable</div></div>
  `;
  resultsOutput.appendChild(stats);

  // Infostealer warning
  if (infostealers.length > 0) {
    const alert = el('div', 'infostealer-alert');
    alert.innerHTML = `
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>
      <div>
        <h4>⚠ Infostealer Malware Detected</h4>
        <p>This email was found in <strong>${infostealers.length}</strong> infostealer log${infostealers.length !== 1 ? 's' : ''} in the Nyx Data database. The device associated with this email may have been compromised by credential-stealing malware. Change passwords immediately.</p>
      </div>`;
    resultsOutput.appendChild(alert);
  }

  // Breach card
  renderBreachCard(apiBreaches, breach?.sourceStatus);

  // Infostealer card
  if (infostealers.length > 0) renderInfostealerCard(infostealers);

  // DB cross-reference card
  if (dbMatches.length > 0) renderDBRefCard(dbMatches, email?.domain);

  // Email info card
  if (email) renderEmailCard(email, query);
}

// ─── Breach-only ──────────────────────────────────────────────
function renderBreachResults(data, query) {
  const { breach } = data;
  const breaches    = breach?.breaches || [];
  const dbMatches   = breach?.dbMatches || [];
  const infostealers = breaches.filter(b => b.isInfostealer);
  const apiBreaches  = breaches.filter(b => !b.isInfostealer);
  const hasAny       = breaches.length > 0;

  const summary = el('div', `summary-banner ${hasAny ? 'danger' : 'safe'}`);
  summary.innerHTML = hasAny
    ? `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg><span><strong>${breaches.length} record${breaches.length !== 1 ? 's' : ''} found in Nyx Data</strong> for ${esc(query)}</span>`
    : `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M22 11.08V12a10 10 0 11-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg><span><strong>Not found in Nyx Data</strong> for ${esc(query)}</span>`;
  resultsOutput.appendChild(summary);

  if (infostealers.length > 0) {
    const alert = el('div', 'infostealer-alert');
    alert.innerHTML = `
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>
      <div><h4>⚠ Infostealer Records Found</h4><p>Found in <strong>${infostealers.length}</strong> infostealer log${infostealers.length !== 1 ? 's' : ''} in Nyx Data. Device may be compromised.</p></div>`;
    resultsOutput.appendChild(alert);
  }

  renderBreachCard(apiBreaches, breach?.sourceStatus);
  if (infostealers.length > 0) renderInfostealerCard(infostealers);
  if (dbMatches.length > 0) renderDBRefCard(dbMatches, breach?.domain);

  // Nyx Data source card
  if (breach?.sourceStatus?.length) {
    const card = makeCard('Nyx Data Intelligence', 'purple',
      `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><ellipse cx="12" cy="5" rx="9" ry="3"/><path d="M3 5v4c0 1.66 4.03 3 9 3s9-1.34 9-3V5"/><path d="M3 9v4c0 1.66 4.03 3 9 3s9-1.34 9-3V9"/><path d="M3 13v4c0 1.66 4.03 3 9 3s9-1.34 9-3v-4"/></svg>`);
    const body = card.querySelector('.card-body');
    const note = el('p');
    note.style.cssText = 'font-size:13px;color:var(--text-2);';
    note.innerHTML = `Searched across <strong style="color:var(--accent)">30B+ records</strong> in the Nyx Data breach intelligence database.`;
    body.appendChild(note);
    resultsOutput.appendChild(card);
  }
}

function renderBreachCard(breaches, sourceStatus) {
  const card = makeCard(
    `Breach Records (${breaches.length})`,
    breaches.length > 0 ? 'red' : 'green',
    `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M12 2L3 7v5c0 5.25 3.75 10.15 9 11.35C17.25 22.15 21 17.25 21 12V7z"/><line x1="12" y1="9" x2="12" y2="13"/><circle cx="12" cy="16" r="1" fill="currentColor"/></svg>`
  );
  const body = card.querySelector('.card-body');

  if (breaches.length === 0) {
    const p = el('p'); p.style.cssText = 'color:var(--green);font-size:13px;';
    p.textContent = '✔  Not found in Nyx Data.';
    body.appendChild(p);
  } else {
    const table = el('table', 'data-table');
    table.innerHTML = `<thead><tr><th>Breach Name</th><th>Date</th><th>Records</th><th>Data Types</th></tr></thead>`;
    const tbody = el('tbody');
    breaches.forEach(b => {
      const tr = el('tr');
      tr.innerHTML = `
        <td class="name">${esc(b.name || 'Unknown')}</td>
        <td>${esc(b.date || '—')}</td>
        <td>${b.pwnCount ? Number(b.pwnCount).toLocaleString() : '—'}</td>
        <td class="text-dim">${(b.dataClasses || []).slice(0, 4).map(esc).join(', ') || '—'}</td>`;
      tbody.appendChild(tr);
    });
    table.appendChild(tbody);
    body.appendChild(table);
  }
  resultsOutput.appendChild(card);
}

function renderInfostealerCard(infostealers) {
  const card = makeCard(`Infostealer Records (${infostealers.length})`, 'orange',
    `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><circle cx="12" cy="16" r="1" fill="currentColor"/></svg>`
  );
  const body = card.querySelector('.card-body');
  const table = el('table', 'data-table');
  table.innerHTML = `<thead><tr><th>Malware Family</th><th>Date Compromised</th><th>Computer Name</th><th>OS</th></tr></thead>`;
  const tbody = el('tbody');
  infostealers.forEach(b => {
    const tr = el('tr');
    tr.innerHTML = `
      <td class="name warn">${esc(b.malware || 'Unknown malware')}</td>
      <td>${esc(b.date || '—')}</td>
      <td class="mono">${esc(b.computerName || '—')}</td>
      <td>${esc(b.os || '—')}</td>`;
    tbody.appendChild(tr);
  });
  table.appendChild(tbody);
  body.appendChild(table);
  resultsOutput.appendChild(card);
}

function renderDBRefCard(dbMatches, domain) {
  const card = makeCard(`Domain Found in ${dbMatches.length} Known Breach${dbMatches.length !== 1 ? 'es' : ''}`, 'yellow',
    `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><ellipse cx="12" cy="5" rx="9" ry="3"/><path d="M3 5v4c0 1.66 4.03 3 9 3s9-1.34 9-3V5"/><path d="M3 9v4c0 1.66 4.03 3 9 3s9-1.34 9-3V9"/><path d="M3 13v4c0 1.66 4.03 3 9 3s9-1.34 9-3v-4"/></svg>`
  );
  const body = card.querySelector('.card-body');
  const note = el('p');
  note.style.cssText = 'font-size:12px;color:var(--text-2);margin-bottom:12px;';
  note.innerHTML = `The domain <strong class="mono text-blue">${esc(domain || '')}</strong> is associated with the following known company breaches in our database:`;
  body.appendChild(note);

  dbMatches.forEach(b => {
    const item = el('div', 'dbref-item');
    item.innerHTML = `
      <span class="dbref-sev ${b.severity || 'Low'}">${b.severity || 'Low'}</span>
      <div class="dbref-info">
        <div class="dbref-name">${esc(b.name)}</div>
        <div class="dbref-meta">${esc(b.date || '—')} &nbsp;·&nbsp; ${b.pwnCount ? Number(b.pwnCount).toLocaleString() + ' records' : 'Unknown records'} &nbsp;·&nbsp; ${esc(b.category || '')}</div>
      </div>`;
    body.appendChild(item);
  });
  resultsOutput.appendChild(card);
}

function renderEmailCard(email, query) {
  const card = makeCard('Email Analysis', 'blue',
    `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><rect x="2" y="4" width="20" height="16" rx="2"/><polyline points="2,4 12,13 22,4"/></svg>`);
  const body = card.querySelector('.card-body');
  body.appendChild(makeKV([
    ['Email',          query,                              'blue'],
    ['Domain',         email.domain || '—',                'text'],
    ['Provider',       email.providerGuess || 'Unknown',   'text'],
    ['DNS Resolvable', email.dnsResolvable ? 'Yes' : 'No', email.dnsResolvable ? 'green' : 'red'],
    ['Has MX Records', email.hasMX ? 'Yes' : 'No',         email.hasMX ? 'green' : 'red'],
    ['Disposable',     email.isDisposable ? 'Yes ⚠' : 'No', email.isDisposable ? 'red' : 'green'],
    ['Gravatar',       email.gravatar?.hasGravatar ? 'Profile found ✔' : 'None', email.gravatar?.hasGravatar ? 'green' : 'dim'],
  ]));
  if (email.gravatar?.displayName) {
    const d = el('div'); d.style.marginTop = '8px';
    d.appendChild(makeKV([['Gravatar Name', email.gravatar.displayName, 'text']]));
    body.appendChild(d);
  }
  if (email.localPatterns?.length) {
    const tags = el('div', 'tag-list'); tags.style.marginTop = '12px';
    email.localPatterns.forEach(p => { const t = el('span', 'tag yellow'); t.textContent = p; tags.appendChild(t); });
    body.appendChild(tags);
  }
  if (email.mxRecords?.length) {
    const mxDiv = el('div'); mxDiv.style.marginTop = '14px';
    const mxTitle = el('p');
    mxTitle.style.cssText = 'font-size:12px;color:var(--text-2);margin-bottom:8px;font-weight:500;';
    mxTitle.textContent = 'MX Records';
    mxDiv.appendChild(mxTitle);
    const list = el('ul', 'mx-list');
    email.mxRecords.forEach(r => {
      const li = el('li', 'mx-item');
      li.innerHTML = `<span class="mx-priority">${r.priority}</span><span class="mx-host">${esc(r.exchange)}</span>`;
      list.appendChild(li);
    });
    mxDiv.appendChild(list);
    body.appendChild(mxDiv);
  }
  resultsOutput.appendChild(card);
}

// ─── Password ─────────────────────────────────────────────────
function renderPasswordResults(data, query) {
  const { count, pwned, prefix } = data.password;

  const severity = count === 0 ? 'safe' : count < 10 ? 'warn' : 'danger';
  const summary  = el('div', `summary-banner ${severity}`);

  if (pwned) {
    summary.innerHTML = `
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>
      <span><strong>Password is PWNED!</strong> Seen <strong>${count.toLocaleString()} time${count !== 1 ? 's' : ''}</strong> in data breaches. Do not use this password.</span>`;
  } else {
    summary.innerHTML = `
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M22 11.08V12a10 10 0 11-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>
      <span><strong>Password not found</strong> in any known breach. Still use a strong, unique password.</span>`;
  }
  resultsOutput.appendChild(summary);

  // Strength meter
  const strength = measureStrength(query);
  const card = makeCard('Password Analysis', strength.level >= 3 ? 'green' : strength.level >= 2 ? 'yellow' : 'red',
    `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0110 0v4"/></svg>`);
  const body = card.querySelector('.card-body');

  const meterWrap = el('div', 'pw-meter');
  const meterBar  = el('div', 'pw-meter-bar');
  const fill      = el('div', 'pw-meter-fill');
  const colors    = ['#4a5568','#ff4d6a','#f97316','#f5c542','#22d3a3'];
  fill.style.width      = `${(strength.level / 4) * 100}%`;
  fill.style.background = colors[strength.level];
  meterBar.appendChild(fill);
  const label = el('div', `pw-strength-label strength-${strength.level}`);
  label.textContent = ['—','Weak','Fair','Good','Strong'][strength.level];
  meterWrap.appendChild(meterBar);
  meterWrap.appendChild(label);
  body.appendChild(meterWrap);

  const div = el('div'); div.style.marginTop = '14px';
  div.appendChild(makeKV([
    ['Breach Exposure',  pwned ? `${count.toLocaleString()} occurrences` : 'Not found', pwned ? 'red' : 'green'],
    ['Length',           `${query.length} characters`,  query.length >= 12 ? 'green' : query.length >= 8 ? 'yellow' : 'red'],
    ['Has Uppercase',    /[A-Z]/.test(query) ? 'Yes' : 'No', /[A-Z]/.test(query) ? 'green' : 'red'],
    ['Has Lowercase',    /[a-z]/.test(query) ? 'Yes' : 'No', /[a-z]/.test(query) ? 'green' : 'red'],
    ['Has Numbers',      /\d/.test(query) ? 'Yes' : 'No',    /\d/.test(query) ? 'green' : 'red'],
    ['Has Symbols',      /[^a-zA-Z0-9]/.test(query) ? 'Yes' : 'No', /[^a-zA-Z0-9]/.test(query) ? 'green' : 'red'],
    ['SHA-1 Prefix',     prefix.slice(0, 5) + '…', 'dim'],
  ]));
  body.appendChild(div);
  resultsOutput.appendChild(card);
}

function measureStrength(pw) {
  let score = 0;
  if (pw.length >= 8)  score++;
  if (pw.length >= 12) score++;
  if (/[A-Z]/.test(pw) && /[a-z]/.test(pw)) score++;
  if (/\d/.test(pw)) score++;
  if (/[^a-zA-Z0-9]/.test(pw)) score++;
  return { level: Math.min(4, Math.floor(score * 0.85)) };
}

// ─── Username ─────────────────────────────────────────────────
function renderUsernameResults(data, query) {
  const results = data?.username?.results || [];
  const found   = results.filter(r => r.found);
  const missing = results.filter(r => !r.found);

  const stats = el('div', 'stats-row');
  stats.innerHTML = `
    <div class="stat-box"><div class="stat-num green">${found.length}</div><div class="stat-label">Found</div></div>
    <div class="stat-box"><div class="stat-num red">${missing.length}</div><div class="stat-label">Not Found</div></div>
    <div class="stat-box"><div class="stat-num blue">${results.length}</div><div class="stat-label">Checked</div></div>`;
  resultsOutput.appendChild(stats);

  if (found.length > 0) {
    const card = makeCard(`Found on ${found.length} Platform${found.length !== 1 ? 's' : ''}`, 'green',
      `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>`);
    const body = card.querySelector('.card-body');
    const grid = el('div', 'platform-grid');
    found.forEach(r => {
      const item = el('div', 'platform-item found');
      item.innerHTML = `<span class="platform-dot found"></span><span class="platform-name">${esc(r.platform)}</span><a href="${esc(r.url)}" target="_blank" rel="noopener" class="platform-link">Visit ↗</a>`;
      grid.appendChild(item);
    });
    body.appendChild(grid);
    resultsOutput.appendChild(card);
  }

  if (missing.length > 0) {
    const card = makeCard(`Not Found (${missing.length})`, 'purple',
      `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><circle cx="12" cy="12" r="10"/><line x1="8" y1="8" x2="16" y2="16"/><line x1="16" y1="8" x2="8" y2="16"/></svg>`, true);
    const body = card.querySelector('.card-body');
    const grid = el('div', 'platform-grid');
    missing.forEach(r => {
      const item = el('div', 'platform-item miss');
      item.innerHTML = `<span class="platform-dot miss"></span><span class="platform-name">${esc(r.platform)}</span><span class="platform-link text-dim">—</span>`;
      grid.appendChild(item);
    });
    body.appendChild(grid);
    resultsOutput.appendChild(card);
  }
}

// ─── Phone ────────────────────────────────────────────────────
function renderPhoneResults(data, query) {
  const d = data?.phone || {};
  if (d.error) { showError(d.error); return; }

  const card = makeCard('Phone Number Intelligence', 'blue',
    `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M22 16.92v3a2 2 0 01-2.18 2 19.79 19.79 0 01-8.63-3.07A19.5 19.5 0 013.12 12 19.79 19.79 0 01.1 3.39 2 2 0 012.07 1h3a2 2 0 012 1.72c.127.96.361 1.903.7 2.81a2 2 0 01-.45 2.11L6.91 8.09a16 16 0 006 6l.91-.91a2 2 0 012.11-.45c.907.339 1.85.573 2.81.7A2 2 0 0122 16.92z"/></svg>`);
  const body = card.querySelector('.card-body');
  body.appendChild(makeKV([
    ['Number',      d.phone || query,              'blue'],
    ['Valid',       d.valid === true ? 'Yes' : d.valid === false ? 'No' : 'Unknown', d.valid ? 'green' : d.valid === false ? 'red' : 'dim'],
    ['Country',     d.countryName || '—',           'text'],
    ['Country Code',d.countryCode || '—',           'text'],
    ['Location',    d.location || '—',              'text'],
    ['Carrier',     d.carrier || '—',               'text'],
    ['Line Type',   d.lineType || '—',              'text'],
    ['Timezones',   d.timezones?.join(', ') || '—', 'dim'],
  ]));
  resultsOutput.appendChild(card);
}

// ─── IP/Domain ────────────────────────────────────────────────
function renderIPResults(data, query) {
  const d = data?.ip || {};
  if (d.error) { const b = el('div','summary-banner warn'); b.innerHTML = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg><span>${esc(d.error)}</span>`; resultsOutput.appendChild(b); return; }

  const geoCard = makeCard('Geolocation & Network', 'blue',
    `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 010 20M12 2a15.3 15.3 0 000 20"/></svg>`);
  const geoBody = geoCard.querySelector('.card-body');
  geoBody.appendChild(makeKV([
    ['IP / Target',  d.ip || query,                'blue'],
    ['Hostname',     d.hostname || '—',             'text'],
    ['Organization', d.org || '—',                  'text'],
    ['ASN',          d.asn || '—',                  'dim'],
    ['Country',      d.country ? `${d.countryFlag || ''} ${d.country}` : '—', 'text'],
    ['Region',       d.region || '—',               'text'],
    ['City',         d.city || '—',                 'text'],
    ['Timezone',     d.timezone || '—',             'dim'],
    ['Coordinates',  d.lat && d.lon ? `${d.lat}, ${d.lon}` : '—', 'dim'],
  ]));
  resultsOutput.appendChild(geoCard);

  if (d.vpn !== undefined || d.abuse) {
    const threatCard = makeCard('Threat Intelligence', d.abuse?.confidence > 20 ? 'red' : 'green',
      `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M12 2L3 7v5c0 5.25 3.75 10.15 9 11.35C17.25 22.15 21 17.25 21 12V7z"/></svg>`);
    const tBody = threatCard.querySelector('.card-body');
    const rows = [
      ['VPN / Proxy', d.vpn  ? 'Detected ⚠' : 'No', d.vpn  ? 'red' : 'green'],
      ['Tor Exit Node',d.tor  ? 'Detected ⚠' : 'No', d.tor  ? 'red' : 'green'],
      ['Hosting / DC', d.hosting ? 'Yes'      : 'No', d.hosting ? 'yellow' : 'text'],
    ];
    if (d.abuse) {
      rows.push(['Abuse Score', `${d.abuse.confidence}%`, d.abuse.confidence > 20 ? 'red' : 'green']);
      rows.push(['Reports',     String(d.abuse.totalReports || 0), d.abuse.totalReports > 0 ? 'yellow' : 'green']);
    }
    tBody.appendChild(makeKV(rows));
    resultsOutput.appendChild(threatCard);
  }

  if (d.dns && Object.keys(d.dns).length > 0) {
    const dnsCard = makeCard('DNS Records', 'purple',
      `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><rect x="2" y="3" width="20" height="14" rx="2"/><line x1="8" y1="21" x2="16" y2="21"/><line x1="12" y1="17" x2="12" y2="21"/></svg>`);
    const dnsBody = dnsCard.querySelector('.card-body');
    const rows = Object.entries(d.dns).flatMap(([type, vals]) =>
      (Array.isArray(vals) ? vals : [vals]).map(v => [type, String(v)])
    );
    dnsBody.appendChild(makeSimpleTable(['Type', 'Value'], rows));
    resultsOutput.appendChild(dnsCard);
  }
}

// ── DB Browser ─────────────────────────────────────────────────
let dbPage = 1;
const DB_PER_PAGE = 24;
let dbFiltered = [];

async function initDBBrowser() {
  const db = await loadBreachDB();
  // Populate category filter
  const cats = [...new Set(db.map(b => b.category))].sort();
  dbCategory.innerHTML = '<option value="">All Categories</option>' +
    cats.map(c => `<option value="${esc(c)}">${esc(c)}</option>`).join('');

  dbFiltered = db;
  dbPage = 1;
  renderDBPage();
}

function filterDB() {
  const db   = state.breachDB || [];
  const q    = dbSearch.value.toLowerCase();
  const cat  = dbCategory.value;
  const sev  = dbSeverity.value;

  dbFiltered = db.filter(b => {
    const matchQ   = !q   || b.name.toLowerCase().includes(q) || (b.domain || '').toLowerCase().includes(q) || (b.description || '').toLowerCase().includes(q);
    const matchCat = !cat || b.category === cat;
    const matchSev = !sev || b.severity === sev;
    return matchQ && matchCat && matchSev;
  });

  dbPage = 1;
  renderDBPage();
}

function renderDBPage() {
  const total = dbFiltered.length;
  const pages = Math.max(1, Math.ceil(total / DB_PER_PAGE));
  const slice = dbFiltered.slice((dbPage - 1) * DB_PER_PAGE, dbPage * DB_PER_PAGE);

  dbSub.textContent = `${total.toLocaleString()} breach${total !== 1 ? 'es' : ''} · sorted by date`;

  // Cards
  dbGrid.innerHTML = '';
  slice.forEach(b => {
    const card = el('div', 'db-card');
    card.innerHTML = `
      <div class="db-card-header">
        <span class="db-card-name">${esc(b.name)}</span>
        <span class="db-sev-badge ${b.severity || 'Low'}">${esc(b.severity || 'Low')}</span>
      </div>
      <div class="db-card-domain">${esc(b.domain || 'unknown')}</div>
      <div class="db-card-records"><strong>${b.pwnCount ? Number(b.pwnCount).toLocaleString() : 'Unknown'}</strong> records</div>
      <div class="db-card-date">${esc(b.date || '—')} &nbsp;·&nbsp; ${esc(b.category || '')}</div>
      <div class="db-card-tags">${(b.dataClasses || []).slice(0, 4).map(t => `<span class="db-card-tag">${esc(t)}</span>`).join('')}</div>
    `;
    card.addEventListener('click', () => showBreachModal(b));
    dbGrid.appendChild(card);
  });

  // Pagination
  dbPagination.innerHTML = '';
  if (pages > 1) {
    const prev = el('button', 'db-page-btn'); prev.textContent = '←'; prev.disabled = dbPage === 1;
    prev.addEventListener('click', () => { dbPage--; renderDBPage(); });
    dbPagination.appendChild(prev);

    for (let i = 1; i <= pages; i++) {
      if (i === 1 || i === pages || Math.abs(i - dbPage) <= 2) {
        const btn = el('button', `db-page-btn${i === dbPage ? ' active' : ''}`);
        btn.textContent = i;
        btn.addEventListener('click', () => { dbPage = i; renderDBPage(); });
        dbPagination.appendChild(btn);
      } else if (Math.abs(i - dbPage) === 3) {
        const dots = el('span'); dots.textContent = '…'; dots.style.cssText = 'color:var(--text-3);padding:0 4px;line-height:32px;';
        dbPagination.appendChild(dots);
      }
    }

    const next = el('button', 'db-page-btn'); next.textContent = '→'; next.disabled = dbPage === pages;
    next.addEventListener('click', () => { dbPage++; renderDBPage(); });
    dbPagination.appendChild(next);
  }
}

// DB search events
dbSearch.addEventListener('input',   filterDB);
dbCategory.addEventListener('change', filterDB);
dbSeverity.addEventListener('change', filterDB);

function showBreachModal(b) {
  breachModalTitle.textContent = b.name;
  breachModalBody.innerHTML = '';

  const sections = [
    { label: 'Overview', content: makeKV([
      ['Domain',    b.domain || '—',                 'blue'],
      ['Date',      b.date   || '—',                 'text'],
      ['Records',   b.pwnCount ? Number(b.pwnCount).toLocaleString() : 'Unknown', 'red'],
      ['Category',  b.category || '—',               'text'],
      ['Severity',  b.severity || '—',               b.severity === 'Critical' ? 'red' : b.severity === 'High' ? 'orange' : b.severity === 'Medium' ? 'yellow' : 'dim'],
    ])},
  ];

  sections.forEach(s => {
    const div = el('div', 'breach-detail-section');
    const h4  = el('h4'); h4.textContent = s.label;
    div.appendChild(h4);
    div.appendChild(s.content);
    breachModalBody.appendChild(div);
  });

  if (b.description) {
    const div = el('div', 'breach-detail-section');
    const h4  = el('h4'); h4.textContent = 'Description';
    const p   = el('p', 'breach-detail-desc'); p.textContent = b.description;
    div.appendChild(h4); div.appendChild(p);
    breachModalBody.appendChild(div);
  }

  if (b.dataClasses?.length) {
    const div = el('div', 'breach-detail-section');
    const h4  = el('h4'); h4.textContent = 'Exposed Data';
    const tags = el('div', 'tag-list');
    b.dataClasses.forEach(t => { const tag = el('span', 'tag red'); tag.textContent = t; tags.appendChild(tag); });
    div.appendChild(h4); div.appendChild(tags);
    breachModalBody.appendChild(div);
  }

  breachModal.classList.remove('hidden');
}

$('breach-modal-close').addEventListener('click', () => breachModal.classList.add('hidden'));
breachModal.addEventListener('click', e => { if (e.target === breachModal) breachModal.classList.add('hidden'); });

// ── UI helpers ────────────────────────────────────────────────
function el(tag, cls = '') { const e = document.createElement(tag); if (cls) e.className = cls; return e; }

function esc(str) {
  return String(str).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

function makeCard(title, iconColor = 'blue', iconSvg = '', startCollapsed = false) {
  const card   = el('div', 'result-card');
  const header = el('div', 'card-header');
  header.innerHTML = `
    <div class="card-title-wrap">
      <div class="card-icon ${iconColor}">${iconSvg}</div>
      <div><div class="card-title">${esc(title)}</div></div>
    </div>
    <span class="card-toggle ${startCollapsed ? '' : 'open'}">⌄</span>`;
  const body = el('div', `card-body${startCollapsed ? ' collapsed' : ''}`);
  header.addEventListener('click', () => {
    body.classList.toggle('collapsed');
    header.querySelector('.card-toggle').classList.toggle('open', !body.classList.contains('collapsed'));
  });
  card.appendChild(header); card.appendChild(body);
  return card;
}

function makeKV(rows) {
  const grid = el('div', 'kv-grid');
  rows.forEach(([key, val, color = 'text']) => {
    const k = el('div', 'kv-key'); k.textContent = key;
    const v = el('div', `kv-val ${color === 'text' ? '' : color}`); v.textContent = val;
    grid.appendChild(k); grid.appendChild(v);
  });
  return grid;
}

function makeSimpleTable(headers, rows) {
  const table = el('table', 'data-table');
  const thead = el('thead'); thead.innerHTML = `<tr>${headers.map(h => `<th>${esc(h)}</th>`).join('')}</tr>`;
  const tbody = el('tbody');
  rows.forEach(row => {
    const tr = el('tr');
    tr.innerHTML = row.map((c, i) => `<td class="${i === 0 ? 'name' : ''}">${esc(String(c || '—'))}</td>`).join('');
    tbody.appendChild(tr);
  });
  table.appendChild(thead); table.appendChild(tbody);
  return table;
}

function showEmpty() { emptyState.classList.remove('hidden'); loadingState.classList.add('hidden'); resultsOutput.classList.add('hidden'); resultsOutput.innerHTML = ''; }
function showLoading(msg='Scanning…') { emptyState.classList.add('hidden'); loadingState.classList.remove('hidden'); resultsOutput.classList.add('hidden'); resultsOutput.innerHTML = ''; loadingText.textContent = msg; setProgress(0); }
function hideLoading() { loadingState.classList.add('hidden'); }
function setProgress(p) { progressBar.style.width = `${p}%`; }

function showError(msg) {
  hideLoading(); resultsOutput.innerHTML = ''; resultsOutput.classList.remove('hidden'); emptyState.classList.add('hidden');
  const b = el('div', 'summary-banner danger');
  b.innerHTML = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/></svg><span><strong>Error:</strong> ${esc(msg)}</span>`;
  resultsOutput.appendChild(b);
}

// ── History ───────────────────────────────────────────────────
function loadHistory()    { try { return JSON.parse(localStorage.getItem('nyx_history') || '[]'); } catch { return []; } }
function saveHistory(h)   { localStorage.setItem('nyx_history', JSON.stringify(h)); }

function addToHistory(query, mode) {
  let h = loadHistory().filter(i => !(i.query === query && i.mode === mode));
  h.unshift({ query, mode, ts: Date.now() });
  if (h.length > 20) h = h.slice(0, 20);
  saveHistory(h);
  renderHistory();
}

function renderHistory() {
  const h = loadHistory();
  historyList.innerHTML = '';
  if (!h.length) { historyList.innerHTML = '<p class="history-empty">No recent searches</p>'; return; }
  h.forEach(item => {
    const chip = el('button', 'history-chip');
    chip.innerHTML = `<span class="chip-mode">${esc(item.mode)}</span>${esc(item.query)}`;
    chip.addEventListener('click', () => {
      const modeBtn = document.querySelector(`.pill[data-mode="${item.mode}"]`);
      if (modeBtn) modeBtn.click();
      searchInput.value = item.query;
      runSearch(item.query);
    });
    historyList.appendChild(chip);
  });
}

clearHistBtn.addEventListener('click', () => { localStorage.removeItem('nyx_history'); renderHistory(); });

// ── Export ─────────────────────────────────────────────────────
function openExportModal()  { exportModal.classList.remove('hidden'); }
function closeExportModal() { exportModal.classList.add('hidden'); }
modalClose.addEventListener('click', closeExportModal);
exportModal.addEventListener('click', e => { if (e.target === exportModal) closeExportModal(); });

$('export-json').addEventListener('click', () => {
  downloadFile(JSON.stringify({ query: state.lastQuery, mode: state.mode, results: state.lastResults, timestamp: new Date().toISOString() }, null, 2), `nyx-${state.lastQuery}-${state.mode}.json`, 'application/json');
  closeExportModal();
});

$('export-csv').addEventListener('click', () => {
  downloadFile(resultsToCSV(state.lastResults, state.mode, state.lastQuery), `nyx-${state.lastQuery}-${state.mode}.csv`, 'text/csv');
  closeExportModal();
});

$('export-html').addEventListener('click', () => {
  downloadFile(generateHTMLReport(state.lastQuery, state.mode, state.lastResults), `nyx-report-${state.lastQuery}.html`, 'text/html');
  closeExportModal();
});

function downloadFile(content, filename, mime) {
  const blob = new Blob([content], { type: mime });
  const url  = URL.createObjectURL(blob);
  const a    = document.createElement('a');
  a.href = url; a.download = filename;
  document.body.appendChild(a); a.click();
  document.body.removeChild(a); URL.revokeObjectURL(url);
}

function resultsToCSV(data, mode, query) {
  if (mode === 'email' || mode === 'breach') {
    const breaches = data?.breach?.breaches || [];
    const rows = [['Query','Breach Name','Date','Records','Data Types','Source']];
    breaches.forEach(b => rows.push([query, b.name, b.date, b.pwnCount, (b.dataClasses||[]).join(';'), b.source]));
    return rows.map(r => r.map(c => `"${String(c||'').replace(/"/g,'""')}"`).join(',')).join('\n');
  }
  if (mode === 'username') {
    const results = data?.username?.results || [];
    const rows = [['Username','Platform','Found','URL']];
    results.forEach(r => rows.push([query, r.platform, r.found?'Yes':'No', r.url]));
    return rows.map(r => r.map(c => `"${String(c||'').replace(/"/g,'""')}"`).join(',')).join('\n');
  }
  if (mode === 'password') {
    const p = data?.password || {};
    return `"Password","Pwned","Count"\n"[REDACTED]","${p.pwned}","${p.count}"`;
  }
  return `"Query","Mode","Data"\n"${query}","${mode}","${JSON.stringify(data).replace(/"/g,'""')}"`;
}

function generateHTMLReport(query, mode, data) {
  const ts       = new Date().toLocaleString();
  const breaches = data?.breach?.breaches || [];
  const username = data?.username?.results || [];
  return `<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><title>Nyx OSINT — ${esc(query)}</title>
<style>body{font-family:system-ui,sans-serif;background:#090b0f;color:#e2e8f0;max-width:900px;margin:0 auto;padding:40px 24px;}
h1{color:#00d4ff;font-size:22px;}h2{color:#8892a4;font-size:13px;margin-bottom:28px;font-weight:400;}
h3{color:#e2e8f0;font-size:15px;margin:22px 0 10px;border-bottom:1px solid #1e2530;padding-bottom:6px;}
table{width:100%;border-collapse:collapse;font-size:13px;}th{text-align:left;padding:7px 12px;background:#141820;color:#4a5568;font-size:11px;text-transform:uppercase;border-bottom:1px solid #1e2530;}
td{padding:9px 12px;border-bottom:1px solid #1e2530;color:#8892a4;}td.n{color:#e2e8f0;font-weight:500;}.f{color:#22d3a3;}.r{color:#ff4d6a;}
p.meta{font-size:11px;color:#4a5568;margin-top:36px;border-top:1px solid #1e2530;padding-top:14px;}</style></head><body>
<h1>◈ Nyx OSINT Report</h1><h2>Target: <strong style="color:#e2e8f0">${esc(query)}</strong> &nbsp;·&nbsp; Mode: ${esc(mode)} &nbsp;·&nbsp; ${ts}</h2>
${(mode==='email'||mode==='breach')&&breaches.length?`<h3>Breach Records (${breaches.length})</h3><table><thead><tr><th>Name</th><th>Date</th><th>Records</th><th>Data Types</th><th>Source</th></tr></thead><tbody>${
  breaches.map(b=>`<tr><td class="n">${esc(b.name||'—')}</td><td>${esc(b.date||'—')}</td><td>${b.pwnCount?Number(b.pwnCount).toLocaleString():'—'}</td><td>${(b.dataClasses||[]).slice(0,4).map(esc).join(', ')||'—'}</td><td>${esc(b.source||'—')}</td></tr>`).join('')
}</tbody></table>`:mode==='email'||mode==='breach'?'<h3>Breach Records</h3><p class="f">No records found.</p>':''}
${mode==='username'&&username.length?`<h3>Username Results (${username.filter(r=>r.found).length} found)</h3><table><thead><tr><th>Platform</th><th>Status</th><th>URL</th></tr></thead><tbody>${
  username.map(r=>`<tr><td class="n">${esc(r.platform)}</td><td class="${r.found?'f':'miss'}">${r.found?'FOUND':'Not Found'}</td><td>${r.found?`<a href="${esc(r.url)}" style="color:#00d4ff">${esc(r.url)}</a>`:'—'}</td></tr>`).join('')
}</tbody></table>`:''}
<p class="meta">Generated by Nyx OSINT &mdash; For authorized security research only. ${ts}</p></body></html>`;
}

// ── Init ──────────────────────────────────────────────────────
renderHistory();
