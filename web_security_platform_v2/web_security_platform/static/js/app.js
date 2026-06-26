/* WebGuard Pro — Main App Logic */
'use strict';

// ── State ─────────────────────────────────────────────────────────
const state = {
  token: localStorage.getItem('wg_token'),
  user: JSON.parse(localStorage.getItem('wg_user') || 'null'),
  currentPage: 'dashboard',
  activeScanId: null,
  activePentestId: null,
  pollInterval: null,
};

// ── API Helper ────────────────────────────────────────────────────
async function api(method, path, body = null) {
  const opts = {
    method,
    headers: {
      'Content-Type': 'application/json',
      ...(state.token ? { Authorization: `Bearer ${state.token}` } : {}),
    },
  };
  if (body) opts.body = JSON.stringify(body);

  const res = await fetch(`/api${path}`, opts);
  const data = await res.json().catch(() => ({}));

  if (res.status === 401) {
    logout();
    throw new Error('Session expired');
  }
  if (!res.ok) throw new Error(data.detail || data.error || `HTTP ${res.status}`);
  return data;
}

// ── Auth ──────────────────────────────────────────────────────────
function switchAuth(tab) {
  document.querySelectorAll('.auth-tab').forEach((t, i) => t.classList.toggle('active', (i === 0 && tab === 'login') || (i === 1 && tab === 'register')));
  document.getElementById('loginForm').classList.toggle('hidden', tab !== 'login');
  document.getElementById('registerForm').classList.toggle('hidden', tab !== 'register');
}

async function handleLogin(e) {
  e.preventDefault();
  const btn = document.getElementById('loginBtn');
  const errEl = document.getElementById('loginError');
  errEl.classList.add('hidden');
  btn.innerHTML = '<span class="spinner"></span> Authenticating...';
  btn.disabled = true;

  try {
    const data = await api('POST', '/auth/login', {
      username: document.getElementById('loginUsername').value,
      password: document.getElementById('loginPassword').value,
    });
    state.token = data.access_token;
    state.user = data.user;
    localStorage.setItem('wg_token', state.token);
    localStorage.setItem('wg_user', JSON.stringify(state.user));
    initApp();
  } catch (err) {
    errEl.textContent = err.message;
    errEl.classList.remove('hidden');
  } finally {
    btn.innerHTML = '<span>Sign In</span><i class="fas fa-arrow-right"></i>';
    btn.disabled = false;
  }
}

async function handleRegister(e) {
  e.preventDefault();
  const errEl = document.getElementById('registerError');
  errEl.classList.add('hidden');

  const pwd = document.getElementById('regPassword').value;
  const confirm = document.getElementById('regConfirm').value;
  if (pwd !== confirm) {
    errEl.textContent = 'Passwords do not match';
    errEl.classList.remove('hidden');
    return;
  }

  try {
    await api('POST', '/auth/register', {
      username: document.getElementById('regUsername').value,
      email: document.getElementById('regEmail').value,
      password: pwd,
      confirm_password: confirm,
    });
    toast('Registration successful! Please log in.', 'success');
    switchAuth('login');
  } catch (err) {
    errEl.textContent = err.message;
    errEl.classList.remove('hidden');
  }
}

function logout() {
  localStorage.removeItem('wg_token');
  localStorage.removeItem('wg_user');
  state.token = null;
  state.user = null;
  clearInterval(state.pollInterval);
  document.getElementById('app').classList.add('hidden');
  document.getElementById('authOverlay').classList.remove('hidden');
}

// ── App Init ──────────────────────────────────────────────────────
function initApp() {
  document.getElementById('authOverlay').classList.add('hidden');
  document.getElementById('app').classList.remove('hidden');

  if (state.user) {
    document.getElementById('userInfo').innerHTML = `
      <strong>${state.user.username}</strong>
      <span style="font-size:11px;color:var(--accent-blue)">${state.user.role}</span>
    `;
  }

  showPage('dashboard');
  refreshAlertBadge();
  // Refresh alerts badge every 30s
  state.pollInterval = setInterval(refreshAlertBadge, 30000);
}

// ── Navigation ────────────────────────────────────────────────────
function showPage(name) {
  document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
  document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));

  const page = document.getElementById(`page-${name}`);
  if (page) page.classList.add('active');
  document.querySelector(`[data-page="${name}"]`)?.classList.add('active');

  const labels = {
    dashboard: 'Dashboard', scanner: 'Vulnerability Scanner',
    monitor: 'Security Monitor', pentest: 'Penetration Testing',
    alerts: 'Security Alerts', history: 'Login History'
  };
  document.getElementById('breadcrumb').textContent = labels[name] || name;
  state.currentPage = name;

  const loaders = {
    dashboard: loadDashboard,
    alerts: loadAlerts,
    monitor: loadMonitorTargets,
    scanner: loadScanHistory,
    history: loadLoginHistory,
  };
  if (loaders[name]) loaders[name]();
}

function toggleSidebar() {
  document.getElementById('sidebar').classList.toggle('open');
}

function refreshCurrent() {
  showPage(state.currentPage);
}

// ── Dashboard ─────────────────────────────────────────────────────
async function loadDashboard() {
  try {
    const [stats, breakdown, recent] = await Promise.all([
      api('GET', '/dashboard/stats'),
      api('GET', '/dashboard/severity-breakdown'),
      api('GET', '/dashboard/recent-scans'),
    ]);

    document.getElementById('stat-critical').textContent = stats.critical_findings;
    document.getElementById('stat-vulns').textContent = stats.total_vulnerabilities;
    document.getElementById('stat-scans').textContent = stats.total_scans;
    document.getElementById('stat-monitors').textContent = `${stats.monitor_targets.up}/${stats.monitor_targets.total}`;
    document.getElementById('stat-risk').textContent = stats.average_risk_score;
    document.getElementById('stat-alerts').textContent = stats.unread_alerts;

    renderSeverityChart(breakdown);
    renderRecentScans(recent);
  } catch (err) {
    toast('Failed to load dashboard: ' + err.message, 'error');
  }
}

function renderSeverityChart(data) {
  const severities = [
    { key: 'critical', label: 'Critical', color: '#ef4444' },
    { key: 'high', label: 'High', color: '#f97316' },
    { key: 'medium', label: 'Medium', color: '#f59e0b' },
    { key: 'low', label: 'Low', color: '#3b82f6' },
    { key: 'info', label: 'Info', color: '#6b7280' },
  ];
  const max = Math.max(1, ...Object.values(data));
  const el = document.getElementById('severityChart');
  el.innerHTML = severities.map(s => {
    const count = data[s.key] || 0;
    const pct = Math.round((count / max) * 100);
    return `
      <div class="sev-row ${s.key}">
        <span class="sev-label">${s.label}</span>
        <div class="sev-bar-wrap">
          <div class="sev-bar" style="width:${pct}%;background:${s.color}"></div>
        </div>
        <span class="sev-count">${count}</span>
      </div>`;
  }).join('');
}

function renderRecentScans(scans) {
  const el = document.getElementById('recentScansTable');
  if (!scans.length) {
    el.innerHTML = '<div class="empty-state"><i class="fas fa-inbox"></i><p>No scans yet</p></div>';
    return;
  }
  el.innerHTML = `
    <table>
      <thead><tr><th>Target</th><th>Type</th><th>Status</th><th>Risk</th><th>Date</th></tr></thead>
      <tbody>${scans.map(s => `
        <tr>
          <td class="mono" style="max-width:160px;overflow:hidden;text-overflow:ellipsis">${s.target_url}</td>
          <td>${s.scan_type}</td>
          <td><span class="scan-status-badge ${s.status}">${s.status}</span></td>
          <td style="color:${riskColor(s.risk_score)}">${s.risk_score}</td>
          <td>${fmtDate(s.created_at)}</td>
        </tr>`).join('')}
      </tbody>
    </table>`;
}

// ── Scanner ────────────────────────────────────────────────────────
async function startScan() {
  const url = document.getElementById('scanUrl').value.trim();
  if (!url) return toast('Please enter a target URL', 'warning');

  const types = [...document.querySelectorAll('#page-scanner .checkbox-item input:checked')].map(i => i.value);
  if (!types.length) return toast('Select at least one scan module', 'warning');

  try {
    const data = await api('POST', '/scanner/start', { target_url: url, scan_types: types });
    state.activeScanId = data.scan_id;
    toast('Scan started!', 'info');
    setScanStatus('running');
    document.getElementById('scanResults').innerHTML = `
      <div style="text-align:center;padding:40px;color:var(--text-secondary)">
        <div class="spinner" style="width:32px;height:32px;border-width:3px;margin:0 auto 12px"></div>
        <p>Scanning ${url}...</p>
      </div>`;
    pollScanResult();
  } catch (err) {
    toast('Scan failed: ' + err.message, 'error');
  }
}

function setScanStatus(status) {
  const el = document.getElementById('scanStatus');
  const icons = { pending: 'fa-clock', running: 'fa-spinner fa-spin', completed: 'fa-check-circle', failed: 'fa-times-circle' };
  el.className = `scan-status-badge ${status}`;
  el.innerHTML = `<i class="fas ${icons[status] || 'fa-info'}"></i> ${status.toUpperCase()}`;
  el.classList.remove('hidden');
}

function pollScanResult() {
  let attempts = 0;
  const interval = setInterval(async () => {
    attempts++;
    if (attempts > 60) { clearInterval(interval); return; }
    try {
      const data = await api('GET', `/scanner/${state.activeScanId}`);
      setScanStatus(data.status);
      if (data.status === 'completed') {
        clearInterval(interval);
        renderFindings(data, 'scanResults');
        loadScanHistory();
      } else if (data.status === 'failed') {
        clearInterval(interval);
        document.getElementById('scanResults').innerHTML = `<div class="empty-state"><i class="fas fa-times-circle" style="color:var(--accent-red)"></i><p>${data.error_message || 'Scan failed'}</p></div>`;
      }
    } catch { clearInterval(interval); }
  }, 2000);
}

function renderFindings(data, containerId) {
  const el = document.getElementById(containerId);
  const findings = data.findings || [];

  const riskClass = data.risk_score >= 70 ? 'risk-critical' : data.risk_score >= 40 ? 'risk-high' : data.risk_score >= 20 ? 'risk-medium' : 'risk-low';
  const riskLabel = data.risk_score >= 70 ? 'Critical' : data.risk_score >= 40 ? 'High' : data.risk_score >= 20 ? 'Medium' : 'Low';

  let html = `
    <div class="risk-score-display">
      <div class="risk-circle ${riskClass}">
        <span class="risk-num">${Math.round(data.risk_score || 0)}</span>
        <span class="risk-lbl">Risk</span>
      </div>
      <div class="risk-info">
        <h4>${riskLabel} Risk — ${findings.length} finding${findings.length !== 1 ? 's' : ''}</h4>
        <p>Target: <span style="font-family:var(--font-mono);font-size:11px">${data.target_url || data.target || ''}</span></p>
      </div>
    </div>`;

  if (!findings.length) {
    html += '<div class="empty-state"><i class="fas fa-shield-alt" style="color:var(--accent-green)"></i><p>No vulnerabilities found!</p></div>';
  } else {
    const order = ['critical','high','medium','low','info'];
    const sorted = [...findings].sort((a,b) => order.indexOf(a.severity) - order.indexOf(b.severity));
    html += sorted.map((f, i) => `
      <div class="finding-card">
        <div class="finding-header" onclick="toggleFinding(${i})">
          <span class="sev-badge ${f.severity}">${f.severity}</span>
          <span class="finding-title">${f.title}</span>
          <i class="fas fa-chevron-down" id="ficon-${i}" style="color:var(--text-muted);transition:transform 0.2s"></i>
        </div>
        <div class="finding-body" id="fbody-${i}">
          <div class="finding-field"><label>Category</label><span>${f.category}</span></div>
          <div class="finding-field"><label>Description</label><span>${f.description}</span></div>
          ${f.affected_url ? `<div class="finding-field"><label>Affected URL</label><span class="code">${f.affected_url}</span></div>` : ''}
          ${f.evidence ? `<div class="finding-field"><label>Evidence</label><span class="code">${f.evidence}</span></div>` : ''}
          ${f.remediation ? `<div class="finding-field"><label>Remediation</label><span class="remediation">${f.remediation}</span></div>` : ''}
        </div>
      </div>`).join('');
  }
  el.innerHTML = html;
}

function toggleFinding(i) {
  const body = document.getElementById(`fbody-${i}`);
  const icon = document.getElementById(`ficon-${i}`);
  body.classList.toggle('open');
  icon.style.transform = body.classList.contains('open') ? 'rotate(180deg)' : '';
}

async function loadScanHistory() {
  try {
    const scans = await api('GET', '/scanner/');
    const el = document.getElementById('scanHistory');
    if (!scans.length) { el.innerHTML = '<div class="empty-state"><i class="fas fa-inbox"></i><p>No scans yet</p></div>'; return; }
    el.innerHTML = `<table>
      <thead><tr><th>URL</th><th>Status</th><th>Risk</th><th>Vulns</th><th>Date</th></tr></thead>
      <tbody>${scans.map(s => `<tr>
        <td class="mono" style="max-width:200px;overflow:hidden;text-overflow:ellipsis">${s.target_url}</td>
        <td><span class="scan-status-badge ${s.status}">${s.status}</span></td>
        <td style="color:${riskColor(s.risk_score)};font-weight:600">${s.risk_score}</td>
        <td>${s.vulnerabilities_found}</td>
        <td>${fmtDate(s.created_at)}</td>
      </tr>`).join('')}</tbody>
    </table>`;
  } catch {}
}

// ── Monitor ────────────────────────────────────────────────────────
async function addMonitorTarget() {
  const name = document.getElementById('monName').value.trim();
  const url = document.getElementById('monUrl').value.trim();
  const interval = parseInt(document.getElementById('monInterval').value);

  if (!name || !url) return toast('Please fill in name and URL', 'warning');
  try {
    await api('POST', '/monitor/targets', { name, url, check_interval_minutes: interval });
    toast('Target added!', 'success');
    document.getElementById('monName').value = '';
    document.getElementById('monUrl').value = '';
    loadMonitorTargets();
  } catch (err) {
    toast('Error: ' + err.message, 'error');
  }
}

async function loadMonitorTargets() {
  try {
    const targets = await api('GET', '/monitor/targets');
    const el = document.getElementById('monitorTargets');
    if (!targets.length) {
      el.innerHTML = '<div class="empty-state"><i class="fas fa-satellite-dish"></i><p>No targets monitored yet</p></div>';
      return;
    }
    el.innerHTML = targets.map(t => `
      <div class="target-card">
        <div class="target-status ${t.last_status || 'unknown'}"></div>
        <div class="target-info">
          <strong>${t.name}</strong>
          <small>${t.url}</small>
        </div>
        <div class="target-meta">
          <div>${t.last_response_time_ms ? t.last_response_time_ms + 'ms' : '—'}</div>
          <div style="font-size:10px;color:var(--text-muted)">${t.uptime_percentage}% uptime</div>
        </div>
        <button class="target-btn" onclick="checkTarget('${t.id}')">
          <i class="fas fa-sync-alt"></i> Check
        </button>
      </div>`).join('');
  } catch {}
}

async function checkTarget(id) {
  try {
    const result = await api('POST', `/monitor/check/${id}`);
    const icon = result.status === 'up' ? '✅' : '🔴';
    toast(`${icon} ${result.target}: ${result.status.toUpperCase()} (${result.response_time_ms}ms)`, result.status === 'up' ? 'success' : 'error');
    loadMonitorTargets();
  } catch (err) {
    toast('Check failed: ' + err.message, 'error');
  }
}

// ── Pentest ────────────────────────────────────────────────────────
async function startPentest() {
  const target = document.getElementById('pentestTarget').value.trim();
  if (!target) return toast('Please enter a target', 'warning');

  const tests = [...document.querySelectorAll('#page-pentest .checkbox-item input:checked')].map(i => i.value);
  if (!tests.length) return toast('Select at least one test module', 'warning');

  try {
    const data = await api('POST', '/pentest/start', { target, tests });
    state.activePentestId = data.scan_id;
    toast('Pentest launched!', 'warning');
    document.getElementById('pentestStatus').className = 'scan-status-badge running';
    document.getElementById('pentestStatus').innerHTML = '<i class="fas fa-spinner fa-spin"></i> RUNNING';
    document.getElementById('pentestStatus').classList.remove('hidden');
    document.getElementById('pentestResults').innerHTML = `
      <div style="text-align:center;padding:40px;color:var(--text-secondary)">
        <div class="spinner" style="width:32px;height:32px;border-width:3px;margin:0 auto 12px"></div>
        <p>Running penetration tests on ${target}...</p>
      </div>`;
    pollPentestResult();
  } catch (err) {
    toast('Pentest failed: ' + err.message, 'error');
  }
}

function pollPentestResult() {
  let attempts = 0;
  const interval = setInterval(async () => {
    attempts++;
    if (attempts > 90) { clearInterval(interval); return; }
    try {
      const data = await api('GET', `/pentest/${state.activePentestId}`);
      if (data.status === 'completed') {
        clearInterval(interval);
        document.getElementById('pentestStatus').className = 'scan-status-badge completed';
        document.getElementById('pentestStatus').innerHTML = '<i class="fas fa-check-circle"></i> COMPLETED';
        // Reuse findings renderer
        renderFindings({
          risk_score: data.risk_score,
          target_url: data.target,
          findings: data.findings
        }, 'pentestResults');
      } else if (data.status === 'failed') {
        clearInterval(interval);
        document.getElementById('pentestStatus').className = 'scan-status-badge failed';
        document.getElementById('pentestStatus').innerHTML = '<i class="fas fa-times-circle"></i> FAILED';
      }
    } catch { clearInterval(interval); }
  }, 2000);
}

// ── Alerts ─────────────────────────────────────────────────────────
async function loadAlerts() {
  const unreadOnly = document.getElementById('unreadOnly')?.checked || false;
  try {
    const alerts = await api('GET', `/monitor/alerts?unread_only=${unreadOnly}`);
    const el = document.getElementById('alertsList');
    if (!alerts.length) {
      el.innerHTML = '<div class="empty-state"><i class="fas fa-bell-slash"></i><p>No alerts</p></div>';
      return;
    }
    el.innerHTML = alerts.map(a => `
      <div class="alert-item ${!a.is_read ? 'unread' : ''}">
        <div class="alert-icon ${a.severity}"><i class="fas fa-${a.severity === 'critical' ? 'skull' : a.severity === 'high' ? 'exclamation-triangle' : 'info-circle'}"></i></div>
        <div class="alert-content">
          <div class="alert-title">${a.title}</div>
          <div class="alert-msg">${a.message}</div>
          <div class="alert-meta"><i class="fas fa-clock"></i> ${fmtDate(a.created_at)} · ${a.source}</div>
        </div>
        ${!a.is_read ? `<button class="btn btn-sm" onclick="markAlertRead('${a.id}')"><i class="fas fa-check"></i></button>` : ''}
      </div>`).join('');
  } catch {}
}

async function markAlertRead(id) {
  try {
    await api('PUT', `/monitor/alerts/${id}/read`);
    loadAlerts();
    refreshAlertBadge();
  } catch {}
}

async function refreshAlertBadge() {
  try {
    const alerts = await api('GET', '/monitor/alerts?unread_only=true');
    const badge = document.getElementById('alertBadge');
    const count = alerts.length;
    badge.textContent = count;
    badge.style.display = count > 0 ? 'inline' : 'none';
    document.getElementById('stat-alerts')?.textContent !== undefined && (document.getElementById('stat-alerts').textContent = count);
  } catch {}
}

// ── Login History ──────────────────────────────────────────────────
async function loadLoginHistory() {
  try {
    const history = await api('GET', '/auth/login-history');
    const el = document.getElementById('loginHistory');
    if (!history.length) { el.innerHTML = '<div class="empty-state"><i class="fas fa-history"></i><p>No login history</p></div>'; return; }
    el.innerHTML = `<table>
      <thead><tr><th>Status</th><th>IP Address</th><th>User Agent</th><th>Reason</th><th>Time</th></tr></thead>
      <tbody>${history.map(h => `<tr>
        <td>${h.success ? '<span style="color:var(--accent-green)"><i class="fas fa-check-circle"></i> Success</span>' : '<span style="color:var(--accent-red)"><i class="fas fa-times-circle"></i> Failed</span>'}</td>
        <td class="mono">${h.ip}</td>
        <td style="max-width:200px;overflow:hidden;text-overflow:ellipsis;font-size:11px">${h.user_agent || '—'}</td>
        <td style="color:var(--sev-medium)">${h.reason || '—'}</td>
        <td>${fmtDate(h.time)}</td>
      </tr>`).join('')}</tbody>
    </table>`;
  } catch {}
}

// ── Toast ──────────────────────────────────────────────────────────
function toast(msg, type = 'info') {
  const icons = { success: 'check-circle', error: 'times-circle', warning: 'exclamation-triangle', info: 'info-circle' };
  const el = document.createElement('div');
  el.className = `toast ${type}`;
  el.innerHTML = `<i class="fas fa-${icons[type]}"></i><span>${msg}</span>`;
  document.getElementById('toastContainer').appendChild(el);
  setTimeout(() => el.remove(), 4000);
}

// ── Helpers ────────────────────────────────────────────────────────
function fmtDate(iso) {
  if (!iso) return '—';
  try { return new Date(iso).toLocaleString(); } catch { return iso; }
}

function riskColor(score) {
  if (score >= 70) return 'var(--sev-critical)';
  if (score >= 40) return 'var(--sev-high)';
  if (score >= 20) return 'var(--sev-medium)';
  return 'var(--accent-green)';
}

// ── Bootstrap ──────────────────────────────────────────────────────
if (state.token && state.user) {
  initApp();
}
