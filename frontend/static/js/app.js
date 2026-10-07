/**
 * Shadow.Guard - Enterprise Cloud Governance & Rogue Resource Detection Dashboard
 * Manages Live Feed (SSE), Incidents Matrix, SRE Approvals Workflow, and In-Memory Log Analyzer.
 */

// ============================================================================
// Global State
// ============================================================================
const state = {
  activeTab: 'livefeed',
  region: 'all',
  stats: null,
  sseSource: null,
  sseConnected: false,
  feedPaused: false,
  feedEvents: [],
  feedFilters: { search: '', service: '', risk: '', type: '' },
  incidents: [],
  incidentFilters: { search: '', status: '', tier: '', service: '' },
  approvals: [],
  auditLogs: [],
  charts: {
    velocity: null,
    riskDonut: null,
    serviceBars: null,
    logSeverity: null,
    logErrors: null,
    logSources: null,
  },
  velocityHistory: [], // [count, count, ...] for rolling 15 min
  logAnalysis: null,
};

// ============================================================================
// Utilities & Sanitization
// ============================================================================
function escapeHtml(text) {
  if (text === null || text === undefined) return '';
  return String(text)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

function renderSimpleMarkdown(md) {
  if (!md) return '';
  let html = escapeHtml(md);

  // Headers
  html = html.replace(/^### (.*$)/gim, '<h3>$1</h3>');
  html = html.replace(/^## (.*$)/gim, '<h2>$1</h2>');
  html = html.replace(/^# (.*$)/gim, '<h1>$1</h1>');

  // Code blocks
  html = html.replace(/```([a-z]*)\n([\s\S]*?)```/gim, '<pre><code>$2</code></pre>');
  html = html.replace(/`([^`]+)`/gim, '<code>$1</code>');

  // Bold & Italic
  html = html.replace(/\*\*([^*]+)\*\*/gim, '<strong>$1</strong>');
  html = html.replace(/\*([^*]+)\*/gim, '<em>$1</em>');

  // Unordered lists
  html = html.replace(/^\- (.*$)/gim, '<li>$1</li>');
  html = html.replace(/(<li>.*<\/li>)/gim, '<ul>$1</ul>');

  // Horizontal rules
  html = html.replace(/^---$/gim, '<hr style="border: none; border-top: 1px solid var(--border-subtle); margin: 1rem 0;">');

  // Paragraphs
  html = html.replace(/\n\n/gim, '<br><br>');
  return html;
}

function formatRelativeTime(isoString) {
  if (!isoString) return 'N/A';
  try {
    const date = new Date(isoString);
    const now = new Date();
    const diffSec = Math.floor((now - date) / 1000);
    if (diffSec < 15) return 'just now';
    if (diffSec < 60) return `${diffSec}s ago`;
    const diffMin = Math.floor(diffSec / 60);
    if (diffMin < 60) return `${diffMin}m ago`;
    const diffHour = Math.floor(diffMin / 60);
    if (diffHour < 24) return `${diffHour}h ago`;
    const diffDays = Math.floor(diffHour / 24);
    return `${diffDays}d ago`;
  } catch (e) {
    return isoString;
  }
}

function formatAbsoluteTime(isoString) {
  if (!isoString) return 'N/A';
  try {
    const d = new Date(isoString);
    return `${d.toLocaleString()} (UTC: ${d.toISOString()})`;
  } catch (e) {
    return isoString;
  }
}

function animateValue(elemId, start, end, duration = 600, prefix = '', suffix = '') {
  const obj = document.getElementById(elemId);
  if (!obj) return;
  const isFloat = String(end).includes('.');
  const startNum = parseFloat(String(start).replace(/[^0-9.-]+/g, '')) || 0;
  const endNum = parseFloat(String(end).replace(/[^0-9.-]+/g, '')) || 0;
  if (isNaN(endNum)) { obj.textContent = end; return; }

  let startTimestamp = null;
  const step = (timestamp) => {
    if (!startTimestamp) startTimestamp = timestamp;
    const progress = Math.min((timestamp - startTimestamp) / duration, 1);
    const current = startNum + (endNum - startNum) * progress;
    obj.textContent = `${prefix}${isFloat ? current.toFixed(2) : Math.floor(current)}${suffix}`;
    if (progress < 1) {
      window.requestAnimationFrame(step);
    } else {
      obj.textContent = `${prefix}${isFloat ? endNum.toFixed(2) : endNum}${suffix}`;
    }
  };
  window.requestAnimationFrame(step);
}

function showToast(message, type = 'info') {
  const container = document.getElementById('toast-container');
  if (!container) return;
  const toast = document.createElement('div');
  toast.className = `toast toast-${type}`;
  toast.innerHTML = `
    <i data-lucide="${type === 'success' ? 'check-circle' : (type === 'error' ? 'alert-triangle' : 'info')}" style="width: 18px; height: 18px;"></i>
    <span>${escapeHtml(message)}</span>
  `;
  container.appendChild(toast);
  if (window.lucide) lucide.createIcons({ root: toast });

  setTimeout(() => {
    toast.style.opacity = '0';
    toast.style.transform = 'translateX(100%)';
    toast.style.transition = 'all 0.3s ease';
    setTimeout(() => toast.remove(), 300);
  }, 4500);
}

// ============================================================================
// Initialization
// ============================================================================
document.addEventListener('DOMContentLoaded', () => {
  initTabs();
  initRegionSelector();
  initLiveFeedControls();
  initIncidentsFilters();
  initModals();
  initLogAnalyzer();

  // Load initial datasets
  fetchStats();
  fetchIncidents();
  fetchApprovals();

  // Initialize Charts
  initCharts();

  // Connect Server-Sent Events (SSE)
  connectLiveFeedSSE();

  // Periodic Reminder Checker
  setInterval(checkDueReminders, 30000);

  if (window.lucide) lucide.createIcons();
});

// ============================================================================
// Tabs Navigation
// ============================================================================
function initTabs() {
  const tabBtns = document.querySelectorAll('.tab-btn');
  tabBtns.forEach(btn => {
    btn.addEventListener('click', () => {
      const target = btn.dataset.tab;
      switchTab(target);
    });
  });
}

function switchTab(tabId) {
  state.activeTab = tabId;
  document.querySelectorAll('.tab-btn').forEach(b => {
    const isActive = b.dataset.tab === tabId;
    b.classList.toggle('active', isActive);
    b.setAttribute('aria-selected', isActive ? 'true' : 'false');
  });

  document.querySelectorAll('.tab-content').forEach(s => {
    s.classList.toggle('active', s.id === `tab-${tabId}`);
  });

  if (window.lucide) lucide.createIcons();
}

function initRegionSelector() {
  const sel = document.getElementById('select-global-region');
  if (sel) {
    sel.addEventListener('change', (e) => {
      state.region = e.target.value;
      fetchStats();
      fetchIncidents();
      showToast(`Filter set to: ${e.target.value.toUpperCase()}`, 'info');
    });
  }

  const refreshBtn = document.getElementById('btn-manual-refresh');
  if (refreshBtn) {
    refreshBtn.addEventListener('click', () => {
      fetchStats();
      fetchIncidents();
      fetchApprovals();
      showToast('Dashboard data refreshed', 'info');
    });
  }
}

// ============================================================================
// Dashboard KPIs & Aggregations
// ============================================================================
async function fetchStats() {
  try {
    const url = state.region && state.region !== 'all'
      ? `/api/dashboard/stats?region=${encodeURIComponent(state.region)}`
      : '/api/dashboard/stats';
    const res = await fetch(url);
    if (!res.ok) return;
    const data = await res.json();
    state.stats = data;

    // Update KPIs with animated numbers
    animateValue('kpi-total-resources', 0, data.total_resources || 0);
    animateValue('kpi-flagged-resources', 0, data.flagged_resources || 0);
    animateValue('kpi-high-risk', 0, data.risk_buckets?.HIGH || 0);
    animateValue('kpi-wasted-cost', 0, data.wasted_monthly_cost || 0, 600, '$');
    animateValue('kpi-pending-approvals', 0, data.pending_approvals || 0);

    const compElem = document.getElementById('kpi-compliance-rate');
    if (compElem) compElem.textContent = `${data.compliance_rate || 100}% Compliant`;

    const accElem = document.getElementById('kpi-account-id');
    if (accElem && data.account_id) accElem.textContent = `Account: ${data.account_id}`;

    // Update charts
    updateDonutChart(data.risk_buckets);
    updateServiceBars(data.by_type);
  } catch (e) {
    console.warn('Failed to fetch stats:', e);
  }
}

// ============================================================================
// Interactive Visualizations (Chart.js via CDN)
// ============================================================================
function initCharts() {
  // 1. Streaming Line Chart: Events per Minute (rolling 15m)
  const ctxVel = document.getElementById('chart-events-velocity')?.getContext('2d');
  if (ctxVel) {
    const labels = Array.from({ length: 15 }, (_, i) => `-${15 - i}m`);
    const initialData = [1, 2, 0, 3, 2, 4, 1, 5, 3, 2, 4, 3, 5, 4, 6];
    state.velocityHistory = initialData;

    state.charts.velocity = new Chart(ctxVel, {
      type: 'line',
      data: {
        labels: labels,
        datasets: [{
          label: 'Events / Min',
          data: initialData,
          borderColor: '#00f0ff',
          backgroundColor: 'rgba(0, 240, 255, 0.1)',
          borderWidth: 2,
          fill: true,
          tension: 0.35,
          pointRadius: 3,
          pointBackgroundColor: '#00f0ff',
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: { display: false },
          tooltip: {
            backgroundColor: '#0f172a',
            borderColor: 'rgba(255,255,255,0.1)',
            borderWidth: 1,
          }
        },
        scales: {
          x: { grid: { color: 'rgba(255, 255, 255, 0.05)' }, ticks: { color: '#64748b', font: { family: 'JetBrains Mono', size: 10 } } },
          y: { beginAtZero: true, grid: { color: 'rgba(255, 255, 255, 0.05)' }, ticks: { color: '#64748b', font: { family: 'JetBrains Mono', size: 10 } } }
        }
      }
    });
  }

  // 2. Risk Tier Donut
  const ctxDonut = document.getElementById('chart-risk-donut')?.getContext('2d');
  if (ctxDonut) {
    state.charts.riskDonut = new Chart(ctxDonut, {
      type: 'doughnut',
      data: {
        labels: ['HIGH', 'MEDIUM', 'LOW', 'SAFE'],
        datasets: [{
          data: [2, 1, 1, 3],
          backgroundColor: ['#f43f5e', '#f59e0b', '#10b981', '#06b6d4'],
          borderColor: '#0b0f19',
          borderWidth: 3,
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: { position: 'bottom', labels: { color: '#94a3b8', font: { family: 'Inter', size: 11 }, padding: 12 } }
        },
        onClick: (evt, elements) => {
          if (elements && elements.length > 0) {
            const index = elements[0].index;
            const tier = ['HIGH', 'MEDIUM', 'LOW', 'SAFE'][index];
            setFeedFilter('risk', tier);
          }
        }
      }
    });
  }

  // 3. Flagged Resources by Service Bar Chart
  const ctxBars = document.getElementById('chart-service-bars')?.getContext('2d');
  if (ctxBars) {
    state.charts.serviceBars = new Chart(ctxBars, {
      type: 'bar',
      data: {
        labels: ['EC2', 'S3', 'RDS'],
        datasets: [{
          label: 'Flagged Assets',
          data: [3, 1, 2],
          backgroundColor: 'rgba(139, 92, 246, 0.75)',
          borderColor: '#8b5cf6',
          borderWidth: 1,
          borderRadius: 6,
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: { display: false },
          tooltip: { backgroundColor: '#0f172a', borderColor: 'rgba(255,255,255,0.1)', borderWidth: 1 }
        },
        scales: {
          x: { grid: { display: false }, ticks: { color: '#94a3b8', font: { family: 'Inter', size: 11 } } },
          y: { beginAtZero: true, grid: { color: 'rgba(255, 255, 255, 0.05)' }, ticks: { color: '#64748b', font: { family: 'JetBrains Mono', size: 10 } } }
        },
        onClick: (evt, elements) => {
          if (elements && elements.length > 0) {
            const index = elements[0].index;
            const svc = state.charts.serviceBars.data.labels[index];
            setFeedFilter('service', svc);
          }
        }
      }
    });
  }
}

function updateDonutChart(buckets) {
  if (!state.charts.riskDonut || !buckets) return;
  state.charts.riskDonut.data.datasets[0].data = [
    buckets.HIGH || 0,
    buckets.MEDIUM || 0,
    buckets.LOW || 0,
    buckets.SAFE || 0,
  ];
  state.charts.riskDonut.update();
}

function updateServiceBars(byType) {
  if (!state.charts.serviceBars || !byType) return;
  const labels = byType.map(t => t.type);
  const data = byType.map(t => t.flagged_count || 0);
  state.charts.serviceBars.data.labels = labels;
  state.charts.serviceBars.data.datasets[0].data = data;
  state.charts.serviceBars.update();
}

function bumpVelocityChart() {
  if (!state.charts.velocity) return;
  const hist = state.velocityHistory;
  hist[hist.length - 1] = (hist[hist.length - 1] || 0) + 1;
  state.charts.velocity.data.datasets[0].data = [...hist];
  state.charts.velocity.update('none');
}

// ============================================================================
// TAB 1: Live Feed (Task 2 & SSE)
// ============================================================================
function connectLiveFeedSSE() {
  const pill = document.getElementById('sse-connection-pill');
  const text = document.getElementById('sse-status-text');

  if (state.sseSource) {
    state.sseSource.close();
  }

  try {
    state.sseSource = new EventSource('/api/live-feed/stream');

    state.sseSource.onopen = () => {
      state.sseConnected = true;
      if (pill) pill.classList.remove('disconnected');
      if (text) text.textContent = 'LIVE FEED CONNECTED';
    };

    state.sseSource.onmessage = (e) => {
      if (!e.data || e.data.trim() === '') return;
      try {
        const payload = JSON.parse(e.data);
        handleLiveFeedMessage(payload);
      } catch (err) {
        console.warn('Failed to parse SSE event:', err);
      }
    };

    state.sseSource.onerror = () => {
      state.sseConnected = false;
      if (pill) pill.classList.add('disconnected');
      if (text) text.textContent = 'RECONNECTING FEED...';
      // Fallback polling while disconnected
      fetchRecentFeedFallback();
    };
  } catch (e) {
    console.error('SSE initialization error:', e);
    fetchRecentFeedFallback();
  }
}

async function fetchRecentFeedFallback() {
  try {
    const res = await fetch('/api/live-feed');
    if (!res.ok) return;
    const data = await res.json();
    if (data.events) {
      data.events.forEach(evt => addFeedEvent(evt, false));
      renderFeedList();
    }
  } catch (e) {
    console.warn('Fallback feed error:', e);
  }
}

function handleLiveFeedMessage(evt) {
  addFeedEvent(evt, true);
  bumpVelocityChart();

  // If incident or approval related, auto-refresh respective tables
  if (evt.event === 'incident_created' || evt.event === 'runbook_generated' || evt.event === 'approval_updated') {
    fetchStats();
    fetchIncidents();
    fetchApprovals();
  }
}

function addFeedEvent(evt, prepend = true) {
  const existingIdx = state.feedEvents.findIndex(e => e.id === evt.id || (e.timestamp === evt.timestamp && e.data?.resource_id === evt.data?.resource_id));
  if (existingIdx !== -1) return;

  if (prepend) {
    state.feedEvents.unshift(evt);
  } else {
    state.feedEvents.push(evt);
  }

  if (state.feedEvents.length > 150) state.feedEvents.pop();

  if (!state.feedPaused) {
    renderFeedList();
  }
}

function renderFeedList() {
  const container = document.getElementById('live-feed-container');
  if (!container) return;

  const filtered = state.feedEvents.filter(evt => {
    const d = evt.data || {};
    if (state.feedFilters.search) {
      const q = state.feedFilters.search.toLowerCase();
      const match = (d.resource_id || '').toLowerCase().includes(q) ||
                    (d.description || '').toLowerCase().includes(q) ||
                    (d.type || '').toLowerCase().includes(q);
      if (!match) return false;
    }
    if (state.feedFilters.service && (d.type || '').toUpperCase() !== state.feedFilters.service.toUpperCase()) {
      return false;
    }
    if (state.feedFilters.risk && (d.tier || '').toUpperCase() !== state.feedFilters.risk.toUpperCase()) {
      return false;
    }
    if (state.feedFilters.type && evt.event !== state.feedFilters.type) {
      return false;
    }
    return true;
  });

  if (filtered.length === 0) {
    container.innerHTML = `
      <div class="feed-empty-state">
        <i data-lucide="inbox" style="width: 32px; height: 32px; margin: 0 auto 0.5rem; opacity: 0.5;"></i>
        <div>No telemetry events match current filters</div>
      </div>
    `;
    if (window.lucide) lucide.createIcons({ root: container });
    return;
  }

  container.innerHTML = filtered.map(evt => {
    const d = evt.data || {};
    const resId = d.resource_id || 'sys';
    const type = d.type || 'AWS';
    const tier = d.tier || 'INFO';
    const badgeClass = tier === 'HIGH' ? 'badge-high' : (tier === 'MEDIUM' ? 'badge-med' : 'badge-low');
    const desc = d.description || `Event: ${evt.event}`;

    let icon = 'activity';
    if (type === 'EC2') icon = 'server';
    else if (type === 'S3') icon = 'database';
    else if (type === 'RDS') icon = 'hard-drive';

    return `
      <div class="feed-item" data-resource-id="${escapeHtml(resId)}" onclick="onFeedItemClick('${escapeHtml(resId)}')">
        <div class="feed-item-left">
          <div class="feed-item-icon">
            <i data-lucide="${icon}" style="width: 18px; height: 18px;"></i>
          </div>
          <div class="feed-item-info">
            <div class="feed-item-title">
              <span class="resource-id-code">${escapeHtml(resId)}</span>
              <span class="risk-badge ${badgeClass}" style="font-size: 0.7rem; padding: 0.15rem 0.5rem;">${escapeHtml(tier)}</span>
              <span style="font-size: 0.75rem; color: var(--text-dim);">${escapeHtml(evt.event)}</span>
            </div>
            <div class="feed-item-desc">${escapeHtml(desc)}</div>
          </div>
        </div>
        <div class="feed-item-right">
          <span class="feed-item-time" title="${escapeHtml(formatAbsoluteTime(evt.timestamp))}">${formatRelativeTime(evt.timestamp)}</span>
          <i data-lucide="chevron-right" style="width: 16px; height: 16px; color: var(--text-dim);"></i>
        </div>
      </div>
    `;
  }).join('');

  if (window.lucide) lucide.createIcons({ root: container });
}

function onFeedItemClick(resId) {
  if (!resId || resId === 'sys') return;
  // Switch to Incidents tab and highlight/open resource
  switchTab('incidents');
  const searchInput = document.getElementById('input-incident-search');
  if (searchInput) {
    searchInput.value = resId;
    state.incidentFilters.search = resId;
    renderIncidentsTable();
  }
}

function setFeedFilter(key, val) {
  state.feedFilters[key] = val;
  if (key === 'risk') {
    const sel = document.getElementById('select-feed-risk-filter');
    if (sel) sel.value = val;
  } else if (key === 'service') {
    const sel = document.getElementById('select-feed-service-filter');
    if (sel) sel.value = val;
  }
  renderFeedList();
}

function initLiveFeedControls() {
  const pauseBtn = document.getElementById('btn-toggle-stream-pause');
  if (pauseBtn) {
    pauseBtn.addEventListener('click', () => {
      state.feedPaused = !state.feedPaused;
      const icon = document.getElementById('icon-stream-pause');
      const text = document.getElementById('text-stream-pause');
      if (state.feedPaused) {
        if (text) text.textContent = 'Resume Feed';
        if (icon) icon.setAttribute('data-lucide', 'play');
        showToast('Feed paused', 'info');
      } else {
        if (text) text.textContent = 'Pause Feed';
        if (icon) icon.setAttribute('data-lucide', 'pause');
        renderFeedList();
        showToast('Feed resumed', 'info');
      }
      if (window.lucide) lucide.createIcons();
    });
  }

  const clearBtn = document.getElementById('btn-clear-feed');
  if (clearBtn) {
    clearBtn.addEventListener('click', () => {
      state.feedEvents = [];
      renderFeedList();
      showToast('Live feed cleared', 'info');
    });
  }

  const searchInput = document.getElementById('input-feed-search');
  if (searchInput) {
    searchInput.addEventListener('input', (e) => {
      state.feedFilters.search = e.target.value;
      renderFeedList();
    });
  }

  const svcSel = document.getElementById('select-feed-service-filter');
  if (svcSel) {
    svcSel.addEventListener('change', (e) => {
      state.feedFilters.service = e.target.value;
      renderFeedList();
    });
  }

  const riskSel = document.getElementById('select-feed-risk-filter');
  if (riskSel) {
    riskSel.addEventListener('change', (e) => {
      state.feedFilters.risk = e.target.value;
      renderFeedList();
    });
  }

  const typeSel = document.getElementById('select-feed-type-filter');
  if (typeSel) {
    typeSel.addEventListener('change', (e) => {
      state.feedFilters.type = e.target.value;
      renderFeedList();
    });
  }
}

// ============================================================================
// TAB 2: Incidents Matrix & Runbook (Task 3 & Addendum A2, A4)
// ============================================================================
async function fetchIncidents() {
  try {
    let url = '/api/incidents';
    const params = [];
    if (state.incidentFilters.search) params.push(`search=${encodeURIComponent(state.incidentFilters.search)}`);
    if (state.incidentFilters.status) params.push(`status=${encodeURIComponent(state.incidentFilters.status)}`);
    if (state.incidentFilters.tier) params.push(`risk_tier=${encodeURIComponent(state.incidentFilters.tier)}`);
    if (state.incidentFilters.service) params.push(`service=${encodeURIComponent(state.incidentFilters.service)}`);
    if (state.region && state.region !== 'all') params.push(`region=${encodeURIComponent(state.region)}`);

    if (params.length > 0) url += `?${params.join('&')}`;

    const res = await fetch(url);
    if (!res.ok) return;
    const data = await res.json();
    state.incidents = data.incidents || [];
    renderIncidentsTable();
  } catch (e) {
    console.warn('Failed to fetch incidents:', e);
  }
}

function initIncidentsFilters() {
  const searchInput = document.getElementById('input-incident-search');
  if (searchInput) {
    searchInput.addEventListener('input', (e) => {
      state.incidentFilters.search = e.target.value;
      renderIncidentsTable();
    });
  }

  const stSel = document.getElementById('select-incident-status-filter');
  if (stSel) {
    stSel.addEventListener('change', (e) => {
      state.incidentFilters.status = e.target.value;
      fetchIncidents();
    });
  }

  const tierSel = document.getElementById('select-incident-tier-filter');
  if (tierSel) {
    tierSel.addEventListener('change', (e) => {
      state.incidentFilters.tier = e.target.value;
      fetchIncidents();
    });
  }

  const svcSel = document.getElementById('select-incident-service-filter');
  if (svcSel) {
    svcSel.addEventListener('change', (e) => {
      state.incidentFilters.service = e.target.value;
      fetchIncidents();
    });
  }
}

function renderIncidentsTable() {
  const tbody = document.getElementById('incidents-table-body');
  if (!tbody) return;

  const list = state.incidents.filter(inc => {
    if (state.incidentFilters.search) {
      const q = state.incidentFilters.search.toLowerCase();
      const match = (inc.id || '').toLowerCase().includes(q) ||
                    (inc.resource_id || '').toLowerCase().includes(q) ||
                    (inc.resource_name || '').toLowerCase().includes(q);
      if (!match) return false;
    }
    return true;
  });

  if (list.length === 0) {
    tbody.innerHTML = `
      <tr>
        <td colspan="9" style="text-align: center; padding: 2.5rem; color: var(--text-dim);">
          No recorded incidents match criteria
        </td>
      </tr>
    `;
    return;
  }

  tbody.innerHTML = list.map(inc => {
    const statusClean = inc.status || 'Open';
    const statusClass = getStatusBadgeClass(statusClean);
    const tier = (inc.risk_tier || 'HIGH').toUpperCase();
    const tierBadge = tier === 'HIGH' ? 'badge-high' : (tier === 'MEDIUM' ? 'badge-med' : 'badge-low');
    const pipe = inc.pipeline_status || { detected: 'ok', runbook: 'pending', github: 'pending', slack: 'pending' };

    return `
      <tr class="incident-row" data-incident-id="${escapeHtml(inc.id)}" onclick="toggleIncidentAccordion('${escapeHtml(inc.id)}')">
        <td><i data-lucide="chevron-right" id="arrow-${escapeHtml(inc.id)}" style="width: 16px; height: 16px; color: var(--text-dim); transition: transform 0.2s;"></i></td>
        <td><strong style="color: #fff;">${escapeHtml(inc.id)}</strong></td>
        <td><span class="resource-id-code">${escapeHtml(inc.resource_id)}</span></td>
        <td><span class="service-pill">${escapeHtml(inc.type || 'EC2')}</span></td>
        <td><span style="font-family: var(--font-mono); font-size: 0.8rem;">${escapeHtml(inc.region || 'global')}</span></td>
        <td>
          <div style="display: flex; align-items: center; gap: 0.4rem;">
            <span style="font-weight: 700; color: #fff;">${parseFloat(inc.score || 0).toFixed(1)}</span>
            <span class="risk-badge ${tierBadge}" style="font-size: 0.65rem; padding: 0.1rem 0.4rem;">${escapeHtml(tier)}</span>
          </div>
        </td>
        <td>
          <span class="badge-status ${statusClass}">
            <span class="pulsing-dot" style="width: 6px; height: 6px;"></span>
            ${escapeHtml(statusClean)}
          </span>
        </td>
        <td style="font-size: 0.8rem; color: var(--text-dim);" title="${escapeHtml(formatAbsoluteTime(inc.detected_at))}">
          ${formatRelativeTime(inc.detected_at)}
        </td>
        <td>
          <div style="display: flex; align-items: center; gap: 0.35rem; font-size: 0.75rem;">
            <span title="Detected: ${pipe.detected}" style="color: ${pipe.detected === 'ok' ? 'var(--risk-low)' : 'var(--text-dim)'};">● Det</span>
            <span title="Runbook: ${pipe.runbook}" style="color: ${pipe.runbook === 'ok' ? 'var(--risk-low)' : (pipe.runbook === 'failed' ? 'var(--risk-high)' : 'var(--risk-med)')};">● RB</span>
            <span title="GitHub: ${pipe.github}" style="color: ${pipe.github === 'ok' ? 'var(--risk-low)' : (pipe.github === 'failed' ? 'var(--risk-high)' : 'var(--text-dim)')};">● GH</span>
            <span title="Slack: ${pipe.slack}" style="color: ${pipe.slack === 'ok' ? 'var(--risk-low)' : (pipe.slack === 'failed' ? 'var(--risk-high)' : 'var(--risk-med)')};">● Slack</span>
          </div>
        </td>
      </tr>
      <tr class="incident-detail-row" id="detail-row-${escapeHtml(inc.id)}" style="display: none;">
        <td colspan="9">
          <div class="incident-expanded-box" id="detail-box-${escapeHtml(inc.id)}">
            <div style="text-align: center; padding: 2rem; color: var(--text-dim);">
              <div class="pulsing-dot" style="margin: 0 auto 0.5rem;"></div>
              Loading GenAI Incident Runbook...
            </div>
          </div>
        </td>
      </tr>
    `;
  }).join('');

  if (window.lucide) lucide.createIcons({ root: tbody });
}

function getStatusBadgeClass(st) {
  const s = String(st).toLowerCase();
  if (s.includes('open')) return 'badge-open';
  if (s.includes('pending')) return 'badge-pending';
  if (s.includes('approved')) return 'badge-approved';
  if (s.includes('rejected')) return 'badge-rejected';
  if (s.includes('snoozed')) return 'badge-snoozed';
  if (s.includes('resolved')) return 'badge-resolved';
  return 'badge-open';
}

async function toggleIncidentAccordion(incId) {
  const detailRow = document.getElementById(`detail-row-${incId}`);
  const arrow = document.getElementById(`arrow-${incId}`);
  if (!detailRow) return;

  const isVisible = detailRow.style.display !== 'none';
  if (isVisible) {
    detailRow.style.display = 'none';
    if (arrow) arrow.style.transform = 'rotate(0deg)';
  } else {
    detailRow.style.display = 'table-row';
    if (arrow) arrow.style.transform = 'rotate(90deg)';
    await loadIncidentRunbook(incId);
  }
}

async function loadIncidentRunbook(incId) {
  const box = document.getElementById(`detail-box-${incId}`);
  if (!box) return;

  try {
    const res = await fetch(`/api/incidents/${incId}/report`);
    if (!res.ok) throw new Error('Failed to load incident report');
    const data = await res.json();
    renderIncidentRunbookContent(incId, data);
  } catch (e) {
    box.innerHTML = `
      <div style="color: var(--risk-high); padding: 1.5rem; text-align: center;">
        Failed to load incident report: ${escapeHtml(e.message)}
      </div>
    `;
  }
}

function renderIncidentRunbookContent(incId, data) {
  const box = document.getElementById(`detail-box-${incId}`);
  if (!box) return;

  const mdHtml = renderSimpleMarkdown(data.markdown);
  const ghUrl = data.github_url;
  const generator = data.generator || 'template';

  box.innerHTML = `
    <!-- Action Bar & Links -->
    <div style="display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid var(--border-subtle); padding-bottom: 0.75rem;">
      <div style="display: flex; gap: 0.75rem; align-items: center;">
        <span class="badge-tag" style="background: rgba(139, 92, 246, 0.15); color: var(--purple-accent);">
          Runbook v${data.version} (${generator})
        </span>
        ${ghUrl ? `
          <a href="${escapeHtml(ghUrl)}" target="_blank" class="btn btn-secondary" style="padding: 0.35rem 0.75rem; font-size: 0.75rem;">
            <i data-lucide="github" style="width: 14px; height: 14px;"></i> View on GitHub
          </a>
        ` : `
          <span style="font-size: 0.75rem; color: var(--text-dim);">GitHub: Mock / Unconfigured</span>
        `}
      </div>
      <div>
        <button class="btn btn-primary" onclick="regenerateRunbook('${escapeHtml(incId)}')" style="padding: 0.35rem 0.85rem; font-size: 0.75rem;">
          <i data-lucide="refresh-cw" style="width: 14px; height: 14px;"></i> Regenerate Runbook
        </button>
      </div>
    </div>

    <!-- Rendered Markdown Box -->
    <div class="markdown-preview-box">
      ${mdHtml}
    </div>
  `;

  if (window.lucide) lucide.createIcons({ root: box });
}

async function regenerateRunbook(incId) {
  const box = document.getElementById(`detail-box-${incId}`);
  if (box) {
    box.innerHTML = `
      <div style="text-align: center; padding: 2rem; color: var(--text-dim);">
        <div class="pulsing-dot" style="margin: 0 auto 0.5rem;"></div>
        Regenerating Runbook with LLM engine...
      </div>
    `;
  }

  try {
    const res = await fetch(`/api/incidents/${incId}/regenerate`, { method: 'POST' });
    if (!res.ok) throw new Error('Regeneration request failed');
    const data = await res.json();
    renderIncidentRunbookContent(incId, data);
    showToast(`Runbook regenerated (v${data.version})`, 'success');
  } catch (e) {
    showToast(e.message, 'error');
    loadIncidentRunbook(incId);
  }
}

// ============================================================================
// TAB 3: SRE Approvals & Audit Trail (Task 5 & Addendum A3)
// ============================================================================
async function fetchApprovals() {
  try {
    const res = await fetch('/api/approvals');
    if (!res.ok) return;
    const data = await res.json();
    state.approvals = data.approvals || [];
    renderApprovalsTable();
    renderAuditTrail();
  } catch (e) {
    console.warn('Failed to fetch approvals:', e);
  }
}

function renderApprovalsTable() {
  const tbody = document.getElementById('approvals-table-body');
  if (!tbody) return;

  if (state.approvals.length === 0) {
    tbody.innerHTML = `
      <tr>
        <td colspan="7" style="text-align: center; padding: 2.5rem; color: var(--text-dim);">
          No active approval requests in governance queue
        </td>
      </tr>
    `;
    return;
  }

  tbody.innerHTML = state.approvals.map(app => {
    const st = app.status || 'PENDING';
    const isSlackControlled = st.toUpperCase().includes('APPROVED') || st.toUpperCase().includes('REJECTED');
    const remCount = app.pending_reminders_count || 0;
    const comCount = app.comments_count || 0;

    return `
      <tr>
        <td>
          <div style="display: flex; flex-direction: column;">
            <strong style="color: #fff;">${escapeHtml(app.resource_id)}</strong>
            <span style="font-size: 0.75rem; color: var(--text-dim);">${escapeHtml(app.name || 'Unnamed')}</span>
          </div>
        </td>
        <td>
          <span class="service-pill">${escapeHtml(app.type || 'EC2')}</span>
          <span style="font-size: 0.8rem; color: var(--text-dim); margin-left: 0.25rem;">${escapeHtml(app.region || 'global')}</span>
        </td>
        <td>
          <span style="font-weight: 700; color: #fff;">${parseFloat(app.score || 0).toFixed(1)}</span>
        </td>
        <td>
          <select class="workflow-select" ${isSlackControlled ? 'disabled' : ''} onchange="onWorkflowStatusChange(${app.id}, this.value)">
            <option value="Pending" ${st.toUpperCase() === 'PENDING' ? 'selected' : ''}>Pending</option>
            <option value="In Review" ${st === 'In Review' ? 'selected' : ''}>In Review</option>
            <option value="Snoozed" ${st.toUpperCase() === 'SNOOZED' ? 'selected' : ''}>Snoozed</option>
            <option value="Escalated" ${st === 'Escalated' ? 'selected' : ''}>Escalated</option>
            ${isSlackControlled ? `<option value="${escapeHtml(st)}" selected>${escapeHtml(st)} (via Slack)</option>` : ''}
          </select>
          ${isSlackControlled ? `<div style="font-size: 0.7rem; color: var(--text-dim); margin-top: 0.2rem;">Action by: ${escapeHtml(app.sre_name || 'Slack SRE')}</div>` : ''}
        </td>
        <td>
          <button class="btn btn-secondary" onclick="openReminderModal(${app.id}, '${escapeHtml(app.resource_id)}')" style="padding: 0.35rem 0.65rem; font-size: 0.75rem;">
            <i data-lucide="bell" style="width: 13px; height: 13px;"></i>
            <span>${remCount > 0 ? `${remCount} active` : 'Set Reminder'}</span>
          </button>
        </td>
        <td>
          <button class="btn btn-secondary" onclick="openCommentsModal(${app.id}, '${escapeHtml(app.resource_id)}')" style="padding: 0.35rem 0.65rem; font-size: 0.75rem;">
            <i data-lucide="message-square" style="width: 13px; height: 13px;"></i>
            <span>${comCount > 0 ? `${comCount} notes` : 'Add note'}</span>
          </button>
        </td>
        <td style="font-size: 0.75rem; color: var(--text-dim);">
          <div title="Decided: ${escapeHtml(formatAbsoluteTime(app.decided_at))}">
            ${app.decided_at ? `Decided: ${formatRelativeTime(app.decided_at)}` : 'Decision pending'}
          </div>
        </td>
      </tr>
    `;
  }).join('');

  if (window.lucide) lucide.createIcons({ root: tbody });
}

function renderAuditTrail() {
  const tbody = document.getElementById('audit-table-body');
  if (!tbody) return;

  const records = state.approvals.filter(a => a.status && a.status !== 'PENDING');
  if (records.length === 0) {
    tbody.innerHTML = `
      <tr>
        <td colspan="6" style="text-align: center; padding: 2rem; color: var(--text-dim);">
          Audit trail is currently recording decisions
        </td>
      </tr>
    `;
    return;
  }

  tbody.innerHTML = records.map(a => `
    <tr>
      <td style="font-family: var(--font-mono); font-size: 0.75rem;" title="${escapeHtml(formatAbsoluteTime(a.decided_at))}">
        ${formatRelativeTime(a.decided_at)}
      </td>
      <td><span class="resource-id-code">${escapeHtml(a.resource_id)}</span></td>
      <td><span class="badge-status ${getStatusBadgeClass(a.status)}">${escapeHtml(a.status)}</span></td>
      <td><strong>${escapeHtml(a.sre_name || 'sre.operator')}</strong></td>
      <td style="font-size: 0.8rem; color: var(--text-muted);">${escapeHtml(a.action_taken || 'Status update')}</td>
      <td style="font-size: 0.8rem; color: var(--text-dim);">${escapeHtml(a.reason || 'Standard operational review')}</td>
    </tr>
  `).join('');
}

async function onWorkflowStatusChange(approvalId, newStatus) {
  try {
    const res = await fetch(`/api/approvals/${approvalId}/status`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ status: newStatus, reviewer: 'sre.web', reason: 'Web console workflow transition' })
    });
    if (!res.ok) {
      const err = await res.json();
      throw new Error(err.detail || 'Failed to update workflow status');
    }
    showToast(`Status updated to ${newStatus}`, 'success');
    fetchApprovals();
    fetchIncidents();
  } catch (e) {
    showToast(e.message, 'error');
    fetchApprovals();
  }
}

// ----------------------------------------------------------------------------
// Reminders & Comments Modals
// ----------------------------------------------------------------------------
function initModals() {
  document.querySelectorAll('.btn-close-modal').forEach(b => {
    b.addEventListener('click', () => {
      document.querySelectorAll('.modal-overlay').forEach(m => m.classList.remove('active'));
    });
  });

  // Preset buttons
  document.querySelectorAll('.btn-preset-reminder').forEach(b => {
    b.addEventListener('click', () => {
      const hours = parseInt(b.dataset.hours, 10);
      const target = new Date(Date.now() + hours * 3600 * 1000);
      const isoLocal = new Date(target.getTime() - target.getTimezoneOffset() * 60000).toISOString().slice(0, 16);
      const input = document.getElementById('input-custom-reminder-time');
      if (input) input.value = isoLocal;
    });
  });

  // Submit reminder
  const subRem = document.getElementById('btn-submit-reminder');
  if (subRem) {
    subRem.addEventListener('click', submitReminder);
  }

  // Submit comment
  const subComm = document.getElementById('btn-submit-comment');
  if (subComm) {
    subComm.addEventListener('click', submitComment);
  }
}

function openReminderModal(approvalId, resId) {
  document.getElementById('reminder-approval-id').value = approvalId;
  document.getElementById('reminder-target-resource').textContent = resId;

  // Set default time to 4 hours from now
  const target = new Date(Date.now() + 4 * 3600 * 1000);
  const isoLocal = new Date(target.getTime() - target.getTimezoneOffset() * 60000).toISOString().slice(0, 16);
  const input = document.getElementById('input-custom-reminder-time');
  if (input) input.value = isoLocal;

  document.getElementById('modal-reminder').classList.add('active');
  if (window.lucide) lucide.createIcons();
}

async function submitReminder() {
  const approvalId = document.getElementById('reminder-approval-id').value;
  const timeVal = document.getElementById('input-custom-reminder-time').value;
  const noteVal = document.getElementById('input-reminder-note').value;
  const postSlack = document.getElementById('check-reminder-slack').checked;

  if (!timeVal) {
    showToast('Please select a reminder date & time', 'error');
    return;
  }

  try {
    const res = await fetch(`/api/approvals/${approvalId}/reminders`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        scheduled_time: new Date(timeVal).toISOString(),
        note: noteVal || 'SRE Follow-up',
        post_to_slack: postSlack
      })
    });
    if (!res.ok) throw new Error('Failed to create reminder');
    showToast('Reminder scheduled successfully', 'success');
    document.getElementById('modal-reminder').classList.remove('active');
    fetchApprovals();
  } catch (e) {
    showToast(e.message, 'error');
  }
}

async function openCommentsModal(approvalId, resId) {
  document.getElementById('comments-approval-id').value = approvalId;
  document.getElementById('comments-target-resource').textContent = resId;
  document.getElementById('modal-comments').classList.add('active');

  await loadCommentsThread(approvalId);
}

async function loadCommentsThread(approvalId) {
  const list = document.getElementById('comments-thread-list');
  if (!list) return;

  try {
    const res = await fetch(`/api/approvals/${approvalId}/comments`);
    if (!res.ok) throw new Error('Failed to fetch comments');
    const data = await res.json();
    const comments = data.comments || [];

    if (comments.length === 0) {
      list.innerHTML = `<div style="text-align: center; padding: 1.5rem; color: var(--text-dim);">No investigation notes recorded yet.</div>`;
      return;
    }

    list.innerHTML = comments.map(c => `
      <div class="comment-card">
        <div class="comment-card-top">
          <span class="comment-card-author">${escapeHtml(c.author_name)}</span>
          <div style="display: flex; align-items: center; gap: 0.5rem;">
            <span style="color: var(--text-dim); font-size: 0.7rem;">${formatRelativeTime(c.created_at)}</span>
            <button class="btn btn-secondary btn-icon-only" onclick="deleteComment(${approvalId}, ${c.id})" style="padding: 0.15rem; border: none; background: transparent;">
              <i data-lucide="trash" style="width: 12px; height: 12px; color: var(--risk-high);"></i>
            </button>
          </div>
        </div>
        <div class="comment-card-text">${escapeHtml(c.comment_text)}</div>
      </div>
    `).join('');

    if (window.lucide) lucide.createIcons({ root: list });
  } catch (e) {
    list.innerHTML = `<div style="color: var(--risk-high); padding: 1rem;">Failed to load notes.</div>`;
  }
}

async function submitComment() {
  const approvalId = document.getElementById('comments-approval-id').value;
  const author = document.getElementById('input-comment-author').value || 'sre.operator';
  const textInput = document.getElementById('input-comment-text');
  const text = textInput?.value || '';
  const postSlack = document.getElementById('check-comment-slack').checked;

  if (!text.trim()) {
    showToast('Please enter comment text', 'error');
    return;
  }

  try {
    const res = await fetch(`/api/approvals/${approvalId}/comments`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ author_name: author, comment_text: text, post_to_slack: postSlack })
    });
    if (!res.ok) throw new Error('Failed to add comment');
    textInput.value = '';
    showToast('Investigation note saved', 'success');
    await loadCommentsThread(approvalId);
    fetchApprovals();
  } catch (e) {
    showToast(e.message, 'error');
  }
}

async function deleteComment(approvalId, commentId) {
  try {
    const res = await fetch(`/api/approvals/${approvalId}/comments/${commentId}`, { method: 'DELETE' });
    if (!res.ok) throw new Error('Failed to delete comment');
    showToast('Comment deleted', 'info');
    await loadCommentsThread(approvalId);
    fetchApprovals();
  } catch (e) {
    showToast(e.message, 'error');
  }
}

async function checkDueReminders() {
  // Checks active approvals for reminders due in local time
  const now = new Date();
  state.approvals.forEach(async (app) => {
    try {
      const res = await fetch(`/api/approvals/${app.id}/reminders`);
      if (!res.ok) return;
      const data = await res.json();
      (data.reminders || []).forEach(r => {
        if (r.status === 'PENDING') {
          const due = new Date(r.scheduled_time);
          if (due <= now) {
            showToast(`⏰ REMINDER DUE: Resource ${app.resource_id} (${r.note})`, 'info');
          }
        }
      });
    } catch (e) {}
  });
}

// ============================================================================
// TAB 4: Log Analyzer (Task 4 - In-Memory Zero-Persistence)
// ============================================================================
function initLogAnalyzer() {
  const dropzone = document.getElementById('log-upload-dropzone');
  const fileInput = document.getElementById('log-file-input');
  const browseBtn = document.getElementById('btn-browse-log-file');

  if (browseBtn && fileInput) {
    browseBtn.addEventListener('click', () => fileInput.click());
  }

  if (fileInput) {
    fileInput.addEventListener('change', (e) => {
      if (e.target.files && e.target.files[0]) {
        processUploadedLogFile(e.target.files[0]);
      }
    });
  }

  if (dropzone) {
    dropzone.addEventListener('dragover', (e) => {
      e.preventDefault();
      dropzone.classList.add('dragover');
    });
    dropzone.addEventListener('dragleave', () => dropzone.classList.remove('dragover'));
    dropzone.addEventListener('drop', (e) => {
      e.preventDefault();
      dropzone.classList.remove('dragover');
      if (e.dataTransfer.files && e.dataTransfer.files[0]) {
        processUploadedLogFile(e.dataTransfer.files[0]);
      }
    });
  }

  const copyBtn = document.getElementById('btn-copy-log-report');
  if (copyBtn) {
    copyBtn.addEventListener('click', () => {
      if (state.logAnalysis?.report_markdown) {
        navigator.clipboard.writeText(state.logAnalysis.report_markdown);
        showToast('Report markdown copied to clipboard', 'success');
      }
    });
  }

  const downloadBtn = document.getElementById('btn-download-log-report');
  if (downloadBtn) {
    downloadBtn.addEventListener('click', () => {
      if (state.logAnalysis?.report_markdown) {
        const blob = new Blob([state.logAnalysis.report_markdown], { type: 'text/markdown;charset=utf-8' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `incident_report_${Date.now()}.md`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
        showToast('Report downloaded', 'info');
      }
    });
  }

  const clearBtn = document.getElementById('btn-clear-log-analysis');
  if (clearBtn) {
    clearBtn.addEventListener('click', () => {
      state.logAnalysis = null;
      document.getElementById('log-results-container').style.display = 'none';
      document.getElementById('log-upload-dropzone').style.display = 'block';
      if (fileInput) fileInput.value = '';
      showToast('Log analysis cleared from memory', 'info');
    });
  }
}

async function processUploadedLogFile(file) {
  // Client-side validation: extension and max size 5 MB
  const ext = file.name.split('.').pop().toLowerCase();
  if (ext !== 'txt' && ext !== 'log') {
    showToast('Invalid file format. Please upload a .txt or .log file.', 'error');
    return;
  }

  const maxBytes = 5 * 1024 * 1024;
  if (file.size > maxBytes) {
    showToast(`File size (${(file.size / 1024 / 1024).toFixed(2)} MB) exceeds 5 MB limit.`, 'error');
    return;
  }

  const dropzone = document.getElementById('log-upload-dropzone');
  const resultsBox = document.getElementById('log-results-container');
  dropzone.style.display = 'none';
  resultsBox.style.display = 'block';

  const preview = document.getElementById('log-report-preview');
  if (preview) {
    preview.innerHTML = `
      <div style="text-align: center; padding: 3rem; color: var(--text-dim);">
        <div class="pulsing-dot" style="margin: 0 auto 0.75rem;"></div>
        <div>Parsing log file in-memory and synthesizing AI Incident Report...</div>
      </div>
    `;
  }

  const formData = new FormData();
  formData.append('file', file);

  try {
    const res = await fetch('/api/log-analyzer', { method: 'POST', body: formData });
    if (!res.ok) {
      const err = await res.json();
      throw new Error(err.detail || 'Log analysis failed');
    }

    const data = await res.json();
    state.logAnalysis = data;

    // Populate Results
    document.getElementById('log-file-name-badge').textContent = data.filename;
    document.getElementById('log-file-meta-text').textContent = `${data.metrics?.total_lines || 0} lines analyzed &bull; ${(data.file_size_bytes / 1024).toFixed(1)} KB`;

    renderLogCharts(data.metrics);
    if (preview) {
      preview.innerHTML = renderSimpleMarkdown(data.report_markdown);
    }
    renderLogExcerptsTable(data.metrics?.excerpts || []);
    showToast('Log analyzed successfully (in-memory only)', 'success');
  } catch (e) {
    showToast(e.message, 'error');
    dropzone.style.display = 'block';
    resultsBox.style.display = 'none';
  }
}

function renderLogCharts(metrics) {
  if (!metrics) return;

  // 1. Severity Donut
  const ctxSev = document.getElementById('chart-log-severity')?.getContext('2d');
  if (ctxSev) {
    if (state.charts.logSeverity) state.charts.logSeverity.destroy();
    const sevs = metrics.severities || {};
    state.charts.logSeverity = new Chart(ctxSev, {
      type: 'doughnut',
      data: {
        labels: ['CRITICAL', 'ERROR', 'WARN', 'INFO'],
        datasets: [{
          data: [sevs.CRITICAL || 0, sevs.ERROR || 0, sevs.WARN || 0, sevs.INFO || 0],
          backgroundColor: ['#f43f5e', '#fb7185', '#f59e0b', '#38bdf8'],
          borderColor: '#0b0f19',
          borderWidth: 2
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: { legend: { position: 'bottom', labels: { color: '#94a3b8', font: { size: 10 } } } }
      }
    });
  }

  // 2. Error Signatures Bar
  const ctxErr = document.getElementById('chart-log-errors')?.getContext('2d');
  if (ctxErr) {
    if (state.charts.logErrors) state.charts.logErrors.destroy();
    const topErrs = metrics.top_errors || [];
    state.charts.logErrors = new Chart(ctxErr, {
      type: 'bar',
      data: {
        labels: topErrs.map((e, idx) => `Pattern #${idx + 1}`),
        datasets: [{
          label: 'Occurrences',
          data: topErrs.map(e => e.count),
          backgroundColor: 'rgba(244, 63, 94, 0.75)',
          borderColor: '#f43f5e',
          borderRadius: 4
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: { display: false },
          tooltip: {
            callbacks: {
              afterLabel: (ctx) => {
                const item = topErrs[ctx.dataIndex];
                return item ? `Snippet: ${item.signature}` : '';
              }
            }
          }
        },
        scales: {
          x: { ticks: { color: '#94a3b8' } },
          y: { beginAtZero: true, ticks: { color: '#64748b' } }
        }
      }
    });
  }

  // 3. Top Sources Bar
  const ctxSrc = document.getElementById('chart-log-sources')?.getContext('2d');
  if (ctxSrc) {
    if (state.charts.logSources) state.charts.logSources.destroy();
    const topIps = metrics.top_ips || [];
    const topRes = metrics.top_resources || [];
    const combined = [...topIps.map(i => ({ label: i.ip, count: i.count })), ...topRes.map(r => ({ label: r.resource, count: r.count }))].slice(0, 5);

    state.charts.logSources = new Chart(ctxSrc, {
      type: 'bar',
      data: {
        labels: combined.map(c => c.label),
        datasets: [{
          label: 'Hits',
          data: combined.map(c => c.count),
          backgroundColor: 'rgba(0, 240, 255, 0.7)',
          borderColor: '#00f0ff',
          borderRadius: 4
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: { legend: { display: false } },
        scales: {
          x: { ticks: { color: '#94a3b8', font: { family: 'JetBrains Mono', size: 9 } } },
          y: { beginAtZero: true, ticks: { color: '#64748b' } }
        }
      }
    });
  }
}

function renderLogExcerptsTable(excerpts) {
  const tbody = document.getElementById('log-excerpts-table-body');
  if (!tbody) return;

  if (excerpts.length === 0) {
    tbody.innerHTML = `<tr><td colspan="6" style="text-align: center; color: var(--text-dim); padding: 2rem;">No excerpts extracted</td></tr>`;
    return;
  }

  tbody.innerHTML = excerpts.map(ex => {
    const sevClass = ex.severity === 'CRITICAL' || ex.severity === 'ERROR' ? 'badge-high' : (ex.severity === 'WARN' ? 'badge-med' : 'badge-low');
    return `
      <tr>
        <td style="font-family: var(--font-mono); font-size: 0.75rem; color: var(--text-dim);">${ex.line_number}</td>
        <td style="font-family: var(--font-mono); font-size: 0.75rem;">${escapeHtml(ex.timestamp)}</td>
        <td><span class="risk-badge ${sevClass}" style="font-size: 0.65rem; padding: 0.1rem 0.4rem;">${escapeHtml(ex.severity)}</span></td>
        <td style="font-family: var(--font-mono); font-size: 0.8rem; color: #fff;">${escapeHtml(ex.message)}</td>
        <td style="font-family: var(--font-mono); font-size: 0.75rem; color: var(--cyan-primary);">${escapeHtml(ex.ip || '-')}</td>
        <td style="font-family: var(--font-mono); font-size: 0.75rem; color: var(--purple-accent);">${escapeHtml(ex.resource || '-')}</td>
      </tr>
    `;
  }).join('');
}
