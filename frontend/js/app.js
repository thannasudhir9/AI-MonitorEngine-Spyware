/**
 * AegisShield Cyber SOC Dashboard Controller
 * Real-time threat detection, process monitor, network origin tracer,
 * access control allow/block rules, and email alert reporting.
 */

// Application State
const state = {
    activeTab: 'threats',
    autoRefresh: true,
    refreshInterval: null,
    telemetryWs: null,
    lastScanData: null,
    processFilter: 'all',
    searchQuery: '',
    netFilter: 'all',
    netSearchQuery: '',
    lastNetworkData: null,
    adblockFilter: 'all',
    adblockSearchQuery: '',
    systemProxyEnabled: false,
    privateMode: false,
    lastAdblockData: null,
    soundEnabled: false, // Notification sounds removed / disabled per user request
    isScanning: false,
    selectedProcess: null,
    threatSubView: 'all',
    lastLedgerData: [],
    servicesFilter: 'all',
    servicesSearchQuery: '',
    lastServicesData: null
};

// Web Audio API Synthesizer - Notification Sounds Removed / Silent by Default
const CyberAudio = {
    ctx: null,
    init() {
        if (state.soundEnabled && !this.ctx && (window.AudioContext || window.webkitAudioContext)) {
            this.ctx = new (window.AudioContext || window.webkitAudioContext)();
        }
    },
    playChime(type = 'threat') {
        // Notification sounds removed - strictly check if sound is enabled
        if (!state.soundEnabled) return;
        try {
            this.init();
            if (!this.ctx) return;
            const now = this.ctx.currentTime;
            const osc = this.ctx.createOscillator();
            const gain = this.ctx.createGain();
            osc.connect(gain);
            gain.connect(this.ctx.destination);

            if (type === 'threat') {
                osc.type = 'sawtooth';
                osc.frequency.setValueAtTime(440, now);
                osc.frequency.exponentialRampToValueAtTime(220, now + 0.35);
                gain.gain.setValueAtTime(0.15, now);
                gain.gain.exponentialRampToValueAtTime(0.01, now + 0.35);
                osc.start(now);
                osc.stop(now + 0.35);
            } else if (type === 'kill') {
                osc.type = 'sine';
                osc.frequency.setValueAtTime(587.33, now);
                osc.frequency.setValueAtTime(880, now + 0.1);
                gain.gain.setValueAtTime(0.12, now);
                gain.gain.exponentialRampToValueAtTime(0.01, now + 0.25);
                osc.start(now);
                osc.stop(now + 0.25);
            }
        } catch (e) {
            // Audio context restriction or silent failure
        }
    }
};

// UI Toast Notification System
function showToast(title, message, type = 'info') {
    const container = document.getElementById('toast-container');
    if (!container) return;

    const toast = document.createElement('div');
    toast.className = 'toast';

    let iconColor = 'text-cyan-400';
    let borderColor = 'border-cyan-500/30';
    if (type === 'danger' || type === 'threat') {
        iconColor = 'text-red-400';
        borderColor = 'border-red-500/50';
    } else if (type === 'success') {
        iconColor = 'text-emerald-400';
        borderColor = 'border-emerald-500/50';
    } else if (type === 'warning') {
        iconColor = 'text-amber-400';
        borderColor = 'border-amber-500/50';
    }

    toast.classList.add(borderColor);
    toast.innerHTML = `
        <div class="flex-shrink-0 ${iconColor}">
            <i data-lucide="${type === 'danger' ? 'alert-triangle' : (type === 'success' ? 'check-circle' : 'info')}" class="w-6 h-6"></i>
        </div>
        <div class="flex-1">
            <div class="font-semibold text-sm">${title}</div>
            <div class="text-xs text-slate-400 mt-0.5">${message}</div>
        </div>
        <button onclick="this.parentElement.remove()" class="text-slate-400 hover:text-white text-xs">✕</button>
    `;

    container.appendChild(toast);
    if (window.lucide) lucide.createIcons();

    setTimeout(() => {
        toast.style.opacity = '0';
        toast.style.transform = 'translateX(100%)';
        setTimeout(() => toast.remove(), 300);
    }, 4500);
}

// Initialize Application
document.addEventListener('DOMContentLoaded', () => {
    initClock();
    initTheme();
    initSound();
    initTabs();
    initWebSocket();
    checkPrivacyStatus();
    loadAppInfo();
    runScan(true);

    // Auto-refresh interval (every 6 seconds)
    state.refreshInterval = setInterval(() => {
        if (state.autoRefresh && !state.isScanning) {
            runScan(false);
            if (state.activeTab === 'network') loadNetworkTracer();
        }
    }, 6000);
});

// App & Sub-Systems Info Loader
async function loadAppInfo() {
    try {
        const res = await fetch('/api/app-info');
        if (!res.ok) return;
        const data = await res.json();
        const pidEl = document.getElementById('footer-pid');
        const adminText = document.getElementById('footer-admin-text');
        const adminBadge = document.getElementById('footer-admin-badge');

        if (pidEl) pidEl.textContent = data.server_pid || '--';
        if (adminText && adminBadge) {
            if (data.is_admin) {
                adminText.textContent = 'Administrator: ACTIVE';
                adminBadge.className = 'px-2 py-0.5 rounded text-[10px] font-bold bg-emerald-500/20 text-emerald-300 border border-emerald-500/40 cursor-default';
            } else {
                adminText.textContent = 'Standard User (Elevation Available)';
                adminBadge.className = 'px-2 py-0.5 rounded text-[10px] font-bold bg-amber-500/20 text-amber-300 border border-amber-500/40 cursor-pointer hover:bg-amber-500/30';
            }
        }
    } catch (e) {
        console.warn('App info fetch error', e);
    }
}

// Real-Time Clock
function initClock() {
    function update() {
        const now = new Date();
        const timeEl = document.getElementById('live-time');
        const footerTimeEl = document.getElementById('footer-live-time');
        const formatted = now.toLocaleTimeString() + ' | ' + now.toLocaleDateString();
        if (timeEl) timeEl.textContent = formatted;
        if (footerTimeEl) footerTimeEl.textContent = formatted + ' (Local SOC)';
    }
    update();
    setInterval(update, 1000);
}

// WebSocket Connection for Telemetry
function initWebSocket() {
    const loc = window.location;
    const protocol = loc.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsUrl = `${protocol}//${loc.host}/ws/telemetry`;

    try {
        state.telemetryWs = new WebSocket(wsUrl);
        state.telemetryWs.onmessage = (event) => {
            const data = JSON.parse(event.data);
            updateTelemetryDisplay(data);
        };
        state.telemetryWs.onerror = () => {};
    } catch (e) {
        console.warn('WebSocket fallback to polling', e);
    }
}

function updateTelemetryDisplay(data) {
    const cpuEl = document.getElementById('stat-cpu');
    const memEl = document.getElementById('stat-memory');
    const procEl = document.getElementById('stat-total-procs');

    if (cpuEl) cpuEl.textContent = `${Math.round(data.cpu_percent)}%`;
    if (memEl) memEl.textContent = `${Math.round(data.memory_percent)}%`;
    if (procEl) procEl.textContent = data.process_count;

    if (data.private_mode !== undefined && data.private_mode !== state.privateMode) {
        updatePrivacyUI(data.private_mode);
    }
}

// Tab Switching
function initTabs() {
    const tabButtons = document.querySelectorAll('.tab-btn');
    tabButtons.forEach(btn => {
        btn.addEventListener('click', () => {
            const tabName = btn.dataset.tab;
            switchTab(tabName);
        });
    });
}

function switchTab(tabName) {
    state.activeTab = tabName;
    document.querySelectorAll('.tab-btn').forEach(btn => {
        if (btn.dataset.tab === tabName) {
            btn.classList.add('active', 'font-semibold');
            btn.classList.add('bg-cyan-500/20', 'text-cyan-300', 'border-cyan-500');
            btn.classList.remove('text-slate-400', 'border-transparent');
        } else {
            btn.classList.remove('active', 'font-semibold');
            btn.classList.remove('bg-cyan-500/20', 'text-cyan-300', 'border-cyan-500');
            btn.classList.add('text-slate-400', 'border-transparent');
        }
    });

    document.querySelectorAll('.tab-content').forEach(view => {
        view.classList.add('hidden');
    });

    const activeView = document.getElementById(`view-${tabName}`);
    if (activeView) activeView.classList.remove('hidden');

    if (tabName === 'services') loadWindowsServices();
    if (tabName === 'sysinfo') loadSystemInfo();
    if (tabName === 'drives') loadDriveAnalyzer();
    if (tabName === 'threats') {
        if (state.threatSubView === 'ledger') loadThreatLedger();
        else if (state.threatSubView === 'blocked_history') loadBlockedHistory();
    }
    if (tabName === 'network') loadNetworkTracer();
    if (tabName === 'adblock') loadAdBlockDashboard();
    if (tabName === 'policy') loadPolicyRules();
    if (tabName === 'persistence') loadPersistence();
    if (tabName === 'email') loadEmailConfig();
    if (tabName === 'audit') loadAuditLog();
    if (tabName === 'docs') switchDocSection('overview');
    if (window.lucide) lucide.createIcons();
}

function navigateToTab(tabName) {
    switchTab(tabName);
    const view = document.getElementById(`view-${tabName}`);
    if (view) {
        view.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }
}

function navigateToThreatsTab(subView = 'active') {
    navigateToTab('threats');
    switchThreatsSubView(subView);
}

function navigateToProcessTab(subView = 'active') {
    navigateToTab('processes');
    switchProcessSubView(subView);
}

function navigateToRMMTab(subView = 'active') {
    navigateToTab('rmm');
    switchRMMSubView(subView);
}

function navigateToNetworkTab(subView = 'active') {
    navigateToTab('network');
    switchNetworkSubView(subView);
}

function switchProcessSubView(subView) {
    const activeContainer = document.getElementById('procs-active-container');
    const historyView = document.getElementById('processes-history-view');
    const btnActive = document.getElementById('btn-procs-active');
    const btnHistory = document.getElementById('btn-procs-history');

    if (subView === 'blocked') {
        if (activeContainer) activeContainer.classList.add('hidden');
        if (historyView) historyView.classList.remove('hidden');
        if (btnActive) {
            btnActive.classList.remove('bg-cyan-600', 'text-white');
            btnActive.classList.add('text-slate-400');
        }
        if (btnHistory) {
            btnHistory.classList.add('bg-cyan-600', 'text-white');
            btnHistory.classList.remove('text-slate-400');
        }
        loadProcessHistory();
    } else {
        if (activeContainer) activeContainer.classList.remove('hidden');
        if (historyView) historyView.classList.add('hidden');
        if (btnActive) {
            btnActive.classList.add('bg-cyan-600', 'text-white');
            btnActive.classList.remove('text-slate-400');
        }
        if (btnHistory) {
            btnHistory.classList.remove('bg-cyan-600', 'text-white');
            btnHistory.classList.add('text-slate-400');
        }
    }
    if (window.lucide) lucide.createIcons();
}

async function loadProcessHistory() {
    try {
        const res = await fetch('/api/blocked-history');
        const history = await res.json();
        const tbody = document.getElementById('procs-history-table-body');
        const countBadge = document.getElementById('sub-procs-killed-count');

        const procEvents = (history || []).filter(e => (e.action || '').includes('KILL') || (e.action || '').includes('PROCESS'));
        if (countBadge) countBadge.textContent = procEvents.length;
        if (!tbody) return;

        if (procEvents.length === 0) {
            tbody.innerHTML = `<tr><td colspan="6" class="p-6 text-center text-slate-400 text-xs">No processes terminated yet. Terminated processes will be tracked here.</td></tr>`;
            return;
        }

        tbody.innerHTML = procEvents.map(item => {
            const statusClass = item.status === 'SUCCESS' ? 'text-emerald-400 font-bold' : (item.status === 'FAILED' ? 'text-red-400 font-bold' : 'text-amber-400 font-bold');
            const canElevate = item.status === 'FAILED' || (item.details || '').includes('Access denied');
            return `
                <tr class="border-b border-slate-800/60 hover:bg-slate-800/30 transition">
                    <td class="p-3 text-slate-400">${escapeHtml(item.time_display || item.timestamp || '')}</td>
                    <td class="p-3 font-bold text-white">${escapeHtml(item.target || 'N/A')}</td>
                    <td class="p-3 text-slate-300 font-mono">${item.pid || '-'}</td>
                    <td class="p-3">
                        <span class="px-2 py-0.5 rounded text-[10px] font-mono font-bold border ${item.status === 'SUCCESS' ? 'bg-emerald-600/20 text-emerald-300 border-emerald-500/30' : 'bg-red-600/20 text-red-300 border-red-500/30'}">
                            ${escapeHtml(item.action)}
                        </span>
                    </td>
                    <td class="p-3 text-slate-300">${escapeHtml(item.details || '')}</td>
                    <td class="p-3 text-right">
                        <span class="${statusClass} mr-2">${escapeHtml(item.status)}</span>
                        ${canElevate && item.pid ? `<button onclick="showElevatedKillModal(${item.pid}, '${escapeHtml(item.target)}', '${escapeHtml(item.details)}', null, 'taskkill /F /PID ${item.pid}')" class="px-2 py-0.5 rounded bg-red-600 hover:bg-red-500 text-white font-bold text-[10px]">⚡ Elevate</button>` : ''}
                    </td>
                </tr>
            `;
        }).join('');
    } catch (e) {
        console.error('Failed to load process history:', e);
    }
}

function switchRMMSubView(subView) {
    const activeContainer = document.getElementById('rmm-active-container');
    const historyView = document.getElementById('rmm-history-view');
    const btnActive = document.getElementById('btn-rmm-active');
    const btnHistory = document.getElementById('btn-rmm-history');

    if (subView === 'blocked') {
        if (activeContainer) activeContainer.classList.add('hidden');
        if (historyView) historyView.classList.remove('hidden');
        if (btnActive) {
            btnActive.classList.remove('bg-cyan-600', 'text-white');
            btnActive.classList.add('text-slate-400');
        }
        if (btnHistory) {
            btnHistory.classList.add('bg-cyan-600', 'text-white');
            btnHistory.classList.remove('text-slate-400');
        }
        loadRMMHistory();
    } else {
        if (activeContainer) activeContainer.classList.remove('hidden');
        if (historyView) historyView.classList.add('hidden');
        if (btnActive) {
            btnActive.classList.add('bg-cyan-600', 'text-white');
            btnActive.classList.remove('text-slate-400');
        }
        if (btnHistory) {
            btnHistory.classList.remove('bg-cyan-600', 'text-white');
            btnHistory.classList.add('text-slate-400');
        }
    }
    if (window.lucide) lucide.createIcons();
}

async function loadRMMHistory() {
    try {
        const res = await fetch('/api/blocked-history');
        const history = await res.json();
        const tbody = document.getElementById('rmm-history-table-body');
        const countBadge = document.getElementById('sub-rmm-blocked-count');

        const rmmNames = ['anydesk', 'teamviewer', 'rustdesk', 'vnc', 'screenconnect', 'logmein', 'parsec', 'splashtop', 'ngrok', 'frp'];
        const rmmEvents = (history || []).filter(e => {
            const targetLower = (e.target || '').toLowerCase();
            const detailsLower = (e.details || '').toLowerCase();
            return rmmNames.some(r => targetLower.includes(r) || detailsLower.includes(r));
        });

        if (countBadge) countBadge.textContent = rmmEvents.length;
        if (!tbody) return;

        if (rmmEvents.length === 0) {
            tbody.innerHTML = `<tr><td colspan="6" class="p-6 text-center text-slate-400 text-xs">No RMM tools or remote control sessions terminated yet.</td></tr>`;
            return;
        }

        tbody.innerHTML = rmmEvents.map(item => `
            <tr class="border-b border-slate-800/60 hover:bg-slate-800/30 transition">
                <td class="p-3 text-slate-400">${escapeHtml(item.time_display || item.timestamp || '')}</td>
                <td class="p-3 font-bold text-cyan-300">${escapeHtml(item.target || 'N/A')}</td>
                <td class="p-3 text-slate-300">${item.pid || '-'}</td>
                <td class="p-3 font-mono text-xs text-red-300">${escapeHtml(item.action)}</td>
                <td class="p-3 text-slate-300">${escapeHtml(item.details || '')}</td>
                <td class="p-3 text-right font-bold text-emerald-400">${escapeHtml(item.status)}</td>
            </tr>
        `).join('');
    } catch (e) {
        console.error('Failed to load RMM history:', e);
    }
}

function switchNetworkSubView(subView) {
    const activeContainer = document.getElementById('net-active-container');
    const blockedView = document.getElementById('net-blocked-view');
    const btnActive = document.getElementById('btn-net-active');
    const btnBlocked = document.getElementById('btn-net-blocked');

    if (subView === 'blocked') {
        if (activeContainer) activeContainer.classList.add('hidden');
        if (blockedView) blockedView.classList.remove('hidden');
        if (btnActive) {
            btnActive.classList.remove('bg-emerald-600', 'text-white');
            btnActive.classList.add('text-slate-400');
        }
        if (btnBlocked) {
            btnBlocked.classList.add('bg-emerald-600', 'text-white');
            btnBlocked.classList.remove('text-slate-400');
        }
        loadNetworkBlockedHistory();
    } else {
        if (activeContainer) activeContainer.classList.remove('hidden');
        if (blockedView) blockedView.classList.add('hidden');
        if (btnActive) {
            btnActive.classList.add('bg-emerald-600', 'text-white');
            btnActive.classList.remove('text-slate-400');
        }
        if (btnBlocked) {
            btnBlocked.classList.remove('bg-emerald-600', 'text-white');
            btnBlocked.classList.add('text-slate-400');
        }
    }
    if (window.lucide) lucide.createIcons();
}

async function loadNetworkBlockedHistory() {
    try {
        const res = await fetch('/api/policy/rules');
        const rules = await res.json();
        const tbody = document.getElementById('net-blocked-table-body');
        const countBadge = document.getElementById('sub-net-blocked-count');

        const blockedIPs = (rules.blocked_ips || []);
        if (countBadge) countBadge.textContent = blockedIPs.length;
        if (!tbody) return;

        if (blockedIPs.length === 0) {
            tbody.innerHTML = `<tr><td colspan="6" class="p-6 text-center text-slate-400 text-xs">No remote IPs currently blocked in Windows Firewall. Click 'Block New IP' to add one.</td></tr>`;
            return;
        }

        tbody.innerHTML = blockedIPs.map(rule => `
            <tr class="border-b border-slate-800/60 hover:bg-slate-800/30 transition">
                <td class="p-3 text-slate-400">${escapeHtml(rule.created_at || 'Active')}</td>
                <td class="p-3 font-bold text-red-400 font-mono">${escapeHtml(rule.value || rule.ip)}</td>
                <td class="p-3 text-slate-300">${escapeHtml(rule.comment || 'Blocked Inbound/Outbound')}</td>
                <td class="p-3"><span class="px-2 py-0.5 rounded text-[10px] font-mono bg-red-600/20 text-red-300 border border-red-500/30">Netsh Blocked</span></td>
                <td class="p-3 text-slate-400 text-xs">Firewall rule enforced via Windows Netsh API</td>
                <td class="p-3 text-right">
                    <button onclick="removePolicyRule('${rule.id}')" class="px-2.5 py-1 rounded bg-slate-800 hover:bg-red-600 text-slate-300 hover:text-white text-xs transition">Unblock</button>
                </td>
            </tr>
        `).join('');
    } catch (e) {
        console.error('Failed to load network blocked history:', e);
    }
}

function switchDocSection(sec) {
    const sections = ['overview', 'engines', 'elevation', 'gallery', 'brain', 'commands'];
    sections.forEach(s => {
        const el = document.getElementById(`doc-sec-${s}`);
        const btn = document.getElementById(`doc-tab-${s}`);
        if (s === sec) {
            if (el) el.classList.remove('hidden');
            if (btn) {
                btn.classList.add('bg-cyan-600', 'text-white', 'font-bold');
                btn.classList.remove('bg-slate-800', 'text-slate-300');
            }
        } else {
            if (el) el.classList.add('hidden');
            if (btn) {
                btn.classList.remove('bg-cyan-600', 'text-white', 'font-bold');
                btn.classList.add('bg-slate-800', 'text-slate-300');
            }
        }
    });
    if (window.lucide) lucide.createIcons();
}

function switchThreatsSubView(subView) {
    state.threatSubView = subView;
    const grid = document.getElementById('threats-grid');
    const ledgerView = document.getElementById('threats-ledger-view');
    const historyView = document.getElementById('threats-history-view');
    const badge = document.getElementById('threats-mode-badge');

    const btnAll = document.getElementById('btn-threats-all');
    const btnCritical = document.getElementById('btn-threats-critical');
    const btnSuspicious = document.getElementById('btn-threats-suspicious');
    const btnLedger = document.getElementById('btn-threats-ledger');
    const btnHistory = document.getElementById('btn-threats-history');

    [btnAll, btnCritical, btnSuspicious, btnLedger, btnHistory].forEach(b => {
        if (!b) return;
        b.classList.remove('bg-cyan-600', 'bg-red-600', 'bg-amber-600', 'bg-indigo-600', 'text-white', 'font-bold');
        b.classList.add('text-slate-400');
    });

    if (grid) grid.classList.add('hidden');
    if (ledgerView) ledgerView.classList.add('hidden');
    if (historyView) historyView.classList.add('hidden');

    if (subView === 'ledger') {
        if (ledgerView) ledgerView.classList.remove('hidden');
        if (btnLedger) {
            btnLedger.classList.add('bg-indigo-600', 'text-white', 'font-bold');
            btnLedger.classList.remove('text-slate-400');
        }
        if (badge) {
            badge.innerText = 'Persistent Threat Tracking Ledger';
            badge.className = 'px-2 py-0.5 rounded text-[10px] font-mono bg-indigo-600/30 text-indigo-300 border border-indigo-500/40';
        }
        loadThreatLedger();
    } else if (subView === 'blocked_history') {
        if (historyView) historyView.classList.remove('hidden');
        if (btnHistory) {
            btnHistory.classList.add('bg-cyan-600', 'text-white', 'font-bold');
            btnHistory.classList.remove('text-slate-400');
        }
        if (badge) {
            badge.innerText = 'Blocked & Eradicated Tracking';
            badge.className = 'px-2 py-0.5 rounded text-[10px] font-mono bg-cyan-600/30 text-cyan-300 border border-cyan-500/40';
        }
        loadBlockedHistory();
    } else if (subView === 'critical') {
        if (grid) grid.classList.remove('hidden');
        if (btnCritical) {
            btnCritical.classList.add('bg-red-600', 'text-white', 'font-bold');
            btnCritical.classList.remove('text-slate-400');
        }
        if (badge) {
            badge.innerText = 'Critical Severe Threats (Score ≥ 75)';
            badge.className = 'px-2 py-0.5 rounded text-[10px] font-mono bg-red-600/30 text-red-300 border border-red-500/40';
        }
        if (state.lastScanData) renderThreats(state.lastScanData.threats);
    } else if (subView === 'suspicious') {
        if (grid) grid.classList.remove('hidden');
        if (btnSuspicious) {
            btnSuspicious.classList.add('bg-amber-600', 'text-white', 'font-bold');
            btnSuspicious.classList.remove('text-slate-400');
        }
        if (badge) {
            badge.innerText = 'Suspicious Anomalies & Droppers (Score 20-74)';
            badge.className = 'px-2 py-0.5 rounded text-[10px] font-mono bg-amber-600/30 text-amber-300 border border-amber-500/40';
        }
        if (state.lastScanData) renderThreats(state.lastScanData.threats);
    } else {
        if (grid) grid.classList.remove('hidden');
        if (btnAll) {
            btnAll.classList.add('bg-cyan-600', 'text-white', 'font-bold');
            btnAll.classList.remove('text-slate-400');
        }
        if (badge) {
            badge.innerText = 'Active Detections & Risks';
            badge.className = 'px-2 py-0.5 rounded text-[10px] font-mono bg-cyan-600/30 text-cyan-300 border border-cyan-500/40';
        }
        if (state.lastScanData) renderThreats(state.lastScanData.threats);
    }
    if (window.lucide) lucide.createIcons();
}

async function loadThreatLedger() {
    try {
        const res = await fetch('/api/threats/tracking-ledger');
        if (!res.ok) return;
        const ledger = await res.json();
        state.lastLedgerData = ledger || [];
        const countBadge = document.getElementById('sub-ledger-count');
        if (countBadge) countBadge.textContent = state.lastLedgerData.length;
        filterThreatLedger();
    } catch (e) {
        console.error('Failed to load threat ledger:', e);
    }
}

function filterThreatLedger() {
    const searchInput = document.getElementById('ledger-search-input');
    const sevSelect = document.getElementById('ledger-filter-severity');
    const statSelect = document.getElementById('ledger-filter-status');
    const tbody = document.getElementById('threat-ledger-table-body');
    if (!tbody) return;

    const query = (searchInput ? searchInput.value : '').toLowerCase().trim();
    const severityFilter = (sevSelect ? sevSelect.value : '').toUpperCase();
    const statusFilter = (statSelect ? statSelect.value : '').toUpperCase();

    let items = state.lastLedgerData || [];

    if (query) {
        items = items.filter(e =>
            (e.name || '').toLowerCase().includes(query) ||
            (e.exe || '').toLowerCase().includes(query) ||
            (e.primary_category || '').toLowerCase().includes(query) ||
            String(e.pid || '').includes(query)
        );
    }

    if (severityFilter) {
        if (severityFilter === 'MEDIUM') {
            items = items.filter(e => e.severity === 'MEDIUM' || e.severity === 'LOW');
        } else {
            items = items.filter(e => (e.severity || '').toUpperCase() === severityFilter);
        }
    }

    if (statusFilter) {
        items = items.filter(e => (e.status || '').toUpperCase() === statusFilter);
    }

    if (items.length === 0) {
        tbody.innerHTML = `
            <tr>
                <td colspan="7" class="p-8 text-center text-slate-400 text-xs">
                    No threat ledger records match your filter criteria.
                </td>
            </tr>
        `;
        return;
    }

    tbody.innerHTML = items.map(item => {
        let badgeClass = 'badge-medium';
        if (item.severity === 'CRITICAL') badgeClass = 'badge-critical';
        else if (item.severity === 'HIGH' || item.severity === 'SUSPICIOUS') badgeClass = 'badge-high';

        let statusBadge = 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/30';
        if (item.status === 'ACTIVE') {
            statusBadge = 'bg-red-500/20 text-red-300 border border-red-500/40 animate-pulse';
        } else if (item.status === 'ERADICATED') {
            statusBadge = 'bg-slate-800 text-slate-300 border border-slate-700';
        } else if (item.status === 'QUARANTINED') {
            statusBadge = 'bg-purple-500/20 text-purple-300 border border-purple-500/30';
        }

        const firstSeen = item.first_seen_display || (item.first_seen ? item.first_seen.replace('T', ' ').substring(0, 19) : '--');
        const lastSeen = item.last_seen_display || (item.last_seen ? item.last_seen.replace('T', ' ').substring(0, 19) : '--');

        const reasonsHtml = (item.reasons || []).slice(0, 2).map(r =>
            `<div class="text-[11px] text-slate-400 truncate">• <strong class="text-slate-300">${escapeHtml(r.vector || '')}:</strong> ${escapeHtml(r.detail || '')}</div>`
        ).join('');

        return `
            <tr class="border-b border-slate-800/60 hover:bg-slate-800/30 transition">
                <td class="p-3 text-slate-400 text-[11px]">
                    <div><span class="text-slate-500">First:</span> ${escapeHtml(firstSeen)}</div>
                    <div><span class="text-slate-500">Last:</span> ${escapeHtml(lastSeen)}</div>
                    <div class="text-[10px] text-cyan-400 mt-0.5">Observed: ${item.times_observed || 1}x</div>
                </td>
                <td class="p-3 text-slate-300 font-mono">${item.pid || '-'}</td>
                <td class="p-3">
                    <div class="font-bold text-white">${escapeHtml(item.name || 'Unknown')}</div>
                    <div class="text-slate-400 text-[11px] truncate max-w-xs" title="${escapeHtml(item.exe || '')}">${escapeHtml(item.exe || 'In-Memory')}</div>
                </td>
                <td class="p-3">
                    <span class="px-2 py-0.5 rounded text-[10px] font-mono font-bold border ${badgeClass}">
                        ${item.threat_score || 0} [${escapeHtml(item.severity || 'LOW')}]
                    </span>
                </td>
                <td class="p-3 max-w-sm">
                    <div class="font-semibold text-slate-200 text-xs">${escapeHtml(item.primary_category || 'SUSPICIOUS')}</div>
                    ${reasonsHtml}
                </td>
                <td class="p-3">
                    <span class="px-2 py-0.5 rounded text-[10px] font-mono font-bold ${statusBadge}">
                        ${escapeHtml(item.status || 'ACTIVE')}
                    </span>
                </td>
                <td class="p-3 text-right">
                    <div class="flex items-center justify-end gap-1">
                        ${item.pid ? `
                            <button onclick="killProcess(${item.pid}, '${escapeHtml(item.name)}')" class="px-2 py-1 bg-red-600/80 hover:bg-red-500 text-white rounded text-[11px] font-bold" title="Kill PID ${item.pid}">
                                Kill
                            </button>
                            <button onclick="killTree(${item.pid}, '${escapeHtml(item.name)}')" class="px-2 py-1 bg-amber-600/30 hover:bg-amber-600 text-amber-300 rounded text-[11px]" title="Kill Process Tree">
                                Tree
                            </button>
                        ` : ''}
                        ${item.exe ? `
                            <button onclick="quarantineFile('${escapeHtml(item.exe)}')" class="px-2 py-1 bg-purple-600/30 hover:bg-purple-600 text-purple-300 rounded text-[11px]" title="Quarantine Executable">
                                Quaran
                            </button>
                        ` : ''}
                    </div>
                </td>
            </tr>
        `;
    }).join('');
    if (window.lucide) lucide.createIcons();
}

async function clearThreatLedger() {
    if (!confirm('Are you sure you want to reset and clear the persistent threat tracking ledger?')) return;
    try {
        const res = await fetch('/api/threats/tracking-ledger/clear', { method: 'POST' });
        const data = await res.json();
        showToast('Ledger Cleared', data.message || 'Tracking ledger reset.', 'success');
        loadThreatLedger();
    } catch (e) {
        showToast('Ledger Error', 'Failed to clear threat ledger.', 'danger');
    }
}

async function loadSystemInfo() {
    try {
        const res = await fetch('/api/system-info');
        if (!res.ok) return;
        const data = await res.json();

        // 1. OS & Uptime
        const osNameEl = document.getElementById('sys-os-name');
        const kernelEl = document.getElementById('sys-kernel');
        const archEl = document.getElementById('sys-arch');
        const hostEl = document.getElementById('sys-host');
        const uptimeEl = document.getElementById('sys-uptime');

        if (osNameEl) osNameEl.textContent = data.os?.os_name || 'Windows';
        if (kernelEl) kernelEl.textContent = data.os?.version || '--';
        if (archEl) archEl.textContent = data.os?.architecture || '--';
        if (hostEl) hostEl.textContent = data.os?.hostname || '--';
        if (uptimeEl) uptimeEl.textContent = data.system_uptime || '--';

        // 2. CPU
        const cpuLoadEl = document.getElementById('sys-cpu-load');
        const cpuCoresEl = document.getElementById('sys-cpu-cores');
        const cpuThreadsEl = document.getElementById('sys-cpu-threads');
        const cpuFreqEl = document.getElementById('sys-cpu-freq');
        const pythonVerEl = document.getElementById('sys-python-ver');

        if (cpuLoadEl) cpuLoadEl.textContent = `${Math.round(data.cpu?.current_load_percent || 0)}%`;
        if (cpuCoresEl) cpuCoresEl.textContent = data.cpu?.physical_cores || 1;
        if (cpuThreadsEl) cpuThreadsEl.textContent = data.cpu?.logical_threads || 1;
        if (cpuFreqEl) cpuFreqEl.textContent = `${data.cpu?.current_frequency_mhz || 0} MHz`;
        if (pythonVerEl) pythonVerEl.textContent = data.os?.python_version || '--';

        // 3. Memory & Swap
        const ramUsedEl = document.getElementById('sys-ram-used');
        const ramTotalEl = document.getElementById('sys-ram-total');
        const ramBarEl = document.getElementById('sys-ram-bar');
        const ramFreeEl = document.getElementById('sys-ram-free');
        const swapUsedEl = document.getElementById('sys-swap-used');
        const swapPctEl = document.getElementById('sys-swap-pct');

        if (ramUsedEl) ramUsedEl.textContent = `${data.memory?.used_gb || 0} GB`;
        if (ramTotalEl) ramTotalEl.textContent = `${data.memory?.total_gb || 0} GB`;
        if (ramBarEl) ramBarEl.style.width = `${Math.min(data.memory?.percent_used || 0, 100)}%`;
        if (ramFreeEl) ramFreeEl.textContent = `${data.memory?.available_gb || 0} GB`;
        if (swapUsedEl) swapUsedEl.textContent = `${data.memory?.swap_used_gb || 0} GB`;
        if (swapPctEl) swapPctEl.textContent = `${data.memory?.swap_percent || 0}%`;

        // 4. Baseline
        const baseAdminEl = document.getElementById('sys-baseline-admin');
        if (baseAdminEl) {
            baseAdminEl.textContent = data.security_baseline?.is_admin ? 'ELEVATED (ADMIN)' : 'Standard User Token';
            baseAdminEl.className = data.security_baseline?.is_admin ? 'text-emerald-400 font-bold' : 'text-amber-400 font-bold';
        }

        // 5. Network Adapters Table
        const adaptersTbody = document.getElementById('sysinfo-adapters-tbody');
        if (adaptersTbody && data.network_adapters) {
            if (data.network_adapters.length === 0) {
                adaptersTbody.innerHTML = `<tr><td colspan="6" class="p-4 text-center text-slate-400">No active network adapters found.</td></tr>`;
            } else {
                adaptersTbody.innerHTML = data.network_adapters.map(nic => `
                    <tr class="border-b border-slate-800/60 hover:bg-slate-800/30 transition">
                        <td class="p-2.5 font-bold text-white">${escapeHtml(nic.name)}</td>
                        <td class="p-2.5 text-cyan-300 font-mono">${escapeHtml(nic.ipv4 || 'Unassigned')}</td>
                        <td class="p-2.5 text-slate-400 font-mono">${escapeHtml(nic.mac || '--')}</td>
                        <td class="p-2.5 text-slate-300">${nic.speed_mbps ? `${nic.speed_mbps} Mbps` : 'Auto'}</td>
                        <td class="p-2.5 text-slate-300">${escapeHtml(nic.duplex || 'Full')}</td>
                        <td class="p-2.5 text-right">
                            <span class="px-2 py-0.5 rounded text-[10px] font-bold ${nic.is_up ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/30' : 'bg-red-500/20 text-red-300'}">
                                ${nic.is_up ? 'ONLINE (UP)' : 'DOWN'}
                            </span>
                        </td>
                    </tr>
                `).join('');
            }
        }
        if (window.lucide) lucide.createIcons();
    } catch (e) {
        console.error('Failed to load system info:', e);
    }
}

async function loadDriveAnalyzer() {
    try {
        const resDrives = await fetch('/api/drives');
        if (resDrives.ok) {
            const dataDrives = await resDrives.json();

            const poolTotalEl = document.getElementById('drive-pool-total');
            const poolUsedEl = document.getElementById('drive-pool-used');
            const poolFreeEl = document.getElementById('drive-pool-free');
            const statDrivesUsed = document.getElementById('stat-drives-used');

            if (poolTotalEl) poolTotalEl.textContent = `${dataDrives.total_capacity_gb || 0} GB`;
            if (poolUsedEl) poolUsedEl.textContent = `${dataDrives.total_used_gb || 0} GB`;
            if (poolFreeEl) poolFreeEl.textContent = `${dataDrives.total_free_gb || 0} GB`;
            if (statDrivesUsed) statDrivesUsed.textContent = `${dataDrives.overall_percent_used || 0}%`;

            const cardsGrid = document.getElementById('drives-cards-grid');
            if (cardsGrid && dataDrives.drives) {
                cardsGrid.innerHTML = dataDrives.drives.map(d => {
                    const pct = d.percent_used || 0;
                    let barColor = 'from-emerald-500 to-cyan-500';
                    if (pct > 85) barColor = 'from-red-500 to-rose-600';
                    else if (pct > 70) barColor = 'from-amber-500 to-yellow-500';

                    return `
                        <div class="p-3.5 bg-slate-900/90 rounded-xl border border-slate-800 space-y-2">
                            <div class="flex items-center justify-between">
                                <div class="font-bold text-white flex items-center gap-1.5 font-mono">
                                    <i data-lucide="hard-drive" class="w-4 h-4 text-cyan-400"></i>
                                    <span>${escapeHtml(d.mountpoint)}</span>
                                    <span class="text-[10px] text-slate-400 font-normal">(${escapeHtml(d.fstype)})</span>
                                </div>
                                <span class="text-xs font-mono font-bold text-cyan-300">${pct}%</span>
                            </div>
                            <div class="w-full bg-slate-800 rounded-full h-2 overflow-hidden">
                                <div class="bg-gradient-to-r ${barColor} h-2 rounded-full transition-all duration-500" style="width: ${Math.min(pct, 100)}%"></div>
                            </div>
                            <div class="text-[11px] font-mono text-slate-400 flex justify-between">
                                <span>Used: <strong class="text-slate-200">${d.used_gb} GB</strong></span>
                                <span>Free: <strong class="text-emerald-400">${d.free_gb} GB</strong></span>
                                <span>Total: ${d.total_gb} GB</span>
                            </div>
                        </div>
                    `;
                }).join('');
            }
        }

        const resDroppers = await fetch('/api/drives/dropper-zones');
        if (resDroppers.ok) {
            const dataDroppers = await resDroppers.json();
            const scannedEl = document.getElementById('dropper-files-scanned');
            const countEl = document.getElementById('dropper-count');
            const mbEl = document.getElementById('dropper-mb');
            const tbody = document.getElementById('droppers-table-body');

            if (scannedEl) scannedEl.textContent = dataDroppers.total_files_scanned || 0;
            if (countEl) countEl.textContent = dataDroppers.dropper_count || 0;
            if (mbEl) mbEl.textContent = dataDroppers.dropper_size_mb || 0;

            if (tbody) {
                if (!dataDroppers.droppers || dataDroppers.droppers.length === 0) {
                    tbody.innerHTML = `
                        <tr>
                            <td colspan="6" class="p-8 text-center text-slate-400 text-xs">
                                No executable or script droppers found in monitored staging zones (%TEMP%, AppData, Windows Temp).
                            </td>
                        </tr>
                    `;
                } else {
                    tbody.innerHTML = dataDroppers.droppers.map(drop => {
                        const isSusp = drop.is_suspicious;
                        const badgeClass = isSusp ? 'bg-red-500/20 text-red-300 border-red-500/30' : 'bg-slate-800 text-slate-300 border-slate-700';

                        return `
                            <tr class="border-b border-slate-800/60 hover:bg-slate-800/30 transition">
                                <td class="p-2.5 text-cyan-300 font-bold">${escapeHtml(drop.zone)}</td>
                                <td class="p-2.5 text-white font-bold">${escapeHtml(drop.filename)}</td>
                                <td class="p-2.5 text-slate-400 text-[11px] truncate max-w-xs" title="${escapeHtml(drop.path)}">${escapeHtml(drop.path)}</td>
                                <td class="p-2.5 text-slate-300">${drop.size_kb} KB</td>
                                <td class="p-2.5 text-slate-400">${escapeHtml(drop.modified)}</td>
                                <td class="p-2.5 text-right">
                                    <div class="flex items-center justify-end gap-1.5">
                                        <span class="px-2 py-0.5 rounded text-[10px] font-bold border ${badgeClass}">
                                            ${isSusp ? 'SUSPICIOUS DROPPER' : 'TEMP ARTIFACT'}
                                        </span>
                                        <button onclick="quarantineFile('${escapeHtml(drop.path)}')" class="px-2 py-0.5 bg-purple-600/30 hover:bg-purple-600 text-purple-200 rounded text-[10px]" title="Quarantine file">
                                            Quarantine
                                        </button>
                                    </div>
                                </td>
                            </tr>
                        `;
                    }).join('');
                }
            }
        }
        if (window.lucide) lucide.createIcons();
    } catch (e) {
        console.error('Failed to load drive analyzer:', e);
    }
}

async function cleanTempDroppers() {
    if (!confirm('Clean all temporary dropper staging files in your user %TEMP% directory?')) return;
    try {
        const res = await fetch('/api/drives/clean-temp', { method: 'POST' });
        const data = await res.json();
        showToast('Temp Cleanup', data.message || 'Temp files cleaned.', data.success ? 'success' : 'warning');
        loadDriveAnalyzer();
    } catch (e) {
        showToast('Cleanup Error', 'Failed to clean temp directory.', 'danger');
    }
}

// ==============================================================
// Windows Services Management Controller (services.msc)
// ==============================================================

async function loadWindowsServices(force = false) {
    const tbody = document.getElementById('services-table-body');
    if (tbody && !state.lastServicesData) {
        tbody.innerHTML = `<tr><td colspan="6" class="p-8 text-center text-slate-400">Loading Windows services catalog...</td></tr>`;
    }

    try {
        const url = `/api/services${force ? '?force=true' : ''}`;
        const res = await fetch(url);
        if (!res.ok) return;
        const data = await res.json();
        state.lastServicesData = data.services || [];

        // Update KPI metrics
        const statTotal = document.getElementById('stat-services-total');
        const statRunning = document.getElementById('stat-services-running');
        const statStopped = document.getElementById('stat-services-stopped');
        const statRmm = document.getElementById('stat-services-rmm');

        if (statTotal) statTotal.innerText = data.total_count ?? state.lastServicesData.length;
        if (statRunning) statRunning.innerText = data.running_count ?? state.lastServicesData.filter(s => s.is_running).length;
        if (statStopped) statStopped.innerText = data.stopped_count ?? state.lastServicesData.filter(s => !s.is_running).length;
        if (statRmm) statRmm.innerText = data.rmm_count ?? state.lastServicesData.filter(s => s.is_rmm).length;

        renderServicesTable();
    } catch (e) {
        console.error('Failed to load Windows Services:', e);
        if (tbody) {
            tbody.innerHTML = `<tr><td colspan="6" class="p-8 text-center text-rose-500 font-mono">Failed to query Windows services catalog.</td></tr>`;
        }
    }
}

function renderServicesTable() {
    const tbody = document.getElementById('services-table-body');
    if (!tbody) return;

    let services = state.lastServicesData || [];

    // Apply Filter
    if (state.servicesFilter === 'running') {
        services = services.filter(s => s.is_running);
    } else if (state.servicesFilter === 'stopped') {
        services = services.filter(s => !s.is_running);
    } else if (state.servicesFilter === 'auto') {
        services = services.filter(s => (s.start_type || '').toLowerCase().includes('auto'));
    } else if (state.servicesFilter === 'manual') {
        services = services.filter(s => ['manual', 'demand'].includes((s.start_type || '').toLowerCase()));
    } else if (state.servicesFilter === 'disabled') {
        services = services.filter(s => (s.start_type || '').toLowerCase() === 'disabled');
    } else if (state.servicesFilter === 'rmm') {
        services = services.filter(s => s.is_rmm || (s.threat_score || 0) > 0);
    }

    // Apply Search
    if (state.servicesSearchQuery.trim()) {
        const q = state.servicesSearchQuery.trim().toLowerCase();
        services = services.filter(s =>
            (s.name || '').toLowerCase().includes(q) ||
            (s.display_name || '').toLowerCase().includes(q) ||
            String(s.pid || '').includes(q) ||
            (s.binpath || '').toLowerCase().includes(q) ||
            (s.description || '').toLowerCase().includes(q)
        );
    }

    if (services.length === 0) {
        tbody.innerHTML = `<tr><td colspan="6" class="p-8 text-center text-slate-400">No Windows services found matching criteria.</td></tr>`;
        return;
    }

    tbody.innerHTML = services.map(svc => {
        const isRunning = svc.is_running;
        const isRmm = svc.is_rmm;
        
        let statusBadge = '';
        if (isRmm) {
            statusBadge = `<span class="px-2 py-0.5 rounded text-[10px] font-bold font-mono badge-critical flex items-center gap-1 w-max"><span class="w-1.5 h-1.5 rounded-full bg-rose-500 animate-pulse"></span> RMM / THREAT</span>`;
        } else if (isRunning) {
            statusBadge = `<span class="px-2 py-0.5 rounded text-[10px] font-bold font-mono badge-safe flex items-center gap-1 w-max"><span class="w-1.5 h-1.5 rounded-full bg-emerald-500"></span> RUNNING</span>`;
        } else {
            statusBadge = `<span class="px-2 py-0.5 rounded text-[10px] font-bold font-mono bg-slate-100 text-slate-600 border border-slate-200 dark:bg-slate-800 dark:text-slate-400 dark:border-slate-700 flex items-center gap-1 w-max">STOPPED</span>`;
        }

        const pidBadge = svc.pid && svc.pid > 0 ? 
            `<span class="px-2 py-0.5 rounded text-[11px] font-mono bg-slate-100 dark:bg-slate-800 text-slate-700 dark:text-slate-300 border border-slate-200 dark:border-slate-700">PID ${svc.pid}</span>` :
            `<span class="text-slate-400 text-[11px]">—</span>`;

        return `
            <tr class="hover:bg-slate-50/80 dark:hover:bg-slate-800/40 transition-colors">
                <td class="p-3 align-top">${statusBadge}</td>
                <td class="p-3 align-top">
                    <div class="font-bold text-slate-900 dark:text-white flex items-center gap-2">
                        <span>${escapeHtml(svc.name)}</span>
                        ${isRmm ? '<span class="text-[10px] px-1.5 py-0.5 rounded bg-rose-100 text-rose-700 font-bold border border-rose-300">POTENTIAL RAT / RMM</span>' : ''}
                    </div>
                    <div class="text-[11px] text-slate-600 dark:text-slate-400 truncate max-w-md font-medium" title="${escapeHtml(svc.display_name)}">
                        ${escapeHtml(svc.display_name)}
                    </div>
                    ${svc.description ? `<div class="text-[10px] text-slate-500 dark:text-slate-500 line-clamp-1 max-w-lg mt-0.5" title="${escapeHtml(svc.description)}">${escapeHtml(svc.description)}</div>` : ''}
                </td>
                <td class="p-3 align-top">${pidBadge}</td>
                <td class="p-3 align-top">
                    <select onchange="changeServiceStartupType('${escapeHtml(svc.name)}', this.value)" class="text-xs px-2 py-1 rounded bg-white dark:bg-slate-800 border border-slate-200 dark:border-slate-700 text-slate-700 dark:text-slate-200 focus:outline-hidden cursor-pointer">
                        <option value="auto" ${(svc.start_type || '').toLowerCase().includes('auto') ? 'selected' : ''}>Automatic</option>
                        <option value="manual" ${['manual', 'demand'].includes((svc.start_type || '').toLowerCase()) ? 'selected' : ''}>Manual</option>
                        <option value="disabled" ${(svc.start_type || '').toLowerCase() === 'disabled' ? 'selected' : ''}>Disabled</option>
                    </select>
                </td>
                <td class="p-3 align-top">
                    <div class="text-[11px] font-mono text-slate-600 dark:text-slate-400 truncate max-w-xs" title="${escapeHtml(svc.binpath || 'Windows Shared Host (svchost)')}">
                        ${escapeHtml(svc.binpath || 'Windows Shared Host (svchost)')}
                    </div>
                </td>
                <td class="p-3 align-top text-right space-x-1 whitespace-nowrap">
                    ${isRunning ? `
                        <button onclick="stopService('${escapeHtml(svc.name)}')" class="px-2 py-1 rounded bg-amber-500/10 hover:bg-amber-500/20 text-amber-700 dark:text-amber-400 border border-amber-300 dark:border-amber-500/30 text-[11px] font-medium transition" title="Stop Service">
                            Stop
                        </button>
                        <button onclick="restartService('${escapeHtml(svc.name)}')" class="px-2 py-1 rounded bg-sky-500/10 hover:bg-sky-500/20 text-sky-700 dark:text-sky-400 border border-sky-300 dark:border-sky-500/30 text-[11px] font-medium transition" title="Restart Service">
                            Restart
                        </button>
                    ` : `
                        <button onclick="startService('${escapeHtml(svc.name)}')" class="px-2.5 py-1 rounded bg-emerald-500/10 hover:bg-emerald-500/20 text-emerald-700 dark:text-emerald-400 border border-emerald-300 dark:border-emerald-500/30 text-[11px] font-medium transition" title="Start Service">
                            Start
                        </button>
                    `}
                </td>
            </tr>
        `;
    }).join('');

    if (window.lucide) lucide.createIcons();
}

function setServiceFilter(filter) {
    state.servicesFilter = filter;
    document.querySelectorAll('.svc-filter-btn').forEach(btn => {
        if (btn.dataset.svcFilter === filter) {
            btn.className = 'svc-filter-btn px-3 py-1.5 rounded-lg bg-sky-600 text-white font-medium transition shadow-xs';
        } else {
            btn.className = 'svc-filter-btn px-3 py-1.5 rounded-lg bg-slate-100 dark:bg-slate-800 text-slate-600 dark:text-slate-300 font-medium hover:bg-slate-200 transition';
        }
    });
    renderServicesTable();
}

function filterServicesTable() {
    const input = document.getElementById('services-search-input');
    state.servicesSearchQuery = input ? input.value : '';
    renderServicesTable();
}

async function startService(name) {
    try {
        const res = await fetch(`/api/services/${encodeURIComponent(name)}/start`, { method: 'POST' });
        const data = await res.json();
        showToast(
            data.success ? 'Service Started' : 'Start Command Sent',
            data.message || `Started ${name}`,
            data.success ? 'success' : 'info'
        );
        loadWindowsServices(true);
    } catch (e) {
        showToast('Error', `Failed to start service ${name}`, 'danger');
    }
}

async function stopService(name) {
    if (!confirm(`Are you sure you want to stop service '${name}'?`)) return;
    try {
        const res = await fetch(`/api/services/${encodeURIComponent(name)}/stop`, { method: 'POST' });
        const data = await res.json();
        showToast(
            data.success ? 'Service Stopped' : 'Stop Command Sent',
            data.message || `Stopped ${name}`,
            data.success ? 'success' : 'info'
        );
        loadWindowsServices(true);
    } catch (e) {
        showToast('Error', `Failed to stop service ${name}`, 'danger');
    }
}

async function restartService(name) {
    try {
        const res = await fetch(`/api/services/${encodeURIComponent(name)}/restart`, { method: 'POST' });
        const data = await res.json();
        showToast(
            data.success ? 'Service Restarted' : 'Restart Command Sent',
            data.message || `Restarted ${name}`,
            data.success ? 'success' : 'info'
        );
        loadWindowsServices(true);
    } catch (e) {
        showToast('Error', `Failed to restart service ${name}`, 'danger');
    }
}

async function changeServiceStartupType(name, type) {
    try {
        const res = await fetch(`/api/services/${encodeURIComponent(name)}/config`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ startup_type: type })
        });
        const data = await res.json();
        showToast(
            data.success ? 'Startup Type Updated' : 'Notice',
            data.message || `Startup type set to ${type}`,
            data.success ? 'success' : 'warning'
        );
    } catch (e) {
        showToast('Error', `Failed to update startup type for ${name}`, 'danger');
    }
}

async function loadBlockedHistory() {
    try {
        const res = await fetch('/api/blocked-history');
        const history = await res.json();
        const tbody = document.getElementById('blocked-history-table-body');
        const countBadge = document.getElementById('sub-blocked-count');

        if (countBadge) countBadge.textContent = history.length;
        if (!tbody) return;

        if (!history || history.length === 0) {
            tbody.innerHTML = `
                <tr>
                    <td colspan="6" class="p-8 text-center text-slate-400 text-xs">
                        No previous threat blocks or kills recorded yet. Active scanning will record all eradicated threats here.
                    </td>
                </tr>
            `;
            return;
        }

        tbody.innerHTML = history.map(item => {
            let actionBadge = 'bg-red-600/20 text-red-300 border-red-500/30';
            if (item.action === 'IP_BLOCKED') actionBadge = 'bg-amber-600/20 text-amber-300 border-amber-500/30';
            if (item.action === 'FILE_QUARANTINED') actionBadge = 'bg-purple-600/20 text-purple-300 border-purple-500/30';
            if (item.action === 'PROCESS_KILLED') actionBadge = 'bg-emerald-600/20 text-emerald-300 border-emerald-500/30';

            const statusClass = item.status === 'SUCCESS' ? 'text-emerald-400 font-bold' : (item.status === 'FAILED' ? 'text-red-400 font-bold' : 'text-amber-400 font-bold');

            return `
                <tr class="border-b border-slate-800/60 hover:bg-slate-800/30 transition">
                    <td class="p-3 text-slate-400">${escapeHtml(item.time_display || item.timestamp || '')}</td>
                    <td class="p-3">
                        <span class="px-2 py-0.5 rounded text-[10px] font-mono font-bold border ${actionBadge}">
                            ${escapeHtml(item.action)}
                        </span>
                    </td>
                    <td class="p-3 font-bold text-white">${escapeHtml(item.target || 'N/A')}</td>
                    <td class="p-3 text-slate-300">${item.pid || '-'}</td>
                    <td class="p-3 text-slate-300">${escapeHtml(item.details || '')}</td>
                    <td class="p-3 text-right ${statusClass}">${escapeHtml(item.status)}</td>
                </tr>
            `;
        }).join('');
    } catch (e) {
        console.error('Failed to load blocked history:', e);
    }
}

// Core Scanning Logic
async function runScan(detailed = false) {
    if (state.isScanning) return;
    state.isScanning = true;

    const scanBtn = document.getElementById('btn-scan');
    const radar = document.getElementById('scan-radar');
    if (scanBtn) scanBtn.classList.add('opacity-75', 'cursor-not-allowed');
    if (radar) radar.classList.remove('hidden');

    try {
        const response = await fetch(`/api/scan?detailed=${detailed}`);
        if (!response.ok) throw new Error('Scan API error');
        const data = await response.json();
        state.lastScanData = data;

        renderDashboard(data);

        if (data.critical_count > 0 || data.high_count > 0) {
            CyberAudio.playChime('threat');
        }
    } catch (err) {
        showToast('Scan Notice', 'Telemetry polling in progress', 'info');
    } finally {
        state.isScanning = false;
        if (scanBtn) scanBtn.classList.remove('opacity-75', 'cursor-not-allowed');
        if (radar) radar.classList.add('hidden');
    }
}

// Render Dashboard Data
function renderDashboard(data) {
    // 1. Metric Badges
    const totalProcsEl = document.getElementById('stat-total-procs');
    const criticalEl = document.getElementById('stat-critical');
    const suspiciousEl = document.getElementById('stat-suspicious');
    const rmmEl = document.getElementById('stat-rmm');
    const healthEl = document.getElementById('stat-health');

    if (totalProcsEl) totalProcsEl.textContent = data.total_processes;
    if (criticalEl) criticalEl.textContent = data.critical_count !== undefined ? data.critical_count : 0;
    if (suspiciousEl) suspiciousEl.textContent = data.suspicious_count !== undefined ? data.suspicious_count : 0;
    if (rmmEl) rmmEl.textContent = data.rmm_count;
    if (healthEl) healthEl.textContent = `${data.system_health_index}%`;

    // System Health Shield status
    const healthBadge = document.getElementById('system-status-indicator');
    if (healthBadge) {
        if (data.critical_count > 0) {
            healthBadge.className = 'px-3 py-1 rounded-full text-xs font-mono font-bold bg-red-500/20 text-red-400 border border-red-500/50 flex items-center gap-2 animate-pulse';
            healthBadge.innerHTML = '<span class="w-2 h-2 rounded-full bg-red-500"></span> CRITICAL THREAT DETECTED';
        } else if (data.suspicious_count > 0 || data.high_count > 0 || data.total_threats > 0) {
            healthBadge.className = 'px-3 py-1 rounded-full text-xs font-mono font-bold bg-amber-500/20 text-amber-400 border border-amber-500/50 flex items-center gap-2';
            healthBadge.innerHTML = '<span class="w-2 h-2 rounded-full bg-amber-500"></span> POTENTIAL RISKS ACTIVE';
        } else {
            healthBadge.className = 'px-3 py-1 rounded-full text-xs font-mono font-bold bg-emerald-500/20 text-emerald-400 border border-emerald-500/50 flex items-center gap-2';
            healthBadge.innerHTML = '<span class="w-2 h-2 rounded-full bg-emerald-500"></span> SYSTEM PROTECTED & SECURE';
        }
    }

    // 2. Render Threat Center
    renderThreats(data.threats);

    // 3. Render Remote Desktop & RMM Tab
    renderRMM(data.rmm_tools);

    // 4. Render Live Process Table
    renderProcessTable(data.processes);

    if (window.lucide) lucide.createIcons();
}

// Render Active / Filtered Threats
function renderThreats(threats) {
    const container = document.getElementById('threats-grid');
    const subActive = document.getElementById('sub-active-count');
    const subAll = document.getElementById('sub-all-count');
    const subCritical = document.getElementById('sub-critical-count');
    const subSuspicious = document.getElementById('sub-suspicious-count');

    const allThreats = threats || [];
    const criticalThreats = allThreats.filter(t => t.is_critical || t.severity === 'CRITICAL' || t.severity === 'HIGH');
    const suspiciousThreats = allThreats.filter(t => t.is_suspicious || (t.threat_score >= 20 && t.threat_score < 75));

    if (subActive) subActive.textContent = allThreats.length;
    if (subAll) subAll.textContent = allThreats.length;
    if (subCritical) subCritical.textContent = criticalThreats.length;
    if (subSuspicious) subSuspicious.textContent = suspiciousThreats.length;

    if (!container) return;

    let displayList = allThreats;
    if (state.threatSubView === 'critical') displayList = criticalThreats;
    else if (state.threatSubView === 'suspicious') displayList = suspiciousThreats;

    if (displayList.length === 0) {
        let emptyTitle = 'Zero Active Threats Found';
        let emptyMsg = 'Your running processes have passed behavioral heuristics, signature checks, and LOLRMM analysis.';
        if (state.threatSubView === 'critical') {
            emptyTitle = 'Zero Critical Threats Active';
            emptyMsg = 'No severe threats with risk score exceeding 75 are currently present.';
        } else if (state.threatSubView === 'suspicious') {
            emptyTitle = 'Zero Suspicious Anomalies Active';
            emptyMsg = 'No heuristic dropper anomalies or low-tier suspicious patterns are currently active.';
        }

        container.innerHTML = `
            <div class="col-span-full cyber-card p-12 text-center">
                <div class="w-16 h-16 mx-auto rounded-full bg-emerald-500/10 border border-emerald-500/30 flex items-center justify-center text-emerald-400 mb-4">
                    <i data-lucide="shield-check" class="w-8 h-8"></i>
                </div>
                <h3 class="text-lg font-semibold text-white">${emptyTitle}</h3>
                <p class="text-sm text-slate-400 mt-1 max-w-md mx-auto">
                    ${emptyMsg}
                </p>
                <div class="mt-6 flex justify-center gap-3">
                    <button onclick="spawnTestSimulation('temp_trojan')" class="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-xs font-mono text-cyan-400 rounded-lg border border-slate-700 flex items-center gap-2">
                        <i data-lucide="flask-conical" class="w-4 h-4"></i> Spawn Test Threat to Verify Eradication
                    </button>
                </div>
            </div>
        `;
        if (window.lucide) lucide.createIcons();
        return;
    }

    let html = '';
    threats.forEach(t => {
        const severityClass = t.severity === 'CRITICAL' ? 'threat-card-critical' : (t.severity === 'HIGH' ? 'threat-card-high' : 'threat-card-medium');
        const badgeClass = t.severity === 'CRITICAL' ? 'badge-critical' : (t.severity === 'HIGH' ? 'badge-high' : 'badge-medium');
        const scoreColor = t.threat_score >= 80 ? 'bg-red-500' : (t.threat_score >= 50 ? 'bg-amber-500' : 'bg-purple-500');

        html += `
            <div class="cyber-card p-5 ${severityClass}">
                <div class="flex items-start justify-between">
                    <div>
                        <div class="flex items-center gap-2">
                            <span class="font-bold text-base text-white font-mono">${escapeHtml(t.name)}</span>
                            <span class="text-xs font-mono text-slate-400">(PID: ${t.pid})</span>
                            <span class="px-2 py-0.5 rounded text-[10px] font-mono font-bold uppercase ${badgeClass}">${t.primary_category}</span>
                        </div>
                        <div class="text-xs text-slate-400 font-mono mt-1 truncate max-w-lg" title="${escapeHtml(t.exe)}">
                            ${escapeHtml(t.exe || 'In-Memory / Unknown Executable')}
                        </div>
                    </div>
                    <div class="text-right">
                        <div class="text-xs font-mono text-slate-400">Risk Score</div>
                        <div class="text-xl font-bold font-mono text-white">${t.threat_score}<span class="text-xs text-slate-500">/100</span></div>
                    </div>
                </div>

                <!-- Threat Score Bar -->
                <div class="w-full bg-slate-800 h-1.5 rounded-full overflow-hidden mt-3 mb-4">
                    <div class="${scoreColor} h-full" style="width: ${t.threat_score}%"></div>
                </div>

                <!-- Triggered Heuristics & Signatures -->
                <div class="space-y-1.5 my-3">
                    ${t.reasons.map(r => `
                        <div class="flex items-start gap-2 text-xs">
                            <span class="text-red-400 mt-0.5">•</span>
                            <div>
                                <strong class="text-slate-300 font-medium">${escapeHtml(r.vector)}:</strong>
                                <span class="text-slate-400">${escapeHtml(r.detail)}</span>
                            </div>
                        </div>
                    `).join('')}
                </div>

                <!-- Action Controls: Allow, Block, Kill, Inspect -->
                <div class="mt-4 pt-3 border-t border-slate-800 flex items-center justify-between">
                    <div class="flex items-center gap-1.5">
                        <button onclick="quickAllowProcess('${escapeHtml(t.name)}', '${escapeHtml(t.exe)}')" class="px-2.5 py-1 bg-emerald-600/20 hover:bg-emerald-600/30 text-emerald-300 text-xs font-mono rounded border border-emerald-500/40" title="Whitelist and trust this process">
                            <i data-lucide="check" class="w-3 h-3 inline"></i> Allow
                        </button>
                        <button onclick="quickBlockProcess('${escapeHtml(t.name)}', '${escapeHtml(t.exe)}')" class="px-2.5 py-1 bg-red-600/20 hover:bg-red-600/30 text-red-300 text-xs font-mono rounded border border-red-500/40" title="Blacklist and ban this process">
                            <i data-lucide="ban" class="w-3 h-3 inline"></i> Block
                        </button>
                    </div>
                    <div class="flex items-center gap-2">
                        <button onclick="inspectProcess(${t.pid})" class="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-xs font-mono text-slate-300 rounded border border-slate-700 transition">
                            Inspect
                        </button>
                        <button onclick="killTree(${t.pid}, '${escapeHtml(t.name)}')" class="px-3 py-1.5 bg-amber-600/20 hover:bg-amber-600/30 text-amber-300 text-xs font-mono rounded border border-amber-500/40 transition">
                            Kill Tree
                        </button>
                        <button onclick="killProcess(${t.pid}, '${escapeHtml(t.name)}')" class="px-4 py-1.5 bg-red-600 hover:bg-red-500 text-white font-bold text-xs font-mono rounded transition flex items-center gap-1.5 shadow-lg shadow-red-900/30">
                            <i data-lucide="zap" class="w-3.5 h-3.5"></i> KILL
                        </button>
                    </div>
                </div>
            </div>
        `;
    });

    container.innerHTML = html;
}

// Render Remote Desktop & RMM Tab
function renderRMM(rmmList) {
    const container = document.getElementById('rmm-table-body');
    if (!container) return;

    if (!rmmList || rmmList.length === 0) {
        container.innerHTML = `
            <tr>
                <td colspan="6" class="p-8 text-center text-slate-400 text-sm">
                    No active Remote Desktop, VNC, RMM, or unauthorized RAT tools running.
                </td>
            </tr>
        `;
        return;
    }

    let html = '';
    rmmList.forEach(r => {
        const ports = r.network?.connections?.map(c => `${c.local_port || ''} -> ${c.remote_addr || 'LISTEN'}`).join(', ') || 'No active sockets';
        html += `
            <tr class="border-b border-slate-800/60 hover:bg-slate-800/30">
                <td class="p-3 font-mono font-bold text-cyan-400">${escapeHtml(r.name)}</td>
                <td class="p-3 font-mono text-xs text-slate-300">${r.pid}</td>
                <td class="p-3">
                    <span class="px-2 py-0.5 rounded text-[10px] font-mono font-bold badge-rmm">
                        ${r.primary_category}
                    </span>
                </td>
                <td class="p-3 font-mono text-xs text-slate-400 truncate max-w-xs" title="${escapeHtml(r.exe)}">${escapeHtml(r.exe)}</td>
                <td class="p-3 font-mono text-xs text-slate-300">${escapeHtml(ports)}</td>
                <td class="p-3 text-right">
                    <button onclick="killProcess(${r.pid}, '${escapeHtml(r.name)}')" class="px-3 py-1 bg-red-600/30 hover:bg-red-600 text-red-200 text-xs font-mono rounded border border-red-500/50">
                        Disconnect & Kill
                    </button>
                </td>
            </tr>
        `;
    });

    container.innerHTML = html;
}

// Render Process Explorer Table
function renderProcessTable(processes) {
    const tbody = document.getElementById('process-table-body');
    if (!tbody) return;

    let filtered = processes || [];

    if (state.processFilter === 'threats') {
        filtered = filtered.filter(p => p.is_threat);
    } else if (state.processFilter === 'rmm') {
        filtered = filtered.filter(p => p.primary_category.includes('REMOTE') || p.primary_category.includes('TUNNEL'));
    } else if (state.processFilter === 'high_cpu') {
        filtered = filtered.filter(p => p.cpu_percent > 5.0);
    }

    if (state.searchQuery.trim()) {
        const q = state.searchQuery.toLowerCase();
        filtered = filtered.filter(p => 
            p.name.toLowerCase().includes(q) ||
            p.pid.toString().includes(q) ||
            p.exe.toLowerCase().includes(q) ||
            p.username.toLowerCase().includes(q)
        );
    }

    if (filtered.length === 0) {
        tbody.innerHTML = `
            <tr>
                <td colspan="7" class="p-8 text-center text-slate-400 text-sm">
                    No matching processes found.
                </td>
            </tr>
        `;
        return;
    }

    let html = '';
    filtered.slice(0, 150).forEach(p => {
        let badge = '<span class="px-2 py-0.5 rounded text-[10px] font-mono font-bold badge-safe">SAFE</span>';
        if (p.primary_category === 'TRUSTED WHITELIST') {
            badge = '<span class="px-2 py-0.5 rounded text-[10px] font-mono font-bold badge-allowed">ALLOWED</span>';
        } else if (p.primary_category === 'BLOCKED BY POLICY') {
            badge = '<span class="px-2 py-0.5 rounded text-[10px] font-mono font-bold badge-blocked">BANNED</span>';
        } else if (p.severity === 'CRITICAL') {
            badge = '<span class="px-2 py-0.5 rounded text-[10px] font-mono font-bold badge-critical">CRITICAL</span>';
        } else if (p.severity === 'HIGH') {
            badge = '<span class="px-2 py-0.5 rounded text-[10px] font-mono font-bold badge-high">HIGH</span>';
        } else if (p.severity === 'MEDIUM') {
            badge = '<span class="px-2 py-0.5 rounded text-[10px] font-mono font-bold badge-medium">MEDIUM</span>';
        }

        html += `
            <tr class="border-b border-slate-800/40 hover:bg-slate-800/30 transition">
                <td class="p-3 font-mono text-xs text-slate-400">${p.pid}</td>
                <td class="p-3">
                    <div class="font-mono font-semibold text-white text-sm hover:text-cyan-400 cursor-pointer" onclick="inspectProcess(${p.pid})">
                        ${escapeHtml(p.name)}
                    </div>
                    <div class="text-[11px] text-slate-500 font-mono truncate max-w-sm" title="${escapeHtml(p.exe)}">${escapeHtml(p.exe || 'Protected/System')}</div>
                </td>
                <td class="p-3">${badge}</td>
                <td class="p-3 font-mono text-xs ${p.cpu_percent > 10 ? 'text-amber-400 font-bold' : 'text-slate-300'}">${p.cpu_percent}%</td>
                <td class="p-3 font-mono text-xs text-slate-300">${p.memory_mb} MB</td>
                <td class="p-3 font-mono text-xs text-slate-400 truncate max-w-[120px]">${escapeHtml(p.username)}</td>
                <td class="p-3 text-right">
                    <div class="flex items-center justify-end gap-1.5">
                        <button onclick="quickAllowProcess('${escapeHtml(p.name)}', '${escapeHtml(p.exe)}')" class="px-2 py-0.5 bg-emerald-600/20 hover:bg-emerald-600/30 text-emerald-300 text-[11px] font-mono rounded border border-emerald-500/30" title="Allow/Whitelist">
                            Allow
                        </button>
                        <button onclick="quickBlockProcess('${escapeHtml(p.name)}', '${escapeHtml(p.exe)}')" class="px-2 py-0.5 bg-red-600/20 hover:bg-red-600/30 text-red-300 text-[11px] font-mono rounded border border-red-500/30" title="Block/Blacklist">
                            Block
                        </button>
                        <button onclick="inspectProcess(${p.pid})" class="px-2.5 py-1 bg-slate-800 hover:bg-slate-700 text-xs font-mono text-slate-300 rounded border border-slate-700">
                            Inspect
                        </button>
                        ${p.is_protected ? `
                            <span class="text-xs text-slate-500 font-mono px-2 py-1">Protected</span>
                        ` : `
                            <button onclick="killProcess(${p.pid}, '${escapeHtml(p.name)}')" class="px-2.5 py-1 bg-red-600/30 hover:bg-red-600 text-red-200 text-xs font-mono rounded border border-red-500/40">
                                Kill
                            </button>
                        `}
                    </div>
                </td>
            </tr>
        `;
    });

    tbody.innerHTML = html;
}

// ==============================================================
// Network Radar & Origin Tracer Controller
// ==============================================================

async function loadNetworkTracer() {
    const tbody = document.getElementById('net-table-body');
    if (!tbody) return;

    try {
        const res = await fetch('/api/network/tracer');
        if (!res.ok) throw new Error('Network tracer API error');
        const data = await res.json();
        state.lastNetworkData = data;

        // Update Counter Cards
        document.getElementById('net-stat-procs').textContent = data.total_network_processes;
        document.getElementById('net-stat-established').textContent = data.established_sockets;
        document.getElementById('net-stat-listening').textContent = data.listening_sockets;
        document.getElementById('net-stat-genuine').textContent = data.genuine_cdn_sockets;
        document.getElementById('net-stat-suspicious').textContent = data.suspicious_sockets;

        renderNetworkTable(data.connections);
    } catch (e) {
        tbody.innerHTML = `<tr><td colspan="7" class="p-8 text-center text-slate-400">Failed to load active network connections.</td></tr>`;
    }
}

function renderNetworkTable(conns) {
    const tbody = document.getElementById('net-table-body');
    if (!tbody) return;

    let filtered = conns || [];

    // Filter by category
    if (state.netFilter === 'external') {
        filtered = filtered.filter(c => !c.is_private && c.remote_ip);
    } else if (state.netFilter === 'suspicious') {
        filtered = filtered.filter(c => c.is_suspicious || c.trace.verdict.includes('SUSPICIOUS'));
    } else if (state.netFilter === 'genuine') {
        filtered = filtered.filter(c => c.trace.verdict === 'GENUINE CLOUD / CDN');
    } else if (state.netFilter === 'listening') {
        filtered = filtered.filter(c => c.status === 'LISTEN');
    }

    // Filter by search query
    if (state.netSearchQuery.trim()) {
        const q = state.netSearchQuery.toLowerCase();
        filtered = filtered.filter(c =>
            c.process_name.toLowerCase().includes(q) ||
            c.pid.toString().includes(q) ||
            c.local_addr.toLowerCase().includes(q) ||
            c.remote_addr.toLowerCase().includes(q) ||
            (c.trace?.hostname || '').toLowerCase().includes(q) ||
            (c.trace?.org || '').toLowerCase().includes(q)
        );
    }

    if (filtered.length === 0) {
        tbody.innerHTML = `<tr><td colspan="7" class="p-8 text-center text-slate-400">No matching network connections found.</td></tr>`;
        return;
    }

    let html = '';
    filtered.slice(0, 150).forEach(c => {
        let badgeClass = 'badge-unverified';
        if (c.trace.verdict === 'GENUINE CLOUD / CDN') {
            badgeClass = 'badge-genuine';
        } else if (c.trace.verdict === 'PRIVATE LAN') {
            badgeClass = 'badge-private';
        } else if (c.is_suspicious || c.trace.verdict.includes('SUSPICIOUS')) {
            badgeClass = 'badge-suspicious-ip';
        }

        const stateColor = c.status === 'ESTABLISHED' ? 'text-emerald-400' : (c.status === 'LISTEN' ? 'text-amber-400' : 'text-slate-400');

        html += `
            <tr class="border-b border-slate-800/40 hover:bg-slate-800/30 transition">
                <td class="p-3">
                    <span class="font-bold text-white">${escapeHtml(c.process_name)}</span>
                    <span class="text-xs text-slate-500">(${c.pid})</span>
                </td>
                <td class="p-3 font-mono text-xs text-slate-300">${escapeHtml(c.local_addr)}</td>
                <td class="p-3 font-mono text-xs text-cyan-400 font-semibold">${escapeHtml(c.remote_addr)}</td>
                <td class="p-3 text-xs">
                    <div class="text-slate-200 truncate max-w-xs" title="${escapeHtml(c.trace?.hostname)}">${escapeHtml(c.trace?.hostname || 'Unknown Host')}</div>
                    <div class="text-[10px] text-slate-500">${escapeHtml(c.trace?.org || 'Unverified')}</div>
                </td>
                <td class="p-3">
                    <span class="px-2 py-0.5 rounded text-[10px] font-mono font-bold ${badgeClass}">
                        ${c.trace?.verdict || 'UNVERIFIED'}
                    </span>
                    ${c.threat_note ? `<div class="text-[10px] text-red-400 mt-0.5 font-bold">${escapeHtml(c.threat_note)}</div>` : ''}
                </td>
                <td class="p-3 font-mono text-xs font-bold ${stateColor}">${c.status}</td>
                <td class="p-3 text-right">
                    <div class="flex items-center justify-end gap-1.5">
                        ${c.remote_ip && !c.is_private ? `
                            <button onclick="deepTraceIP('${escapeHtml(c.remote_ip)}')" class="px-2 py-1 bg-slate-800 hover:bg-slate-700 text-xs text-cyan-300 rounded border border-slate-700" title="Trace IP intelligence">
                                Trace
                            </button>
                            <button onclick="blockIP('${escapeHtml(c.remote_ip)}')" class="px-2 py-1 bg-red-600/20 hover:bg-red-600/30 text-red-300 text-xs rounded border border-red-500/40" title="Block this IP in Firewall">
                                Block IP
                            </button>
                        ` : ''}
                        <button onclick="killProcess(${c.pid}, '${escapeHtml(c.process_name)}')" class="px-2.5 py-1 bg-red-600 hover:bg-red-500 text-white font-bold text-xs rounded shadow">
                            Kill
                        </button>
                    </div>
                </td>
            </tr>
        `;
    });

    tbody.innerHTML = html;
}

function setNetFilter(f) {
    state.netFilter = f;
    document.querySelectorAll('.net-filter-btn').forEach(btn => {
        if (btn.dataset.netFilter === f) {
            btn.classList.add('bg-cyan-600', 'text-white');
            btn.classList.remove('bg-slate-800', 'text-slate-400');
        } else {
            btn.classList.remove('bg-cyan-600', 'text-white');
            btn.classList.add('bg-slate-800', 'text-slate-400');
        }
    });
    if (state.lastNetworkData) {
        renderNetworkTable(state.lastNetworkData.connections);
    }
}

function filterNetworkTable() {
    const input = document.getElementById('net-search');
    state.netSearchQuery = input ? input.value : '';
    if (state.lastNetworkData) {
        renderNetworkTable(state.lastNetworkData.connections);
    }
}

async function deepTraceIP(ip) {
    if (!ip) return;
    try {
        const res = await fetch('/api/network/trace-ip', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ ip: ip })
        });
        const trace = await res.json();

        const modal = document.getElementById('ip-trace-modal');
        const content = document.getElementById('ip-trace-modal-content');
        if (!modal || !content) return;

        content.innerHTML = `
            <div class="flex items-center justify-between border-b border-slate-800 pb-3">
                <h3 class="text-sm font-bold text-cyan-400 flex items-center gap-2">
                    <i data-lucide="globe" class="w-4 h-4"></i> IP Origin & Threat Intelligence
                </h3>
                <button onclick="document.getElementById('ip-trace-modal').classList.add('hidden')" class="text-slate-400 hover:text-white">✕</button>
            </div>
            <div class="space-y-2 bg-slate-900/80 p-3 rounded-lg border border-slate-800">
                <div><strong class="text-slate-400">Remote IP:</strong> <span class="text-white select-all">${trace.ip}</span></div>
                <div><strong class="text-slate-400">Reverse DNS Hostname:</strong> <span class="text-cyan-300 break-all">${trace.hostname}</span></div>
                <div><strong class="text-slate-400">Organization / ISP:</strong> <span class="text-slate-200">${trace.org}</span></div>
                <div><strong class="text-slate-400">Location:</strong> <span class="text-slate-200">${trace.country}</span></div>
                <div><strong class="text-slate-400">Genuineness Verdict:</strong> <span class="font-bold ${trace.is_genuine ? 'text-emerald-400' : 'text-amber-400'}">${trace.verdict}</span></div>
            </div>
            <div class="pt-3 border-t border-slate-800 flex justify-end gap-2">
                <button onclick="document.getElementById('ip-trace-modal').classList.add('hidden')" class="px-3 py-1.5 bg-slate-800 text-slate-300 rounded">Close</button>
                <button onclick="blockIP('${trace.ip}'); document.getElementById('ip-trace-modal').classList.add('hidden');" class="px-4 py-1.5 bg-red-600 hover:bg-red-500 text-white font-bold rounded">
                    Block IP in Firewall
                </button>
            </div>
        `;

        modal.classList.remove('hidden');
        if (window.lucide) lucide.createIcons();
    } catch (e) {
        showToast('Trace Error', 'Failed to trace remote IP', 'danger');
    }
}

async function blockIP(ip) {
    if (!confirm(`Are you sure you want to ban remote IP ${ip}?\nThis will create an outbound Windows Firewall rule and sever rogue communication.`)) return;

    try {
        const res = await fetch('/api/network/block-ip', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ ip: ip, comment: 'Banned from Network Explorer', apply_firewall: true })
        });
        const data = await res.json();
        if (data.success) {
            showToast('IP Blocked', data.message, 'success');
            loadNetworkTracer();
        } else {
            showToast('Block Failed', data.message, 'danger');
        }
    } catch (e) {
        showToast('Error', 'Unable to block IP', 'danger');
    }
}

// ==============================================================
// Access Control Policy Engine Controller
// ==============================================================

async function loadPolicyRules() {
    try {
        const res = await fetch('/api/policy/rules');
        const rules = await res.json();

        // Render Allowed
        const allowedContainer = document.getElementById('policy-list-allowed');
        const countAllowed = document.getElementById('policy-count-allowed');
        const allowedList = rules.allowed_processes || [];
        if (countAllowed) countAllowed.textContent = `${allowedList.length} rules`;
        if (allowedContainer) {
            allowedContainer.innerHTML = allowedList.map(r => `
                <div class="p-2.5 bg-slate-900/60 rounded border border-slate-800 flex items-center justify-between text-xs">
                    <div>
                        <div class="font-bold text-emerald-400 font-mono">${escapeHtml(r.value)}</div>
                        <div class="text-[10px] text-slate-500">${escapeHtml(r.comment || 'Whitelisted')}</div>
                    </div>
                    <button onclick="deletePolicyRule('${r.id}')" class="text-red-400 hover:text-red-300 text-xs px-2 py-1">✕</button>
                </div>
            `).join('') || '<div class="text-xs text-slate-500 p-2">No whitelist rules added.</div>';
        }

        // Render Blocked Processes
        const blockedContainer = document.getElementById('policy-list-blocked');
        const countBlocked = document.getElementById('policy-count-blocked');
        const blockedList = rules.blocked_processes || [];
        if (countBlocked) countBlocked.textContent = `${blockedList.length} rules`;
        if (blockedContainer) {
            blockedContainer.innerHTML = blockedList.map(r => `
                <div class="p-2.5 bg-slate-900/60 rounded border border-slate-800 flex items-center justify-between text-xs">
                    <div>
                        <div class="font-bold text-red-400 font-mono">${escapeHtml(r.value)}</div>
                        <div class="text-[10px] text-slate-500">${escapeHtml(r.comment || 'Blacklisted')}</div>
                    </div>
                    <button onclick="deletePolicyRule('${r.id}')" class="text-red-400 hover:text-red-300 text-xs px-2 py-1">✕</button>
                </div>
            `).join('') || '<div class="text-xs text-slate-500 p-2">No blacklist rules added.</div>';
        }

        // Render Blocked IPs
        const ipsContainer = document.getElementById('policy-list-ips');
        const countIps = document.getElementById('policy-count-ips');
        const ipsList = rules.blocked_ips || [];
        if (countIps) countIps.textContent = `${ipsList.length} rules`;
        if (ipsContainer) {
            ipsContainer.innerHTML = ipsList.map(r => `
                <div class="p-2.5 bg-slate-900/60 rounded border border-slate-800 flex items-center justify-between text-xs">
                    <div>
                        <div class="font-bold text-amber-400 font-mono">${escapeHtml(r.value)}</div>
                        <div class="text-[10px] text-slate-500">${escapeHtml(r.comment || 'Banned IP')}</div>
                    </div>
                    <button onclick="deletePolicyRule('${r.id}')" class="text-red-400 hover:text-red-300 text-xs px-2 py-1">✕</button>
                </div>
            `).join('') || '<div class="text-xs text-slate-500 p-2">No IP bans configured.</div>';
        }

    } catch (e) {
        showToast('Error', 'Unable to load policy rules', 'danger');
    }
}

async function deletePolicyRule(ruleId) {
    if (!confirm('Remove this security rule?')) return;
    try {
        const res = await fetch(`/api/policy/rule/${ruleId}`, { method: 'DELETE' });
        const data = await res.json();
        if (data.success) {
            showToast('Rule Removed', data.message, 'success');
            loadPolicyRules();
            runScan(false);
        }
    } catch (e) {
        showToast('Error', 'Failed to remove rule', 'danger');
    }
}

function openAddRuleModal() {
    const modal = document.getElementById('add-rule-modal');
    if (modal) modal.classList.remove('hidden');
}

function closeAddRuleModal() {
    const modal = document.getElementById('add-rule-modal');
    if (modal) modal.classList.add('hidden');
}

async function handleCreateRule(e) {
    e.preventDefault();
    const action = document.getElementById('rule-action').value;
    const type = document.getElementById('rule-type').value;
    const value = document.getElementById('rule-value').value;
    const comment = document.getElementById('rule-comment').value;

    const endpoint = action === 'allow' ? '/api/policy/allow' : '/api/policy/block';
    const ruleType = action === 'block_ip' ? 'ip' : type;

    try {
        const res = await fetch(endpoint, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ type: ruleType, value: value, comment: comment })
        });
        const data = await res.json();
        if (data.success) {
            showToast('Rule Created', data.message, 'success');
            closeAddRuleModal();
            loadPolicyRules();
            runScan(false);
        } else {
            showToast('Failed', data.message, 'danger');
        }
    } catch (err) {
        showToast('Error', 'Failed to create policy rule', 'danger');
    }
}

async function quickAllowProcess(name, exe) {
    if (!confirm(`Whitelist and trust '${name}'?\nThis will suppress all threat alerts and exempt it from termination.`)) return;
    try {
        const res = await fetch('/api/policy/allow', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ type: 'name', value: name, comment: `User Whitelisted (${exe || 'Process'})` })
        });
        const data = await res.json();
        if (data.success) {
            showToast('Whitelisted', `Added '${name}' to allowed software policy.`, 'success');
            runScan(true);
        }
    } catch (e) {
        showToast('Error', 'Failed to allow process', 'danger');
    }
}

async function quickBlockProcess(name, exe) {
    if (!confirm(`Blacklist and ban '${name}'?\nThis will mark it as a Critical threat and ban it by policy.`)) return;
    try {
        const res = await fetch('/api/policy/block', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ type: 'name', value: name, comment: `User Blacklisted (${exe || 'Process'})` })
        });
        const data = await res.json();
        if (data.success) {
            showToast('Blacklisted', `Added '${name}' to blocked software policy.`, 'warning');
            runScan(true);
        }
    } catch (e) {
        showToast('Error', 'Failed to block process', 'danger');
    }
}

// ==============================================================
// Email Dispatch & Settings Controller
// ==============================================================

async function loadEmailConfig() {
    try {
        const res = await fetch('/api/email/config');
        const cfg = await res.json();

        document.getElementById('email-smtp-server').value = cfg.smtp_server || '';
        document.getElementById('email-smtp-port').value = cfg.smtp_port || 587;
        document.getElementById('email-sender').value = cfg.sender_email || '';
        document.getElementById('email-password').value = cfg.sender_password || '';
        document.getElementById('email-recipient').value = cfg.recipient_email || '';
        document.getElementById('email-auto-alert').checked = cfg.auto_email_on_critical || false;
    } catch (e) {
        showToast('Error', 'Unable to load email configuration', 'danger');
    }
}

async function handleSaveEmailConfig(e) {
    e.preventDefault();
    const payload = {
        smtp_server: document.getElementById('email-smtp-server').value,
        smtp_port: parseInt(document.getElementById('email-smtp-port').value, 10),
        use_tls: true,
        sender_email: document.getElementById('email-sender').value,
        sender_password: document.getElementById('email-password').value,
        recipient_email: document.getElementById('email-recipient').value,
        auto_email_on_critical: document.getElementById('email-auto-alert').checked
    };

    try {
        const res = await fetch('/api/email/config', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });
        const data = await res.json();
        if (data.success) {
            showToast('Settings Saved', data.message, 'success');
        } else {
            showToast('Failed', data.message, 'danger');
        }
    } catch (err) {
        showToast('Error', 'Failed to save email settings', 'danger');
    }
}

async function sendTestEmail() {
    showToast('Sending...', 'Dispatching SMTP test verification...', 'info');
    try {
        const res = await fetch('/api/email/send-test', { method: 'POST' });
        const data = await res.json();
        if (data.success) {
            showToast('Test Email Sent', data.message, 'success');
        } else {
            showToast('SMTP Test Failed', data.message, 'danger');
        }
    } catch (e) {
        showToast('Error', 'SMTP dispatch failed', 'danger');
    }
}

async function sendFullReport() {
    showToast('Compiling...', 'Generating HTML security report and sending...', 'info');
    try {
        const res = await fetch('/api/email/send-report', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({})
        });
        const data = await res.json();
        if (data.success) {
            showToast('Report Dispatched', data.message, 'success');
        } else {
            showToast('Dispatch Failed', data.message, 'danger');
        }
    } catch (e) {
        showToast('Error', 'Failed to send security report', 'danger');
    }
}

function openEmailModal() {
    switchTab('email');
}

// ==============================================================
// Process Killer & Eradication Controls
// ==============================================================

// Elevated Admin Eradication State
let elevatedTarget = { pid: null, name: null, service: null };

function showElevatedKillModal(pid, name, message, serviceName, adminCmd) {
    elevatedTarget = { pid, name, service: serviceName };
    const modal = document.getElementById('elevated-kill-modal');
    const pidEl = document.getElementById('elev-modal-pid');
    const nameEl = document.getElementById('elev-modal-name');
    const msgEl = document.getElementById('elev-modal-message');
    const cmdEl = document.getElementById('elev-modal-command');
    const svcContainer = document.getElementById('elev-modal-service-container');
    const svcNameEl = document.getElementById('elev-modal-service-name');
    const btnStopSvc = document.getElementById('btn-elev-stop-service');

    if (pidEl) pidEl.textContent = pid;
    if (nameEl) nameEl.textContent = name || 'Process';
    if (msgEl) msgEl.textContent = message || `Target process PID ${pid} is protected by Windows SYSTEM or Administrator rights.`;
    if (cmdEl) cmdEl.value = adminCmd || `taskkill /F /PID ${pid}`;

    if (serviceName) {
        if (svcContainer) svcContainer.classList.remove('hidden');
        if (svcNameEl) svcNameEl.textContent = serviceName;
        if (btnStopSvc) btnStopSvc.classList.remove('hidden');
    } else {
        if (svcContainer) svcContainer.classList.add('hidden');
        if (btnStopSvc) btnStopSvc.classList.add('hidden');
    }

    if (modal) modal.classList.remove('hidden');
    if (window.lucide) lucide.createIcons();
}

function closeElevatedKillModal() {
    const modal = document.getElementById('elevated-kill-modal');
    if (modal) modal.classList.add('hidden');
}

async function triggerElevatedUACKill() {
    if (!elevatedTarget.pid) return;
    const { pid, name } = elevatedTarget;
    closeElevatedKillModal();
    await elevateKillProcess(pid, name);
}

async function stopElevatedService() {
    if (!elevatedTarget.service) return;
    try {
        showToast('Stopping Service', `Sending stop signal to Windows Service '${elevatedTarget.service}'...`, 'info');
        const res = await fetch(`/api/admin/stop-service/${encodeURIComponent(elevatedTarget.service)}`, { method: 'POST' });
        const data = await res.json();
        if (data.success) {
            showToast('Service Stopped', `Successfully stopped Windows Service '${elevatedTarget.service}'.`, 'success');
            closeElevatedKillModal();
            runScan(true);
        } else {
            showToast('Service Stop Notice', data.output || 'Unable to stop service.', 'warning');
        }
    } catch (e) {
        showToast('Error', 'Failed to communicate with service manager', 'danger');
    }
}

function copyElevatedCommand() {
    const cmdEl = document.getElementById('elev-modal-command');
    if (cmdEl) {
        cmdEl.select();
        navigator.clipboard.writeText(cmdEl.value);
        showToast('Command Copied', `Copied to clipboard: ${cmdEl.value}`, 'success');
    }
}

async function restartAsAdminPrompt() {
    if (!confirm("Would you like to relaunch AegisShield with Full Administrator Privileges?\n\nThis will trigger the Windows UAC confirmation dialog and allow terminating protected Windows system PIDs.")) return;
    try {
        const res = await fetch('/api/admin/restart-as-admin', { method: 'POST' });
        const data = await res.json();
        showToast('Elevation Triggered', data.message || 'Please accept the Windows UAC dialog on your screen.', 'info');
    } catch (e) {
        showToast('Error', 'Unable to invoke elevated restart.', 'danger');
    }
}

async function killProcess(pid, name) {
    if (!confirm(`Are you sure you want to terminate process '${name}' (PID: ${pid})?`)) return;

    try {
        const res = await fetch('/api/kill', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ pid: pid, force: true, reason: 'Dashboard User Termination' })
        });
        const data = await res.json();
        if (data.success) {
            CyberAudio.playChime('kill');
            showToast('Process Terminated', data.message, 'success');
            runScan(false);
            if (state.activeTab === 'network') loadNetworkTracer();
        } else {
            if (data.requires_admin || (data.message && data.message.includes('Access denied'))) {
                showElevatedKillModal(pid, name, data.message, data.service_name, data.admin_command);
                return;
            }
            showToast('Kill Failed', data.message, 'danger');
        }
    } catch (e) {
        showToast('Error', 'Failed to communicate with eradication engine', 'danger');
    }
}

async function elevateKillProcess(pid, name) {
    try {
        showToast('Requesting Admin Elevation', `Prompting Windows UAC dialog for PID ${pid}...`, 'info');
        const res = await fetch(`/api/admin/elevate-kill/${pid}`, { method: 'POST' });
        const data = await res.json();
        if (data.success) {
            CyberAudio.playChime('kill');
            showToast('Process Eradicated', `Successfully terminated PID ${pid} via Administrator UAC.`, 'success');
            runScan(true);
        } else {
            showToast('Elevation Triggered', data.message || 'Please approve the Windows UAC security dialog on screen.', 'warning');
            setTimeout(() => runScan(true), 2500);
        }
    } catch (e) {
        showToast('Elevation Error', 'Unable to invoke UAC prompt', 'danger');
    }
}

async function killTree(pid, name) {
    if (!confirm(`Eradicate process tree for '${name}' (PID: ${pid}) and all spawned sub-processes?`)) return;

    try {
        const res = await fetch('/api/kill-tree', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ pid: pid, reason: 'Tree Eradication' })
        });
        const data = await res.json();
        if (data.success) {
            CyberAudio.playChime('kill');
            showToast('Process Tree Eradicated', data.message, 'success');
            runScan(false);
            if (state.activeTab === 'network') loadNetworkTracer();
        } else {
            showToast('Tree Kill Failed', data.message, 'danger');
            if (data.requires_admin || (data.message && (data.message.includes('Access denied') || data.message.includes('rights required')))) {
                showElevatedKillModal(pid, name, data.service_name, data.message);
            }
        }
    } catch (e) {
        showToast('Error', 'Communication error', 'danger');
    }
}

async function emergencyKillAll() {
    if (!state.lastScanData || state.lastScanData.total_threats === 0) {
        showToast('No Threats Detected', 'There are no active threats requiring bulk eradication.', 'info');
        return;
    }

    const threatCount = state.lastScanData.total_threats;
    const confirmed = confirm(`EMERGENCY REMEDIATION:\n\nAre you sure you want to instantly terminate all ${threatCount} detected threat processes? Protected Windows system processes will be safely preserved.`);
    if (!confirmed) return;

    try {
        const res = await fetch('/api/kill-all-threats', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ min_score: 40 })
        });
        const data = await res.json();
        if (data.success) {
            CyberAudio.playChime('kill');
            showToast('Bulk Eradication Complete', data.message, 'success');
            runScan(true);
            if (state.activeTab === 'network') loadNetworkTracer();
        } else {
            showToast('Bulk Action Failed', data.message, 'danger');
        }
    } catch (e) {
        showToast('Error', 'Failed to execute bulk kill', 'danger');
    }
}

// Deep Process Inspection Modal
async function inspectProcess(pid) {
    try {
        const res = await fetch(`/api/process/${pid}`);
        if (!res.ok) throw new Error('Process inspection failed');
        const p = await res.json();
        state.selectedProcess = p;

        const modal = document.getElementById('inspect-modal');
        const content = document.getElementById('inspect-modal-content');
        if (!modal || !content) return;

        content.innerHTML = `
            <div class="space-y-4">
                <div class="flex items-center justify-between border-b border-slate-800 pb-3">
                    <div>
                        <h3 class="text-lg font-bold font-mono text-cyan-400">${escapeHtml(p.name)} (PID: ${p.pid})</h3>
                        <div class="text-xs text-slate-400 font-mono">Parent: ${escapeHtml(p.parent_name || 'None')} (PPID: ${p.ppid})</div>
                    </div>
                    <span class="px-3 py-1 rounded text-xs font-mono font-bold ${p.threat_score >= 50 ? 'badge-critical' : 'badge-safe'}">
                        Threat Score: ${p.threat_score}/100
                    </span>
                </div>

                <div class="bg-slate-900/80 p-3 rounded-lg border border-slate-800 space-y-2 text-xs font-mono">
                    <div><strong class="text-slate-400">Path:</strong> <span class="text-slate-200 select-all">${escapeHtml(p.exe || 'N/A')}</span></div>
                    <div><strong class="text-slate-400">Command Line:</strong> <span class="text-slate-300 break-all">${escapeHtml(p.cmdline || 'N/A')}</span></div>
                    <div><strong class="text-slate-400">SHA256:</strong> <span class="text-cyan-400 select-all">${p.pe_info?.hashes?.sha256 || 'N/A'}</span></div>
                    <div><strong class="text-slate-400">MD5:</strong> <span class="text-cyan-400 select-all">${p.pe_info?.hashes?.md5 || 'N/A'}</span></div>
                    <div><strong class="text-slate-400">File Entropy:</strong> <span class="text-amber-400">${p.pe_info?.file_entropy || 'N/A'} ${p.pe_info?.is_packed ? '(High - Packed/Encrypted)' : ''}</span></div>
                    <div><strong class="text-slate-400">Architecture:</strong> <span class="text-slate-300">${p.pe_info?.machine || 'N/A'}</span></div>
                </div>

                ${p.pe_info?.matched_apis?.length ? `
                    <div class="border border-amber-500/30 bg-amber-500/10 p-3 rounded-lg text-xs">
                        <div class="font-bold text-amber-300 font-mono mb-1">Suspicious Imported APIs Detected:</div>
                        <ul class="list-disc list-inside space-y-0.5 text-slate-300 font-mono">
                            ${p.pe_info.matched_apis.map(a => `<li><span class="text-amber-400 font-semibold">${a.api}</span>: ${a.role}</li>`).join('')}
                        </ul>
                    </div>
                ` : ''}

                <div>
                    <h4 class="text-xs font-mono font-bold text-slate-300 mb-2">Network Connections (${p.network?.connections?.length || 0})</h4>
                    <div class="max-h-32 overflow-y-auto space-y-1">
                        ${p.network?.connections?.length ? p.network.connections.map(c => `
                            <div class="text-xs font-mono p-2 bg-slate-900 rounded border border-slate-800 flex justify-between">
                                <span class="text-slate-300">${c.type} ${c.local_addr} -> ${c.remote_addr}</span>
                                <span class="text-cyan-400 font-semibold">${c.status}</span>
                            </div>
                        `).join('') : '<div class="text-xs text-slate-500 font-mono">No active network sockets</div>'}
                    </div>
                </div>

                <div class="pt-4 border-t border-slate-800 flex items-center justify-between">
                    <div class="flex gap-2">
                        <button onclick="quickAllowProcess('${escapeHtml(p.name)}', '${escapeHtml(p.exe)}')" class="px-3 py-1.5 bg-emerald-600/20 text-emerald-300 text-xs font-mono rounded border border-emerald-500/40">
                            Allow (Whitelist)
                        </button>
                        <button onclick="quickBlockProcess('${escapeHtml(p.name)}', '${escapeHtml(p.exe)}')" class="px-3 py-1.5 bg-red-600/20 text-red-300 text-xs font-mono rounded border border-red-500/40">
                            Block (Blacklist)
                        </button>
                    </div>
                    <div class="flex gap-2">
                        <button onclick="closeInspectModal()" class="px-4 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-mono rounded">
                            Close
                        </button>
                        <button onclick="killProcess(${p.pid}, '${escapeHtml(p.name)}'); closeInspectModal();" class="px-4 py-1.5 bg-red-600 hover:bg-red-500 text-white font-bold text-xs font-mono rounded">
                            Terminate Process
                        </button>
                    </div>
                </div>
            </div>
        `;

        modal.classList.remove('hidden');
        if (window.lucide) lucide.createIcons();
    } catch (e) {
        showToast('Error', 'Unable to inspect process details', 'danger');
    }
}

function closeInspectModal() {
    const modal = document.getElementById('inspect-modal');
    if (modal) modal.classList.add('hidden');
}

// Persistence Tab Logic
async function loadPersistence() {
    const tbody = document.getElementById('persistence-table-body');
    if (!tbody) return;

    tbody.innerHTML = `<tr><td colspan="5" class="p-6 text-center text-slate-400 font-mono text-xs">Scanning Windows Startup & Autoruns...</td></tr>`;

    try {
        const res = await fetch('/api/persistence');
        const data = await res.json();

        if (!data.entries || data.entries.length === 0) {
            tbody.innerHTML = `<tr><td colspan="5" class="p-6 text-center text-slate-400 font-mono text-xs">No autorun persistence entries found.</td></tr>`;
            return;
        }

        let html = '';
        data.entries.forEach(item => {
            html += `
                <tr class="border-b border-slate-800/40 hover:bg-slate-800/20">
                    <td class="p-3 font-mono font-semibold text-white text-xs">${escapeHtml(item.name)}</td>
                    <td class="p-3 font-mono text-xs text-cyan-400">${escapeHtml(item.location_type)}</td>
                    <td class="p-3 font-mono text-xs text-slate-400 truncate max-w-sm" title="${escapeHtml(item.target_path)}">${escapeHtml(item.target_path)}</td>
                    <td class="p-3">
                        ${item.is_suspicious ? `
                            <span class="px-2 py-0.5 rounded text-[10px] font-mono font-bold badge-high">SUSPICIOUS</span>
                        ` : `
                            <span class="px-2 py-0.5 rounded text-[10px] font-mono font-bold badge-safe">NORMAL</span>
                        `}
                    </td>
                    <td class="p-3 text-right">
                        <button onclick="disablePersistenceEntry('${item.id}', '${escapeHtml(item.target_path)}', '${item.location_type}')" class="px-2.5 py-1 bg-amber-600/20 hover:bg-amber-600/30 text-amber-300 text-xs font-mono rounded border border-amber-500/40">
                            Disable
                        </button>
                    </td>
                </tr>
            `;
        });

        tbody.innerHTML = html;
    } catch (e) {
        tbody.innerHTML = `<tr><td colspan="5" class="p-6 text-center text-red-400 font-mono text-xs">Failed to load persistence items.</td></tr>`;
    }
}

async function disablePersistenceEntry(id, path, type) {
    if (!confirm(`Disable persistence item?\nLocation: ${type}\nTarget: ${path}`)) return;

    try {
        const res = await fetch('/api/persistence/disable', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ id: id, target_path: path, location_type: type })
        });
        const data = await res.json();
        if (data.success) {
            showToast('Persistence Disabled', data.message, 'success');
            loadPersistence();
        } else {
            showToast('Failed', data.message, 'danger');
        }
    } catch (e) {
        showToast('Error', 'Unable to disable persistence', 'danger');
    }
}

// Threat Simulation Lab
async function spawnTestSimulation(type) {
    try {
        const res = await fetch('/api/simulator/spawn', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ type: type })
        });
        const data = await res.json();
        if (data.success) {
            showToast('Simulated Threat Spawned', `Spawned test process (PID: ${data.pid}). Running scan...`, 'warning');
            setTimeout(() => runScan(true), 1000);
        } else {
            showToast('Simulation Error', data.message, 'danger');
        }
    } catch (e) {
        showToast('Error', 'Could not start simulation', 'danger');
    }
}

async function cleanupSimulations() {
    try {
        const res = await fetch('/api/simulator/cleanup', { method: 'POST' });
        const data = await res.json();
        showToast('Cleanup Complete', data.message, 'success');
        runScan(false);
    } catch (e) {
        showToast('Error', 'Failed to clean simulations', 'danger');
    }
}

// Audit Log Viewer
async function loadAuditLog() {
    const container = document.getElementById('audit-log-container');
    if (!container) return;

    try {
        const res = await fetch('/api/audit-log');
        const logs = await res.json();

        if (!logs || logs.length === 0) {
            container.innerHTML = `<div class="p-8 text-center text-slate-500 font-mono text-xs">No audit events recorded yet.</div>`;
            return;
        }

        let html = '';
        logs.forEach(evt => {
            const statusColor = evt.status === 'SUCCESS' ? 'text-emerald-400' : (evt.status === 'BLOCKED' ? 'text-amber-400' : 'text-red-400');
            html += `
                <div class="p-3 bg-slate-900/60 rounded border border-slate-800 font-mono text-xs flex items-start justify-between">
                    <div>
                        <div class="flex items-center gap-2">
                            <span class="text-slate-500">${evt.time_display}</span>
                            <span class="font-bold text-cyan-400">${escapeHtml(evt.action)}</span>
                            <span class="text-white">${escapeHtml(evt.target)}</span>
                            ${evt.pid ? `<span class="text-slate-400">(PID: ${evt.pid})</span>` : ''}
                        </div>
                        <div class="text-slate-400 mt-1">${escapeHtml(evt.details)}</div>
                    </div>
                    <span class="font-bold ${statusColor}">${evt.status}</span>
                </div>
            `;
        });

        container.innerHTML = html;
    } catch (e) {
        container.innerHTML = `<div class="p-6 text-center text-red-400 font-mono text-xs">Error loading audit log.</div>`;
    }
}

function exportAuditLog() {
    fetch('/api/audit-log')
        .then(r => r.json())
        .then(data => {
            const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `AegisShield_Audit_Report_${new Date().toISOString().replace(/[:.]/g, '-')}.json`;
            a.click();
            URL.revokeObjectURL(url);
        });
}

// Utility Helpers
function escapeHtml(str) {
    if (!str) return '';
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
}

function setSearchQuery(val) {
    state.searchQuery = val;
    if (state.lastScanData) {
        renderProcessTable(state.lastScanData.processes);
    }
}

function setProcessFilter(filter) {
    state.processFilter = filter;
    document.querySelectorAll('.proc-filter-btn').forEach(btn => {
        if (btn.dataset.filter === filter) {
            btn.classList.add('bg-cyan-600', 'text-white');
            btn.classList.remove('bg-slate-800', 'text-slate-400');
        } else {
            btn.classList.remove('bg-cyan-600', 'text-white');
            btn.classList.add('bg-slate-800', 'text-slate-400');
        }
    });
    if (state.lastScanData) {
        renderProcessTable(state.lastScanData.processes);
    }
}

function toggleAutoRefresh() {
    state.autoRefresh = !state.autoRefresh;
    const btn = document.getElementById('btn-auto-refresh');
    if (btn) {
        btn.innerHTML = state.autoRefresh ? 
            `<i data-lucide="refresh-cw" class="w-4 h-4 text-emerald-400 animate-spin"></i> Auto-Refresh: ON` : 
            `<i data-lucide="pause" class="w-4 h-4 text-slate-400"></i> Auto-Refresh: PAUSED`;
        if (window.lucide) lucide.createIcons();
    }
}

// ==============================================================
// AdBlocker & Web Traffic Analytics Controller
// ==============================================================

async function loadAdBlockDashboard() {
    try {
        const [statusRes, analyticsRes, trafficRes] = await Promise.all([
            fetch('/api/adblock/status'),
            fetch('/api/adblock/analytics'),
            fetch('/api/adblock/traffic')
        ]);

        const status = await statusRes.json();
        const analytics = await analyticsRes.json();
        const traffic = await trafficRes.json();

        state.lastAdblockData = traffic;
        state.systemProxyEnabled = status.system_proxy_enabled;

        // Update Proxy Status Header
        const pill = document.getElementById('adblock-proxy-pill');
        const proxyBtn = document.getElementById('btn-toggle-system-proxy');
        const proxyBtnText = document.getElementById('proxy-btn-text');

        if (pill) {
            pill.className = status.system_proxy_enabled ? 
                'px-2.5 py-0.5 rounded-full text-[10px] font-mono font-bold bg-emerald-500/20 text-emerald-400 border border-emerald-500/40 flex items-center gap-1.5' : 
                'px-2.5 py-0.5 rounded-full text-[10px] font-mono font-bold bg-slate-800 text-slate-400 border border-slate-700';
            pill.innerHTML = status.system_proxy_enabled ? 
                '<span class="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse"></span> Proxy: Active (All Browsers Protected)' : 
                'Proxy: Port 8080 Active (Direct Connection)';
        }

        if (proxyBtn && proxyBtnText) {
            if (status.system_proxy_enabled) {
                proxyBtn.className = 'px-4 py-2 rounded-lg bg-red-600 hover:bg-red-500 text-white font-bold flex items-center gap-2 shadow-lg shadow-red-900/30 transition';
                proxyBtnText.textContent = 'Disable System Proxy';
            } else {
                proxyBtn.className = 'px-4 py-2 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-black font-bold flex items-center gap-2 shadow-lg shadow-emerald-600/20 transition';
                proxyBtnText.textContent = 'Enable System Proxy';
            }
        }

        // Update Metric Counters
        document.getElementById('adblock-stat-total').textContent = status.total_requests;
        document.getElementById('adblock-stat-blocked').textContent = status.total_blocked;
        document.getElementById('adblock-stat-rate').textContent = `${status.block_rate_percent}%`;
        document.getElementById('adblock-stat-saved').textContent = `${status.estimated_mb_saved} MB`;

        // Render Visual Analytics
        renderWebAnalytics(analytics);

        // Render Live Browsing Feed
        renderTrafficTable(traffic);

        if (window.lucide) lucide.createIcons();
    } catch (e) {
        showToast('Error', 'Unable to load AdBlocker dashboard', 'danger');
    }
}

async function toggleSystemProxy() {
    const nextState = !state.systemProxyEnabled;
    try {
        const res = await fetch('/api/adblock/toggle-proxy', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ enable: nextState })
        });
        const data = await res.json();
        if (data.success) {
            state.systemProxyEnabled = nextState;
            showToast(nextState ? 'System Proxy Active' : 'System Proxy Disabled', data.message, nextState ? 'success' : 'info');
            loadAdBlockDashboard();
        } else {
            showToast('Proxy Error', data.message, 'danger');
        }
    } catch (e) {
        showToast('Error', 'Failed to toggle proxy settings', 'danger');
    }
}

function renderWebAnalytics(analytics) {
    // 1. Top Visited Domains
    const visitedContainer = document.getElementById('adblock-top-visited');
    if (visitedContainer) {
        if (!analytics.top_visited_domains || analytics.top_visited_domains.length === 0) {
            visitedContainer.innerHTML = `<div class="text-slate-500 text-[11px] p-2">No clean websites browsed yet.</div>`;
        } else {
            const maxCount = Math.max(...analytics.top_visited_domains.map(d => d.count), 1);
            visitedContainer.innerHTML = analytics.top_visited_domains.map(d => {
                const pct = Math.round((d.count / maxCount) * 100);
                return `
                    <div class="space-y-1">
                        <div class="flex justify-between text-xs">
                            <span class="text-slate-200 font-mono font-medium truncate max-w-[180px]">${escapeHtml(d.domain)}</span>
                            <span class="text-cyan-400 font-bold">${d.count} visits</span>
                        </div>
                        <div class="w-full bg-slate-800 h-1 rounded-full overflow-hidden">
                            <div class="bg-cyan-500 h-full" style="width: ${pct}%"></div>
                        </div>
                    </div>
                `;
            }).join('');
        }
    }

    // 2. Top Blocked Ad Networks
    const blockedContainer = document.getElementById('adblock-top-blocked');
    if (blockedContainer) {
        if (!analytics.top_blocked_domains || analytics.top_blocked_domains.length === 0) {
            blockedContainer.innerHTML = `<div class="text-slate-500 text-[11px] p-2">No ad or tracker blocks recorded yet.</div>`;
        } else {
            const maxBad = Math.max(...analytics.top_blocked_domains.map(d => d.count), 1);
            blockedContainer.innerHTML = analytics.top_blocked_domains.map(d => {
                const pct = Math.round((d.count / maxBad) * 100);
                return `
                    <div class="space-y-1">
                        <div class="flex justify-between text-xs">
                            <span class="text-rose-300 font-mono font-medium truncate max-w-[180px]">${escapeHtml(d.domain)}</span>
                            <span class="text-rose-400 font-bold">${d.count} blocked</span>
                        </div>
                        <div class="w-full bg-slate-800 h-1 rounded-full overflow-hidden">
                            <div class="bg-rose-500 h-full" style="width: ${pct}%"></div>
                        </div>
                    </div>
                `;
            }).join('');
        }
    }

    // 3. Category Breakdown
    const catContainer = document.getElementById('adblock-categories');
    if (catContainer) {
        if (!analytics.category_breakdown || analytics.category_breakdown.length === 0) {
            catContainer.innerHTML = `<div class="text-slate-500 text-[11px] p-2">Awaiting browsing telemetry.</div>`;
        } else {
            catContainer.innerHTML = analytics.category_breakdown.map(c => `
                <div class="p-2 bg-slate-900/60 rounded border border-slate-800 flex items-center justify-between">
                    <span class="text-slate-300 text-xs">${escapeHtml(c.category)}</span>
                    <span class="text-amber-400 font-bold text-xs">${c.count}</span>
                </div>
            `).join('');
        }
    }
}

function renderTrafficTable(traffic) {
    const tbody = document.getElementById('traffic-table-body');
    if (!tbody) return;

    let filtered = traffic || [];

    if (state.adblockFilter === 'blocked') {
        filtered = filtered.filter(r => r.is_blocked);
    } else if (state.adblockFilter === 'allowed') {
        filtered = filtered.filter(r => !r.is_blocked);
    }

    if (state.adblockSearchQuery.trim()) {
        const q = state.adblockSearchQuery.toLowerCase();
        filtered = filtered.filter(r =>
            r.domain.toLowerCase().includes(q) ||
            r.category.toLowerCase().includes(q) ||
            r.date_time.toLowerCase().includes(q)
        );
    }

    if (filtered.length === 0) {
        tbody.innerHTML = `<tr><td colspan="6" class="p-8 text-center text-slate-400 text-sm">No recorded browsing requests match the selected filter.</td></tr>`;
        return;
    }

    tbody.innerHTML = filtered.slice(0, 150).map(r => {
        const statusBadge = r.is_blocked ? 
            '<span class="px-2 py-0.5 rounded text-[10px] font-mono font-bold badge-critical">BLOCKED</span>' : 
            '<span class="px-2 py-0.5 rounded text-[10px] font-mono font-bold badge-safe">ALLOWED</span>';

        return `
            <tr class="border-b border-slate-800/40 hover:bg-slate-800/30 transition">
                <td class="p-3 font-mono text-xs text-slate-400">${escapeHtml(r.date_time)}</td>
                <td class="p-3">
                    <div class="font-mono font-semibold text-white text-xs ${r.is_blocked ? 'text-rose-300' : 'text-slate-200'}">
                        ${escapeHtml(r.domain)}
                    </div>
                    <div class="text-[10px] text-slate-500 truncate max-w-sm" title="${escapeHtml(r.reason)}">${escapeHtml(r.reason)}</div>
                </td>
                <td class="p-3 font-mono text-xs text-cyan-400">${escapeHtml(r.method)}:${r.port}</td>
                <td class="p-3 font-mono text-xs text-slate-300">${escapeHtml(r.category)}</td>
                <td class="p-3">${statusBadge}</td>
                <td class="p-3 text-right">
                    ${r.is_blocked ? `
                        <button onclick="quickAllowProcess('${escapeHtml(r.domain)}', 'Domain Whitelist')" class="px-2 py-1 bg-emerald-600/20 hover:bg-emerald-600/30 text-emerald-300 text-[11px] rounded border border-emerald-500/30">
                            Allow Domain
                        </button>
                    ` : `
                        <button onclick="quickBlockProcess('${escapeHtml(r.domain)}', 'Domain Blocklist')" class="px-2 py-1 bg-red-600/20 hover:bg-red-600/30 text-red-300 text-[11px] rounded border border-red-500/30">
                            Block Domain
                        </button>
                    `}
                </td>
            </tr>
        `;
    }).join('');
}

function setTrafficFilter(f) {
    state.adblockFilter = f;
    document.querySelectorAll('.traffic-filter-btn').forEach(btn => {
        if (btn.dataset.trafficFilter === f) {
            btn.classList.add('bg-rose-600', 'text-white');
            btn.classList.remove('bg-slate-800', 'text-slate-400');
        } else {
            btn.classList.remove('bg-rose-600', 'text-white');
            btn.classList.add('bg-slate-800', 'text-slate-400');
        }
    });
    if (state.lastAdblockData) {
        renderTrafficTable(state.lastAdblockData);
    }
}

function filterTrafficTable() {
    const input = document.getElementById('traffic-search');
    state.adblockSearchQuery = input ? input.value : '';
    if (state.lastAdblockData) {
        renderTrafficTable(state.lastAdblockData);
    }
}

async function clearWebTrafficLogs() {
    if (!confirm('Clear all logged web browsing history and analytics?')) return;
    try {
        const res = await fetch('/api/adblock/clear-logs', { method: 'POST' });
        const data = await res.json();
        if (data.success) {
            showToast('Logs Cleared', data.message, 'success');
            loadAdBlockDashboard();
        }
    } catch (e) {
        showToast('Error', 'Unable to clear traffic logs', 'danger');
    }
}

// ==============================================================
// Theme Toggle (Dark Cyber Mode / Light Clean Mode)
// ==============================================================

function initTheme() {
    const savedTheme = localStorage.getItem('aegis_theme') || 'light';
    setTheme(savedTheme, false);
}

function toggleTheme() {
    const currentTheme = document.body.classList.contains('theme-light') ? 'light' : 'dark';
    const newTheme = currentTheme === 'dark' ? 'light' : 'dark';
    setTheme(newTheme, true);
}

function setTheme(theme, notify = true) {
    const btn = document.getElementById('btn-theme-toggle');
    const label = document.getElementById('theme-toggle-label');
    const icon = document.getElementById('theme-toggle-icon');

    if (theme === 'light') {
        document.body.classList.add('theme-light');
        document.documentElement.classList.add('theme-light');
        if (label) label.innerText = 'Dark Mode';
        if (icon) icon.setAttribute('data-lucide', 'moon');
        localStorage.setItem('aegis_theme', 'light');
        if (notify) showToast('Light Mode Activated', 'Clean daylight SOC interface applied', 'info');
    } else {
        document.body.classList.remove('theme-light');
        document.documentElement.classList.remove('theme-light');
        if (label) label.innerText = 'Light Mode';
        if (icon) icon.setAttribute('data-lucide', 'sun');
        localStorage.setItem('aegis_theme', 'dark');
        if (notify) showToast('Dark Mode Activated', 'Dark cyber SOC theme restored', 'info');
    }
    if (window.lucide) lucide.createIcons();
}

// ==============================================================
// Sound Controls (Notification Sounds Removed / Silent by Default)
// ==============================================================

function initSound() {
    const savedSound = localStorage.getItem('aegis_sound');
    state.soundEnabled = savedSound === 'true' ? true : false; // Default is strictly false (SILENT)
    updateSoundUI(state.soundEnabled, false);
}

function toggleSound() {
    state.soundEnabled = !state.soundEnabled;
    localStorage.setItem('aegis_sound', state.soundEnabled ? 'true' : 'false');
    updateSoundUI(state.soundEnabled, true);
}

function updateSoundUI(enabled, notify = false) {
    const btn = document.getElementById('btn-sound-toggle');
    const label = document.getElementById('sound-toggle-label');
    const icon = document.getElementById('sound-toggle-icon');

    if (!enabled) {
        if (label) label.innerText = 'Silent';
        if (icon) icon.setAttribute('data-lucide', 'volume-x');
        if (btn) btn.className = 'px-2.5 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-xs font-mono text-slate-400 border border-slate-700 flex items-center gap-1.5 transition shadow-sm';
        if (notify) showToast('Sound Muted', 'Notification sounds are disabled (Silent Mode)', 'info');
    } else {
        if (label) label.innerText = 'Sound ON';
        if (icon) icon.setAttribute('data-lucide', 'volume-2');
        if (btn) btn.className = 'px-2.5 py-1.5 rounded-lg bg-cyan-950/40 hover:bg-cyan-900/60 text-xs font-mono text-cyan-300 border border-cyan-500/40 flex items-center gap-1.5 transition shadow-sm';
        if (notify) showToast('Sound Enabled', 'Notification audio alerts enabled', 'info');
    }
    if (window.lucide) lucide.createIcons();
}

// ==============================================================
// Private Stealth Mode Controls
// ==============================================================

async function checkPrivacyStatus() {
    try {
        const res = await fetch('/api/privacy/status');
        const data = await res.json();
        state.privateMode = data.private_mode;
        updatePrivacyUI(state.privateMode);
    } catch (e) {
        console.warn('Failed to fetch privacy status:', e);
    }
}

function updatePrivacyUI(isPrivate) {
    state.privateMode = isPrivate;
    const headerBtn = document.getElementById('btn-private-mode');
    const headerLabel = document.getElementById('private-mode-label');
    const tabLabel = document.getElementById('tab-private-label');
    const tabBtn = document.getElementById('btn-tab-private-mode');
    const banner = document.getElementById('private-mode-banner');

    if (isPrivate) {
        if (headerLabel) headerLabel.innerText = 'Private Mode: ON';
        if (tabLabel) tabLabel.innerText = 'Private Mode: ON';
        if (headerBtn) {
            headerBtn.classList.add('bg-purple-600', 'text-white', 'border-purple-400');
            headerBtn.classList.remove('bg-slate-800', 'text-purple-300');
        }
        if (tabBtn) {
            tabBtn.classList.add('bg-purple-600', 'text-white');
            tabBtn.classList.remove('bg-purple-950/80', 'text-purple-200');
        }
        if (banner) banner.classList.remove('hidden');
    } else {
        if (headerLabel) headerLabel.innerText = 'Private Mode: OFF';
        if (tabLabel) tabLabel.innerText = 'Private Mode: OFF';
        if (headerBtn) {
            headerBtn.classList.remove('bg-purple-600', 'text-white', 'border-purple-400');
            headerBtn.classList.add('bg-slate-800', 'text-purple-300');
        }
        if (tabBtn) {
            tabBtn.classList.remove('bg-purple-600', 'text-white');
            tabBtn.classList.add('bg-purple-950/80', 'text-purple-200');
        }
        if (banner) banner.classList.add('hidden');
    }
}

async function togglePrivateMode() {
    const nextState = !state.privateMode;
    try {
        const res = await fetch('/api/privacy/toggle', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ enable: nextState })
        });
        const data = await res.json();
        if (data.success) {
            state.privateMode = data.private_mode;
            updatePrivacyUI(state.privateMode);
            CyberAudio.playChime(nextState ? 'kill' : 'threat');
            showToast(
                nextState ? 'Private Mode Active' : 'Private Mode Disabled',
                nextState ? 'Zero disk logging & volatile buffers activated' : 'Standard logging restored',
                nextState ? 'success' : 'info'
            );
        }
    } catch (e) {
        showToast('Error', 'Failed to toggle Private Mode', 'danger');
    }
}

async function panicWipe() {
    if (!confirm('Execute Stealth Panic Wipe? This will immediately purge all web browsing logs, volatile memory buffers, and DNS caches.')) return;
    try {
        const res = await fetch('/api/privacy/panic-wipe', { method: 'POST' });
        const data = await res.json();
        if (data.success) {
            CyberAudio.playChime('kill');
            showToast('Stealth Panic Wipe', data.message, 'success');
            loadAdBlockDashboard();
        }
    } catch (e) {
        showToast('Error', 'Panic wipe failed', 'danger');
    }
}
