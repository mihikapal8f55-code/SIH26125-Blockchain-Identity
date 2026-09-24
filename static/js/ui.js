// ==================================================================
// SIH26125 — UI SHELL  (utilities + app shell: activity, theme,
// sidebar navigation, guided tour, topbar status)
// ==================================================================

/* ---------- Core utilities (lifted from the old inline template) ---------- */

function showAlert(message, type = 'success', timeout = 4000) {
    const container = document.getElementById('alertContainer');
    const alert = document.createElement('div');
    alert.className = `alert alert-${type} show`;
    alert.innerHTML = message;
    alert.setAttribute('role', type === 'error' ? 'alert' : 'status');
    container.appendChild(alert);

    setTimeout(() => {
        alert.style.opacity = '0';
        alert.style.transition = 'opacity 0.5s';
        setTimeout(() => alert.remove(), 500);
    }, timeout);

    if (type === 'error') {
        const label = message.replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ').trim().slice(0, 90);
        ACTIVITY.add('Error', label || 'Unknown error', 'error');
    }
}

function copyToClipboard(text) {
    const done = () => showAlert('<i class="fas fa-copy"></i> Copied to clipboard!', 'info', 2000);
    const fallback = () => {
        try {
            const ta = document.createElement('textarea');
            ta.value = text;
            ta.style.position = 'fixed';
            ta.style.opacity = '0';
            document.body.appendChild(ta);
            ta.focus();
            ta.select();
            const ok = document.execCommand('copy');
            document.body.removeChild(ta);
            ok ? done() : showAlert('Could not copy. Please select the hash manually.', 'error', 3000);
        } catch (e) {
            showAlert('Could not copy. Please select the hash manually.', 'error', 3000);
        }
    };
    if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(text).then(done).catch(fallback);
    } else {
        fallback();
    }
}

// Escape untrusted strings before injecting into innerHTML (XSS guard).
// Used for user-provided identity fields rendered into tables/alerts.
function escapeHtml(value) {
    return String(value == null ? '' : value)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}

async function fetchAPI(url, options = {}) {
    try {
        const response = await fetch(url, options);
        const data = await response.json();
        const ok = !!(data && data.success !== false);
        const verb = options.method && options.method !== 'GET' ? options.method : 'GET';
        ACTIVITY.add(`${verb} ${url}`, ok ? 'OK' : 'failed', ok ? 'info' : 'error');
        return data;
    } catch (error) {
        showAlert(`API Error: ${error.message}`, 'error');
        ACTIVITY.add('API Error', `${url}: ${error.message}`, 'error');
        return { success: false, error: error.message };
    }
}

/* ---------- Live activity log ---------- */

const ACTIVITY = {
    items: [],
    add(action, detail, level = 'info') {
        const t = new Date().toLocaleTimeString('en-GB', { hour12: false });
        this.items.unshift({ t, action, detail, level });
        if (this.items.length > 80) this.items.pop();
        this.render();
    },
    render() {
        const body = document.getElementById('activityBody');
        if (!body) return;
        if (!this.items.length) {
            body.innerHTML = '<div class="empty-state"><i class="fas fa-stream"></i> No activity yet — run a demo and watch the live log here.</div>';
            return;
        }
        body.innerHTML = this.items.map(e => `
            <div class="activity-entry level-${e.level}">
                <div class="activity-time">${e.t}</div>
                <div class="activity-text"><b>${e.action}</b>${e.detail ? ' — ' + e.detail : ''}</div>
            </div>`).join('');
    }
};

function toggleActivity(force) {
    const rail = document.getElementById('activityRail');
    if (!rail) return;
    const open = force !== undefined ? force : !rail.classList.contains('open');
    rail.classList.toggle('open', open);
}

/* ---------- Sidebar / workspace navigation ---------- */

function gotoSection(id, btn) {
    document.querySelectorAll('.workspace').forEach(s => s.classList.toggle('active', s.id === id));
    document.querySelectorAll('.nav-item[data-ws]').forEach(b => b.classList.toggle('active', b.dataset.ws === id));
    const target = document.getElementById(id);
    if (target) {
        window.setTimeout(() => target.scrollIntoView({ behavior: 'smooth', block: 'start' }), 0);
        const title = target.querySelector('.workspace-title');
        ACTIVITY.add('Navigate', title ? title.textContent.trim().replace(/\s+/g, ' ') : id);
    }
    toggleDrawer(false);
}

function toggleDrawer(force) {
    const sb = document.getElementById('sidebar');
    const backdrop = document.getElementById('drawerBackdrop');
    if (!sb) return;
    const open = force !== undefined ? force : !sb.classList.contains('open');
    sb.classList.toggle('open', open);
    if (backdrop && window.innerWidth <= 860) backdrop.classList.toggle('show', open);
}

/* ---------- Sidebar collapse (icon-only rail) ---------- */

function toggleSidebarCollapse(force) {
    const shell = document.querySelector('.app-shell');
    if (!shell) return;
    const collapsed = force !== undefined ? force : !shell.classList.contains('collapsed');
    shell.classList.toggle('collapsed', collapsed);
    const btn = document.querySelector('.sidebar-collapse');
    if (btn) {
        btn.title = collapsed ? 'Expand sidebar' : 'Collapse sidebar';
        btn.setAttribute('aria-label', collapsed ? 'Expand sidebar' : 'Collapse sidebar');
    }
    try { localStorage.setItem('sih-sidebar', collapsed ? 'collapsed' : 'expanded'); } catch (e) { /* ignore */ }
    ACTIVITY.add('Sidebar', collapsed ? 'Collapsed to icon rail' : 'Expanded full sidebar');
}

/* ---------- Theme (light / dark) ---------- */

function applyTheme(theme) {
    document.documentElement.setAttribute('data-theme', theme);
    try { localStorage.setItem('sih-theme', theme); } catch (e) { /* private mode */ }
    const label = document.getElementById('themeToggleLabel');
    const icon = document.querySelector('#themeToggleBtn i');
    const btn = document.getElementById('themeToggleBtn');
    if (label) label.textContent = theme === 'dark' ? 'Light Mode' : 'Dark Mode';
    if (icon) icon.className = theme === 'dark' ? 'fas fa-sun' : 'fas fa-moon';
    if (btn) btn.setAttribute('aria-label', theme === 'dark' ? 'Switch to light mode' : 'Switch to dark mode');
}

function toggleTheme() {
    const next = document.documentElement.getAttribute('data-theme') === 'dark' ? 'light' : 'dark';
    applyTheme(next);
    ACTIVITY.add('Theme', next === 'dark' ? 'Dark mode enabled' : 'Light mode enabled');
}

/* ---------- Topbar status pills ---------- */

async function refreshTopbar() {
    try {
        const info = await fetchAPI('/api/blockchain/info');
        if (info && info.success) {
            const d = info.data || {};
            const blocks = document.getElementById('topBlocks');
            const ids = document.getElementById('topIdentities');
            const chain = document.getElementById('topChainStatus');
            if (blocks) blocks.textContent = `#${d.total_blocks} total blocks`;
            if (ids) ids.textContent = `${d.total_identities} identities`;
            if (chain) {
                const ok = d.chain_valid !== false;
                chain.textContent = ok ? 'Chain VALID' : 'Chain TAMPERED';
                chain.className = 'status-pill ' + (ok ? 'chain-ok' : 'chain-bad');
            }
        }
    } catch (e) { /* defensive — topbar is secondary */ }
    try {
        const net = await fetchAPI('/api/network/status');
        if (net && net.success && Array.isArray(net.nodes)) {
            let online = 0, total = net.nodes.length;
            try {
                const health = await fetchAPI('/api/network/health');
                if (health && health.success && Array.isArray(health.nodes)) {
                    online = health.nodes.filter(n => n.online || n.online === undefined).length;
                } else { online = total; }
            } catch (e2) { online = total; }
            const nodes = document.getElementById('topNodeCount');
            if (nodes) nodes.textContent = `${online}/${total} nodes online`;
        }
    } catch (e) { /* ignore */ }
}

/* ---------- Guided tour ---------- */

const TOUR_STEPS = [
    { ws: 'ws-dashboard', title: 'Dashboard', text: 'Live chain statistics, the tamper-proof block visualization, and network & consensus metrics — a snapshot of the whole system the moment it boots.' },
    { ws: 'ws-identity', title: 'Identity & Registration', text: 'Register identities, mint them into a block with PoW, verify hashes on-chain, and check resource access permissions.' },
    { ws: 'ws-verification', title: 'Verification & Zero-Knowledge', text: 'Passwordless RSA auth, ZK predicates, QR verification, biometric matching, and W3C self-sovereign DIDs with verifiable credentials.' },
    { ws: 'ws-access', title: 'Access Control', text: 'Deterministic smart-contract rules (work-hours + geo-fencing) and full attribute-based access control: Role, Clearance, Geofence and Device hash.' },
    { ws: 'ws-network', title: 'Network & IPFS', text: 'Three-node distributed network with longest-valid-chain consensus, malicious fork rejection, plus IPFS document storage with on-chain CIDs.' },
    { ws: 'ws-assets', title: 'Digital Assets & Storage', text: 'Dynamic lifecycle NFTs driven by signed IoT telemetry, and dual-layer AES-256-GCM + Shamir threshold encrypted storage gated by ZK proofs.' },
    { ws: 'ws-audit', title: 'Audit & Security', text: 'On-chain audit trail, the red-team attack playbook, and full chain export / import for portability.' },
    { ws: 'ws-gseries', title: 'G-Series Security', text: 'The newest green-field controls: break-glass emergency windows, adaptive just-in-time step-up authentication, TOTP second factor (RFC 6238), a global revocation list with ZK status proofs, honeytoken deception traps, physical velocity/teleport detection, k-anonymity export-safe reports, measured-boot device attestation, PII redaction/right-to-erasure, and cross-org federation trust anchors.' }
];

const TOUR = { active: false, i: 0 };

function startTour() {
    if (TOUR.active) return;
    TOUR.active = true;
    TOUR.i = 0;
    const overlay = document.getElementById('tourOverlay');
    overlay.classList.add('open');
    overlay.innerHTML = '<div class="tour-mask"></div><div class="tour-bubble"></div>';
    renderTourStep();
    ACTIVITY.add('Tour', 'Guided tour started');
}

function endTour() {
    TOUR.active = false;
    const overlay = document.getElementById('tourOverlay');
    if (overlay) { overlay.classList.remove('open'); overlay.innerHTML = ''; }
}

function tourStep(i) {
    TOUR.i = Math.max(0, Math.min(TOUR_STEPS.length - 1, i));
    renderTourStep();
}

function renderTourStep() {
    const overlay = document.getElementById('tourOverlay');
    const step = TOUR_STEPS[TOUR.i];
    gotoSection(step.ws, null);

    window.setTimeout(() => {
        const mask = overlay.querySelector('.tour-mask');
        const bubble = overlay.querySelector('.tour-bubble');
        const target = document.getElementById(step.ws);
        if (!mask || !bubble) return;

        // Render the bubble content FIRST so offsetHeight reflects real content
        // when the bubble is positioned below/above the section (ordering bug:
        // the old code measured the height of an empty bubble).
        const stepIcon = step.ws === 'ws-dashboard' ? 'chart-pie'
            : step.ws === 'ws-identity' ? 'users'
            : step.ws === 'ws-verification' ? 'fingerprint'
            : step.ws === 'ws-access' ? 'lock'
            : step.ws === 'ws-network' ? 'network-wired'
            : step.ws === 'ws-assets' ? 'cubes' : 'history';
        bubble.innerHTML = `
            <h4><i class="fas fa-${stepIcon}"></i>
            ${TOUR.i + 1} / ${TOUR_STEPS.length} — ${step.title}</h4>
            <p>${step.text}</p>
            <div class="tour-actions">
                <button class="btn btn-outline btn-small" onclick="endTour()" aria-label="Close tour">Close</button>
                <button class="btn btn-primary btn-small" onclick="tourStep(${TOUR.i + 1})" aria-label="Next tour step" ${TOUR.i >= TOUR_STEPS.length - 1 ? 'hidden' : ''}>
                    Next <i class="fas fa-arrow-right"></i>
                </button>
                <button class="btn btn-success btn-small" onclick="endTour()" aria-label="Finish tour" ${TOUR.i < TOUR_STEPS.length - 1 ? 'hidden' : ''}>
                    <i class="fas fa-check"></i> Done
                </button>
                <span class="spacer"></span>
                <span class="tour-dots" aria-hidden="true">${TOUR_STEPS.map((s, idx) => `<span class="tour-dot ${idx === TOUR.i ? 'on' : ''}"></span>`).join('')}</span>
            </div>`;

        if (target) {
            const r = target.getBoundingClientRect();
            mask.hidden = false;
            mask.style.top = Math.max(8, r.top - 6) + 'px';
            mask.style.left = Math.max(8, r.left - 6) + 'px';
            mask.style.width = Math.min(r.width + 12, window.innerWidth - 16) + 'px';
            mask.style.height = Math.min(r.height + 12, window.innerHeight - 16) + 'px';

            const bw = bubble.offsetWidth || 380;
            const bx = Math.round((window.innerWidth - bw) / 2);
            bubble.style.left = Math.max(4, Math.min(bx, window.innerWidth - bw - 4)) + 'px';
            const above = r.top > 160;
            bubble.style.top = above ? Math.max(10, r.top - bubble.offsetHeight - 16) + 'px'
                                     : Math.min(r.bottom + 16, window.innerHeight - bubble.offsetHeight - 10) + 'px';
        } else {
            mask.hidden = true;
            bubble.style.left = '50%';
            bubble.style.top = '50%';
            bubble.style.transform = 'translate(-50%, -50%)';
        }
    }, 360);
}

/* ---------- Init ---------- */

// Collapse the "How it works" step explainers into a toggle so feature
// cards stay compact and fit the viewport without scrolling.
function collapseStepCards() {
    document.querySelectorAll('.zk-steps').forEach(block => {
        if (block.dataset.collapsed === '1') return;
        block.dataset.collapsed = '1';
        const steps = Array.from(block.children).filter(el => el.classList && el.classList.contains('step'));
        if (!steps.length) return;
        steps.forEach(s => s.remove());
        const body = document.createElement('div');
        body.className = 'zk-steps-body';
        steps.forEach(s => body.appendChild(s));
        const btn = document.createElement('button');
        btn.type = 'button';
        btn.className = 'zk-toggle';
        btn.setAttribute('aria-expanded', 'false');
        btn.innerHTML = `<span><i class="fas fa-play-circle"></i> How it works (${steps.length} ${steps.length === 1 ? 'step' : 'steps'})</span><span class="chev"><i class="fas fa-chevron-down"></i></span>`;
        btn.onclick = () => {
            const open = block.classList.toggle('open');
            btn.setAttribute('aria-expanded', String(open));
        };
        block.appendChild(btn);
        block.appendChild(body);
    });
}

function initShell() {
    let saved = 'light';
    try { saved = localStorage.getItem('sih-theme') || saved; } catch (e) { /* ignore */ }
    if (saved !== 'light' && saved !== 'dark') {
        saved = window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
    }
    applyTheme(saved);

    let sidebarState = 'expanded';
    try { sidebarState = localStorage.getItem('sih-sidebar') || sidebarState; } catch (e) { /* ignore */ }
    if (sidebarState === 'collapsed' && window.innerWidth > 860) toggleSidebarCollapse(true);

    collapseStepCards();

    document.getElementById('activityRail').addEventListener('keydown', e => {
        if (e.key === 'Escape') toggleActivity(false);
    });

    document.addEventListener('keydown', e => {
        if (e.target && /INPUT|TEXTAREA|SELECT/i.test(e.target.tagName)) return;
        const map = { '1': 'ws-dashboard', '2': 'ws-identity', '3': 'ws-verification',
                      '4': 'ws-access', '5': 'ws-network', '6': 'ws-assets', '7': 'ws-audit', '8': 'ws-gseries' };
        if (map[e.key]) gotoSection(map[e.key]);
        if (e.key === 'l' || e.key === 'L') toggleActivity();
        if (e.key === 't' || e.key === 'T') startTour();
        if (e.key === 'Escape' && TOUR.active) endTour();
    });

    refreshTopbar();
    ACTIVITY.add('System online', 'Dashboard ready');
}