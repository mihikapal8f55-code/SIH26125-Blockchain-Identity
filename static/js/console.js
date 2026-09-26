// ==================================================================
// SIH26125 — RESULT CONSOLE (v6)
//
// The previous build had 97 independent result containers, each
// dumping raw HTML into its card. Nothing was comparable, nothing was
// scannable, and 84 cards each grew a wall of text after you pressed
// a button.
//
// This module turns every one of those containers into a single
// structured verdict:
//
//   1. A MutationObserver watches all result containers.
//   2. On change it classifies the outcome (GRANTED / DENIED /
//      BLOCKED / PENDING / INFO) and extracts a one-line summary.
//   3. The card shows a COMPACT verdict chip; the original markup is
//      kept behind a "raw output" disclosure so nothing is lost.
//   4. Every verdict is also pushed to the dock, where runs can be
//      filtered by outcome and exported.
//
// No feature code in app.js had to change.
// ==================================================================

const VERDICT_RULES = [
    // Order matters: the first match wins, so specific words precede generic.
    { v: 'denied',  kw: ['ACCESS DENIED', 'DENIED', 'REFUSED', 'FORBIDDEN', 'NOT FOUND', 'REJECTED', 'FAILED', 'INVALID', 'EXPIRED', 'NOT YET ACTIVE', 'NOT_YET_ACTIVE', 'REVOKED'] },
    { v: 'blocked', kw: ['BLOCKED', 'TAMPERED', 'TAMPER', 'ATTACK', 'INTEGRITY FAILURE', 'INVALID CHAIN', 'CONTAINED', 'REJECTED BY', 'ALERT RAISED'] },
    { v: 'granted', kw: ['GRANTED', 'ACCESS GRANTED', 'VERIFIED', 'AUTHENTICATED', 'APPROVED', 'VOUCHED', 'VALID', 'AUTHENTICITY CONFIRMED', 'MINTED', 'SEALED'] },
    { v: 'pending', kw: ['PENDING', 'AWAITING', 'IN PROGRESS', 'PROPOSED', 'NOT YET', 'SYNCING', 'RUNNING'] },
];

const ALERT_VERDICT = {
    'alert-success': 'granted',
    'alert-error': 'denied',
    'alert-danger': 'denied',
    'alert-warning': 'pending',
    'alert-info': 'info',
};

const CONSOLE = {
    el: null,
    listEl: null,
    badge: null,
    entries: [],            // newest first
    filter: 'all',
    seq: 0,
    seen: new WeakMap(),    // container -> { doc, raw }
    lastText: new WeakMap(),// container -> last captured summary
    observer: null,
    queue: new Set(),       // containers awaiting capture
    suppress: false,        // true while we are rewriting a container
    MAX: 60,

    /* ---------------------------------------------------------------- */
    init() {
        this.el = document.getElementById('vcPanel');
        this.listEl = document.getElementById('vcList');
        this.badge = document.getElementById('vcBadge');
        if (!this.listEl) return;

        this.wireTabs();
        this.wireFilters();
        this.discover();
        this.render();
    },

    /* Every element the app uses as an output surface. */
    discover() {
        const sel = [
            '[id$="Result"]', '[id$="result"]', '[id$="Output"]', '[id$="output"]',
            '[id$="Stats"]', '[id$="Board"]', '[id$="Detail"]', '[id$="Receipts"]',
            '[id$="List"]', '#identityTable', '#metricsContainer', '#postureGauge',
            '#chainVisualization', '#auditStats', '#threatResult', '#f15propResult',
        ].join(',');

        const targets = Array.from(document.querySelectorAll(sel))
            .filter(el => !el.closest('.vc'));   // never observe the dock itself

        targets.forEach(el => {
            if (el.dataset.vc === '1') return;
            el.dataset.vc = '1';
            // Screen readers now hear the outcome instead of silently mutating.
            if (!el.hasAttribute('role')) el.setAttribute('role', 'status');
            if (!el.hasAttribute('aria-live')) el.setAttribute('aria-live', 'polite');
        });

        this.observer = new MutationObserver(muts => {
            if (this.suppress) return;
            let touched = false;
            muts.forEach(m => {
                const node = m.target.nodeType === 1 ? m.target : m.target.parentElement;
                if (!node) return;
                // Our own chip / disclosure churn is not new output.
                if (node.closest('.vc-compact, .vc-raw')) return;
                const host = node.closest('[data-vc="1"]');
                if (host) { this.queue.add(host); touched = true; }
            });
            if (touched) this.flush();
        });

        targets.forEach(el => this.observer.observe(el, {
            childList: true, subtree: true, characterData: true,
        }));

        // Coming back to the tab is the moment to drain anything the
        // hidden-tab timer could not have flushed.
        document.addEventListener('visibilitychange', () => {
            if (!document.hidden && this.queue.size) this.flush();
        });
    },

    /* Coalesce a burst of mutations into one capture per container.
     * rAF pauses in a hidden tab, so a demo that keeps running while the
     * user is on another tab would never be captured. Fall back to a
     * timer in that case. */
    flush() {
        const run = () => {
            if (this._flushing) return;
            this._flushing = true;
            if (!this.queue.size) { this._flushing = false; return; }
            const batch = Array.from(this.queue);
            this.queue.clear();
            this.begin();
            batch.forEach(el => this.capture(el));
            this.end();
            this._flushing = false;
        };
        if (document.hidden) this._timer = setTimeout(run, 120);
        else this._raf = requestAnimationFrame(run);
    },

    /* Rewriting a container makes the observer fire on our own DOM.
     * Mutation records are delivered as microtasks, i.e. before any
     * timeout, so clearing the flag in a macrotask is reliable. */
    begin() {
        this.suppress = true;
        clearTimeout(this._suppressTimer);
        this._suppressTimer = setTimeout(() => { this.suppress = false; }, 0);
    },
    end() { /* the timeout above clears it */ },

    /* ---------------------------------------------------------------- */
    showTab(name) {
        const tab = document.querySelector('.vc-tab[data-vc-tab="' + name + '"]');
        if (!tab) return;
        document.querySelectorAll('.vc-tab').forEach(b => b.setAttribute('aria-selected', 'false'));
        document.querySelectorAll('.vc-panel').forEach(p => p.classList.remove('active'));
        tab.setAttribute('aria-selected', 'true');
        const panel = document.getElementById('vcPanel-' + tab.dataset.vcTab);
        if (panel) panel.classList.add('active');
    },

    wireTabs() {
        document.querySelectorAll('.vc-tab').forEach(btn => {
            btn.addEventListener('click', () => this.showTab(btn.dataset.vcTab));
        });
    },

    wireFilters() {
        document.querySelectorAll('.vc-chip').forEach(chip => {
            chip.addEventListener('click', () => {
                this.filter = chip.dataset.v === 'all' ? 'all' : chip.dataset.v;
                document.querySelectorAll('.vc-chip').forEach(c => c.setAttribute('aria-pressed', 'false'));
                chip.setAttribute('aria-pressed', 'true');
                this.render();
            });
        });
    },

    /* ---------------------------------------------------------------- */
    /* Classification                                                    */
    /* ---------------------------------------------------------------- */

    /* Fallback label when we only know the outcome, not the wording. */
    labelFor(v) {
        return {
            granted: 'GRANTED',
            denied: 'DENIED',
            blocked: 'BLOCKED',
            pending: 'PENDING',
            info: 'OUTPUT',
        }[v] || 'OUTPUT';
    },

    classify(el) {
        // 1) an alert-* class on the container or a descendant is the
        //    strongest signal the app emits
        const alertEl = el.matches('[class*="alert-"]')
            ? el
            : el.querySelector('[class*="alert-"]');
        if (alertEl) {
            const cls = Array.from(alertEl.classList).find(c => ALERT_VERDICT[c]);
            if (cls) return { v: ALERT_VERDICT[cls], label: this.labelFor(ALERT_VERDICT[cls]) };
        }
        // 2) otherwise scan the visible text for a verdict keyword
        const text = (el.textContent || '').replace(/\s+/g, ' ').toUpperCase();
        for (const rule of VERDICT_RULES) {
            for (const kw of rule.kw) {
                if (text.indexOf(kw) !== -1) {
                    return { v: rule.v, label: kw };
                }
            }
        }
        if (el.querySelector('table')) return { v: 'info', label: 'DATA' };
        return { v: 'info', label: 'OUTPUT' };
    },

    summary(el) {
        const clone = el.cloneNode(true);
        clone.querySelectorAll('script, style, .vc-compact, .vc-raw').forEach(n => n.remove());
        const t = (clone.textContent || '').replace(/\s+/g, ' ').trim();
        return t.length > 220 ? t.slice(0, 218) + '…' : t;
    },

    context(el) {
        const card = el.closest('.card');
        const ws = el.closest('.workspace');
        const panel = card ? card.querySelector('.feature-tab.active') : null;
        const h2 = card ? card.querySelector('h2') : null;
        const title = h2 ? h2.textContent.replace(/\s+/g, ' ').trim() : 'Result';
        const tab = panel ? panel.textContent.replace(/\s+/g, ' ').trim() : null;
        return {
            tool: tab ? title + ' · ' + tab : title,
            wsId: ws ? ws.id : '',
            wsName: ws ? this.wsName(ws.id) : '',
        };
    },

    wsName(id) {
        const btn = document.querySelector('.nav-item[data-ws="' + id + '"]');
        return btn ? btn.textContent.replace(/\s+/g, ' ').trim() : id;
    },

    /* ---------------------------------------------------------------- */
    /* Capture: build the compact chip + push a dock entry              */
    /* ---------------------------------------------------------------- */

    capture(el) {
        if (!el || !el.isConnected) return;
        if (el.closest('.vc')) return;

        // Recover from a stale wrap: if the app replaced innerHTML, our chip
        // and disclosure are already gone, so the record must be dropped
        // without touching the DOM.
        this.unwrap(el);

        const summary = this.summary(el);
        if (!summary || summary.length < 3) return;

        // Same bytes as last time -> not a new result, just re-render noise.
        if (this.lastText.get(el) === summary) return;
        this.lastText.set(el, summary);

        const verdict = this.classify(el);
        const ctx = this.context(el);
        const time = new Date().toLocaleTimeString('en-GB', { hour12: false });

        /* --- dock entry --- */
        this.entries.unshift({
            n: ++this.seq, v: verdict.v, label: verdict.label,
            tool: ctx.tool, ws: ctx.wsName, wsId: ctx.wsId,
            sum: summary, time, ref: el,
        });
        if (this.entries.length > this.MAX) this.entries.length = this.MAX;
        this.render();

        /* --- in-card compact chip --- */
        // Skip the visual treatment for containers that are pure charts,
        // tables or gauges: a chip above a sparkline just adds noise.
        if (el.querySelector('canvas, table') && !el.querySelector('[class*="alert-"]')) return;
        if (el.tagName === 'TABLE' || el.closest('.table-container')) return;

        this.wrap(el, verdict, summary, ctx);
    },

    wrap(el, verdict, summary, ctx) {
        const doc = document.createElement('div');
        doc.className = 'vc-compact v--' + verdict.v;
        doc.setAttribute('tabindex', '0');
        doc.setAttribute('role', 'button');
        doc.setAttribute('aria-expanded', 'false');
        doc.innerHTML =
            '<span class="vc-verdict"></span>' +
            '<span class="vc-compact-text">' +
                '<span class="vc-compact-title"></span>' +
                '<span class="vc-compact-sum"></span>' +
            '</span>' +
            '<i class="fas fa-chevron-down vc-caret"></i>';
        doc.querySelector('.vc-verdict').textContent = verdict.label;
        doc.querySelector('.vc-compact-title').textContent = ctx.tool;
        doc.querySelector('.vc-compact-sum').textContent = summary;

        const raw = document.createElement('div');
        raw.className = 'vc-raw';
        raw.hidden = true;

        // Move the app's own output into the disclosure, then insert the chip.
        while (el.firstChild) raw.appendChild(el.firstChild);
        el.appendChild(doc);
        el.appendChild(raw);
        el.dataset.vcReady = '1';

        const flip = () => {
            const open = doc.getAttribute('aria-expanded') === 'true';
            doc.setAttribute('aria-expanded', open ? 'false' : 'true');
            raw.hidden = open;
        };
        doc.addEventListener('click', flip);
        doc.addEventListener('keydown', e => {
            if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); flip(); }
        });

        this.seen.set(el, { doc, raw });
    },

    unwrap(el) {
        const rec = this.seen.get(el);
        // Always drop the bookkeeping, even if our markup is already gone.
        this.seen.delete(el);
        delete el.dataset.vcReady;
        if (!rec) return;

        // The app may have overwritten innerHTML since we wrapped; in that
        // case doc/raw are detached and the live children are already the
        // app's own output. Touching them would destroy real data.
        if (rec.doc.parentNode !== el || rec.raw.parentNode !== el) return;

        el.removeChild(rec.doc);
        while (rec.raw.firstChild) el.insertBefore(rec.raw.firstChild, rec.raw);
        el.removeChild(rec.raw);
    },

    /* ---------------------------------------------------------------- */
    /* Dock rendering                                                   */
    /* ---------------------------------------------------------------- */

    render() {
        if (!this.listEl) return;
        if (this.badge) this.badge.textContent = this.entries.length;

        const rows = this.filter === 'all'
            ? this.entries
            : this.entries.filter(e => e.v === this.filter);

        if (!rows.length) {
            this.listEl.innerHTML =
                '<div class="empty-state vc-empty"><i class="fas fa-wave-square"></i>' +
                (this.entries.length
                    ? 'No ' + this.filter + ' results yet.'
                    : 'Results stream here as you run demos. Every operation, one place — verdict first, raw output on demand.') +
                '</div>';
            return;
        }

        this.listEl.innerHTML = rows.map(e => {
            const where = e.ws ? '<span class="ws">' + escapeHtml(e.ws) + '</span> &middot; ' + escapeHtml(e.wsId) : '';
            return '<div class="vc-row v--' + e.v + '" data-seq="' + e.n + '" tabindex="0" role="button">' +
                '<div class="vc-row-top">' +
                    '<span class="vc-verdict">' + escapeHtml(e.label) + '</span>' +
                    '<span class="vc-tool">' + escapeHtml(e.tool) + '</span>' +
                    '<span class="vc-time">' + escapeHtml(e.time) + '</span>' +
                '</div>' +
                '<div class="vc-sum">' + escapeHtml(e.sum) + '</div>' +
                (where ? '<div class="vc-where">' + where + '</div>' : '') +
            '</div>';
        }).join('');

        // Click a row -> jump to the card and open its disclosure.
        this.listEl.querySelectorAll('.vc-row').forEach(row => {
            const go = () => this.focusEntry(Number(row.dataset.seq));
            row.addEventListener('click', go);
            row.addEventListener('keydown', e => {
                if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); go(); }
            });
        });
    },

    focusEntry(seq) {
        const entry = this.entries.find(e => e.n === seq);
        if (!entry || !entry.ref || !entry.ref.isConnected) return;
        if (entry.wsId && typeof gotoSection === 'function') gotoSection(entry.wsId);
        window.setTimeout(() => {
            entry.ref.scrollIntoView({ behavior: 'smooth', block: 'center' });
            const rec = this.seen.get(entry.ref);
            if (rec && rec.doc.getAttribute('aria-expanded') !== 'true') rec.doc.click();
            entry.ref.animate
                ? entry.ref.animate(
                    [{ boxShadow: '0 0 0 0 rgba(37,99,235,.55)' }, { boxShadow: '0 0 0 10px rgba(37,99,235,0)' }],
                    { duration: 900, easing: 'ease-out' })
                : null;
        }, 260);
    },

    /* ---------------------------------------------------------------- */
    clear() {
        this.entries = [];
        this.render();
        if (window.INSPECTOR) INSPECTOR.clear();
        showAlert('<i class="fas fa-broom"></i> Result console cleared', 'info', 1800);
    },

    /* Public API for new tools: push a structured verdict without DOM sniffing. */
    push(spec) {
        this.entries.unshift({
            n: ++this.seq,
            v: spec.v || 'info',
            label: spec.label || 'OUTPUT',
            tool: spec.tool || (spec.ref ? this.context(spec.ref).tool : 'Result'),
            ws: spec.ws || '',
            wsId: spec.wsId || '',
            sum: spec.sum || '',
            time: new Date().toLocaleTimeString('en-GB', { hour12: false }),
            ref: spec.ref || null,
        });
        if (this.entries.length > this.MAX) this.entries.length = this.MAX;
        this.render();
    },

    exportJson() {
        const payload = this.entries.map(e => ({
            time: e.time, verdict: e.label, outcome: e.v,
            tool: e.tool, workspace: e.ws || e.wsId, summary: e.sum,
        }));
        const blob = new Blob([JSON.stringify(payload, null, 2)], { type: 'application/json' });
        const a = document.createElement('a');
        a.href = URL.createObjectURL(blob);
        a.download = 'sih26125-verdicts.json';
        a.click();
        setTimeout(() => URL.revokeObjectURL(a.href), 1500);
        showAlert('<i class="fas fa-file-export"></i> Exported ' + payload.length + ' verdicts', 'success', 2200);
    },

    exportCsv() {
        const esc = s => '"' + String(s == null ? '' : s).replace(/"/g, '""') + '"';
        // Each row must itself be an array: the header is one row, not six.
        const head = [['time', 'verdict', 'outcome', 'tool', 'workspace', 'summary']];
        const body = this.entries.map(e => [e.time, e.label, e.v, e.tool, e.ws || e.wsId, e.sum]);
        const rows = head.concat(body).map(r => r.map(esc).join(',')).join('\r\n');
        const blob = new Blob([rows], { type: 'text/csv' });
        const a = document.createElement('a');
        a.href = URL.createObjectURL(blob);
        a.download = 'sih26125-verdicts.csv';
        a.click();
        setTimeout(() => URL.revokeObjectURL(a.href), 1500);
        showAlert('<i class="fas fa-file-csv"></i> Exported ' + this.entries.length + ' verdicts as CSV', 'success', 2200);
    },

    open(tab) {
        const el = this.el || document.getElementById('vcPanel');
        if (!el) return;
        el.classList.add('open');
        el.setAttribute('aria-hidden', 'false');
        const btn = document.getElementById('vcToggle');
        if (btn) {
            btn.setAttribute('aria-expanded', 'true');
            btn.title = 'Hide result console';
        }
        if (tab) this.showTab(tab);
        this.render();
    },

    toggle(force) {
        const el = this.el || document.getElementById('vcPanel');
        if (!el) return;
        const open = force !== undefined ? force : !el.classList.contains('open');
        el.classList.toggle('open', open);
        el.setAttribute('aria-hidden', open ? 'false' : 'true');
        const btn = document.getElementById('vcToggle');
        if (btn) {
            btn.setAttribute('aria-expanded', open ? 'true' : 'false');
            btn.title = open ? 'Hide result console' : 'Show result console';
        }
        if (open) this.render();
        if (window.ACTIVITY) {
            ACTIVITY.add('Console', open ? 'Result console opened' : 'Result console closed');
        }
    },
};

window.CONSOLE = CONSOLE;
