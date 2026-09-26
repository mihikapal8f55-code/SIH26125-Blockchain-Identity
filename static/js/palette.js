// ==================================================================
// SIH26125 — COMMAND PALETTE (Ctrl/Cmd + K)
//
// The build ships 8 workspaces, 84 tool cards, ~270 buttons and 287
// API endpoints with no way to find any of them. The palette indexes
// all four layers and lets you jump or run in one keystroke.
//
//   Workspaces  ->  navigate
//   Tools       ->  focus the card, fill demo fields, run the primary action
//   Actions     ->  run any onclick handler on the page
//   API         ->  call a backend endpoint and show the verdict
// ==================================================================

const PALETTE = {
    el: null,
    input: null,
    list: null,
    open: false,
    items: [],
    results: [],
    active: 0,
    _shiftHeld: false,
    _lastFocus: null,

    /* ---------------------------------------------------------------- */
    init() {
        this.el = document.getElementById('palette');
        this.input = document.getElementById('paletteInput');
        this.list = document.getElementById('paletteList');
        if (!this.el || !this.input || !this.list) return;

        this.input.addEventListener('input', () => this.query(this.input.value));
        this.input.addEventListener('keydown', e => {
            if (e.key === 'ArrowDown') { e.preventDefault(); this.move(1); }
            else if (e.key === 'ArrowUp') { e.preventDefault(); this.move(-1); }
            else if (e.key === 'Home') { e.preventDefault(); this.active = 0; this.paint(); }
            else if (e.key === 'End') { e.preventDefault(); this.active = this.items.length - 1; this.paint(); }
            else if (e.key === 'Enter') { e.preventDefault(); this.commit(e); }
            else if (e.key === 'Escape') { e.preventDefault(); this.close(); }
        });

        const scrim = this.el.querySelector('.palette-scrim');
        if (scrim) scrim.addEventListener('click', () => this.close());

        const trigger = document.getElementById('paletteTrigger');
        if (trigger) trigger.addEventListener('click', () => this.show());

        this.index();
    },

    /* ---------------------------------------------------------------- */
    /* Build the index from the live DOM — no hand-maintained list.      */
    /* ---------------------------------------------------------------- */

    index() {
        const items = [];

        /* --- workspaces (from the sidebar, so they stay in sync) --- */
        document.querySelectorAll('.nav-item[data-ws]').forEach(btn => {
            const id = btn.dataset.ws;
            const label = btn.textContent.replace(/\s+/g, ' ').trim();
            const hint = (btn.getAttribute('title') || '').split(' ')[0];
            const ws = document.getElementById(id);
            const n = ws ? ws.querySelectorAll('.card').length : 0;
            items.push({
                group: 'Workspaces',
                icon: btn.querySelector('i') ? btn.querySelector('i').className.replace('fas ', '') : 'layer-group',
                name: label,
                path: n + ' tools',
                hint: hint,
                hay: (label + ' ' + id + ' workspace').toLowerCase(),
                run: () => gotoSection(id),
            });
        });

        /* --- tool cards --- */
        document.querySelectorAll('.card').forEach(card => {
            const h2 = card.querySelector('h2');
            if (!h2) return;
            const name = h2.textContent.replace(/\s+/g, ' ').trim();
            const ws = card.closest('.workspace');
            const wsId = ws ? ws.id : '';
            const wsBtn = document.querySelector('.nav-item[data-ws="' + wsId + '"]');
            const wsName = wsBtn ? wsBtn.textContent.replace(/\s+/g, ' ').trim() : '';
            const icon = h2.querySelector('i') ? h2.querySelector('i').className.replace('fas ', '') : 'wrench';
            const primary = card.querySelector('.btn-primary, .btn-danger, .btn-success, .btn');

            const hint = card.dataset.vcHint || '';
            items.push({
                group: 'Tools',
                icon,
                name,
                path: wsName,
                hint,
                hay: (name + ' ' + wsName + ' ' + idText(card)).toLowerCase(),
                run: () => {
                    if (wsId) gotoSection(wsId);
                    window.setTimeout(() => {
                        card.scrollIntoView({ behavior: 'smooth', block: 'center' });
                        card.animate
                            ? card.animate(
                                [{ boxShadow: '0 0 0 0 rgba(37,99,235,.5)' }, { boxShadow: '0 0 0 12px rgba(37,99,235,0)' }],
                                { duration: 1000, easing: 'ease-out' })
                            : null;
                        const f = card.querySelector('input, select, textarea');
                        if (f) window.setTimeout(() => f.focus(), 380);
                    }, 240);
                },
                runAction: primary ? () => {
                    if (wsId) gotoSection(wsId);
                    window.setTimeout(() => primary.click(), 260);
                } : null,
            });
        });

        /* --- direct actions (every visible button gets a shortcut) --- */
        const seenAction = new Set();
        document.querySelectorAll('main button, .hero button').forEach(btn => {
            const text = (btn.textContent || '').replace(/\s+/g, ' ').trim();
            if (!text || text.length < 3) return;
            const key = btn.getAttribute('onclick') || text;
            if (seenAction.has(key)) return;
            seenAction.add(key);
            const card = btn.closest('.card');
            const h2 = card && card.querySelector('h2');
            const owner = h2 ? h2.textContent.replace(/\s+/g, ' ').trim() : '';
            const icon = btn.querySelector('i') ? btn.querySelector('i').className.replace('fas ', '') : 'play';
            items.push({
                group: 'Actions',
                icon,
                name: text,
                path: owner,
                hay: (text + ' ' + owner).toLowerCase(),
                run: () => btn.click(),
            });
        });

        /* --- API endpoints: read-only routes from generated catalogue --- */
        (window.PALETTE_ENDPOINTS || []).forEach(ep => {
            const path = typeof ep === 'string' ? ep : ep.path;
            if (!path) return;
            const pretty = path.replace(/^\/api\//, '').replace(/[-/]/g, ' ');
            const seg = path.split('/').filter(Boolean);
            items.push({
                group: 'API',
                icon: 'plug',
                name: pretty,
                path: seg.slice(0, 3).join(' / '),
                hay: (path + ' ' + pretty).toLowerCase(),
                run: () => this.callApi(path),
            });
        });

        this.items = items;
    },

    /* ---------------------------------------------------------------- */
    /* Query                                                            */
    /* ---------------------------------------------------------------- */

    query(q) {
        const needle = (q || '').trim().toLowerCase();
        let pool = this.items;

        if (needle) {
            const words = needle.split(/\s+/).filter(Boolean);
            pool = this.items.map(it => {
                let score = 0;
                const name = it.name.toLowerCase();
                for (const w of words) {
                    if (name.startsWith(w)) score += 12;
                    else if (name.includes(w)) score += 8;
                    else if (it.path.toLowerCase().includes(w)) score += 4;
                    else if (it.hay.includes(w)) score += 2;
                    else { score = -1; break; }
                }
                return { it, score };
            }).filter(r => r.score > 0)
              .sort((a, b) => b.score - a.score)
              .map(r => r.it);
        } else {
            // Default view: the highest-value entry points only.
            pool = this.items.filter(it =>
                it.group === 'Workspaces' ||
                (it.group === 'Tools' && it.hint) ||
                (it.group === 'API' && /^(playbook|metrics|network\/health|blockchain\/info)/.test(it.path)));
        }

        this.results = pool.slice(0, 60);
        this.active = 0;
        this.paint(needle);
    },

    paint(needle) {
        if (!this.results || !this.results.length) {
            this.list.innerHTML = '<div class="empty-state"><i class="fas fa-magnifying-glass"></i> Nothing matches “' + escapeHtml(needle || '') + '”</div>';
            return;
        }

        const out = [];
        let group = null;
        this.results.forEach((it, i) => {
            if (it.group !== group) {
                group = it.group;
                out.push('<div class="palette-group">' + escapeHtml(group) + '</div>');
            }
            out.push(
                '<button class="palette-item" type="button" role="option" data-i="' + i + '"' +
                ' aria-selected="' + (i === this.active) + '">' +
                    '<i class="fas fa-' + escapeHtml(it.icon) + ' pal-ico"></i>' +
                    '<span class="pal-text">' +
                        '<span class="pal-name">' + hl(it.name, needle) + '</span>' +
                        (it.path ? '<span class="pal-path">' + escapeHtml(it.path) + '</span>' : '') +
                    '</span>' +
                    (it.hint ? '<span class="pal-hint">' + escapeHtml(it.hint) + '</span>' : '') +
                    (it.runAction ? '<span class="pal-hint">run</span>' : '') +
                '</button>');
        });
        this.list.innerHTML = out.join('');

        this.list.querySelectorAll('.palette-item').forEach(el => {
            el.addEventListener('click', () => { this.active = Number(el.dataset.i); this.commit(); });
            el.addEventListener('mousemove', () => {
                if (this.active === Number(el.dataset.i)) return;
                this.active = Number(el.dataset.i);
                this.list.querySelectorAll('.palette-item').forEach(x => x.setAttribute('aria-selected', 'false'));
                el.setAttribute('aria-selected', 'true');
            });
        });
    },

    move(dir) {
        if (!this.results || !this.results.length) return;
        this.active = (this.active + dir + this.results.length) % this.results.length;
        this.list.querySelectorAll('.palette-item').forEach(x =>
            x.setAttribute('aria-selected', String(Number(x.dataset.i) === this.active)));
        const sel = this.list.querySelector('.palette-item[data-i="' + this.active + '"]');
        if (sel) sel.scrollIntoView({ block: 'nearest' });
    },

    commit(e) {
        const it = this.results && this.results[this.active];
        if (!it) return;
        // Shift+Enter runs the tool's primary action instead of just
        // navigating to it. Take the flag from the event that got us here;
        // window.event is not reliable across browsers.
        const runAction = !!(e && e.shiftKey) || !!this._shiftHeld;
        this.close();
        window.setTimeout(() => {
            if (runAction && it.runAction) it.runAction();
            else it.run();
        }, 90);
    },

    /* ---------------------------------------------------------------- */
    show() {
        if (this.open) return;
        this.open = true;
        this._lastFocus = document.activeElement;
        this.el.classList.add('open');
        this.el.setAttribute('aria-hidden', 'false');
        this.input.value = '';
        this.query('');
        window.setTimeout(() => this.input.focus(), 30);
    },

    close() {
        if (!this.open) return;
        this.open = false;
        this.el.classList.remove('open');
        this.el.setAttribute('aria-hidden', 'true');
        if (this._lastFocus && this._lastFocus.focus) {
            try { this._lastFocus.focus(); } catch (e) { /* ignore */ }
        }
        this._lastFocus = null;
    },

    toggle() { this.open ? this.close() : this.show(); },

    /* Fire a read-only endpoint and let the console carry the verdict. */
    async callApi(path) {
        if (typeof fetchAPI !== 'function') return;
        showAlert('<i class="fas fa-plug"></i> GET ' + escapeHtml(path), 'info', 1800);
        const res = await fetchAPI(path);
        const ok = !!(res && res.success !== false);
        const body = (res && (res.error || res.message)) || summariseApi(res);
        CONSOLE.push({
            v: ok ? 'info' : 'denied',
            label: ok ? 'API OK' : 'API FAIL',
            tool: 'GET ' + path,
            ws: 'API',
            sum: body,
        });
    },
};

function summariseApi(res) {
    if (!res || typeof res !== 'object') return String(res);
    const d = res.data;
    if (Array.isArray(d)) return d.length + ' item(s) returned';
    if (d && typeof d === 'object') {
        return Object.keys(d).slice(0, 6).map(k => k + '=' + short(d[k])).join(' · ');
    }
    return Object.keys(res).slice(0, 6).map(k => k + '=' + short(res[k])).join(' · ');
}

function short(v) {
    const s = typeof v === 'object' ? (Array.isArray(v) ? '[' + v.length + ']' : '{…}') : String(v);
    return s.length > 26 ? s.slice(0, 24) + '…' : s;
}

/* Collect the field labels inside a card so tool search matches input names. */
function idText(root) {
    return Array.from(root.querySelectorAll('label'))
        .map(l => l.textContent.trim()).join(' ');
}

/* Bold the matched substring without using innerHTML on raw input. */
function hl(text, needle) {
    if (!needle) return escapeHtml(text);
    const i = text.toLowerCase().indexOf(needle.toLowerCase());
    if (i === -1) return escapeHtml(text);
    return escapeHtml(text.slice(0, i)) +
        '<mark>' + escapeHtml(text.slice(i, i + needle.length)) + '</mark>' +
        escapeHtml(text.slice(i + needle.length));
}

window.PALETTE = PALETTE;
