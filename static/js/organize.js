// ==================================================================
// SIH26125 — ORGANISATION LAYER (v6)
//
// Four jobs, all of them structural rather than cosmetic:
//
//   1. GROUPS   89 undifferentiated cards -> named, collapsible
//               clusters with a live tool count.
//   2. KINDS    Tag every card with an archetype so the palette and
//               screen can tell a table from a chart from a form.
//   3. ROUTING  Real hash routes (#/access) so a refresh or the browser
//               back button keeps your place, and links are shareable.
//   4. CONTEXT  One identity + resource value in the topbar that every
//               tool reads, replacing 28 hardcoded demo emails.
// ==================================================================

/* ------------------------------------------------------------------ */
/* 1. Group map                                                        */
/*    Keys are workspace ids; each entry is a named cluster of cards.   */
/*    Cards are matched on a prefix of their <h2> text.                */
/* ------------------------------------------------------------------ */

const GROUPS = {
    'ws-dashboard': [
        { title: 'Chain & Consensus', icon: 'cubes', sub: 'The live ledger and the network that agrees on it.',
          cards: ['Blockchain Visualization', 'Network & Consensus Metrics'] },
        { title: 'Security Posture', icon: 'heart-pulse', sub: 'One score, broken down into the components that produce it.',
          cards: ['Security Posture Score', 'Live Threat Board', 'Posture Breakdown', 'Point-in-Time Audit Slider'] },
        { title: 'Scenario Lab', icon: 'flask-vial', sub: 'End-to-end narratives and latency probes.',
          cards: ['BEL Defense Unified Mission Showcase', 'Scenario Theater', 'Block-Propagation Map', 'Performance Benchmarks'] },
    ],
    'ws-identity': [
        { title: 'Identity Ledger', icon: 'user-plus', sub: 'The core issue → verify → check path.',
          cards: ['Register New Identity', 'Verify Identity', 'Access Control Check', 'Registered Identities'] },
        { title: 'Onboarding Controls', icon: 'user-check', sub: 'Nothing reaches the chain without passing these.',
          cards: ['Duplicate / Synthetic Identity', 'Bulk CSV Onboarding', 'Join-Request Approval', 'Web-of-Trust Vouching'] },
        { title: 'Identity Operations', icon: 'screwdriver-wrench', sub: 'Day-two operations on live identities.',
          cards: ['Visual Hash Identicons', 'Emergency Containment Revoke'] },
    ],
    'ws-verification': [
        { title: 'Credentials & Passwordless', icon: 'key', sub: 'RSA signatures, biometrics and physical passes.',
          cards: ['Advanced Verification', 'Physical Check-In', 'Interactive Liveness Verification'] },
        { title: 'Zero-Knowledge & SSI', icon: 'eye-slash', sub: 'Prove a claim without disclosing the holder.',
          cards: ['ZK Self-Sovereign Identity', 'ZK Range Proof', 'Selective-Disclosure Claim Picker', 'Witness Co-Signing', 'DID Rescue Kits'] },
        { title: 'Key Material & Post-Quantum', icon: 'microchip', sub: 'Rotation, transparency and quantum-safe signing.',
          cards: ['Credential Lifecycle', 'Key Transparency Log', 'Identity Lifecycle Cascade'] },
    ],
    'ws-access': [
        { title: 'Policy Engines', icon: 'gavel', sub: 'Deterministic rules with a full audit trace.',
          cards: ['Smart Contract Access Rules', 'Attribute-Based Access Control', 'Rule Dry-Run Simulator', 'Data-Classification Rule Layers'] },
        { title: 'Role-Based Access Control', icon: 'user-shield', sub: 'Four canonical roles plus custom ones; every decision shows role AND capability AND resource.',
          cards: ['Role-Based Access Control Panel', 'RBAC Permissions Matrix Visualizer'] },
        { title: 'Credential Scoping', icon: 'clock', sub: 'Bound every credential in time, space and purpose.',
          cards: ['Disposable / Timed Access Tokens', 'Delegation Chains', 'Travel-Mode Context Access', 'Purpose Binding'] },
        { title: 'Human Controls', icon: 'user-lock', sub: 'What the operator has to do, and what they must never show.',
          cards: ['Two-Person Integrity', 'Risk-Adaptive Step-Up Auth'] },
    ],
    'ws-network': [
        { title: 'Distributed Consensus', icon: 'network-wired', sub: 'Longest-valid-chain agreement and its failure modes.',
          cards: ['Multi-Node Distributed Network', 'Cross-Node Trust Scoring', 'Split-Brain Partition Drill'] },
        { title: 'Node Trust & Resilience', icon: 'server', sub: 'Signed gossip, re-pinning and offline transfer.',
          cards: ['Node PKI', 'Pinning Reputation', 'Air-Gapped Sync Pack'] },
        { title: 'Content-Addressed Storage', icon: 'database', sub: 'Off-chain bytes, on-chain CIDs.',
          cards: ['IPFS Document Storage', 'Chain Backups', 'Audit-Root Notarization'] },
    ],
    'ws-assets': [
        { title: 'Tokenised Lifecycle', icon: 'cubes', sub: 'Hardware state advances only on signed telemetry.',
          cards: ['Dynamic Lifecycle NFTs', 'Lifecycle Timeline Visualizer', 'Maintenance Work Orders', 'Recall Campaign'] },
        { title: 'Ownership & Transfer Governance', icon: 'shield-halved', sub: 'Who may mint, who holds it, and who may move it.',
          cards: ['dNFT Minting & Ownership Governance', 'DID-Based NFT Ownership', 'Ownership Transfer & Consent'] },
        { title: 'Encrypted & Attested Supply Chain', icon: 'lock', sub: 'AES-256-GCM payloads, SBOM and provenance gates.',
          cards: ['Firmware / SBOM Integrity Gate', 'Supply-Chain Provenance Graph'] },
        { title: 'Custody Controls', icon: 'location-crosshairs', sub: 'Physical location is part of the policy.',
          cards: ['Custody-Geofence Binding'] },
    ],
    'ws-audit': [
        { title: 'Auditable Activities', icon: 'list-check', sub: 'The six provable activities, each filterable on its own.',
          cards: ['Auditable Activities'] },
        { title: 'Immutable Audit & Governance', icon: 'landmark', sub: 'The record itself, and who may change it.',
          cards: ['Audit Trail & Advanced Security', 'Quorum-Approved Privileged Ops', 'Third-Party Attestation Receipts'] },
        { title: 'Adversarial Testing', icon: 'biohazard', sub: 'Attack the system and watch it defend itself.',
          cards: ['Red Team Attack Playbook', 'Live Defense', 'Anomaly Scoring', 'Forensic Diff View'] },
        { title: 'Forensics & Compliance', icon: 'folder-open', sub: 'Read the chain, export the evidence, map the controls.',
          cards: ['Auditor Portal & Compliance Hub', 'Chain Portability', 'Activity Report', 'Case Management', 'Compliance Mapping', 'Least-Privilege Recommender'] },
    ],
    'ws-gseries': [
        { title: 'Emergency & Adaptive Access (G1–G2)', icon: 'life-ring', sub: 'Break-glass windows and just-in-time step-up.',
          cards: ['G1 ·', 'G2 ·'] },
        { title: 'Second Factors & Global Revocation (G3–G4)', icon: 'key', sub: 'RFC 6238 TOTP and a ZK-provable revocation list.',
          cards: ['G3 ·', 'G4 ·'] },
        { title: 'Deception & Physical Security (G5–G6)', icon: 'ghost', sub: 'Honeytokens and movement plausibility.',
          cards: ['G5 ·', 'G6 ·'] },
        { title: 'Privacy, Devices & Federation (G7–G10)', icon: 'globe', sub: 'Aggregate disclosure, redaction, measured boot, trust anchors.',
          cards: ['G7 ·', 'G8 ·', 'G9 ·', 'G10 ·'] },
    ],
};

const WORKSPACE_META = {
    // The dashboard deliberately has no purpose line — the stat cards below it
    // already say what the page is for. An empty purpose renders nothing.
    'ws-dashboard':     { purpose: '' },
    'ws-identity':      { purpose: 'Issue, verify and govern the on-chain identity record. Every action here mines a tamper-proof block.' },
    'ws-verification':  { purpose: 'Prove who you are, and prove what you hold, without revealing either.' },
    'ws-access':        { purpose: 'Deterministic policy: RBAC enforced by smart contracts and strengthened with ABAC, plus the human controls wrapped around them.' },
    'ws-network':       { purpose: 'Three independent nodes, real consensus, content-addressed storage — and the failure drills that prove it.' },
    'ws-assets':        { purpose: 'Lifecycle tokens, who may mint and hold them, encrypted payloads, and the supply-chain gates that sit between them.' },
    'ws-audit':         { purpose: 'The six auditable activities, the immutable record, the attacks launched against it, and the forensic tools that read it.' },
    'ws-gseries':       { purpose: 'Ten additional security controls, each one shipped, wired to the API and demoable on click.' },
};

const ORGANIZE = {

    /* ---------------------------------------------------------------- */
    init() {
        this.flattenGrids();
        this.tagKinds();
        this.buildGroups();
        this.wireRouting();
        this.wireContext();
        this.decorateWorkspaces();
    },

    /* ---------------------------------------------------------------- */
    /* 1. Flatten: many `.main-grid > div > .card` column wrappers become */
    /*    a single grid of cards, so a group header can span the row.     */
    /* ---------------------------------------------------------------- */

    flattenGrids() {
        document.querySelectorAll('.workspace .main-grid').forEach(grid => {
            const kids = Array.from(grid.children);
            if (!kids.length) return;
            // Only flatten when every child is a pure column wrapper.
            const pure = kids.every(k =>
                k.tagName === 'DIV' &&
                k.className.trim() === '' &&
                Array.from(k.children).every(c => c.classList.contains('card')));
            if (!pure) return;

            const cards = [];
            kids.forEach(col => Array.from(col.children).forEach(c => cards.push(c)));
            cards.forEach(c => grid.appendChild(c));   // appendChild moves
            kids.forEach(col => col.remove());
        });
    },

    /* ---------------------------------------------------------------- */
    /* 2. Archetype tags                                                  */
    /* ---------------------------------------------------------------- */

    tagKinds() {
        document.querySelectorAll('.card').forEach(card => {
            if (card.dataset.kind) return;
            let kind = 'DEMO';
            if (card.querySelector('.table-container, table')) kind = 'TABLE';
            else if (card.querySelector('canvas')) kind = 'VISUAL';
            else if (card.querySelector('.feature-tabs')) kind = 'LAB';
            else if (card.querySelector('input, select, textarea')) kind = 'TOOL';
            card.dataset.kind = kind;

            // The palette shows a shortcut hint on the card's primary action.
            const primary = card.querySelector('.btn-primary, .btn-danger, .btn-success, .btn');
            if (primary) card.dataset.vcHint = 'run';
        });
    },

    /* ---------------------------------------------------------------- */
    /* 3. Group headers                                                   */
    /* ---------------------------------------------------------------- */

    buildGroups() {
        Object.keys(GROUPS).forEach(wsId => {
            const ws = document.getElementById(wsId);
            if (!ws) return;
            const defs = GROUPS[wsId];

            // A workspace may hold several consecutive .main-grid blocks
            // with nothing separating them. Group across all of them at
            // once, otherwise every group name would appear two or three
            // times in the same workspace.
            const grids = Array.from(ws.querySelectorAll('.main-grid'));
            if (!grids.length) return;

            const cards = [];
            grids.forEach(grid => {
                Array.from(grid.children).forEach(c => {
                    if (c.classList.contains('card')) cards.push(c);
                });
            });
            if (cards.length < 4) return;   // too small to need scaffolding

            const buckets = defs.map(d => ({ def: d, cards: [] }));
            const orphans = [];
            cards.forEach(card => {
                const h2 = card.querySelector('h2');
                const title = (h2 ? h2.textContent : '').replace(/\s+/g, ' ').trim();
                const bucket = buckets.find(b => b.def.cards.some(p => title.indexOf(p) === 0));
                (bucket ? bucket.cards : orphans).push(card);
            });

            // A mis-grouped card is worse than an ungrouped one, so bail
            // out and leave the whole workspace exactly as authored.
            if (orphans.length) {
                console.warn('[organize] leaving ' + wsId + ' ungrouped, unmatched:',
                    orphans.map(c => (c.querySelector('h2') || {}).textContent));
                return;
            }

            const frag = document.createDocumentFragment();
            buckets.forEach(b => {
                if (!b.cards.length) return;
                const group = document.createElement('div');
                group.className = 'tool-group';
                group.appendChild(this.groupHeader(b.def, b.cards.length));
                const body = document.createElement('div');
                body.className = 'tool-group-body';
                b.cards.forEach(c => body.appendChild(c));
                group.appendChild(body);
                frag.appendChild(group);
            });

            // Drop every original grid, then drop the groups in their place.
            const anchor = grids[0];
            grids.forEach(g => g.remove());
            ws.insertBefore(frag, anchor.nextSibling);
        });
    },

    groupHeader(def, count) {
        const el = document.createElement('div');
        el.className = 'tool-group-head';
        el.innerHTML =
            '<h3><i class="fas fa-' + def.icon + '"></i>' + def.title + '</h3>' +
            '<span class="group-sub">' + def.sub + '</span>' +
            '<span class="tool-group-count">' + count + ' tool' + (count === 1 ? '' : 's') + '</span>' +
            '<button class="tool-group-toggle" type="button" aria-expanded="true" ' +
                'aria-label="Collapse the ' + def.title + ' group">' +
                '<span>collapse</span> <i class="fas fa-chevron-down chev"></i>' +
            '</button>';
        const btn = el.querySelector('.tool-group-toggle');
        // Currently expanded -> this click should collapse it.
        btn.addEventListener('click', () => this.setCollapsed(el.parentElement, this.isOpen(btn)));
        return el;
    },

    isOpen(btn) { return btn.getAttribute('aria-expanded') === 'true'; },

    /* Single place that owns the collapsed state, so the header button and
     * the "collapse all" toolbar can never disagree with the CSS. */
    setCollapsed(group, collapsed) {
        if (!group) return;
        const btn = group.querySelector('.tool-group-toggle');
        const label = btn && btn.querySelector('span');
        group.setAttribute('data-collapsed', collapsed ? '1' : '0');
        if (btn) {
            btn.setAttribute('aria-expanded', collapsed ? 'false' : 'true');
            if (label) label.textContent = collapsed ? 'expand ' : 'collapse ';
        }
        const body = group.querySelector('.tool-group-body');
        if (body) body.setAttribute('aria-hidden', collapsed ? 'true' : 'false');
    },

    /* ---------------------------------------------------------------- */
    /* 4. Hash routing                                                    */
    /* ---------------------------------------------------------------- */

    wireRouting() {
        const readHash = () => {
            const raw = (location.hash || '').replace(/^#\/?/, '').split('?')[0];
            return raw && document.getElementById(raw) ? raw : '';
        };

        const original = window.gotoSection;
        if (typeof original !== 'function') return;

        // Central writer: pushState for real navigation so Back works,
        // replaceState only for the very first normalisation.
        let suppressHashWrite = false;
        const writeHash = (id, push) => {
            if (!id || !document.getElementById(id)) return;
            if (location.hash === '#/' + id) return;
            const url = '#/' + id;
            if (push) history.pushState(null, '', url);
            else history.replaceState(null, '', url);
        };

        window.gotoSection = function (id) {
            if (id && document.getElementById(id)) writeHash(id, !suppressHashWrite);
            return original.apply(this, arguments);
        };

        // Back / forward: the browser already moved the hash, so just
        // render the target without writing history again.
        window.addEventListener('popstate', () => {
            const id = readHash();
            if (!id) return;
            suppressHashWrite = true;
            try { original.call(window, id); } finally { suppressHashWrite = false; }
        });

        // Manual hash edits (#/ws-access typed in the address bar).
        window.addEventListener('hashchange', () => {
            if (suppressHashWrite) return;
            const id = readHash();
            if (!id || id === window.currentWs) return;
            window.gotoSection(id);
        });

        const initial = readHash();
        if (initial) {
            window.setTimeout(() => original.call(window, initial), 120);
        } else {
            history.replaceState(null, '', '#/ws-dashboard');
        }
    },

    /* ---------------------------------------------------------------- */
    /* 5. Identity / resource context                                    */
    /* ---------------------------------------------------------------- */

    wireContext() {
        const idInput = document.getElementById('ctxIdentity');
        const resInput = document.getElementById('ctxResource');
        if (!idInput) return;

        const ID_FIELDS = 'publicId,adPublicId,bioPublicId,zrSecret,qrPublicId,vcPublicId,kitPublicId,pqPublicId,' +
            'lvPublicId,ktPublicId,f15sHolder,f15sVc,f15wRequester,repPublicId,vlPublicId,abacPublicId,' +
            'dryPublicId,rsPublicId,schedPublicId,htPublicId,f15lPid,f15lpId,f15lRes,' +
            'dupNormalPin,dupPanicPin,dupTestPin,dlgDelegator,dlgDelegate,bgRequester,bgPublicId,' +
            'f15ntAnchor,f15gfLng,f15gfLat,f15gfTLng,f15gfTLat,f15cDept,f15cActor,f15vName,f15vEmail,' +
            'f15vId,f15vTarget,f15vVoucher,f15wReq,f15wRequester,f15wResource,f15wWitness,revokePublicId,' +
            'joinId,f15lpRes,schedResource,prUnit,qResource,foIndex';

        // "publicId"-style fields are the identity handle; the rest are
        // resource/actor handles. Only mirror the identity ones automatically.
        const idFieldSet = new Set();
        ID_FIELDS.split(',').forEach(f => {
            if (/PublicId$|^f15v|Identity|Pid$|^revokePublicId$|^joinId$/.test(f)) idFieldSet.add(f.trim());
        });

        const applyId = () => {
            const v = idInput.value.trim();
            if (!v) return;
            document.querySelectorAll('input, select').forEach(el => {
                if (idFieldSet.has(el.id)) el.value = v;
            });
            if (window.ACTIVITY) ACTIVITY.add('Context', 'identity → ' + v);
        };
        const applyRes = () => {
            const v = resInput.value.trim();
            if (!v) return;
            const targets = ['f15wResource', 'f15lpRes', 'schedResource', 'qResource', 'prUnit', 'f15lRes'];
            targets.forEach(id => { const el = document.getElementById(id); if (el) el.value = v; });
            if (window.ACTIVITY) ACTIVITY.add('Context', 'resource → ' + v);
        };

        // 'input' so the context applies as you type, 'change' for the
        // paste-and-blur case. Debounced, because one keystroke would
        // otherwise rewrite ~26 fields and spam the activity log.
        let idTimer = null;
        idInput.addEventListener('input', () => {
            clearTimeout(idTimer);
            idTimer = setTimeout(applyId, 250);
        });
        idInput.addEventListener('change', applyId);
        resInput.addEventListener('change', applyRes);

        const reset = document.getElementById('ctxReset');
        if (reset) {
            reset.addEventListener('click', () => {
                idInput.value = 'aarav.sharma@bel.gov.in';
                resInput.value = 'vault';
                applyId();
                applyRes();
                showAlert('<i class="fas fa-rotate-left"></i> Context reset to the demo persona', 'info', 1800);
            });
        }
    },

    /* ---------------------------------------------------------------- */
    /* 6. Workspace headers: purpose line + live tool count              */
    /* ---------------------------------------------------------------- */

    decorateWorkspaces() {
        Object.keys(WORKSPACE_META).forEach(wsId => {
            const ws = document.getElementById(wsId);
            if (!ws) return;
            const head = ws.querySelector('.workspace-title');
            if (!head) return;

            const n = ws.querySelectorAll('.card').length;
            const actions = n + (n === 1 ? ' tool' : ' tools');

            const meta = WORKSPACE_META[wsId] || {};
            let purpose = ws.querySelector('.workspace-purpose');
            if (meta.purpose) {
                if (!purpose) {
                    purpose = document.createElement('p');
                    purpose.className = 'workspace-purpose';
                    head.insertAdjacentElement('afterend', purpose);
                }
                purpose.textContent = meta.purpose;
            } else if (purpose) {
                // Purpose was cleared: drop the line instead of leaving it blank.
                purpose.remove();
                purpose = null;
            }

            let tools = ws.querySelector('.workspace-tools');
            if (!tools) {
                tools = document.createElement('div');
                tools.className = 'workspace-tools';
                // Sit directly after the purpose line, not at children[1],
                // which would place it before the heading on some workspaces.
                // With no purpose line, anchor to the heading itself.
                (purpose || head).insertAdjacentElement('afterend', tools);
            }
            if (!tools.querySelector('.ws-stat')) {
                tools.innerHTML =
                    '<span class="ws-stat">' + actions + '</span>' +
                    '<span class="spacer"></span>' +
                    '<button class="btn btn-secondary btn-sm" type="button" onclick="fillDemoSection(\'' + wsId + '\')">' +
                        '<i class="fas fa-wand-magic-sparkles"></i> Fill demo fields</button>' +
                    '<button class="btn btn-secondary btn-sm" type="button" data-collapse-all ' +
                        'onclick="toggleAllGroups(\'' + wsId + '\')">' +
                        '<i class="fas fa-chevron-up"></i> <span>Collapse groups</span></button>';
            }
        });
    },
};

/* Collapse / expand every group in one workspace. */
function toggleAllGroups(wsId, force) {
    const ws = document.getElementById(wsId);
    if (!ws) return;
    const groups = Array.from(ws.querySelectorAll('.tool-group'));
    if (!groups.length) return;
    const anyOpen = groups.some(g => {
        const b = g.querySelector('.tool-group-toggle');
        return b && b.getAttribute('aria-expanded') === 'true';
    });
    const open = force !== undefined ? force : !anyOpen;
    groups.forEach(g => ORGANIZE.setCollapsed(g, !open));

    const btn = ws.querySelector('[data-collapse-all]');
    if (btn) {
        btn.querySelector('span').textContent = open ? 'Collapse groups' : 'Expand groups';
        // The arrows-collapse/expand glyphs are Font Awesome Pro and render as
        // nothing in the vendored free build, so use the free chevrons.
        btn.querySelector('i').className = 'fas ' + (open ? 'fa-chevron-up' : 'fa-chevron-down');
    }
}

window.ORGANIZE = ORGANIZE;
