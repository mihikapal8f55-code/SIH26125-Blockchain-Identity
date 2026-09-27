from app import app
import html as _htmlmod
import os
import re

client = app.test_client()
r = client.get('/')
html = r.get_data(as_text=True)
appjs = client.get('/static/js/app.js').get_data(as_text=True)
uijs = client.get('/static/js/ui.js').get_data(as_text=True)
mainjs = client.get('/static/js/main.js').get_data(as_text=True)
css = client.get('/static/css/app.css').get_data(as_text=True)
favicon = client.get('/static/favicon.svg').status_code

# The activity labels live server-side; the UI mirrors them, so both sides are
# compared to stop the button text from silently changing after the first click.
with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'blockchain.py'),
          encoding='utf-8', errors='replace') as _fh:
    blockchain_src = _fh.read()

# ---- v6 organisation layer ----
v6css = client.get('/static/css/v6.css').get_data(as_text=True)
organizejs = client.get('/static/js/organize.js').get_data(as_text=True)
consolejs = client.get('/static/js/console.js').get_data(as_text=True)
palettejs = client.get('/static/js/palette.js').get_data(as_text=True)
endpointsjs = client.get('/static/js/endpoints.js').get_data(as_text=True)

# Icon classes can be emitted from JS as well as the template, so scan both.
markup = html + uijs + appjs + organizejs + consolejs + palettejs

# Every card id must be unique. Group-Object style case-insensitive
# grouping is wrong here: "f15lPid" and "f15lpId" are different ids.
_ids = re.findall(r'\sid="([^"]+)"', html)
_dupes = [i for i in set(_ids) if _ids.count(i) > 1]

# Every gid('x') referenced from app.js must exist in the page.
_gid_refs = set(re.findall(r"_gid\('([^']+)'\)", appjs))
_missing_gids = sorted(_gid_refs - set(_ids))

# The GROUPS map in organize.js must cover every card heading, otherwise
# buildGroups() bails out and the workspace silently stays ungrouped.
def _text(s):
    # Mirror what the browser's textContent gives us: tags stripped and
    # entities decoded, so "Network &amp; Consensus" == "Network & Consensus".
    return re.sub(r'\s+', ' ', _htmlmod.unescape(re.sub(r'<[^>]+>', '', s))).strip()

_ws = {}
for _m in re.finditer(r'<section class="workspace[^"]*" id="(ws-[a-z]+)">(.*?)\n</section>', html, re.S):
    _ws[_m.group(1)] = [_text(h) for h in re.findall(r'<h2>(.*?)</h2>', _m.group(2), re.S)]

_gblock = organizejs[organizejs.index('const GROUPS = {'):organizejs.index('const WORKSPACE_META')]
_groups = {}
for _m in re.finditer(r"'(ws-[a-z]+)':\s*\[(.*?)\n    \],", _gblock, re.S):
    _pfx = []
    for _c in re.finditer(r'cards:\s*\[(.*?)\]', _m.group(2), re.S):
        _pfx += re.findall(r"'([^']+)'", _c.group(1))
    _groups[_m.group(1)] = _pfx

_ungrouped = []
for _wsid, _titles in _ws.items():
    for _t in _titles:
        if not any(_t.startswith(p) for p in _groups.get(_wsid, [])):
            _ungrouped.append(f'{_wsid}:{_t}')

# Only GET routes may be callable straight from the browser.
_ep_routes = re.findall(r"@app\.route\(\s*'([^']+)'([^)]*)\)", open('app.py', encoding='utf-8').read())
_mutating = [p for p, rest in _ep_routes
             if 'methods' in rest and not re.search(r"methods\s*=\s*\[\s*'GET'\s*\]", rest)]
_ep_listed = re.findall(r"path:\s*'([^']+)'", endpointsjs)

checks = {
    # ---- Shell / IA (HTML) ----
    'Sidebar nav': 'class="sidebar"' in html,
    '8 workspaces': html.count('class="workspace') >= 8,
    'Topbar': 'class="topbar"' in html,
    'Activity rail': 'activityRail' in html,
    'Tour overlay': 'tourOverlay' in html,
    'Hero banner': 'class="hero"' in html,
    'Theme toggle': 'themeToggleBtn' in html,
    # The guided-tour compass was removed from the top bar (it sat left of the
    # theme toggle). The tour itself is still reachable from the hero box, and
    # the T shortcut still works.
    'No guided-tour button in the top bar': re.search(
        r'<div class="topbar-actions">(?:(?!</div>).)*?startTour', html, re.S) is None,
    'Top bar keeps its other three icon buttons': html.split(
        '<div class="topbar-actions">')[1].split('</div>')[0].count('class="icon-btn"') == 3,
    'Activity rail + console keep their own icon buttons': html.count('class="icon-btn"') == 8,
    'Guided tour still offered in the hero box': 'Take the guided tour' in html
    and html.count('onclick="startTour()"') == 1,
    'External CSS link': '/static/css/app.css' in html,
    'External JS links': '/static/js/ui.js' in html and '/static/js/app.js' in html,
    'Favicon': '/static/favicon.svg' in html,
    'No inline <style>': '<style' not in html,
    'No inline <script>': '<script>' not in html,

    # ---- Offline-safe assets (no third-party CDN at runtime) ----
    'Font Awesome vendored': '/static/vendor/font-awesome/css/all.min.css' in html,
    'No CDN asset references': not re.search(r'(src|href)=["\']https?://', html),
    'Vendored FA webfonts present': all(
        os.path.exists(os.path.join('static', 'vendor', 'font-awesome', 'webfonts', f))
        for f in ('fa-solid-900.woff2', 'fa-regular-400.woff2', 'fa-brands-400.woff2')),
    'Vendored FA license present': os.path.exists(
        os.path.join('static', 'vendor', 'font-awesome', 'LICENSE.txt')),

    # ---- ARIA correctness ----
    # Only the 8 workspace buttons (data-ws) are navigation; the bottom quick-
    # journey reuses .nav-item for plain links and correctly has no ARIA.
    'Sidebar is nav, not fake tabs': all(
        'role="tab"' not in m for m in re.findall(r'<button class="nav-item[^>]*data-ws[^>]*>', html)),
    'Every nav item marks aria-current': len(
        re.findall(r'<button class="nav-item[^>]*data-ws[^>]*aria-current=', html)) == 8,
    'Exactly one aria-current=page': html.count('aria-current="page"') == 1,

    # ---- Icon sanity ----
    # These names are Font Awesome Pro or do not exist in FA6, so they resolve to
    # content:none and leave a button with no glyph at all.
    'No Pro/missing FA glyphs used': not any(
        n in markup for n in (
            'fa-arrows-collapse', 'fa-arrows-expand', 'fa-radar', 'fa-flash',
            'fa-boundary', 'fa-shield-xmark', 'fa-shield-xmark',
        )),

    # ---- Feature cards (HTML) ----
    'Crypto Panel': 'Passwordless Auth' in html,
    'ZK Panel': 'Zero-Knowledge Proof' in html,
    'QR Panel': 'QR Verification' in html,
    'Smart Contract Panel': 'Smart Contract Access Rules' in html,
    'Time Rules tab': 'Time Rules' in html,
    'Geo-fencing tab': 'Geo-fencing' in html,
    'ZK button': 'Run ZK Proof Demo' in html,
    'QR generate': 'Generate QR' in html,
    'ZK-SSI card': 'ZK Self-Sovereign Identity' in html,
    'ABAC card': 'Attribute-Based Access Control' in html,
    'dNFT card': 'Dynamic Lifecycle NFTs' in html,

    # ---- Feature JS (static/js/app.js) ----
    'Crypto JS': 'runPasswordlessDemo' in appjs,
    'Biometric JS': 'runBiometricDemo' in appjs,
    'Time JS': 'runTimeWindowDemo' in appjs,
    'Geo JS': 'runGeoDemo' in appjs,
    'ZK JS': 'runZkpDemo' in appjs,
    'QR JS': 'generateQR' in appjs,
    'verify QR JS': 'verifyQR' in appjs,
    'Tab2 JS': 'switchTab2' in appjs,
    'ZK-SSI JS': 'runZkSsiDemo' in appjs,
    'DID list JS': 'listDids' in appjs,
    'ABAC JS': 'runAbacDemo' in appjs,
    'dNFT JS': 'runNftDemo' in appjs,
    'dNFT list JS': 'listNfts' in appjs,
    'Dual-layer JS': 'runEncipfsDemo' in appjs,
    'encipfs store JS': 'encipfsStore' in appjs,
    # Exact standalone function definition (NOT the switchTab2..6 variants)
    'tab switch JS': 'function switchTab(' in appjs,

    # ---- Shell JS (static/js/ui.js) ----
    'nav JS': 'function gotoSection(' in uijs,
    'theme JS': 'function toggleTheme(' in uijs,
    'activity JS': 'const ACTIVITY' in uijs,
    'tour JS': 'function startTour(' in uijs and 'function endTour(' in uijs,
    'fetchAPI JS': 'async function fetchAPI(' in uijs,
    'showAlert JS': 'function showAlert(' in uijs,
    'topbar JS': 'function refreshTopbar(' in uijs,
    'copy JS': 'function copyToClipboard(' in uijs,
    'OS theme detection JS': 'function resolveInitialTheme(' in uijs,
    'Ctrl+K shortcut': "e.key === 'k'" in uijs,

    # ---- v6 markup ----
    'v6 CSS linked': '/static/css/v6.css' in html,
    'Skip link': 'class="skip-link"' in html and '#mainContent' in html,
    'Palette markup': 'id="palette"' in html and 'id="paletteInput"' in html,
    'Palette trigger': 'id="paletteTrigger"' in html,
    'Context switcher': 'id="ctxIdentity"' in html and 'id="ctxResource"' in html,
    'Result console dock': 'id="vcPanel"' in html and 'id="vcList"' in html,
    'Console tabs': 'data-vc-tab="verdicts"' in html and 'data-vc-tab="traffic"' in html,
    'Console filters': 'data-v="granted"' in html and 'data-v="denied"' in html,
    'Flagship strip removed': html.count('class="flag"') == 0 and 'class="flagship"' not in html,
    'Hero problem-statement badge removed': 'hero-badge' not in html
    and 'Problem Statement' not in html,
    'Dashboard dividers removed': not any(
        d in html for d in (
            'Live Chain &amp; Consensus',
            'Security Posture &amp; Incident Command',
            'Security Posture &amp; Incident Lab',
        )),
    'Mission divider kept': 'Your mission' in html,
    'Dashboard purpose line removed': 'threat posture at a glance' not in organizejs
    and "'ws-dashboard':     { purpose: '' }" in organizejs,
    'Blank purpose renders no line': 'purpose.remove()' in organizejs
    and '(purpose || head)' in organizejs,
    # Dashboard sections stack their cards in one full-width column.
    'No leftover rowwise machinery': 'rowwise' not in organizejs
    and '--cols' not in organizejs,
    'Dashboard main-grid fallback also single column': css.count(
        'grid-template-columns: minmax(0, 1fr);') >= 2,
    'No dashboard multi-column override': 'repeat(var(--cols' not in css
    and 'repeat(auto-fit, minmax(280px' not in css,
    # Chain strip: blocks sit in one row even after the result console wraps
    # the output, and Genesis is white-on-black in light / same as the rest
    # in dark.
    'Chain strip unwraps the console disclosure': '.chain-visualization > .vc-raw:not([hidden]) { display: contents; }' in css,
    'Chain strip stays a nowrap flex row': '.chain-visualization {' in css
    and 'flex-wrap' not in css.split('.chain-visualization {')[1].split('}')[0],
    'Genesis uses white surface in light theme': '.chain-block.genesis {' in css
    and 'background: var(--surface);' in css.split('.chain-block.genesis {')[1].split('}')[0],
    'Genesis blue-gradient override removed': 'linear-gradient(135deg, #1d4ed8, #4338ca)' not in css,
    'Genesis matches other blocks in dark theme':
    'html[data-theme="dark"] .chain-block.genesis { background: var(--surface-2); border-color: var(--c-hairline); color: var(--c-ink); }' in css,
    'Block titles use theme-aware ink': '.chain-block .block-index {' in css
    and 'color: var(--c-ink);' in css.split('.chain-block .block-index {')[1].split('}')[0],
    # Every workspace stacks its cards in one full-width column. Done with a
    # single `.workspace`-qualified rule rather than eight per-workspace ones.
    # rsplit: `.workspace > .main-grid {` also appears earlier in app.css with
    # the auto-fit grid, and the single-column override comes last.
    'All workspaces single column': 'grid-template-columns: minmax(0, 1fr);'
    in css.rsplit('.workspace .tool-group-body {', 1)[1].split('}')[0],
    'No per-workspace column overrides': not re.findall(
        r'#ws-[a-z]+ \.tool-group-body \{', css),
    'Pre-JS fallback also single column': 'grid-template-columns: minmax(0, 1fr);'
    in css.rsplit('.workspace > .main-grid {', 1)[1].split('}')[0],
    'Result containers in dock': 'id="inspectorBody"' in html,
    'v6 scripts linked': all(s in html for s in (
        'organize.js', 'console.js', 'palette.js', 'endpoints.js')),

    # ---- v6 JS ----
    'organize init': 'ORGANIZE.init()' in mainjs,
    'console init': 'CONSOLE.init()' in mainjs,
    'palette init': 'PALETTE.init()' in mainjs,
    'group map': 'const GROUPS = {' in organizejs,
    'workspace meta': 'const WORKSPACE_META' in organizejs,
    'collapse helper': 'setCollapsed(' in organizejs,
    'collapse all': 'function toggleAllGroups(' in organizejs,
    'context wiring': 'wireContext(' in organizejs and 'idInput.addEventListener' in organizejs,
    'verdict rules': 'const VERDICT_RULES' in consolejs,
    'verdict labels': 'labelFor(' in consolejs,
    'result observer': 'MutationObserver' in consolejs,
    'console export': 'exportCsv()' in consolejs and 'exportJson()' in consolejs,
    'palette index': 'index()' in palettejs and 'PALETTE_ENDPOINTS' in palettejs,
    'palette API catalogue': 'window.PALETTE_ENDPOINTS' in endpointsjs,

    # ---- PS governance layer (RBAC / dNFT ownership / DID / activities) ----
    'PS RBAC panel card': 'Role-Based Access Control Panel' in html,
    'PS RBAC panel result': 'id="rbacPanelResult"' in html,
    'PS RBAC actor field': 'id="rbacActor"' in html,
    'PS RBAC role select': 'id="rbacAssignRoleSel"' in html,
    'PS RBAC custom role field': 'id="rbacNewRole"' in html,
    'PS RBAC load handler': 'function rbacLoadPanel()' in appjs,
    'PS RBAC define handler': 'function rbacDefineRole()' in appjs,
    'PS RBAC assign handler': 'function rbacAssignRole()' in appjs,
    'PS RBAC verify handler': 'function rbacVerifyCapability()' in appjs,
    'PS deny-by-default demo': 'function rbacDenyByDefault()' in appjs,
    'PS gate trace renderer': 'function psGateHtml(' in appjs,
    'PS gate shows role AND capability AND resource':
        'role ' in appjs and "'capability'" in appjs and "'resource'" in appjs,
    'PS dNFT governance card': 'dNFT Minting &amp; Ownership Governance' in html,
    'PS dNFT governance result': 'id="nftGovResult"' in html,
    'PS dNFT actor/owner/token fields':
        all(x in html for x in ('id="nftGovActor"', 'id="nftGovOwner"', 'id="nftGovToken"')),
    'PS dNFT mint handler': 'function nftGovernMint()' in appjs,
    'PS ownership handler': 'function nftGovOwnership(' in appjs,
    'PS lineage handler': 'function nftGovLineage()' in appjs,
    'PS DID ownership card': 'DID-Based NFT Ownership' in html,
    'PS DID ownership result': 'id="didOwnResult"' in html,
    'PS DID register handler': 'function didBindMint()' in appjs,
    'PS DID mint handler': 'function didMintToDid()' in appjs,
    'PS DID cannot act as operator (copy)':
        'can never' in html and 'RBAC operator' in html,
    'PS transfer consent card': 'Ownership Transfer &amp; Consent' in html,
    'PS transfer consent result': 'id="nftTransferResult"' in html,
    'PS transfer scenario handler': 'function nftTransferScenario()' in appjs,
    'PS governed transfer handler': 'function nftTransferGoverned()' in appjs,
    'PS auditable activities card': 'Auditable Activities' in html,
    'PS auditable activities result': 'id="activityResult"' in html,
    'PS activity chips': 'id="activityChips"' in html,
    'PS activity loader': 'function psLoadActivity(' in appjs,
    'PS all six activities exposed':
        all(k in html for k in ('identity_creation', 'nft_creation', 'allocation',
                                 'access_rights', 'ownership_transfer', 'permission_update')),
    'PS activity labels match the server': all(
        lbl in blockchain_src for lbl in ('"label": "Identity creation"', '"label": "NFT creation"',
                                           '"label": "Allocation"', '"label": "Access-rights assignment"',
                                           '"label": "Ownership transfer"', '"label": "Permission update"'))
        and all(lbl in html for lbl in ('Identity creation', 'NFT creation', 'Allocation',
                                         'Access-rights assignment', 'Ownership transfer',
                                         'Permission update')),
    'PS activity filter is server-side':
        "/api/audit/activities" in appjs and 'encodeURIComponent' in appjs,
    'PS join role picker': 'id="joinRoleSel"' in html,
    'PS join approve sends role': "'role': role" in appjs or 'role: role' in appjs,
    'PS groups registered': all(
        g in organizejs for g in ("'Role-Based Access Control'",
                                   "'Ownership & Transfer Governance'",
                                   "'Auditable Activities'")),

    # ---- v6 CSS ----
    'v6 tool groups': '.tool-group-head' in v6css,
    'v6 collapse state': '.tool-group[data-collapsed="1"] .tool-group-body' in v6css,
    'v6 console dock': '.vc' in v6css and '.vc-compact' in v6css,
    'v6 palette': '.palette-box' in v6css,
    'v6 context': '.ctx' in v6css and '.ctx-sep' in v6css,
    'v6 flagship': '.flagship' in v6css,
    # The top bar must stay a single line: no wrapping, and nothing able to spill
    # past its right edge. These are the declarations that guarantee that, so a
    # future edit that reintroduces wrap/overflow fails here instead of on screen.
    'topbar is a single non-wrapping line': bool(re.search(
        r'\.topbar\s*\{[^}]*flex-wrap:\s*nowrap', css, re.S)) and 'overflow: hidden' in re.search(
        r'\.topbar\s*\{[^}]*\}', css, re.S).group(0),
    'topbar status pills never wrap': bool(re.search(
        r'\.topbar-pills\s*\{[^}]*flex-wrap:\s*nowrap', css, re.S)) and not re.search(
        r'\.topbar-pills\s*\{[^}]*flex-wrap:\s*wrap\s*;', css, re.S),
    'topbar actions never squeeze': bool(re.search(
        r'\.topbar-actions\s*\{[^}]*flex-shrink:\s*0', css, re.S)),
    'search label truncates instead of wrapping': bool(re.search(
        r'\.palette-trigger \.pal-label\s*\{[^}]*text-overflow:\s*ellipsis', v6css, re.S)),
    'context switcher may shrink (cannot force overflow)': bool(re.search(
        r'\.ctx\s*\{[^}]*min-width:\s*0', v6css, re.S)) and not re.search(
        r'\.ctx\s*\{[^}]*flex-shrink:\s*0\s*;', v6css, re.S),
    'v6 skip link': '.skip-link' in v6css,
    'v6 reduced motion': 'prefers-reduced-motion' in v6css or 'prefers-reduced-motion' in css,
    'v6 forced colors': 'forced-colors' in v6css,

    # ---- Init / static assets ----
    'init JS': 'initShell()' in mainjs and 'loadBlockchainData()' in mainjs,
    'CSS design tokens': '--sidebar-bg' in css,
    'CSS dark mode': 'data-theme="dark"' in css,
    'CSS responsive': '@media (max-width: 860px)' in css,
    'CSS accented cards': 'accent-zk' in css,
    'favicon served': favicon == 200,

    # ---- Integrity ----
    'No duplicate element ids': not _dupes,
    'All gid() targets exist': not _missing_gids,
    'Every card lands in a group': not _ungrouped,
    'Palette lists only GET routes': not (set(_ep_listed) & set(_mutating)),
    'Endpoint catalogue is non-trivial': len(_ep_listed) > 50,
}

import sys

all_ok = True
for name, present in checks.items():
    status = 'OK' if present else 'MISSING'
    print(f'{name}: {status}')
    if not present:
        all_ok = False

# Surface the reason an integrity check failed, not just its name.
if _dupes:
    print(f'\n  duplicate ids: {_dupes}')
if _missing_gids:
    print(f'\n  gid() targets not in the page: {_missing_gids}')
if _ungrouped:
    print(f'\n  cards with no matching group: {_ungrouped}')
_bad_ep = sorted(set(_ep_listed) & set(_mutating))
if _bad_ep:
    print(f'\n  non-GET routes exposed to the palette: {_bad_ep}')

passed = sum(1 for v in checks.values() if v)
print(f'\n---')
print(f'{passed}/{len(checks)} checks passed')
print('ALL FEATURES PRESENT' if all_ok else 'SOME FEATURES MISSING')
if __name__ == '__main__':
    sys.exit(0 if all_ok else 1)
