from app import app

client = app.test_client()
r = client.get('/')
html = r.get_data(as_text=True)
appjs = client.get('/static/js/app.js').get_data(as_text=True)
uijs = client.get('/static/js/ui.js').get_data(as_text=True)
mainjs = client.get('/static/js/main.js').get_data(as_text=True)
css = client.get('/static/css/app.css').get_data(as_text=True)
favicon = client.get('/static/favicon.svg').status_code

checks = {
    # ---- Shell / IA (HTML) ----
    'Sidebar nav': 'class="sidebar"' in html,
    '7 workspaces': html.count('class="workspace') >= 7,
    'Topbar': 'class="topbar"' in html,
    'Activity rail': 'activityRail' in html,
    'Tour overlay': 'tourOverlay' in html,
    'Hero banner': 'class="hero"' in html,
    'Theme toggle': 'themeToggleBtn' in html,
    'External CSS link': '/static/css/app.css' in html,
    'External JS links': '/static/js/ui.js' in html and '/static/js/app.js' in html,
    'Favicon': '/static/favicon.svg' in html,
    'No inline <style>': '<style' not in html,
    'No inline <script>': '<script>' not in html,

    # ---- Feature cards (HTML) ----
    'Crypto Panel': 'Passwordless Auth' in html,
    'ZK Panel': 'Zero-Knowledge Proof' in html,
    'QR Panel': 'QR Verification' in html,
    'Biometric Panel': 'Biometric Verification' in html,
    'Smart Contract Panel': 'Smart Contract Access Rules' in html,
    'Time Rules tab': 'Time Rules' in html,
    'Geo-fencing tab': 'Geo-fencing' in html,
    'ZK button': 'Run ZK Proof Demo' in html,
    'QR generate': 'Generate QR' in html,
    'ZK-SSI card': 'ZK Self-Sovereign Identity' in html,
    'ABAC card': 'Attribute-Based Access Control' in html,
    'dNFT card': 'Dynamic Lifecycle NFTs' in html,
    'Dual-layer card': 'Dual-Layer Encrypted Storage' in html,

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

    # ---- Init / static assets ----
    'init JS': 'initShell()' in mainjs and 'loadBlockchainData()' in mainjs,
    'CSS design tokens': '--sidebar-bg' in css,
    'CSS dark mode': 'data-theme="dark"' in css,
    'CSS responsive': '@media (max-width: 860px)' in css,
    'CSS accented cards': 'accent-zk' in css,
    'favicon served': favicon == 200,
}

import sys

all_ok = True
for name, present in checks.items():
    status = 'OK' if present else 'MISSING'
    print(f'{name}: {status}')
    if not present:
        all_ok = False

print('\n---')
print('ALL FEATURES PRESENT' if all_ok else 'SOME FEATURES MISSING')
if __name__ == '__main__':
    sys.exit(0 if all_ok else 1)