# SIH26125 - Blockchain Platform for Identity & Access Control

A complete web application demonstrating a **custom blockchain** for secure identity management and access control, built for Smart India Hackathon (SIH 2026).

## Problem Statement
**SIH26125: Blockchain Platform for Identity & Access Control** (BEL - Bharat Electronics Limited)

Build a blockchain-based system that securely manages digital identities and controls access to resources, ensuring tamper-proof records and verifiable authentication.

## Features

### 🖥️ Modern UI / UX (NEW — UI/UX upgrade)
- **Sidebar navigation** with 7 sectioned workspaces (Dashboard, Identity, Verification & ZK, Access Control, Network & IPFS, Digital Assets, Audit & Security) — every card is one click away instead of a single endless scroll.
- **Design system**: CSS custom-property tokens, dark mode with `prefers-color-scheme` detection + persisted toggle, colour-coded accent cards for the four SIH flagship features (ZK-SSI purple, ABAC pink, dNFT orange, dual-layer teal).
- **Sticky command bar** (topbar): live chain status — block count, identity count, chain validity and node health pills update automatically.
- **Live activity rail**: every API call, alert and navigation is streamed into a slide-in audit log panel (shortcut `L`).
- **Guided tour**: a 7-step interactive tour overlay walks through every workspace (shortcut `T`).
- **Visualization upgrades**: rotating Proof-of-Work difficulty sparkline for the block explorer and a shake/red-flash animation + border on any tampered block.
- **States**: shimmer skeletons, empty states, aria-live alert toasts, focus-visible rings, keyboard shortcuts (`1`–`7` jump between workspaces).
- **Responsive**: off-canvas mobile drawer, collapsing status pills, single-column cards on small screens.
- **Engineering hygiene**: CSS/JS extracted from the single `templates/index.html` into `static/css/app.css` and `static/js/{ui,app,main}.js`, plus an inline SVG favicon and cache-busted asset links.

### 🔐 Core Blockchain
- **Custom SHA-256 Blockchain** - Immutable, proof-of-work consensus
- **Genesis Block** - Foundation of the chain
- **Proof-of-Work Mining** - Each new identity record requires computational work
- **Tamper Detection** - Automatically detects any modification to blocks
- **Chain Validation** - Verifies hash integrity at every level

### 👤 Identity Management
- Register new identities (name, role, department, access level)
- Each identity gets a unique cryptographic hash
- Store identity records immutably on the blockchain
- Browse all registered identities

### 🔑 Access Control
- Assign per-identity allowed resources
- Verify identity hashes against blockchain records
- Grant/deny access to specific resources
- Full audit trail via blockchain blocks

### 🕵️ Zero-Knowledge Proofs (NEW)
- **Privacy-preserving access control**: prove you have access WITHOUT revealing your identity
- Commitment-scheme + challenge-response: verifier never sees your identity hash
- Perfect for scenarios where the verifier shouldn't know who's accessing

### 📱 QR-Based Verification (NEW)
- Generate a cryptographic, **time-limited** QR code for an identity
- Scan / verify against the blockchain - no identity hash needed to scan
- Anti-replay protection: tokens expire after 5 minutes
- Look up identities by public ID (email / ID number) without exposing the hash

### 🔐 Cryptographic Identity / Passwordless Auth (NEW)
- **RSA-2048 digital signatures** replace plaintext password hashing
- Each identity gets a private/public key pair
- **ONLY the public key** is stored on the blockchain (private stays with owner)
- Users **sign access requests** with their private key
- System verifies the signature against the on-chain public key
- **Timestamp + nonce** prevents replay attacks
- **True passwordless authentication** - no passwords, no plaintext secrets

### 🕸️ Multi-Node Distributed Network (NEW)
- **3 nodes** (node_1, node_2, node_3) simulate syncing the chain over network (localhost ports / HTTP)
- Each node maintains its **own copy** of the chain - real decentralization
- **Longest-valid-chain consensus**: a node adopts the longest chain that passes integrity validation
- **Malicious fork rejection**: a node that tampers with a block (without recomputing its hash) and tries to broadcast a forged chain is **rejected by the network** because its chain fails integrity validation
- Proves this is a distributed/decentralized system, not just "a blockchain app"

### 🗂️ IPFS Document Storage (NEW)
- Verifiable documents are stored **off-chain on IPFS** (content-addressed by a CID)
- **Only the content hash (CID)** is anchored on the blockchain - lightweight & scalable
- **Content-addressing**: the CID is a Base58-encoded SHA-256 multihash of the file content
- **Tamper detection**: re-hashing retrieved content and comparing to the CID detects any modification
- Each document add is logged on-chain as an audit block, anchoring the CID to the immutable ledger

### 📜 Merkle Roots & Proof-of-Work Difficulty Curve
- Every block exposes a **Merkle root** over its contents, shown in the block explorer
- **Difficulty curve**: difficulty 4 → 5 → 6 as the chain grows, increasing mining cost like real networks
- **Integrity score & mining stats** (nonce work, avg difficulty) surfaced on the metrics dashboard

### 🛡️ Advanced Security (NEW)
- **Multi-Signature (threshold) approval**: high-security actions require N-of-M independent signers; rejections are respected and the proposal reaches APPROVED/REJECTED/ PENDING
- **Replay attack defense**: two layers - timestamp freshness (5-min window) + signature binding over `(resource|timestamp|nonce)`
- **Privilege-escalation detection**: tampering with the on-chain access level is detected via hash mismatch and the chain is reassembled
- **Revocation / Expiry / Restore**: admins can permanently revoke or time-bind credentials; restored ones are re-enabled. State is held in a **side ledger**, so the immutable hash chain stays valid.
- **Time-lock scheduling**: access only within an `[activate_after, expire_before]` window (NOT_YET_ACTIVE / ACTIVE / EXPIRED)
- **AES/Fernet encryption**: encrypt fields on-chain - only ciphertext is stored, decryptable only with the passphrase
- **Zero-Knowledge document possession**: prove you hold a document (IPC CID) without revealing its contents

### 🪪 Zero-Knowledge Self-Sovereign Identity (DID + VC) (NEW)
- **W3C Decentralized Identifiers** (`did:zk:...`): only the public verification method is anchored on-chain - no employee id, department, or clearance in cleartext
- **Verifiable Credentials**: an issuer DID signs claims (e.g. `security_clearance: LEVEL-3`); only a **salted commitment** of the claims is stored on-chain
- **ZK predicate proofs**: the holder proves `clearance >= LEVEL-3` against a server-issued challenge - the smart contract returns only GRANTED/DENIED and **never learns which DID presented**
- Forged presentations and attempts to mint a LEVEL-3 proof from a LEVEL-1 credential are rejected

### 🧩 Attribute-Based Access Control (ABAC) via Smart Contracts (NEW)
- Replaces rigid RBAC with a dynamic policy: `Access = Role ∧ SecurityClearance ∧ Geofence ∧ DeviceSecurityHash`
- **Geofencing**: a defence blueprint is auto-revoked when the request originates outside the BEL-certified perimeter - even for an Administrator
- **Device security hash**: requests from an untrusted endpoint are denied
- Full deterministic, auditable rule trace is returned for every decision

### 🔄 Dynamic Lifecycle NFTs (ERC-1155-style dNFTs) (NEW)
- **Hardware lifecycle**: Manufactured → Deployed → Under Maintenance → Decommissioned
- **Blueprint lifecycle**: Draft → Released(vN) → Superseded → Retired, with version control + content hashes
- State advances **only** via cryptographically signed IoT telemetry (oracle); forged/illegal rollbacks are rejected
- Per-identity **download authorizations** (grant/revoke) gated by the ABAC policy; terminal assets refuse all downloads

### 🔐 Dual-Layer Encrypted Storage (NEW)
- Payloads are encrypted **client-side with AES-256-GCM** before reaching IPFS - a public CID returns only ciphertext
- The AES key is **Shamir-split across 5 threshold nodes** (any 3 reconstruct it)
- Nodes release shares **only after the smart contract verifies a ZK attribute proof** of the required clearance; fewer than 3 shares can never rebuild the key

### 🧱 Auditable, Portable, Distributed
- **On-chain audit trail**: every access-check, revocation, and schedule is a tamper-proof block with stats
- **Chain export/import**: portability / backup / node transfer (only validated chains re-import)
- **Dynamic node topology**: add / remove / bring nodes online-offline / desync live
- **Node health dashboard**: per-node status, chain divergence, consensus & Byzantine-fault tolerance (BFT) count
- **Red Team attack playbook**: one-click hash-tampering, malicious fork, replay, sniffing, and privilege-escalation scenarios, each answered by the system's defenses (BLOCKED)

## Tech Stack
- **Backend:** Python + Flask
- **Blockchain:** Custom implementation (SHA-256, proof-of-work, Merkle roots, difficulty curve)
- **Distributed Network:** Multi-node consensus (longest-valid-chain, malicious fork detection, dynamic topology, BFT)
- **Storage:** IPFS-style content-addressed document store (CID anchoring on-chain) + JSON chain portability
- **Cryptography:** RSA-2048 digital signatures (passwordless auth) + AES/Fernet symmetric encryption
- **Multi-signature:** Threshold-based cryptographic approval workflows
- **Frontend:** HTML5, CSS3, Vanilla JavaScript
- **API:** RESTful JSON endpoints

## Installation & Setup

### Prerequisites
- Python 3.8+

### 1. Install Dependencies
```bash
cd SIH26125-Blockchain-Identity
py -m pip install -r requirements.txt
```

### 2. Run the Application

**Quick start (HTTP):**
```bash
py app.py
```

**Quick start (HTTPS — removes the browser "Not secure" badge):**
```bash
py app.py --https        # or double-click run-https.bat
```

### 3. Access the Dashboard
Open your browser and go to: **http://localhost:8080** (or `https://localhost:8080` in HTTPS mode).

> **Why "Not secure"?** Browsers label any plain-HTTP site "Not secure"; the label
> is especially visible on LAN IPs (e.g. `http://192.168.x.x:8080`) and in Firefox.
> `localhost` is treated as trusted by Chrome/Edge, so it shows the fewest warnings.
> For a fully **encrypted** connection that removes the badge entirely, run with
> `py app.py --https` and open `https://localhost:8080` — the site uses a local
> self-signed certificate, so click **Advanced → Proceed to site** once on the
> first visit.

### Run Flags
| Flag | Purpose |
|------|---------|
| `--https` | Serve over TLS with a self-signed certificate |
| `--host=<ip>` | Bind to a specific interface (default `0.0.0.0`) |
| `--port=<port>` | Change the port (default `8080`) |
| `--no-browser` | Do not auto-open the browser on startup |
| `--no-reload` | Disable the debug auto-reloader (single-process server) |

> The browser opens automatically at the correct URL/scheme on startup **once the
> server is actually listening** (it waits for the port to respond before opening),
> and if port `8080` is already in use it automatically picks the next free port
> (`8081`, `8082`, …) and opens that. If you ever see **"cannot connect to the
> server"**, note the `Open this:` URL printed in the terminal and open exactly
> that — plain `python app.py` is HTTP (not HTTPS), and the port may have shifted.
> Leftover servers from earlier runs can be cleared with
> `Get-Process python | Stop-Process -Force` in PowerShell.

## How It Works

### Blockchain Architecture
```
┌─────────────────────────────────────────────────┐
│              Block Chain Structure             │
├─────────────────────────────────────────────────┤
│  Genesis Block  →  Block 1  →  Block 2  → ...  │
│  [data: genesis]  [identity]  [identity]       │
│  [hash: 0]        [hash]      [hash]           │
│                   [prev: 0]   [prev: hash1]    │
└─────────────────────────────────────────────────┘
```

Each block contains:
- **Index** - Position in the chain
- **Timestamp** - When the block was created
- **Data** - Identity registration record
- **Previous Hash** - Hash of the previous block
- **Nonce** - Proof-of-work value
- **Hash** - SHA-256 of all block contents

### Security Properties
1. **Immutability** - Changing any block data breaks all subsequent hashes
2. **Decentralization** - No single point of failure
3. **Transparency** - All identity records are auditable
4. **Verifiability** - Anyone can recompute and verify hashes

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/` | Main dashboard |
| GET | `/api/blockchain/info` | Blockchain statistics |
| GET | `/api/identities` | List all identities |
| POST | `/api/identities/add` | Register new identity |
| POST | `/api/identities/verify` | Verify identity hash |
| POST | `/api/access/check` | Check access permission |
| GET | `/api/blockchain/chain` | Full blockchain data |
| GET | `/api/blockchain/validate` | Validate chain integrity |
| POST | `/api/blockchain/tamper` | Simulate tampering (demo) |
| POST | `/api/blockchain/reset` | Reset blockchain |
| POST | `/api/zkp/prove` | Generate ZK proof of access |
| POST | `/api/zkp/verify` | Verify ZK proof (no identity revealed) |
| POST | `/api/zkp/demo` | Run full ZK proof demo |
| POST | `/api/qr/generate` | Generate QR payload (by public ID) |
| POST | `/api/qr/verify` | Verify scanned QR payload |
| POST | `/api/qr/generate-from-hash` | Generate QR from identity hash |
| POST | `/api/crypto/register` | Register crypto identity (keypair, pub on-chain) |
| POST | `/api/crypto/sign` | Sign access request with private key |
| POST | `/api/crypto/auth` | Verify signed request (passwordless auth) |
| POST | `/api/crypto/demo` | Full end-to-end passwordless demo |
| GET | `/api/network/status` | Status of all distributed nodes |
| GET | `/api/network/node/<id>/chain` | Get a specific node's chain |
| POST | `/api/network/sync` | Simulate chain sync between nodes (HTTP) |
| POST | `/api/network/malicious-fork` | Simulate malicious fork attack |
| POST | `/api/network/consensus-check` | Run distributed consensus across nodes |
| POST | `/api/ipfs/add` | Add document to IPFS (CID stored on-chain) |
| GET | `/api/ipfs/get/<cid>` | Retrieve & verify document by CID |
| GET | `/api/ipfs/list` | List documents on IPFS network |
| POST | `/api/ipfs/verify` | Verify content matches a CID |
| POST | `/api/ipfs/tamper` | Simulate document tampering (demo) |
| GET | `/api/attacks/replay` | Run replay-attack simulation (blocked) |
| POST | `/api/attacks/escalation` | Run privilege-escalation simulation (blocked) |
| POST | `/api/multisig/create` | Create a multi-signature proposal |
| POST | `/api/multisig/sign` | Approve / reject a proposal |
| GET | `/api/multisig/list` | List all proposals |
| POST | `/api/schedule/set` | Set a time-locked access window |
| POST | `/api/schedule/check` | Evaluate a time-lock window |
| POST | `/api/encrypt/encrypt` | Encrypt a value (AES/Fernet) |
| POST | `/api/encrypt/decrypt` | Decrypt a previously encrypted value |
| POST | `/api/encrypt/store` | Store an encrypted field on-chain |
| GET | `/api/chain/export` | Export the chain as portable JSON |
| POST | `/api/chain/import` | Import & validate a chain JSON |
| GET | `/api/audit/trail` | Retrieve the on-chain audit trail + stats |
| POST | `/api/identity/revoke` | Permanently revoke an identity |
| POST | `/api/identity/expire` | Set an expiry time on credentials |
| POST | `/api/identity/restore` | Restore a revoked/expired identity |
| POST | `/api/zk/possession/prove` | Generate ZK document-possession proof |
| POST | `/api/zk/possession/verify` | Verify a ZK possession proof |
| POST | `/api/network/topology` | Dynamic topology (add/remove/online/offline/desync) |
| GET | `/api/network/health` | Node health / divergence dashboard |
| GET | `/api/metrics` | Quantitative consensus & security metrics |
| POST | `/api/playbook` | Run a Red Team attack scenario (blocked verdict) |
| GET | `/api/did/challenge` | Issue a single-use challenge for a ZK presentation |
| POST | `/api/did/register` | Register a W3C DID (public verification method on-chain) |
| GET | `/api/did/list` | List registered DIDs |
| POST | `/api/did/issue` | Issue a Verifiable Credential (commitment anchored on-chain) |
| POST | `/api/did/present` | Build a ZK attribute presentation for a predicate |
| POST | `/api/did/verify` | Verify a ZK presentation (identity never disclosed) |
| POST | `/api/did/full-demo` | Full ZK-SSI demo (issuer/subject/attacker) |
| POST | `/api/abac/register-device` | Register a BEL-certified device hash for an identity |
| POST | `/api/abac/set-clearance` | Assign a security-clearance attribute |
| POST | `/api/abac/evaluate` | Evaluate `Role ∧ Clearance ∧ Geofence ∧ DeviceHash` |
| POST | `/api/abac/demo` | Full ABAC demo (all four attributes) |
| POST | `/api/nft/mint` | Mint a dynamic NFT (hardware / blueprint) |
| POST | `/api/nft/state` | Advance lifecycle state via signed IoT telemetry |
| POST | `/api/nft/version` | Release a blueprint version (content hash) |
| POST | `/api/nft/grant-download` | Grant a blueprint download authorization |
| POST | `/api/nft/revoke-download` | Revoke a blueprint download authorization |
| POST | `/api/nft/download` | Authorize a download through the ABAC gate |
| POST | `/api/nft/transfer` | Transfer a dNFT to a new owner |
| GET | `/api/nft/list` | List all minted dNFTs |
| POST | `/api/nft/get` | Get a single dNFT by token id |
| POST | `/api/nft/demo` | Full dNFT lifecycle demo |
| POST | `/api/encipfs/add` | Encrypt (AES-256-GCM) + publish to IPFS, split key |
| GET | `/api/encipfs/list` | List encrypted documents |
| POST | `/api/encipfs/peek` | Show that only ciphertext is publicly visible |
| POST | `/api/encipfs/retrieve` | Unlock via a verified ZK attribute proof |
| POST | `/api/encipfs/demo` | Full dual-layer storage demo |

## Demo Walkthrough

### 1. Register an Identity
- Fill in the registration form
- Click "Register & Mine on Blockchain"
- System generates a unique identity hash
- New block is mined and added to the chain

### 2. Verify an Identity
- Paste any identity hash
- System checks the blockchain for the record
- Returns name, role, and block location

### 3. Test Access Control
- Enter an identity hash
- Select a resource to check
- System verifies the identity has permission

### 4. Advanced Security Demo
- Use `/api/blockchain/tamper` to modify a block
- The chain status changes to "TAMPERED"
- All subsequent access checks fail

### 5. Zero-Knowledge Proof Demo
- Go to the "Advanced Verification" card → "Zero-Knowledge Proof" tab
- Enter your identity hash (it stays private!) + a resource
- Click "Run ZK Proof Demo"
- System proves access WITHOUT the verifier seeing your identity hash

### 6. QR Verification Demo
- Switch to the "QR Verification" tab
- Enter a public ID: `aarav.sharma@bel.gov.in` (has admin access)
- Select `admin_dashboard` resource → "Generate QR"
- A QR code appears (expires in 5 min)
- Click "Verify QR" - it scans against the blockchain and confirms access
- Try a resource Aarav doesn't have → verification fails

### 7. Passwordless Auth Demo (NEW)
- Go to the "Advanced Verification" card (first tab: "Passwordless Auth")
- Click **"Run Passwordless Auth Demo"**
- Watch the system:
  1. Register a fresh crypto identity (RSA keypair)
  2. Sign an access request with the private key
  3. Verify the signature against the on-chain public key
- Note: **NO password was ever used** - the identity is proven cryptographically
- The private key is shown once (in reality it would stay secret on the user's device)

**Try the full flow yourself:**
1. **Register:** POST `/api/crypto/register` → get a private key
2. **Sign:** POST `/api/crypto/sign` with that private key
3. **Auth:** POST `/api/crypto/auth` → server verifies signature → access granted
4. **Forge test:** Try signing with a *different* key → verification FAILS (proves security)

### 8. Multi-Node Distributed Network Demo (NEW)
- Go to the **"Multi-Node Distributed Network"** card
- **Network Status:** Load it to see all 3 nodes (node_1/2/3) each holding a valid copy of the chain
- **Sync Nodes:** node_1 broadcasts its (longer) chain → node_2 validates and adopts it (longest-valid-chain consensus)
- **Malicious Fork:** node_3 tampers with a block *without* recomputing its hash, then broadcasts its forged chain → **the network rejects it** because integrity validation fails
- **Impact:** proves real decentralization and Byzantine-fault tolerance

### 9. IPFS Document Storage Demo (NEW)
- Go to the **"IPFS Document Storage"** card
- **Add Document:** type some content → "Add to IPFS" → a **CID** (hash) is returned and anchored on-chain
- Note only the hash is stored on the blockchain (off-chain content, lightweight & scalable)
- **Verify:** paste the CID → "Verify" → content re-hashed and matched against CID → **AUTHENTIC**
- **Simulate Tampering:** tampers the document content → re-verify → the hash no longer matches → **TAMPERED** (integrity failure detected)

### 10. Audit Trail & Advanced Security Demo (NEW)
- Go to the **"Audit Trail & Advanced Security"** card
- **Audit:** "Load On-Chain Audit Trail" - view every access attempt, decision, and reason as blocks, plus GRANTED/DENIED stats
- **Revoke / Expire / Restore:** enter a public ID (e.g. `priya.patel@bel.gov.in`), then revoke → expired → restore. The identity's access is blocked/restored, and the chain **stays valid** (state lives in a side ledger, not by corrupting blocks)
- **Multi-Sig:** create a proposal requiring a threshold of signers, then approve/reject from the buttons; watch it reach APPROVED only after enough independent approvals
- **Time-Lock:** set an `[activate → expire]` window, then check it - stages NOT_YET_ACTIVE / ACTIVE / EXPIRED
- **Encryption:** encrypt a value, then decrypt with the same passphrase; ciphertext (not plaintext) is what's anchored
- **ZK Doc:** prove possession of a document CID without revealing it, then verify with the proof (wrong CID → rejected)

### 11. Red Team Attack Playbook Demo (NEW)
- Go to the **"Red Team Attack Playbook"** card
- Click each attack and watch the system's verdict:
  - **Hash Tampering / Escalation** → BLOCKED (hash mismatch)
  - **Malicious Fork** → BLOCKED (other nodes reject the forged chain)
  - **Replay** → BLOCKED (timestamp freshness + signature binding)
  - **Secret Sniffing** → BLOCKED (everything sensitive is hashed/encrypted)
  - **Privilege Escalation** → BLOCKED (on-chain record edit detected)

### 12. Chain Portability Demo (NEW)
- Go to the **"Chain Portability (Export/Import)"** card
- **Export:** grab the full chain as JSON (for backup / node transfer)
- **Import:** paste it back → only valid chains re-import; tampered JSON is rejected
- **Impact:** proves the chain can move across nodes and survive the network sync

### 13. Network Topology, Health & Metrics (NEW)
- **Multi-Node Distributed Network → Topology tab:** add `/api/network/topology` with node_4, take it offline/online, or desync it
- **Health tab:** "Load Node Health" - per-node status, chain divergence, and network consensus (SYNCED/DIVERGED)
- **Network & Consensus Metrics card:** integrity score, avg difficulty, nonce work, BFT tolerance (tolerates `(n-1)/2` Byzantine faults)
- **Block explorer:** each block now shows its Merkle root; click a block for difficulty + full details

## Project Structure
```
SIH26125-Blockchain-Identity/
├── app.py                 # Main Flask application
├── blockchain.py          # Blockchain + CryptoIdentity implementation
├── requirements.txt       # Python dependencies
├── templates/
│   └── index.html         # Frontend dashboard (app shell + 7 workspaces; no inline CSS/JS)
├── static/
│   ├── favicon.svg        # Brand favicon
│   ├── css/
│   │   └── app.css        # Design system + app shell + dark mode + responsive
│   └── js/
│       ├── ui.js          # Shell: utilities, activity rail, theme, nav, guided tour
│       ├── app.js         # Feature logic for all demo panels
│       └── main.js        # Bootstrap (init shell + load blockchain data)
├── venv/                  # Virtual environment (self-contained)
├── run.bat                # One-click launcher (HTTP)
├── run-https.bat          # One-click launcher (HTTPS, self-signed)
├── test_app.py            # Core blockchain tests
├── test_new_features.py   # ZK + QR feature tests
├── test_crypto.py         # Passwordless auth tests
├── test_biometric_smartcontract.py  # Biometric + smart contract tests
├── test_frontend.py       # Frontend feature presence tests
├── test_network_ipfs.py   # Multi-node network + IPFS storage tests
└── test_advanced_features.py  # Audit, multisig, replay/escalation, revoke, schedule, encryption, ZK doc, topology, health, metrics, playbook
```

## Security Model

| Security Property | How It's Achieved |
|-------------------|-------------------|
| **Immutability** | SHA-256 block chaining + proof-of-work |
| **Passwordless Auth** | RSA-2048 digital signatures (no passwords) |
| **Private Key Security** | Private key NEVER stored on chain - only public key |
| **Replay Protection** | Timestamp + nonce in every signed request |
| **Privacy (ZK)** | Prove access without revealing identity hash |
| **Tamper Detection** | Any block change breaks the entire chain |
| **QR Anti-Replay** | Time-limited (5 min) cryptographic tokens |
| **De-centralization** | Multi-node network with longest-valid-chain consensus |
| **Byzantine-Fault Tolerance** | Malicious forks rejected by integrity validation |
| **Document Integrity (IPFS)** | Content-addressed CIDs, tamper detection via re-hashing |
| **Multi-Signature Governance** | N-of-M threshold approvals for high-security actions |
| **Replay Defense (2-layer)** | Timestamp freshness (5-min) + signature binding over (resource\|ts\|nonce) |
| **Escalation Detection** | Access-level tamper breaks block hash → detected, chain reassembled |
| **Revocation / Expiry** | Admin revocation & time-bound credentials; side-ledger keeps chain valid |
| **Time-Lock Scheduling** | Access only inside an `[activate → expire]` window |
| **Data-at-Rest Encryption** | AES/Fernet - only ciphertext anchored on-chain |
| **ZK Document Possession** | Prove CID ownership without revealing contents |
| **On-Chain Auditability** | Every access/revoke/schedule is an immutable audit block |
| **Chain Portability** | Export/import only validated chains (tampered JSON rejected) |

## Future Enhancements

- [ ] Add encryption for stored identity data
- [x] Implement multi-node consensus (longest-valid-chain, malicious fork rejection)
- [x] Add IPFS off-chain document storage (CID anchoring)
- [ ] Integration with government digital identity (Aadhaar)
- [ ] Smart contracts for automated access rules
- [ ] REST API with JWT authentication
- [ ] Real-time blockchain monitoring dashboard
- [ ] Mobile application for field verification

## Presentation Tips for SIH

1. **Demo-first:** Show a live identity registration and mining
2. **Security demo:** Demonstrate tamper detection (it's visually impressive)
3. **Real-world scenario:** Explain how BEL would use this for secure device access
4. **Scalability:** Discuss how the architecture scales to production
5. **Uniqueness:** Emphasize the custom blockchain (not just "using blockchain")

## Troubleshooting

### Port already in use
```bash
# Change port in app.py (last line)
app.run(debug=True, host='0.0.0.0', port=5001)
```

### Python not found
Using Windows, use `py` instead of `python`:
```bash
py app.py
```

---

**Built for Smart India Hackathon 2026 | SIH26125** 🚀
