# SIH26125 - Blockchain Platform for Identity & Access Control

A complete web application demonstrating a **custom blockchain** for secure identity management and access control, built for Smart India Hackathon (SIH 2026).

## Problem Statement
**SIH26125: Blockchain Platform for Identity & Access Control** (BEL - Bharat Electronics Limited)

Build a blockchain-based system that securely manages digital identities and controls access to resources, ensuring tamper-proof records and verifiable authentication.

## Features

### 🖥️ Modern UI / UX (v6 — organisation layer)
- **Sidebar navigation** with 8 sectioned workspaces (Dashboard, Identity, Verification & ZK, Access Control, Network & IPFS, Digital Assets, Audit & Security, G-Series) — every card is one click away instead of a single endless scroll.
- **Tool groups**: the 89 cards are bucketed into 28 named, collapsible clusters (Identity Ledger, Zero-Knowledge & SSI, Role-Based Access Control, Ownership & Transfer Governance, Auditable Activities, …), each with a live tool count, a one-line purpose and a collapse toggle. A workspace-level *Collapse groups* control folds them all at once.
- **Result Console**: a single dock that watches all 104 result containers, classifies each run as GRANTED / DENIED / BLOCKED / PENDING / INFO, shows a compact verdict chip in the card with the raw output behind a disclosure, and offers outcome filters plus CSV/JSON export of the whole session. An *API Traffic* tab keeps the raw request log.
- **Command palette** (`Ctrl`/`Cmd` + `K`): fuzzy search over 8 workspaces, 89 tools, 285 button actions and 88 read-only API routes. `Enter` navigates, `Shift`+`Enter` runs the tool's primary action.
- **Identity context switcher**: set the identity once in the topbar and it propagates to the 25 identity fields across every tool; a second field sets the default resource for 6 access-control tools. The RBAC/dNFT/DID governance cards are deliberately **excluded** from auto-mirroring - each keeps its own actor field, because the point of those demos is to show the *same* request succeeding for an administrator and being refused for a `USER`.
- **Sticky command bar** (topbar): a single horizontal line that stays one line at every width — live chain status (block count, identity count, chain validity, node health) as pills, the `Ctrl`+`K` search box, the identity/resource context switcher and the console/activity/tour/theme actions. Space pressure is absorbed by shrinking the search label (ellipsis) and then the context inputs, so no label ever wraps and no control can spill past the right edge; the status pills and action buttons never squash.
- **Hash routing**: every workspace is a real route (`#/ws-access`), so a refresh or the browser back button keeps your place and links are shareable.
- **Design system**: CSS custom-property tokens, dark mode with `prefers-color-scheme` detection + persisted toggle, colour-coded accent cards for the four SIH flagship features (ZK-SSI purple, ABAC pink, dNFT orange, dual-layer teal).
- **Live activity rail**: every API call, alert and navigation is streamed into a slide-in audit log panel (shortcut `L`).
- **Guided tour**: a 7-step interactive tour overlay walks through every workspace (shortcut `T`).
- **Visualization upgrades**: rotating Proof-of-Work difficulty sparkline for the block explorer and a shake/red-flash animation + border on any tampered block.
- **States**: shimmer skeletons, empty states, aria-live alert toasts, `role="status"` on every result container, focus-visible rings, skip link, reduced-motion and forced-colors support, keyboard shortcuts (`1`–`8` jump between workspaces, `C` toggles the console, `I` opens API traffic, `L` activity, `T` tour).
- **Responsive**: off-canvas mobile drawer, collapsing status pills, single-column groups on small screens.
- **Engineering hygiene**: CSS/JS extracted from the single `templates/index.html` into `static/css/app.css`, `static/css/v6.css` and `static/js/{ui,app,main,organize,console,palette,endpoints}.js`, plus an inline SVG favicon and cache-busted asset links. `test_frontend.py` asserts 165 structural and integrity invariants (no duplicate ids, every `_gid()` target exists, every card lands in a group, the palette exposes only GET routes, the activity chip labels match the server-side labels, the top bar carries the non-wrapping declarations that keep it on one line, every workspace keeps its cards stacked one after another in a single full-width column (one `.workspace .tool-group-body` rule rather than per-workspace overrides), and the retired hero badge, dashboard purpose line and dashboard section dividers are gone).

### 🔐 Core Blockchain
- **Custom SHA-256 Blockchain** - an **immutable, proof-of-work prototype ledger** written for this project, not a general-purpose chain
- **Genesis Block** - Foundation of the chain
- **Proof-of-Work Mining** - Each new identity record requires computational work
- **Tamper Detection** - Automatically detects any modification to blocks
- **Production path:** this PoW chain is the demonstrable prototype. A production deployment would move permissioned consortium membership and endorsement to **Hyperledger Fabric** (channels, ordering service, endorsement policies, CouchDB state), keeping the same policy/gate semantics and the same on-chain audit shape.
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
- **Strengthens** RBAC rather than replacing it: RBAC stays the coarse-grained backbone (role → capability → resource), and ABAC layers fine-grained attributes on top
- Combined policy: `Access = Role ∧ Capability ∧ Resource ∧ SecurityClearance ∧ Geofence ∧ DeviceSecurityHash`
- **Geofencing**: a defence blueprint is auto-revoked when the request originates outside the BEL-certified perimeter - even for an Administrator
- **Device security hash**: requests from an untrusted endpoint are denied
- Full deterministic, auditable rule trace is returned for every decision

### 🛡️ Role-Based Access Control (RBAC), Enforced by Smart Contracts (NEW)
- Four canonical roles - `ADMINISTRATOR`, `MANAGER`, `AUDITOR`, `USER` - plus any custom role an administrator defines
- Every privileged action is gated on `role AND capability AND resource`, and **denied** calls return a structured gate trace (which leg failed, and why) instead of a bare error string
- **Deny-by-default**: an unregistered subject, or a subject with no matching grant, is not granted
- The panel exposes role → capabilities → members, role definition, role assignment and capability verification
- **Onboarding role picker**: a join request can be approved with a chosen role. Approval is gated on `identity.register`, so an **unregistered or missing approver is refused outright** - "approve with USER" is not an open door to mint identities. Granting anything above `USER` additionally requires `rbac.role.assign`, so a refused escalation leaves the request `PENDING`. A custom role may hold `identity.register` *without* `rbac.role.assign` (an HR-style approver) to onboard ordinary users while still being unable to hand out elevated roles.
- An approved applicant is minted under their **real principal** (their email), never the throwaway `pending.<hex>` handle the request carries while unresolved.

### 🔗 dNFT Ownership, DID Holders and Consent-Gated Transfer
- Minting is an **administrator capability**; a plain `USER` attempt is refused with the gate trace
- Allocation only succeeds against a **verified identity or an anchored DID** - unresolved owners are rejected
- A **DID may hold** a dNFT but can never **act** as an RBAC operator, so a self-asserted identifier cannot buy privilege
- Ownership and full lineage are resolved from the on-chain ledger, not from client state
- Transfer requires either the current owner's **cryptographic consent signature** or an administrator override that passes the full gate; consent nonces are single-use, so replays are rejected
- **A DID that owns a token authorises its own transfer** by signing the canonical consent message with the key in its anchored DID document. Because a DID carries no clearance/geofence/device attributes, the gate trace records attribute policy as *not applicable* and rests the decision on the anchored key plus the new-owner check. Forged signatures and replayed nonces are still refused, and this grants signing capability only - never operator rights.

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

## The Six Auditable Activities

Every block the ledger can produce is classified into exactly one of six auditable
activities, so an auditor can ask "show me only the ownership transfers" and get a
precise answer instead of scanning a flat log.

| Activity key | Block types it covers |
| --- | --- |
| `identity_creation` | `IDENTITY_REGISTRATION`, `DID_REGISTRATION` |
| `nft_creation` | `NFT_MINT` |
| `allocation` | `CLEARANCE_ASSIGNMENT`, `NFT_DOWNLOAD_GRANT`, `CAPABILITY_TOKEN`, `RESOURCE_GRANT_ALLOCATION` |
| `access_rights` | `RESOURCE_GRANT`, `SMART_CONTRACT_RULES`, `ABI_POLICY_UPDATE`, `PERMISSION_GRANT` |
| `ownership_transfer` | `NFT_TRANSFER`, `NFT_OWNERSHIP_VIEW` |
| `permission_update` | `RBAC_ROLE_ASSIGNED`, `RBAC_ROLE_DEFINED`, `REVOCATION`, `RBAC_OPERATOR`, `SMART_CONTRACT_GATE`, `ACCESS_DENIED` |

```
GET /api/audit/activities                  # per-activity block counts
GET /api/audit/activities?activity=nft_creation
GET /api/audit/activities?activity=ownership_transfer&limit=50
```

- Counts are returned for **all six** activities, so one that has not run yet is visible as `0` rather than silently missing.
- **Filtering is applied before the limit**, so a long demo session can never hide an activity behind a page cut-off.
- Structural blocks such as `GENESIS` are not activities and never appear in this view.
- `log_audit` preserves the caller's declared activity type in `event_type` while still writing `type: "AUDIT_LOG"`, so filtering works without breaking existing consumers.

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
| GET | `/api/audit/activities` | The six auditable activities: per-activity counts, optional `?activity=<key>` filter |
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
| POST | `/api/nft/mint` | Mint a dynamic NFT (hardware / blueprint) - admin-gated, returns a `gate` trace |
| POST | `/api/nft/state` | Advance lifecycle state via signed IoT telemetry |
| POST | `/api/nft/version` | Release a blueprint version (content hash) |
| POST | `/api/nft/grant-download` | Grant a blueprint download authorization |
| POST | `/api/nft/revoke-download` | Revoke a blueprint download authorization |
| POST | `/api/nft/download` | Authorize a download through the ABAC gate |
| POST | `/api/nft/transfer` | Transfer a dNFT - requires owner consent signature or admin override; returns a `gate` trace |
| POST | `/api/nft/ownership` | Resolve a token's owner from the chain, plus its full lineage |
| POST | `/api/nft/transfer-demo` | All six transfer-consent scenarios (anon, stranger, forged sig, signed, replay, admin) |
| POST | `/api/rbac/list` | Roles, their capabilities/resources, and current members |
| POST | `/api/rbac/define-role` | Define or update a role (admin-only, returns a `gate` trace on denial) |
| POST | `/api/rbac/assign-role` | Assign a role to a subject (admin-only, returns a `gate` trace on denial) |
| POST | `/api/rbac/verify` | Non-mutating capability check returning the role/capability/resource trace |
| POST | `/api/join/approve` | Approve a join request (gated on `identity.register`; elevated roles also need `rbac.role.assign`) |
| POST | `/api/join/reject` | Reject a join request - gated on the same `identity.register` capability, deny-by-default, HTTP 403 + `gate` trace on denial |
| POST | `/api/join/request` | Submit a self-registration; `identity_data` may be an object or a JSON string |
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

### 14. RBAC, dNFT Ownership & Auditable Activities (NEW)
- **Access Control workspace → "Role-Based Access Control Panel":** *Load Roles & Members* renders all four canonical roles with their capabilities and who holds them. *Verify Capability* evaluates a subject and shows the `role AND capability AND resource` trace. *Deny-by-Default Demo* shows an unregistered subject and a plain `USER` both refused.
- **Assign a role** as `aarav.sharma@bel.gov.in`, then set *Acting as* to `rajesh.kumar@bel.gov.in` and try **Define Custom Role** - it is refused with the failing leg named (`rbac.role.define`).
- **Digital Assets workspace → "dNFT Minting & Ownership Governance":** mint as the admin (granted), then set the actor to `rajesh.kumar@bel.gov.in` and mint again - refused, with the trace naming role `USER` and capability `nft.mint`. Set the owner to `ghost.owner@nowhere.in` to see the *ownership* leg fail.
- **"DID-Based NFT Ownership":** *Register DID* → *Mint dNFT to DID*. The minted token's on-chain owner is the `did:zk:...` string. *Check Ownership* and *Ownership Lineage* read that back from the ledger. The DID can never act as an RBAC operator, but it **can** sign consent for a token it owns.
- **"Ownership Transfer & Consent":** *Run Transfer Consent Scenarios* executes all six cases - unauthenticated, stranger, forged signature and replayed nonce are **denied**; only the genuine signed owner consent (and a full-gate admin override) is allowed. Expand a row to read that scenario's gate trace.
- **Audit & Security workspace → "Auditable Activities":** six chips filter the chain by activity, each with a live block count. Filtering runs server-side *before* the limit, and counts appear for all six so a quiet activity reads as `0` rather than disappearing.

## Project Structure
```
SIH26125-Blockchain-Identity/
├── app.py                 # Main Flask application
├── blockchain.py          # Blockchain + CryptoIdentity implementation
├── requirements.txt       # Python dependencies
├── templates/
│   └── index.html         # Frontend dashboard (app shell + 8 workspaces; no inline CSS/JS)
├── static/
│   ├── favicon.svg        # Brand favicon
│   ├── css/
│   │   ├── app.css        # Design system + app shell + dark mode + responsive
│   │   └── v6.css         # Organisation layer: groups, console, palette, context, flagship
│   └── js/
│       ├── ui.js          # Shell: utilities, activity rail, theme, nav, guided tour
│       ├── app.js         # Feature logic for all demo panels
│       ├── organize.js    # Card grouping, hash routing, identity context, workspace headers
│       ├── console.js     # Result console: verdict capture, filters, CSV/JSON export
│       ├── palette.js     # Command palette (Ctrl+K): workspaces, tools, actions, API
│       ├── endpoints.js   # GENERATED read-only route catalogue for the palette
│       └── main.js        # Bootstrap: shell → v5 → organize → console → palette → data
├── tools/
│   └── gen-endpoints.ps1  # Regenerate static/js/endpoints.js after changing app.py routes
├── venv/                  # Virtual environment (self-contained)
├── run.bat                # One-click launcher (HTTP)
├── run-https.bat          # One-click launcher (HTTPS, self-signed)
├── test_app.py            # Core blockchain tests
├── test_new_features.py   # ZK + QR feature tests
├── test_crypto.py         # Passwordless auth tests
├── test_biometric_smartcontract.py  # Biometric + smart contract tests
├── test_frontend.py       # 165 frontend structural + integrity assertions
├── test_network_ipfs.py   # Multi-node network + IPFS storage tests
├── test_advanced_features.py  # Audit, multisig, replay/escalation, revoke, schedule, encryption, ZK doc, topology, health, metrics, playbook
├── test_rbac_governance.py    # 147 RBAC / dNFT-ownership / DID-consent / six-activity / join-approval-and-rejection checks
```

Run a suite directly (there is no `pytest` in `venv`):

```powershell
venv\Scripts\python.exe test_app.py
venv\Scripts\python.exe test_rbac_governance.py
venv\Scripts\python.exe test_frontend.py
```

`test_rbac_governance.py` also imports `tests/selftest/test_rbac_ownership15.py` and
reports its 20 checks as part of its own total, so the targeted self-test can no
longer drift out of the main suite unnoticed. It also pins the two security
properties that are easy to regress silently: a DID owner must be able to sign
consent for a token it owns (while forged signatures and replayed nonces stay
refused), and **both** join approval and join rejection must be deny-by-default
on `identity.register`.

### Adding a card or a route (v6)

- **New card**: drop it in the right workspace and add its `<h2>` prefix to the
  relevant entry in `GROUPS` inside `static/js/organize.js`. If you forget, the
  card simply stays ungrouped and `test_frontend.py` fails with the offending
  title, so the drift cannot go unnoticed.
- **New route**: only GET routes are callable from the palette, because the
  palette issues them straight from the browser. After adding a route, run
  `powershell -ExecutionPolicy Bypass -File tools\gen-endpoints.ps1`.

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
| **RBAC (smart-contract enforced)** | `role AND capability AND resource`; deny-by-default for unregistered subjects |
| **Attribute-Based Refinement (ABAC)** | Clearance / geofence / device-hash constraints layered on top of RBAC |
| **dNFT Ownership Integrity** | Minting is admin-gated; ownership resolved from the ledger, never from client state |
| **Consent-Gated Transfer** | Owner signature with single-use nonce, or an administrator override that passes the same gate |
| **DID / Identity Separation** | A DID can hold a dNFT but can never resolve as an RBAC operator |
| **Explainable Denials** | Refused calls return which policy leg failed, not a bare error |
| **Activity Attribution** | Six auditable activities, filtered server-side before any limit is applied |
| **Chain Portability** | Export/import only validated chains (tampered JSON rejected) |

> **Scope note on the network rows.** *De-centralization* and *Byzantine-fault
> tolerance* are **demonstrated in a single-process simulation**: the "nodes" are
> in-memory replicas that gossip with each other inside one Python process, and
> the consensus rule (longest valid chain) is real. There is no open p2p port and
> no byzantine adversary on the network boundary. This is a faithful model of the
> algorithm, not a deployed network. A production system would use Hyperledger
> Fabric (see *Production path* above).

## Future Enhancements

- [ ] Add encryption for stored identity data
- [x] Implement multi-node consensus simulation (longest-valid-chain, malicious fork rejection)
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
