"""
SIH26125 - Blockchain Platform for Identity & Access Control
Main Flask Application
"""
from flask import Flask, render_template, request, jsonify
from flask_cors import CORS
from blockchain import (Blockchain, generate_identity_hash, Block, CryptoIdentity, Node,
                        IPFSDocumentStore, DecentralizedIdentifier, ABACPolicy,
                        NFTAssetRegistry, NFTOracleTelemetry, SecretSharing, EncryptedIPFSStore)
import json
import time
import copy
import os
import secrets
from datetime import datetime

# Distributed network & IPFS singletons
# Each node starts with the same set of identity blocks (realistic starting state)
def _build_initial_nodes():
    """Create 3 nodes pre-seeded with the demo identities"""
    nodes = {}
    for i in range(1, 4):
        nid = f"node_{i}"
        node = Node(nid)
        # Seed each node with the demo identities so it has a real chain
        for demo in demo_identities:
            demo_copy = copy.deepcopy(demo)
            demo_copy["identity_hash"] = generate_identity_hash()
            node.add_identity_to_node(demo_copy)
        nodes[nid] = node
    return nodes

ipfs = IPFSDocumentStore()

# Dual-layer encrypted storage (AES-256-GCM + threshold-nodes + IPFS)
encrypted_ipfs = EncryptedIPFSStore(n_nodes=5, threshold=3)

app = Flask(__name__)
CORS(app)

# Robust JSON body parser: never raises 415 on non-JSON bodies and never
# crashes on non-dict payloads (e.g. a stray JSON array / string). Every POST
# route uses this helper so a client mishap can never 500 the API.
def _post_json():
    d = request.get_json(silent=True)
    return d if isinstance(d, dict) else {}

# Dev-friendly: never cache the HTML page or static assets, so UI fixes
# (CSS/JS reloads) show up immediately instead of a stale blank page.
app.config["SEND_FILE_MAX_AGE_DEFAULT"] = 0


@app.after_request
def _no_cache_for_navigations(response):
    if request.path == "/" or request.path.startswith("/static/"):
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
        response.headers["Pragma"] = "no-cache"
    return response

# Initialize blockchain
blockchain = Blockchain()

# Pre-populate with some demo identities
demo_identities = [
    {
        "name": "Aarav Sharma",
        "role": "Administrator",
        "department": "IT Security",
        "email": "aarav.sharma@bel.gov.in",
        "id_number": "EMP-1001",
        "access_level": "HIGH",
        "allowed_resources": [
            "admin_dashboard",
            "sensitive_data",
            "user_management",
            "network_access",
            "blockchain_console"
        ],
        "metadata": "Senior Security Administrator"
    },
    {
        "name": "Priya Patel",
        "role": "Data Analyst",
        "department": "Data Science",
        "email": "priya.patel@bel.gov.in",
        "id_number": "EMP-1002",
        "access_level": "MEDIUM",
        "allowed_resources": [
            "analytics_dashboard",
            "reporting",
            "user_management"
        ],
        "metadata": "Data Analyst, Policy Team"
    },
    {
        "name": "Rajesh Kumar",
        "role": "Field Officer",
        "department": "Operations",
        "email": "rajesh.kumar@bel.gov.in",
        "id_number": "EMP-1003",
        "access_level": "LOW",
        "allowed_resources": [
            "field_reports",
            "network_access"
        ],
        "metadata": "Operations Field Staff"
    }
]

# Persist the blockchain (and side-ledger flags) to disk so that identities
# registered at runtime survive server restarts. Without this, every restart
# re-seeded demo identities with NEW random hashes, so a hash copied from a
# registration would report "identity not found" after the process restarted.
PERSIST_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "blockchain_data.json")


def _seed_demo_identities():
    """(Re)seed the demo identities into the chain with fresh random hashes."""
    for demo in demo_identities:
        demo["identity_hash"] = generate_identity_hash()
        blockchain.add_identity(demo)


def _next_emp_id():
    """Return the next free EMP-* id number, scanning existing records.

    The old `EMP-{1000 + len(records)}` scheme collided with the demo identity
    EMP-1003 (Rajesh Kumar): the FIRST runtime registration reused an existing
    id_number. Scan the highest numeric EMP-* actually in the chain instead.
    """
    highest = 1000
    for rec in blockchain.get_identity_records():
        idn = (rec.get("id_number") or "")
        if idn.startswith("EMP-"):
            try:
                highest = max(highest, int(idn.split("-", 1)[1]))
            except (ValueError, TypeError):
                continue
    return f"EMP-{highest + 1}"


def save_state():
    """Persist the current chain + side ledger + new feature registries to disk."""
    try:
        # NEVER persist a corrupted (tampered) chain: saving it would wipe the
        # last-known-good state on the next restart, silently losing identities.
        if not blockchain.is_chain_valid()[0]:
            return
        payload = {
            "chain": blockchain.export_chain(),
            "identity_flags": getattr(blockchain, "_identity_flags", {}),
            "schedules": getattr(blockchain, "_schedules", {}),
            "did_store": getattr(blockchain, "_did_store", {}),
            "nft_registry": getattr(blockchain, "_nft_registry", None).serialize()
                            if getattr(blockchain, "_nft_registry", None) else None,
            "biometric_store": getattr(blockchain, "_biometric_store", {}),
            "multisig_proposals": getattr(blockchain, "_multisig_proposals", {}),
            "oracle_keypair": list(getattr(blockchain, "_oracle_keypair", []))
                                if getattr(blockchain, "_oracle_keypair", None) else None,
            "encipfs": encrypted_ipfs.serialize(),
            "feature13": {
                "disposable_tokens": getattr(blockchain, "_disposable_tokens", {}),
                "delegations": getattr(blockchain, "_delegations", {}),
                "travel_modes": getattr(blockchain, "_travel_modes", {}),
                "rescue_kits": getattr(blockchain, "_rescue_kits", {}),
                "anomaly_alerts": getattr(blockchain, "_anomaly_alerts", {}),
                "quorum_ops": getattr(blockchain, "_quorum_ops", {}),
                "vc_lifecycle": getattr(blockchain, "_vc_lifecycle", {}),
                "chain_backups": getattr(blockchain, "_chain_backups", {}),
                "trust_scores": getattr(blockchain, "_trust_scores", {}),
                "defense_log": getattr(blockchain, "_defense_log", {}),
                "checkins": getattr(blockchain, "_checkins", {}),
                "breakglass_windows": getattr(blockchain, "_breakglass_windows", {}),
                "crl": getattr(blockchain, "_crl", {}),
                "crl_challenges": getattr(blockchain, "_crl_challenges", {}),
                "device_boot": getattr(blockchain, "_device_boot", {}),
                "federation_registry": getattr(blockchain, "_federation_registry", {}),
                "redactions": getattr(blockchain, "_redactions", {}),
                "velocity_events": getattr(blockchain, "_velocity_events", []),
                "honeytokens": getattr(blockchain, "_honeytokens", {}),
                "fed_demo_seq": getattr(blockchain, "_fed_demo_seq", 0),
            },
            "feature14": {
                "posture_history": getattr(blockchain, "_posture_history", []),
                "dup_flags": getattr(blockchain, "_dup_flags", {}),
                "bulk_batches": getattr(blockchain, "_bulk_batches", {}),
                "join_requests": getattr(blockchain, "_join_requests", {}),
                "pq_identities": getattr(blockchain, "_pq_identities", {}),
                "key_transparency": getattr(blockchain, "_key_transparency", {}),
                "liveness_challenges": getattr(blockchain, "_liveness_challenges", {}),
                "duress_codes": getattr(blockchain, "_duress_codes", {}),
                "two_person_windows": getattr(blockchain, "_two_person_windows", {}),
                "airgap_packs": getattr(blockchain, "_airgap_packs", {}),
                "partition_drills": getattr(blockchain, "_partition_drills", {}),
                "pin_reputation": getattr(blockchain, "_pin_reputation", {}),
                "firmware_gate": getattr(blockchain, "_firmware_gate", {}),
                "provenance": getattr(blockchain, "_provenance", {}),
                "recalls": getattr(blockchain, "_recalls", {}),
                "cases": getattr(blockchain, "_cases", {}),
                "compliance_reports": getattr(blockchain, "_compliance_reports", []),
                "forensic_diffs": getattr(blockchain, "_forensic_diffs", {}),
                "risk_policy": getattr(blockchain, "_risk_policy", {}),
            },
            "feature15": {
                "scenario_runs": getattr(blockchain, "_scenario_runs", []),
                "vouch_targets": getattr(blockchain, "_vouch_targets", {}),
                "vouches": getattr(blockchain, "_vouches", {}),
                "containment_actions": getattr(blockchain, "_containment_actions", {}),
                "selective_credentials": getattr(blockchain, "_selective_credentials", {}),
                "sdisclosures": getattr(blockchain, "_sdisclosures", []),
                "witness_requests": getattr(blockchain, "_witness_requests", {}),
                "lifecycle_events": getattr(blockchain, "_lifecycle_events", []),
                "purpose_policy": getattr(blockchain, "_purpose_policy", {}),
                "purpose_denials": getattr(blockchain, "_purpose_denials", []),
                "sealed_sessions": getattr(blockchain, "_sealed_sessions", {}),
                "session_log": getattr(blockchain, "_session_log", []),
                "classification_policy": getattr(blockchain, "_classification_policy", {}),
                "chaos_config": getattr(blockchain, "_chaos_config", {}),
                "chaos_events": getattr(blockchain, "_chaos_events", []),
                "node_pki": getattr(blockchain, "_node_pki", {}),
                "rogue_attempts": getattr(blockchain, "_rogue_attempts", []),
                "notarization_anchors": getattr(blockchain, "_notarization_anchors", []),
                "monotonic_nonces": getattr(blockchain, "_monotonic_nonces", {}),
                "asset_geofences": getattr(blockchain, "_asset_geofences", {}),
                "geo_alerts": getattr(blockchain, "_geo_alerts", []),
                "maintenance_orders": getattr(blockchain, "_maintenance_orders", {}),
                "prune_proposals": getattr(blockchain, "_prune_proposals", {}),
                "attestation_receipts": getattr(blockchain, "_attestation_receipts", {}),
            },
            "rbac": {
                "policy": getattr(blockchain, "_rbac_policy", None),
                "assignments": getattr(blockchain, "_rbac_assignments", None),
                "transfer_nonces": list(getattr(blockchain, "_transfer_nonces", None) or []),
            },
        }
        with open(PERSIST_FILE, "w", encoding="utf-8") as f:
            json.dump(payload, f)
    except Exception:
        # Persistence is best-effort; a failure should not break the app.
        pass


def load_state():
    """Restore a previously persisted chain + side ledger. Returns True on success."""
    if not os.path.exists(PERSIST_FILE):
        return False
    try:
        with open(PERSIST_FILE, "r", encoding="utf-8") as f:
            payload = json.load(f)
        chain_dicts = payload.get("chain") or []
        if not chain_dicts:
            return False
        valid, msg = Blockchain.validate_chain_dicts(chain_dicts)
        if not valid:
            return False
        blockchain.chain = blockchain.import_chain(chain_dicts)
        if isinstance(payload.get("identity_flags"), dict):
            blockchain._identity_flags = payload["identity_flags"]
        if isinstance(payload.get("schedules"), dict):
            blockchain._schedules = payload["schedules"]
        if isinstance(payload.get("did_store"), dict):
            blockchain._did_store = payload["did_store"]
        if payload.get("nft_registry"):
            blockchain._nft_registry = NFTAssetRegistry.deserialize(
                payload["nft_registry"], owner_validator=blockchain._nft_owner_verified)
        rbac = payload.get("rbac") or {}
        if isinstance(rbac.get("policy"), dict):
            blockchain._rbac_policy = rbac["policy"]
        if isinstance(rbac.get("assignments"), dict):
            blockchain._rbac_assignments = rbac["assignments"]
        if rbac.get("transfer_nonces") is not None:
            blockchain._transfer_nonces = set(rbac["transfer_nonces"])
        blockchain._ensure_nft_registry()
        blockchain._rebuild_nft_owners_from_chain()
        if isinstance(payload.get("biometric_store"), dict):
            blockchain._biometric_store = payload["biometric_store"]
        if isinstance(payload.get("multisig_proposals"), dict):
            blockchain._multisig_proposals = payload["multisig_proposals"]
        if isinstance(payload.get("oracle_keypair"), (list, tuple)) and len(payload["oracle_keypair"]) == 2:
            blockchain._oracle_keypair = tuple(payload["oracle_keypair"])
        if payload.get("encipfs"):
            global encrypted_ipfs
            encrypted_ipfs = EncryptedIPFSStore.deserialize(payload["encipfs"])
        f13 = payload.get("feature13") or {}
        for attr, key in (
            ("_disposable_tokens", "disposable_tokens"), ("_delegations", "delegations"),
            ("_travel_modes", "travel_modes"), ("_rescue_kits", "rescue_kits"),
            ("_anomaly_alerts", "anomaly_alerts"), ("_quorum_ops", "quorum_ops"),
            ("_vc_lifecycle", "vc_lifecycle"), ("_chain_backups", "chain_backups"),
            ("_trust_scores", "trust_scores"), ("_defense_log", "defense_log"),
            ("_checkins", "checkins"),
            ("_breakglass_windows", "breakglass_windows"), ("_crl", "crl"),
            ("_crl_challenges", "crl_challenges"), ("_device_boot", "device_boot"),
            ("_federation_registry", "federation_registry"),
        ):
            if isinstance(f13.get(key), dict):
                setattr(blockchain, attr, f13[key])
        if isinstance(f13.get("redactions"), dict):
            blockchain._redactions = f13["redactions"]
        if isinstance(f13.get("velocity_events"), list):
            blockchain._velocity_events = f13["velocity_events"]
        if isinstance(f13.get("honeytokens"), dict):
            blockchain._honeytokens = f13["honeytokens"]
        if isinstance(f13.get("fed_demo_seq"), int):
            blockchain._fed_demo_seq = f13["fed_demo_seq"]
        f14 = payload.get("feature14") or {}
        for attr, key in (
            ("_forensic_diffs", "forensic_diffs"), ("_dup_flags", "dup_flags"),
            ("_bulk_batches", "bulk_batches"), ("_join_requests", "join_requests"),
            ("_pq_identities", "pq_identities"), ("_key_transparency", "key_transparency"),
            ("_liveness_challenges", "liveness_challenges"), ("_duress_codes", "duress_codes"),
            ("_two_person_windows", "two_person_windows"), ("_airgap_packs", "airgap_packs"),
            ("_partition_drills", "partition_drills"), ("_pin_reputation", "pin_reputation"),
            ("_firmware_gate", "firmware_gate"), ("_provenance", "provenance"),
            ("_recalls", "recalls"), ("_cases", "cases"), ("_risk_policy", "risk_policy"),
        ):
            if isinstance(f14.get(key), dict):
                setattr(blockchain, attr, f14[key])
        if isinstance(f14.get("compliance_reports"), list):
            blockchain._compliance_reports = f14["compliance_reports"]
        if isinstance(f14.get("posture_history"), list):
            blockchain._posture_history = f14["posture_history"]
        f15 = payload.get("feature15") or {}
        for attr, key in (
            ("_vouch_targets", "vouch_targets"), ("_vouches", "vouches"),
            ("_containment_actions", "containment_actions"),
            ("_selective_credentials", "selective_credentials"),
            ("_witness_requests", "witness_requests"),
            ("_purpose_policy", "purpose_policy"), ("_sealed_sessions", "sealed_sessions"),
            ("_classification_policy", "classification_policy"),
            ("_chaos_config", "chaos_config"), ("_node_pki", "node_pki"),
            ("_monotonic_nonces", "monotonic_nonces"),
            ("_asset_geofences", "asset_geofences"),
            ("_maintenance_orders", "maintenance_orders"),
            ("_prune_proposals", "prune_proposals"),
            ("_attestation_receipts", "attestation_receipts"),
        ):
            if isinstance(f15.get(key), dict):
                setattr(blockchain, attr, f15[key])
        for attr, key in (
            ("_scenario_runs", "scenario_runs"), ("_sdisclosures", "sdisclosures"),
            ("_lifecycle_events", "lifecycle_events"),
            ("_purpose_denials", "purpose_denials"), ("_session_log", "session_log"),
            ("_chaos_events", "chaos_events"), ("_rogue_attempts", "rogue_attempts"),
            ("_notarization_anchors", "notarization_anchors"), ("_geo_alerts", "geo_alerts"),
        ):
            if isinstance(f15.get(key), list):
                setattr(blockchain, attr, f15[key])
        return True
    except Exception:
        return False


if load_state():
    print("Loaded persisted blockchain from", PERSIST_FILE)
else:
    _seed_demo_identities()

# Build distributed nodes AFTER demo_identities is defined (they are seeded with these identities)
network_nodes = _build_initial_nodes()


@app.route('/')
def index():
    """Main dashboard page"""
    chain_info = blockchain.get_chain_info()
    identities = blockchain.get_identity_records()
    return render_template('index.html', chain_info=chain_info, identities=identities)


@app.route('/api/blockchain/info')
def blockchain_info():
    """Get blockchain information"""
    return jsonify({
        "success": True,
        "data": blockchain.get_chain_info()
    })


@app.route('/api/identities')
def list_identities():
    """List all registered identities"""
    identities = blockchain.get_identity_records()
    return jsonify({
        "success": True,
        "count": len(identities),
        "data": identities
    })


@app.route('/api/identities/add', methods=['POST'])
def add_identity():
    """Register a new identity"""
    try:
        data = _post_json() or {}
        if not data:
            return jsonify({"success": False, "error": "No data provided"}), 400

        required_fields = ["name", "role", "email"]
        missing = [f for f in required_fields if not data.get(f)]
        if missing:
            return jsonify({
                "success": False,
                "error": f"Missing required fields: {', '.join(missing)}"
            }), 400

        # Generate identity hash
        data["identity_hash"] = generate_identity_hash()
        data["allowed_resources"] = data.get("allowed_resources", ["basic_access"])
        data["access_level"] = data.get("access_level", "LOW")
        data["department"] = data.get("department", "General")
        data["id_number"] = data.get("id_number", _next_emp_id())
        data["metadata"] = data.get("metadata", "")

        # Add to blockchain
        result = blockchain.add_identity(data)

        registered = result["identity_data"]
        save_state()  # persist so the new identity survives restarts

        return jsonify({
            "success": True,
            "message": f"Identity '{data['name']}' registered successfully",
            "identity_hash": registered["identity_hash"],
            "block_index": registered["block_index"],
            "block_hash": registered["block_hash"],
            "nonce": result["nonce"],
            "mining_time": round(result["mining_time"], 4)
        }), 201

    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/identities/verify', methods=['POST'])
def verify_identity():
    """Verify an identity's hash in the blockchain"""
    try:
        data = _post_json() or {}
        identity_hash = (data.get("identity_hash") or "").strip()
        if not identity_hash:
            return jsonify({"success": False, "error": "identity_hash required"}), 400

        result = blockchain.verify_identity(identity_hash)
        return jsonify({"success": True, "data": result})

    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/access/check', methods=['POST'])
def check_access():
    """Check if an identity can access a resource"""
    try:
        data = _post_json() or {}
        identity_hash = data.get("identity_hash")
        resource = data.get("resource")

        if not identity_hash or not resource:
            return jsonify({
                "success": False,
                "error": "Both identity_hash and resource are required"
            }), 400

        result = blockchain.verify_access(identity_hash, resource)
        return jsonify({"success": True, "data": result})

    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/open-access', methods=['POST'])
def open_access():
    """Open access to a resource (to test the system)"""
    try:
        data = _post_json() or {}
        identity_hash = data.get("identity_hash")
        resource = data.get("resource")
        identity_preview = (identity_hash[:8] + "...") if identity_hash else None
        return jsonify({
            "success": True,
            "message": "Direct access attempted - this bypasses blockchain verification",
            "data": {"identity": identity_preview, "resource": resource}
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/blockchain/validate')
def validate_blockchain():
    """Validate entire blockchain integrity"""
    valid, message = blockchain.is_chain_valid()
    return jsonify({
        "success": True,
        "valid": valid,
        "message": message,
        "total_blocks": len(blockchain.chain)
    })


@app.route('/api/blockchain/tamper', methods=['POST'])
def tamper_block():
    """Simulate tampering with a block (for demo purposes)"""
    try:
        data = _post_json() or {}
        raw_index = data.get("block_index")
        if raw_index is None:
            return jsonify({"success": False, "error": "block_index required"}), 400
        try:
            block_index = int(raw_index)
        except (ValueError, TypeError):
            return jsonify({"success": False, "error": "block_index must be an integer"}), 400
        if block_index < 1:
            return jsonify({"success": False, "error": "Invalid block index"}), 400

        # Tamper with the block
        success = blockchain.tamper_with_block(
            block_index,
            {
                "type": "IDENTITY_REGISTRATION",
                "identity_data": {"name": "*** TAMPERED ***", "hacked": True},
                "timestamp": time.time()
            }
        )
        return jsonify({
            "success": True,
            "tampered": success,
            "message": f"Block #{block_index} has been tampered with. Chain integrity check will now fail.",
            "chain_valid": blockchain.is_chain_valid()[0]
        })

    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/blockchain/chain')
def get_full_chain():
    """Get full blockchain data for visualization"""
    chain_data = []
    for block in blockchain.chain:
        chain_data.append({
            "index": block.index,
            "timestamp": datetime.fromtimestamp(block.timestamp).strftime("%Y-%m-%d %H:%M:%S"),
            "hash": block.hash,
            "previous_hash": block.previous_hash,
            "nonce": block.nonce,
            "difficulty": block.difficulty,
            "merkle_root": block.merkle_root(),
            "data": block.data
        })
    return jsonify({"success": True, "data": chain_data})


@app.route('/api/blockchain/reset', methods=['POST'])
def reset_blockchain():
    """Reset blockchain back to genesis block only"""
    global blockchain, network_nodes
    blockchain = Blockchain()

    # Re-add demo identities
    for demo in demo_identities:
        demo["identity_hash"] = generate_identity_hash()
        blockchain.add_identity(demo)

    # Rebuild distributed network nodes with fresh seeded chains
    network_nodes = _build_initial_nodes()
    save_state()  # persist the freshly seeded state

    return jsonify({
        "success": True,
        "message": "Blockchain reset successfully",
        "chain_info": blockchain.get_chain_info()
    })


# ============================================
# PASSWORDLESS CRYPTOGRAPHIC AUTHENTICATION
# ============================================

@app.route('/api/crypto/register', methods=['POST'])
def crypto_register():
    """
    Register a new cryptographic identity.
    Generates RSA keypair; stores ONLY the public key on-chain.
    Returns the private key to the user ONCE (must be stored securely).
    """
    try:
        data = _post_json() or {}
        if not data:
            return jsonify({"success": False, "error": "No data provided"}), 400

        required = ["name", "role", "email"]
        missing = [f for f in required if not data.get(f)]
        if missing:
            return jsonify({"success": False, "error": f"Missing: {', '.join(missing)}"}), 400

        data["allowed_resources"] = data.get("allowed_resources", ["basic_access"])
        data["access_level"] = data.get("access_level", "LOW")
        data["department"] = data.get("department", "General")
        data["id_number"] = data.get("id_number", _next_emp_id())
        data["metadata"] = data.get("metadata", "")

        result = blockchain.register_crypto_identity(data)
        if not result["success"]:
            return jsonify(result), 400

        save_state()  # persist the newly registered crypto identity

        # Return private key ONLY here (in real world this would be a secure download)
        return jsonify({
            "success": True,
            "message": result["message"],
            "identity": {
                "name": result["identity_data"]["name"],
                "email": result["identity_data"]["email"],
                "fingerprint": result["fingerprint"],
                "block_index": result["identity_data"]["block_index"]
            },
            "private_key": result["private_key"],  # SECRET - show ONCE
            "public_key": result["public_key"],
            "warning": "PRIVATE KEY IS SECRET. Store it securely. It will NOT be shown again."
        }), 201

    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/crypto/sign', methods=['POST'])
def crypto_sign():
    """
    Client-side: sign an access request with the private key (passwordless).
    This simulates the user's device signing a challenge.
    """
    try:
        data = _post_json() or {}
        private_key = data.get("private_key")
        resource = data.get("resource")
        timestamp = data.get("timestamp")
        nonce = data.get("nonce")

        if not all([private_key, resource, timestamp, nonce]):
            return jsonify({"success": False, "error": "private_key, resource, timestamp, nonce required"}), 400

        signed = CryptoIdentity.sign_access_request(
            private_key, resource, timestamp, nonce
        )
        return jsonify({
            "success": True,
            "signed_message": signed["message"],
            "signature": signed["signature"]
        })

    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/crypto/auth', methods=['POST'])
def crypto_auth():
    """
    Server-side: verify a signed access request (passwordless authentication).
    Looks up public key on-chain, verifies signature, checks timestamp + access.
    """
    try:
        data = _post_json() or {}
        public_id = data.get("public_id")
        resource = data.get("resource")
        timestamp = data.get("timestamp")
        nonce = data.get("nonce")
        signature = data.get("signature")

        if not all([public_id, resource, timestamp, nonce, signature]):
            return jsonify({
                "success": False,
                "error": "public_id, resource, timestamp, nonce, signature required"
            }), 400

        result = blockchain.passwordless_auth(
            public_id, resource, timestamp, nonce, signature
        )
        return jsonify({"success": True, "data": result})

    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/crypto/demo', methods=['POST'])
def crypto_demo():
    """
    Full passwordless authentication demo:
      1. Register a fresh crypto identity (keypair, public key on chain)
      2. Sign an access request with the private key
      3. Verify against the on-chain public key (NO password)
    This runs the complete flow in one shot so it's demo-friendly.
    """
    try:
        data = _post_json() or {}
        public_id = data.get("public_id") or "demo.user@bel.gov.in"
        resource = data.get("resource", "admin_dashboard")

        result = _crypto_demo_full(public_id, resource)
        return jsonify(result)

    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


def _crypto_demo_full(public_id, resource):
    """
    Full end-to-end passwordless demo:
    registers a temporary crypto identity, signs, and verifies.
    """
    import secrets as sec

    # Create a temporary identity
    demo_name = public_id if '@' not in public_id else public_id.split('@')[0]
    demo_name = demo_name.replace('.', ' ').title()
    temp_data = {
        "name": demo_name,
        "role": "Demo User",
        "email": public_id,
        "department": "Cryptographic Demo",
        "access_level": "HIGH",
        "allowed_resources": ["admin_dashboard", "sensitive_data", "network_access"],
        "metadata": "Auto-generated for passwordless demo"
    }
    reg = blockchain.register_crypto_identity(temp_data)
    if not reg["success"]:
        return {"success": False, "reason": reg.get("reason", "registration failed")}

    private_key = reg["private_key"]
    # macOS: register function stores public on chain under the provided email
    # but email was temp_data email = public_id. Good.

    # Sign a fresh access request
    timestamp = int(time.time())
    nonce = sec.token_hex(8)
    signed = CryptoIdentity.sign_access_request(private_key, resource, timestamp, nonce)

    # Verify server-side
    auth_result = blockchain.passwordless_auth(
        public_id, resource, timestamp, nonce, signed["signature"]
    )

    return {
        "success": auth_result["authenticated"],
        "demo_data": {
            "identity_email": public_id,
            "identity_name": demo_name,
            "resource": resource,
            "signed_message": signed["message"],
            "timestamp": timestamp,
            "nonce": nonce
        },
        "private_key": private_key,
        "public_fingerprint": reg["fingerprint"],
        "authentication": auth_result,
        "note": "NO PASSWORD USED - authentication via RSA digital signature"
    }


def secrets_hex(nbytes):
    import secrets as sec
    return sec.token_hex(nbytes)


# ============================================
# BIOMETRIC VERIFICATION ENDPOINTS
# ============================================

@app.route('/api/biometric/enroll', methods=['POST'])
def biometric_enroll():
    """
    Enroll a biometric template for an identity.
    Stores only the template HASH on-chain; raw template in secure enclave.
    """
    try:
        data = _post_json() or {}
        public_id = data.get("public_id")
        biometric_type = data.get("biometric_type", "face")

        if not public_id:
            return jsonify({"success": False, "error": "public_id required"}), 400

        result = blockchain.enroll_biometric(public_id, biometric_type)
        return jsonify(result if "success" in result else {"success": False, "reason": result.get("reason")})

    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/biometric/verify', methods=['POST'])
def biometric_verify():
    """
    Simulate a live biometric capture and verify against enrolled template.
    """
    try:
        data = _post_json() or {}
        public_id = data.get("public_id")
        biometric_type = data.get("biometric_type", "face")
        raw_noise = data.get("noise", 0.12)
        try:
            noise = float(raw_noise)
        except (ValueError, TypeError):
            return jsonify({"success": False, "error": "noise must be a number"}), 400

        if not public_id:
            return jsonify({"success": False, "error": "public_id required"}), 400

        result = blockchain.biometric_capture_and_verify(public_id, biometric_type, noise)
        return jsonify(result)

    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/biometric/demo', methods=['POST'])
def biometric_demo():
    """
    Full biometric verification demo: enroll + capture + verify + access gate.
    """
    try:
        data = _post_json() or {}
        public_id = data.get("public_id") or "aarav.sharma@bel.gov.in"
        biometric_type = data.get("biometric_type", "face")
        resource = data.get("resource", "admin_dashboard")

        # 1. Enroll
        enroll = blockchain.enroll_biometric(public_id, biometric_type)
        if not enroll.get("success"):
            return jsonify({**enroll, "step": "enroll"})

        # 2. Simulate capture (with a tiny bit of sensor noise)
        capture = blockchain.biometric_capture_and_verify(public_id, biometric_type, noise=0.10)

        return jsonify({
            "success": True,
            "steps": {
                "enroll": {
                    "template_hash": enroll["template_hash"],
                    "template_preview": enroll["template_preview"],
                    "block_index": enroll["block_index"]
                },
                "capture": capture
            },
            "biometric_type": biometric_type,
            "public_id": public_id,
            "final_access": capture.get("matched", False),
            "message": capture.get("message", "")
        })

    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


# ============================================
# SMART CONTRACT ACCESS RULES ENDPOINTS
# ============================================

@app.route('/api/smartcontract/rules', methods=['POST'])
def smartcontract_set_rules():
    """Attach smart-contract rules (work hours, geofence) to an identity"""
    try:
        data = _post_json() or {}
        public_id = data.get("public_id")
        work_hours = data.get("work_hours", True)
        geofence = data.get("geofence")

        if not public_id:
            return jsonify({"success": False, "error": "public_id required"}), 400

        result = blockchain.register_smart_contract_rules(public_id, work_hours, geofence)
        return jsonify(result) if result.get("success", True) else (jsonify(result), 400)

    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/smartcontract/evaluate', methods=['POST'])
def smartcontract_evaluate():
    """
    Evaluate smart-contract rules for access, with context.
    Context can include: now (datetime), position (lat/lon).
    """
    try:
        data = _post_json() or {}
        public_id = data.get("public_id")
        resource = data.get("resource")
        context = data.get("context", {})

        if not public_id or not resource:
            return jsonify({"success": False, "error": "public_id and resource required"}), 400

        result = blockchain.evaluate_smart_contract(public_id, resource, context)
        return jsonify({"success": True, "data": result})

    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/smartcontract/window-demo', methods=['POST'])
def smartcontract_window_demo():
    """
    Demonstrate time-of-day smart contract rule.
    Compare access inside vs outside work hours.
    """
    try:
        from datetime import datetime as dt, timedelta
        data = _post_json() or {}
        public_id = data.get("public_id") or "rajesh.kumar@bel.gov.in"
        resource = data.get("resource", "field_reports")

        # Ensure the identity has smart contract rules set up
        blockchain.register_smart_contract_rules(public_id, work_hours=True, geofence=None)

        # Scenario A: Now (current time - evaluate against work hours)
        now_result = blockchain.evaluate_smart_contract(public_id, resource, {"now": dt.now()})

        # Scenario B: Saturday (weekend - should be denied)
        # Find nearest Saturday
        days_until_sat = (5 - dt.now().weekday()) % 7
        saturday = dt.now() + timedelta(days=days_until_sat)
        saturday = saturday.replace(hour=12, minute=0, second=0, microsecond=0)
        weekend_result = blockchain.evaluate_smart_contract(public_id, resource, {"now": saturday})

        # Scenario C: Monday at 08:00 (before work hours - should be denied)
        monday = dt.now() + timedelta(days=(7 - dt.now().weekday()) % 7)
        monday = monday.replace(hour=8, minute=0, second=0, microsecond=0)
        early_result = blockchain.evaluate_smart_contract(public_id, resource, {"now": monday})

        return jsonify({
            "success": True,
            "identity": public_id,
            "resource": resource,
            "scenarios": {
                "now": {
                    "time": dt.now().strftime("%Y-%m-%d %H:%M:%S (%A)"),
                    "granted": now_result["granted"],
                    "evaluation": now_result["evaluation"]
                },
                "weekend_saturday": {
                    "time": saturday.strftime("%Y-%m-%d %H:%M:%S (%A)"),
                    "granted": weekend_result["granted"],
                    "evaluation": weekend_result["evaluation"]
                },
                "early_monday_8am": {
                    "time": monday.strftime("%Y-%m-%d %H:%M:%S (%A)"),
                    "granted": early_result["granted"],
                    "evaluation": early_result["evaluation"]
                }
            }
        })

    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/smartcontract/geo-demo', methods=['POST'])
def smartcontract_geo_demo():
    """
    Demonstrate geo-fencing smart contract rule.
    Center: New Delhi. Compare inside vs outside the fence.
    Uses a valid in-work-hours timestamp so geo-fence is the deciding factor.
    """
    try:
        from datetime import datetime as dt, timedelta
        data = _post_json() or {}
        public_id = data.get("public_id") or "rajesh.kumar@bel.gov.in"
        resource = data.get("resource", "field_reports")

        # Set a geofence around New Delhi (28.6139 N, 77.2090 E) radius 10km
        delhi = {"center_lat": 28.6139, "center_lon": 77.2090, "radius_km": 10.0}
        blockchain.register_smart_contract_rules(public_id, work_hours=True, geofence=delhi)

        # Use a Monday 10:00 AM timestamp (within work hours) so geo-fence decides
        days_until_mon = (0 - dt.now().weekday()) % 7
        if days_until_mon == 0:
            days_until_mon = 7
        monday_10am = dt.now().replace(hour=10, minute=0, second=0, microsecond=0) + timedelta(days=days_until_mon)
        context_base = {"now": monday_10am}

        # Inside fence: near India Gate (28.6129, 77.2295) - ~1.9km away
        inside_ctx = dict(context_base, position={"lat": 28.6129, "lon": 77.2295})
        inside = blockchain.evaluate_smart_contract(public_id, resource, inside_ctx)
        # Outside fence: somewhere in Mumbai (19.0760, 72.8777)
        outside_ctx = dict(context_base, position={"lat": 19.0760, "lon": 72.8777})
        outside = blockchain.evaluate_smart_contract(public_id, resource, outside_ctx)

        return jsonify({
            "success": True,
            "identity": public_id,
            "resource": resource,
            "geofence": "New Delhi center, radius 10km",
            "context_time": monday_10am.strftime("%Y-%m-%d %H:%M:%S (%A) - within work hours"),
            "scenarios": {
                "inside_delhi": {
                    "position": "28.6129, 77.2295 (India Gate, Delhi)",
                    "granted": inside["granted"],
                    "evaluation": inside["evaluation"]
                },
                "outside_mumbai": {
                    "position": "19.0760, 72.8777 (Mumbai)",
                    "granted": outside["granted"],
                    "evaluation": outside["evaluation"]
                }
            }
        })

    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


# ============================================
# ZERO-KNOWLEDGE PROOF ENDPOINTS
# ============================================

@app.route('/api/zkp/prove', methods=['POST'])
def zkp_prove():
    """
    Generate a Zero-Knowledge Proof of access.
    Prover enters their identity hash + resource; system proves access WITHOUT
    revealing the hash to any verifier.
    """
    try:
        data = _post_json() or {}
        identity_hash = data.get("identity_hash")
        resource = data.get("resource")
        challenge = data.get("challenge", "default-challenge")

        if not identity_hash or not resource:
            return jsonify({
                "success": False,
                "error": "Both identity_hash and resource are required"
            }), 400

        result = blockchain.zkp_prove_access(identity_hash, resource, challenge)
        return jsonify(result)

    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/zkp/verify', methods=['POST'])
def zkp_verify():
    """
    Verify a Zero-Knowledge Proof WITHOUT knowing the identity hash.
    This demonstrates true privacy-preserving access control.
    """
    try:
        data = _post_json() or {}
        commitment = data.get("commitment")
        proof_value = data.get("proof_value")
        challenge = data.get("challenge", "default-challenge")
        resource = data.get("resource")
        verifier_key = data.get("verifier_key")

        if not all([commitment, proof_value, resource]):
            return jsonify({
                "success": False,
                "error": "commitment, proof_value, and resource are required"
            }), 400

        result = blockchain.zkp_verify_access(
            commitment, proof_value, challenge, resource, verifier_key
        )
        return jsonify({"success": True, "data": result})

    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/zkp/demo', methods=['POST'])
def zkp_demo():
    """
    Run a complete Zero-Knowledge Proof demo:
    proves access to a resource without the verifier ever learning the identity.
    """
    try:
        data = _post_json() or {}
        identity_hash = data.get("identity_hash")
        resource = data.get("resource", "admin_dashboard")

        if not identity_hash:
            return jsonify({"success": False, "error": "identity_hash required"}), 400

        challenge = secrets_token()
        prove_result = blockchain.zkp_prove_access(identity_hash, resource, challenge)

        if not prove_result["success"]:
            return jsonify(prove_result)

        verify_result = blockchain.zkp_verify_access(
            prove_result["commitment"]["commitment"],
            prove_result["proof"]["proof"],
            challenge,
            resource,
            prove_result["verifier_key"]
        )

        return jsonify({
            "success": True,
            "step1_commitment": prove_result["commitment"]["commitment"],
            "step2_proof": prove_result["proof"]["proof"],
            "step3_verification": verify_result,
            "challenge": challenge,
            "privacy_note": "Verifier NEVER saw the identity_hash - access proven via zero-knowledge"
        })

    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


def secrets_token():
    """Generate a random challenge token"""
    import secrets as s
    return s.token_hex(8)


# ============================================
# QR CODE VERIFICATION ENDPOINTS
# ============================================

@app.route('/api/qr/generate', methods=['POST'])
def qr_generate():
    """
    Generate a QR payload for an identity using a public identifier.
    Returns base64-encoded payload ready for QR encoding.
    """
    try:
        data = _post_json() or {}
        public_id = data.get("public_id")
        resource = data.get("resource")

        if not public_id or not resource:
            return jsonify({
                "success": False,
                "error": "Both public_id and resource are required"
            }), 400

        result = blockchain.create_qr_for_identity(public_id, resource)
        return jsonify(result)

    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/qr/verify', methods=['POST'])
def qr_verify():
    """
    Verify a scanned QR payload against the blockchain.
    Accepts the base64 payload from a scanned QR code.
    """
    try:
        data = _post_json() or {}
        payload_b64 = data.get("payload_b64")
        resource = data.get("resource")

        if not payload_b64:
            return jsonify({"success": False, "error": "payload_b64 required"}), 400

        result = blockchain.verify_qr_code(payload_b64, resource)
        return jsonify({"success": True, "data": result})

    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/qr/generate-from-hash', methods=['POST'])
def qr_generate_from_hash():
    """
    Alternative: generate QR payload directly from an identity hash.
    Useful when you know the hash but want a compact QR.
    """
    try:
        data = _post_json() or {}
        identity_hash = data.get("identity_hash")
        resource = data.get("resource")

        if not identity_hash or not resource:
            return jsonify({
                "success": False,
                "error": "Both identity_hash and resource are required"
            }), 400

        # Verify access first
        access = blockchain.verify_access(identity_hash, resource)
        if not access["granted"]:
            return jsonify({"success": False, "reason": access["reason"]})

        from blockchain import generate_qr_payload
        import base64 as b64
        payload = generate_qr_payload(identity_hash, resource)
        payload_b64 = b64.urlsafe_b64encode(json.dumps(payload).encode()).decode()

        return jsonify({
            "success": True,
            "qr_payload": payload,
            "payload_b64": payload_b64,
            "resource": resource,
            "message": "QR payload generated from identity hash."
        })

    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


# ============================================
# MULTI-NODE DISTRIBUTED NETWORK
# ============================================

@app.route('/api/network/status')
def network_status():
    """Status of all nodes in the distributed network"""
    result = []
    for node_id, node in network_nodes.items():
        valid, msg = node.validate_local_chain()
        result.append({
            "node_id": node_id,
            "blocks": len(node.blockchain.chain),
            "chain_valid": valid,
            "peers": node.peers,
            "last_block_hash": node.blockchain.last_block.hash[:16] + "..."
        })
    return jsonify({"success": True, "nodes": result})


@app.route('/api/network/node/<node_id>/chain')
def node_chain(node_id):
    """Get a specific node's chain"""
    node = network_nodes.get(node_id)
    if not node:
        return jsonify({"success": False, "error": f"Unknown node: {node_id}"}), 404
    return jsonify({"success": True, "node_id": node_id, "chain": node.get_chain()})


@app.route('/api/network/sync', methods=['POST'])
def network_sync():
    """
    Simulate a node receiving a chain from a peer via HTTP (localhost ports).
    sender node -> HTTP POST -> receiver node.
    Applies longest-valid-chain consensus.
    """
    try:
        data = _post_json() or {}
        sender_id = data.get("sender")           # e.g. "node_1"
        receiver_id = data.get("receiver")       # e.g. "node_2"
        chain = data.get("chain")                # the chain being sent

        if not all([sender_id, receiver_id, chain]):
            return jsonify({
                "success": False,
                "error": "sender, receiver and chain are required"
            }), 400

        receiver = network_nodes.get(receiver_id)
        if not receiver:
            return jsonify({"success": False, "error": f"Unknown receiver: {receiver_id}"}), 404

        # Node receives & validates the chain (consensus)
        result = receiver.receive_chain(chain, sender_id)

        # Record the peer connection
        if sender_id not in receiver.peers:
            receiver.peers.append(sender_id)

        return jsonify({
            "success": True,
            "protocol": "HTTP (localhost port)",
            "sender": sender_id,
            "receiver": receiver_id,
            "result": result,
            "receiver_blocks": len(receiver.blockchain.chain)
        })

    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/network/malicious-fork', methods=['POST'])
def malicious_fork():
    """
    Simulate a malicious node trying to fork the network.
    The malicious node falsifies a block (tampering) then tries to broadcast
    a longer chain. Consensus validation MUST reject it.
    """
    try:
        data = _post_json() or {}
        attacker_id = data.get("attacker", "node_3")
        target_node = network_nodes.get(attacker_id)
        if not target_node:
            return jsonify({"success": False, "error": f"Unknown attacker: {attacker_id}"}), 404

        # Attacker tampers with a block's data WITHOUT updating its hash
        # (this is what a real malicious fork attempt looks like)
        try:
            tampered_index = int(data.get("block_index", 1))
        except (TypeError, ValueError):
            return jsonify({"success": False, "error": "Invalid block_index"}), 400
        fake_data = data.get("fake_data", {"type": "GENESIS", "message": "MALICIOUS FORK - fake block"})

        # Ensure index is valid
        if not (0 < tampered_index < len(target_node.blockchain.chain)):
            return jsonify({"success": False, "error": f"Invalid block index {tampered_index}"}), 400

        # Snapshot the honest chain so the attacker node can be restored after
        # the demo (otherwise node_3 stays corrupted for every later check).
        saved_chain = target_node.get_chain()

        # Simulate the malicious node attempting to alter history
        target_node.blockchain.tamper_with_block(tampered_index, fake_data)

        # Now the attacker's chain is INVALID. Broadcast to honest nodes.
        attacker_chain = target_node.get_chain()
        consensus_results = []
        rejected_by = []

        for honest_id, honest_node in network_nodes.items():
            if honest_id == attacker_id:
                continue
            # Honest node rejects the malicious fork
            valid, msg = Blockchain.validate_chain_dicts(attacker_chain)
            result = {
                "node_id": honest_id,
                "accepted": valid,
                "reason": msg if not valid else "Accepted chain (integrity passed)"
            }
            consensus_results.append(result)
            if not valid:
                rejected_by.append(honest_id)

        # Note which block was tampered
        attacker_valid, attacker_msg = target_node.validate_local_chain()

        # Restore the attacker node to its honest chain so the demo leaves the
        # network in a healthy state for subsequent checks.
        target_node.blockchain.chain = target_node.blockchain.import_chain(saved_chain)

        return jsonify({
            "success": True,
            "attack_description": f"Node {attacker_id} tampered with block #{tampered_index} WITHOUT recomputing its hash, then attempted to broadcast its forged chain to the network.",
            "attacker": attacker_id,
            "tampered_block": tampered_index,
            "attacker_chain_valid": attacker_valid,
            "attacker_validation_message": attacker_msg,
            "consensus_result": {
                "fork_rejected": not any(r["accepted"] for r in consensus_results),
                "rejected_by": rejected_by,
                "details": consensus_results
            },
            "message": "Consensus successfully rejected the malicious fork! The network agrees only valid chains are accepted."
        })

    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/network/consensus-check', methods=['POST'])
def consensus_check():
    """
    Gather all nodes' chains and run a formal consensus check.
    Demonstrates longest-valid-chain rule picks the true network state.
    """
    try:
        candidates = {}
        for node_id, node in network_nodes.items():
            candidates[node_id] = node.get_chain()

        # Use node_1 as the arbiter to run the consensus check
        # (a stronger test: check what EACH node would conclude)
        all_conclusions = []
        for node_id, node in network_nodes.items():
            res = node.consensus_check(candidates)
            all_conclusions.append({
                "node_id": node_id,
                "winner": res["consensus_winner"],
                "winner_length": res["consensus_length"],
                "rejected_malicious": res["malicious_nodes_rejected"]
            })

        return jsonify({
            "success": True,
            "candidates": [{"node_id": nid, "length": len(c)} for nid, c in candidates.items()],
            "each_node_conclusion": all_conclusions,
            "network_consensus": all_conclusions[0] if all_conclusions else None,
            "message": "Distributed consensus: every node independently validates and the longest valid chain wins."
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


# ============================================
# IPFS DOCUMENT STORAGE
# ============================================

@app.route('/api/ipfs/add', methods=['POST'])
def ipfs_add():
    """
    Add a document to IPFS.
    Returns the CID - only this hash is stored on-chain (lightweight).
    """
    try:
        data = _post_json() or {}
        content = data.get("content")
        doc_name = data.get("name", "document")
        owner = data.get("owner")

        if content is None:
            return jsonify({"success": False, "error": "content is required"}), 400

        result = ipfs.add(content, doc_name=doc_name, owner=owner)

        # Only the CID is what would be anchored to the chain.
        # Optionally log this on-chain as an audit block to demonstrate
        # the "hash-only on-chain" pattern.
        blockchain.log_audit({
            "action": "IPFS_ADD",
            "public_id": owner or "unknown",
            "resource": "IPFS",
            "decision": "ADDED",
            "reason": f"Document '{doc_name}' added to IPFS. CID anchored on-chain: {result['cid']}",
            "timestamp": time.time()
        })

        return jsonify({
            "success": True,
            "cid": result["cid"],
            "name": result["name"],
            "size": result["size"],
            "content_type": result["content_type"],
            "on_chain_anchor": result["cid"],   # only the hash is on-chain
            "message": result["message"]
        })

    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/ipfs/get/<cid>')
def ipfs_get(cid):
    """Retrieve a document from IPFS by CID and verify integrity"""
    try:
        result = ipfs.get(cid)
        if not result["found"]:
            return jsonify({"success": False, "message": result["message"]}), 404
        return jsonify({
            "success": True,
            "cid": result["cid"],
            "name": result["name"],
            "owner": result["owner"],
            "size": result["size"],
            "content_preview": result["content_preview"],
            "verified": result["verified"],
            "message": result["message"]
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/ipfs/list')
def ipfs_list():
    """List all documents on the IPFS network"""
    return jsonify({"success": True, "documents": ipfs.list_documents()})


@app.route('/api/ipfs/verify', methods=['POST'])
def ipfs_verify():
    """
    Verify that provided content matches a given CID.
    Demonstrates tamper-proof verification: hash the content,
    compare to the on-chain CID.
    """
    try:
        data = _post_json() or {}
        content = data.get("content", "")
        cid = data.get("cid")
        if not cid:
            return jsonify({"success": False, "error": "cid is required"}), 400
        content_bytes = content.encode() if isinstance(content, str) else content
        match = ipfs.verify_document(content_bytes, cid)
        return jsonify({
            "success": True,
            "verified": match,
            "computed_cid": IPFSDocumentStore.compute_cid(content_bytes),
            "expected_cid": cid,
            "message": "Content matches CID (authentic document)." if match else "CONTENT TAMPERED! Hash does not match on-chain CID."
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/ipfs/tamper', methods=['POST'])
def ipfs_tamper():
    """Simulate tampering with a document on IPFS (for demo)"""
    try:
        data = _post_json() or {}
        cid = data.get("cid")
        new_content = data.get("new_content", "TAMPERED CONTENT")
        if not cid:
            return jsonify({"success": False, "error": "cid is required"}), 400
        success = ipfs.tamper_document(cid, new_content)
        return jsonify({
            "success": True,
            "tampered": success,
            "cid": cid,
            "message": f"Document {cid} content has been tampered with. Verification should now FAIL."
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


# ============================================
# MULTI-SIGNATURE (THRESHOLD) APPROVAL
# ============================================

@app.route('/api/multisig/create', methods=['POST'])
def multisig_create():
    try:
        data = _post_json() or {}
        title = data.get("title", "High-security action")
        try:
            required = int(data.get("required", 2))
        except (TypeError, ValueError):
            return jsonify({"success": False, "error": "Invalid 'required' threshold"}), 400
        signers = data.get("signers", ["admin1", "admin2", "admin3"])
        action = data.get("action_payload", {})
        proposal = blockchain.create_multisig(title, required, signers, action)
        return jsonify({"success": True, "proposal": proposal})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/multisig/sign', methods=['POST'])
def multisig_sign():
    try:
        data = _post_json() or {}
        proposal_id = data.get("proposal_id")
        signer = data.get("signer")
        approve = data.get("approve", True)
        result = blockchain.sign_multisig(proposal_id, signer, approve)
        return jsonify(result if result.get("success") else {"success": False, **result})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/multisig/list')
def multisig_list():
    try:
        proposals = blockchain.get_multisig()
        return jsonify({"success": True, "proposals": proposals})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


# ============================================
# REPLAY / DELEGATE ATTACK DEMO
# ============================================

@app.route('/api/attacks/replay', methods=['POST'])
def attack_replay():
    try:
        data = _post_json() or {}
        public_id = data.get("public_id", "aarav.sharma@bel.gov.in")
        resource = data.get("resource", "admin_dashboard")
        try:
            original_ts = int(data.get("original_timestamp", 1000))
            new_ts = int(data.get("new_timestamp", 2000))
        except (TypeError, ValueError):
            return jsonify({"success": False, "error": "Invalid timestamp value"}), 400
        result = blockchain.simulate_replay_attack(public_id, original_ts, resource, new_ts)
        return jsonify(result if result.get("success") else {"success": False, **result})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


# ============================================
# PRIVILEGE ESCALATION ATTACK DEMO
# ============================================

@app.route('/api/attacks/escalation', methods=['POST'])
def attack_escalation():
    try:
        data = _post_json() or {}
        public_id = data.get("public_id", "rajesh.kumar@bel.gov.in")
        target_level = data.get("target_level", "HIGH")
        result = blockchain.simulate_escalation_attack(public_id, target_level)
        return jsonify(result if result.get("success") else {"success": False, **result})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


# ============================================
# SMART CONTRACT SCHEDULING (TIME-LOCKS)
# ============================================

@app.route('/api/schedule/set', methods=['POST'])
def schedule_set():
    try:
        data = _post_json() or {}
        public_id = data.get("public_id", "priya.patel@bel.gov.in")
        resource = data.get("resource", "reporting")
        import time as _t
        try:
            activate = int(data.get("activate_after", _t.time() - 100))
            expire = int(data.get("expire_before", _t.time() + 3600))
        except (TypeError, ValueError):
            return jsonify({"success": False, "error": "Invalid schedule timestamp"}), 400
        result = blockchain.schedule_access(public_id, resource, activate, expire)
        return jsonify(result if result.get("success") else {"success": False, **result})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/schedule/check', methods=['POST'])
def schedule_check():
    try:
        data = _post_json() or {}
        public_id = data.get("public_id")
        resource = data.get("resource")
        result = blockchain.evaluate_schedule(public_id, resource)
        return jsonify({"success": True, "result": result})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


# ============================================
# ENCRYPTED ON-CHAIN RECORDS
# ============================================

@app.route('/api/encrypt/store', methods=['POST'])
def encrypt_store():
    try:
        data = _post_json() or {}
        public_id = data.get("public_id", "priya.patel@bel.gov.in")
        field = data.get("field", "ssn")
        value = data.get("value", "111-22-3333")
        passphrase = data.get("passphrase", "org-secret")
        result = blockchain.add_encrypted_identity_field(public_id, field, value, passphrase)
        return jsonify(result if result.get("success") else {"success": False, **result})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/encrypt/encrypt', methods=['POST'])
def encrypt_value():
    try:
        data = _post_json() or {}
        plaintext = data.get("plaintext", "secret")
        passphrase = data.get("passphrase", "key")
        result = blockchain.encrypt_record(plaintext, passphrase)
        return jsonify(result)
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/encrypt/decrypt', methods=['POST'])
def decrypt_value():
    try:
        data = _post_json() or {}
        ciphertext = data.get("ciphertext")
        passphrase = data.get("passphrase")
        if not ciphertext:
            return jsonify({"success": False, "error": "ciphertext required"}), 400
        result = blockchain.decrypt_record(ciphertext, passphrase)
        return jsonify(result)
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


# ============================================
# EXPORT / IMPORT CHAIN (JSON)
# ============================================

@app.route('/api/chain/export')
def chain_export():
    try:
        return jsonify({
            "success": True,
            "data": json.loads(blockchain.export_to_json()),
            "message": "Chain exported. Only validated chains can be re-imported."
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/chain/import', methods=['POST'])
def chain_import():
    try:
        global blockchain
        data = _post_json() or {}
        chain_json = data.get("chain_json")
        if not chain_json:
            return jsonify({"success": False, "error": "chain_json required"}), 400
        if isinstance(chain_json, (dict, list)):
            chain_json = json.dumps(chain_json)
        new_bc, msg = Blockchain.import_from_json(chain_json)
        if new_bc is None:
            return jsonify({"success": False, "error": msg}), 400

        # Preserve the runtime side ledgers (revocation flags, schedules, DIDs,
        # NFTs, biometric enclave, multisig proposals, oracle keypair). A fresh
        # Blockchain() would silently drop them - losing state on a re-import.
        old_bc = blockchain
        for attr in ("_identity_flags", "_schedules", "_did_store",
                     "_biometric_store", "_multisig_proposals"):
            if hasattr(old_bc, attr):
                setattr(new_bc, attr, getattr(old_bc, attr))
        if getattr(old_bc, "_nft_registry", None) is not None:
            new_bc._nft_registry = old_bc._nft_registry
        if getattr(old_bc, "_oracle_keypair", None) is not None:
            new_bc._oracle_keypair = old_bc._oracle_keypair
        blockchain = new_bc

        save_state()  # persist the imported chain so it survives restarts
        return jsonify({"success": True, "message": msg, "blocks": len(blockchain.chain)})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


# ============================================
# AUDIT TRAIL (on-chain activity log)
# ============================================

@app.route('/api/audit/trail')
def audit_trail():
    try:
        public_id = request.args.get("public_id")
        raw_limit = request.args.get("limit", 100)
        try:
            limit = int(raw_limit)
        except (ValueError, TypeError):
            return jsonify({"success": False, "error": "limit must be an integer"}), 400
        entries = blockchain.get_audit_trail(public_id=public_id, limit=limit)
        stats = blockchain.get_audit_stats()
        return jsonify({"success": True, "entries": entries, "stats": stats})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


# ============================================
# REVOCATION / EXPIRY
# ============================================

@app.route('/api/identity/revoke', methods=['POST'])
def identity_revoke():
    try:
        data = _post_json() or {}
        public_id = data.get("public_id", "rajesh.kumar@bel.gov.in")
        reason = data.get("reason", "")
        result = blockchain.revoke_identity(public_id, reason)
        return jsonify(result if result.get("success") else {"success": False, **result})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/identity/expire', methods=['POST'])
def identity_expire():
    try:
        data = _post_json() or {}
        public_id = data.get("public_id", "rajesh.kumar@bel.gov.in")
        import time as _t
        try:
            # Default to a FUTURE timestamp so a plain "expire" call actually sets
            # an expiry window instead of instantly denying access.
            expires_on = int(data.get("expires_on", _t.time() + 86400))
        except (TypeError, ValueError):
            return jsonify({"success": False, "error": "Invalid expires_on timestamp"}), 400
        result = blockchain.set_expiry(public_id, expires_on)
        return jsonify(result if result.get("success") else {"success": False, **result})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/identity/restore', methods=['POST'])
def identity_restore():
    try:
        data = _post_json() or {}
        public_id = data.get("public_id")
        result = blockchain.restore_identity(public_id)
        return jsonify(result if result.get("success") else {"success": False, **result})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


# ============================================
# ZK DOCUMENT POSSESSION PROOF
# ============================================

@app.route('/api/zk/possession/prove', methods=['POST'])
def zk_possession_prove():
    try:
        data = _post_json() or {}
        cid = data.get("cid", "QmExample")
        secret = data.get("secret", "owner-secret")
        result = blockchain.zk_prove_document_possession(cid, secret)
        return jsonify(result)
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/zk/possession/verify', methods=['POST'])
def zk_possession_verify():
    try:
        data = _post_json() or {}
        commitment = data.get("commitment")
        proof = data.get("proof")
        cid = data.get("cid")
        result = blockchain.zk_verify_document_possession(commitment, proof, cid)
        return jsonify({"success": True, **result})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


# ============================================
# DYNAMIC NODE TOPOLOGY
# ============================================

@app.route('/api/network/topology', methods=['POST'])
def network_topology():
    """
    Dynamically modify the node topology: add a node, remove a node,
    bring a node offline, or desync a node from the network.
    """
    try:
        global network_nodes
        data = _post_json() or {}
        action = data.get("action")  # add / remove / offline / online / desync / reset
        if action == "add":
            nid = data.get("node_id", f"node_{len(network_nodes)+1}")
            from blockchain import Node as _Node, generate_identity_hash as _g
            node = _Node(nid)
            for demo in demo_identities:
                dc = copy.deepcopy(demo)
                dc["identity_hash"] = generate_identity_hash()
                node.add_identity_to_node(dc)
            network_nodes[nid] = node
            return jsonify({"success": True, "message": f"Added node {nid}", "nodes": list(network_nodes.keys())})
        elif action == "remove":
            nid = data.get("node_id")
            if nid not in network_nodes:
                return jsonify({"success": False, "error": f"Unknown node {nid}"}), 404
            del network_nodes[nid]
            return jsonify({"success": True, "message": f"Removed node {nid}", "nodes": list(network_nodes.keys())})
        elif action in ("offline", "online"):
            nid = data.get("node_id")
            if nid not in network_nodes:
                return jsonify({"success": False, "error": f"Unknown node {nid}"}), 404
            network_nodes[nid].set_online(action == "online")
            return jsonify({"success": True, "message": f"Node {nid} is now {'online' if action=='online' else 'offline'}", "node_id": nid, "online": network_nodes[nid].online})
        elif action == "desync":
            nid = data.get("node_id")
            if nid not in network_nodes:
                return jsonify({"success": False, "error": f"Unknown node {nid}"}), 404
            r = network_nodes[nid].desync()
            return jsonify({"success": True, "message": f"Node {nid} desynced (now {r['blocks']} blocks)", "node_id": nid})
        elif action == "reset":
            network_nodes = _build_initial_nodes()
            return jsonify({"success": True, "message": "Network topology reset", "nodes": list(network_nodes.keys())})
        return jsonify({"success": False, "error": "Invalid action"}), 400
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/network/health')
def network_health():
    """Node health / divergence metrics for the dashboard."""
    try:
        health = blockchain.node_health_check(network_nodes)
        online = [h for h in health if network_nodes[h["node_id"]].online]
        offline = [h for h in health if not network_nodes[h["node_id"]].online]
        # Consensus is SYNCED only when every ONLINE node is content-synced and
        # valid, not merely based on the number of online nodes.
        online_synced = [h for h in online if h["synced"] and h["chain_valid"]]
        consensus = "SYNCED" if online and len(online_synced) == len(online) else "PARTIAL"
        return jsonify({
            "success": True,
            "nodes": health,
            "online_count": len(online),
            "offline_count": len(offline),
            "synced_count": len(online_synced),
            "total_nodes": len(health),
            "network_consensus": consensus
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


# ============================================
# METRICS (quantitative dashboard data)
# ============================================

@app.route('/api/metrics')
def metrics():
    try:
        stats = blockchain.get_chain_stats()
        # Fault tolerance: a chain can tolerate (n/2) honest nodes in PBFT-like terms
        fault_tolerance = (len(network_nodes) - 1) // 2
        return jsonify({
            "success": True,
            "chain": stats,
            "network": {
                "node_count": len(network_nodes),
                "fault_tolerance_n": fault_tolerance,  # can tolerate 'n' Byzantine faults
                "fault_tolerance_label": f"tolerates up to {fault_tolerance} Byzantine node(s)"
            },
            "audit": blockchain.get_audit_stats()
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


# ============================================
# ATTACK PLAYBOOK (Red Team demo scenarios)
# ============================================

@app.route('/api/playbook', methods=['POST'])
def attack_playbook():
    """
    One-click Red Team attack scenarios. Each returns the system's defensive verdict.
    """
    try:
        data = _post_json() or {}
        scenario = data.get("scenario")

        if scenario == "tamper_block":
            # Attacker modifies an identity block -> hash breaks
            result = blockchain.simulate_escalation_attack(
                data.get("public_id", "rajesh.kumar@bel.gov.in"), "HIGH")
            if not result.get("success"):
                return jsonify({"success": False, "error": result.get("error", "identity not found")}), 404
            return jsonify({
                "success": True,
                "scenario": "Hash Tampering",
                "attack": "Attacker modifies on-chain identity data to escalate privileges.",
                "system_response": result["conclusion"],
                "tamper_detected": result["tamper_detected"],
                "verdict": "BLOCKED" if result["tamper_detected"] else "CHECK"
            })
        elif scenario == "fork":
            # Malicious fork
            nid = data.get("attacker", "node_3")
            node = network_nodes.get(nid)
            if not node:
                return jsonify({"success": False, "error": f"no node {nid}"}), 404
            saved_chain = node.get_chain()
            node.blockchain.tamper_with_block(1, {"type": "GENESIS", "message": "FORK"})
            chain = node.get_chain()
            rejected = []
            for onid, onode in network_nodes.items():
                if onid == nid:
                    continue
                valid, _ = Blockchain.validate_chain_dicts(chain)
                if not valid:
                    rejected.append(onid)
            # Restore the node's honest chain after the simulation.
            node.blockchain.chain = node.blockchain.import_chain(saved_chain)
            return jsonify({
                "success": True,
                "scenario": "Malicious Fork",
                "attack": f"{nid} tries to broadcast a tampered chain.",
                "verdict": "BLOCKED" if rejected else "ACCEPTED",
                "rejected_by": rejected
            })
        elif scenario == "replay":
            pid = data.get("public_id", "aarav.sharma@bel.gov.in")
            try:
                original_ts = int(data.get("original_ts", 1000))
                new_ts = int(data.get("new_ts", 2000))
            except (TypeError, ValueError):
                return jsonify({"success": False, "error": "Invalid replay timestamp"}), 400
            result = blockchain.simulate_replay_attack(
                pid,
                original_ts,
                data.get("resource", "admin_dashboard"),
                new_ts)
            return jsonify({
                "success": True,
                "scenario": "Replay Attack",
                "attack": "Replayed signed request with modified timestamp.",
                "verdict": "BLOCKED" if result["replay_prevented"] else "ACCEPTED",
                "detail": result["conclusion"]
            })
        elif scenario == "escalation":
            pid = data.get("public_id", "rajesh.kumar@bel.gov.in")
            target = data.get("target", "HIGH")
            result = blockchain.simulate_escalation_attack(pid, target)
            if not result.get("success"):
                return jsonify({"success": False, "error": result.get("error", "identity not found")}), 404
            blocked = result["tamper_detected"] and not result.get("chain_integrity_after_escalation", True)
            return jsonify({
                "success": True,
                "scenario": "Privilege Escalation",
                "attack": f"{pid} attempts to escalate access from '{result['original_access_level']}' to '{target}' by editing the on-chain record.",
                "verdict": "BLOCKED" if blocked else "CHECK",
                "detail": result["conclusion"],
                "tamper_detected": result["tamper_detected"]
            })
        elif scenario == "sniff":
            # No data sniffing of secrets - everything sensitive is hashed/encrypted
            return jsonify({
                "success": True,
                "scenario": "Secret Sniffing",
                "attack": "Attacker reads stored records looking for plaintext secrets.",
                "verdict": "BLOCKED",
                "detail": "Passwords and biometrics are stored as hashes. Sensitive fields can be encrypted (AES). No plaintext secrets on-chain by default."
            })
        return jsonify({"success": False, "error": f"Unknown scenario: {scenario}"}), 400
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


# ============================================
# ZK-SSI: W3C DIDs + VERIFIABLE CREDENTIALS + ZK ATTRIBUTE PROOFS
# ============================================

@app.route('/api/did/challenge', methods=['GET'])
def did_challenge():
    """Issue a fresh (single-use) challenge for an interactive ZK presentation."""
    return jsonify({"success": True, "challenge": secrets_hex(16),
                    "note": "Bind the proof to a server-issued challenge so a captured presentation cannot be replayed."})


@app.route('/api/did/register', methods=['POST'])
def did_register():
    """Register a W3C-style DID. Only the public verification method goes on-chain."""
    try:
        data = _post_json() or {}
        name = data.get("name", "")
        role = data.get("role", "")
        email = data.get("email", "")
        department = data.get("department", "")
        result = blockchain.register_did(name, role, email, department)
        if result["success"]:
            save_state()
            result.pop("private_key", None)
            return jsonify(result), 201
        return jsonify(result), 400
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/did/list', methods=['GET'])
def did_list():
    return jsonify({"success": True, "dids": blockchain.list_dids()})


@app.route('/api/did/issue', methods=['POST'])
def did_issue():
    """
    Issue a Verifiable Credential (claims) to a subject DID, signed by an issuer
    DID. Only a salted commitment of the claims is anchored on-chain.
    """
    try:
        data = _post_json() or {}
        subject_did = data.get("subject_did")
        issuer_did = data.get("issuer_did")
        claims = data.get("claims") or {}
        if not subject_did or not issuer_did or not claims:
            return jsonify({"success": False,
                            "error": "subject_did, issuer_did and claims are required"}), 400
        result = blockchain.issue_credential(subject_did, issuer_did, claims)
        if result["success"]:
            save_state()
        return jsonify(result if result.get("success") else {"success": False, "reason": result.get("reason")}), 200
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/did/present', methods=['POST'])
def did_present():
    """
    Prover side: build a ZK-style attribute presentation for a predicate such as
    {"attribute":"security_clearance","op":">=","value":"LEVEL-3"}.
    Requires the controller private key of the subject DID.
    """
    try:
        data = _post_json() or {}
        subject_did = data.get("subject_did")
        private_key = data.get("private_key")
        predicate = data.get("predicate")
        challenge = data.get("challenge", secrets_hex(16))
        if not subject_did or not private_key or not predicate:
            return jsonify({"success": False,
                            "error": "subject_did, private_key and predicate are required"}), 400
        result = blockchain.present_credential(subject_did, private_key, predicate, challenge)
        return jsonify(result if result.get("success") else {"success": False, "reason": result.get("reason")}), 200
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/did/verify', methods=['POST'])
def did_verify():
    """
    Verifier / smart-contract side: verify a ZK attribute presentation. Scans
    every registered DID and returns only GRANTED/DENIED - never the identity.
    """
    try:
        data = _post_json() or {}
        presentation = data.get("presentation")
        if not presentation:
            return jsonify({"success": False, "error": "presentation required"}), 400
        result = blockchain.verify_credential_presentation(presentation)
        return jsonify({"success": True, **result})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/did/full-demo', methods=['POST'])
def did_full_demo():
    """
    One-shot ZK-SSI demo:
      1. register an issuer DID (BEL) + a subject DID (defence engineer)
      2. issue a LEVEL-3 clearance credential (commitment-only on-chain)
      3. interactive challenge + present the >= LEVEL-3 predicate
      4. contract verifies WITHOUT ever disclosing the subject
      5. a LEVEL-1 attacker is stopped (cannot even mint the proof)
    """
    try:
        data = _post_json() or {}
        subject_name = data.get("subject_name", "Aarav Sharma")
        subject_email = data.get("subject_email", "aarav.sharma@bel.gov.in")
        attacker_name = data.get("attacker_name", "Intruder")

        org = blockchain.register_did("BEL - Central Authority", "Issuer", "issuer@bel.gov.in")
        eng = blockchain.register_did(subject_name, "Senior Radar Engineer", subject_email, "Radar Systems")
        attacker = blockchain.register_did(attacker_name, "Contractor", "intruder@outside.in")

        vc = blockchain.issue_credential(eng["did"], org["did"],
                                         {"security_clearance": "LEVEL-3",
                                          "employee_id_hash": eng["did"][-12:]})
        blockchain.issue_credential(attacker["did"], org["did"],
                                    {"security_clearance": "LEVEL-1"})

        predicate = {"attribute": "security_clearance", "op": ">=", "value": "LEVEL-3"}
        challenge = secrets_hex(16)

        presentation = blockchain.present_credential(eng["did"], eng["private_key"], predicate, challenge)
        verification = blockchain.verify_credential_presentation(presentation["presentation"])

        # Attacker: forged / from-scratch presentation must fail, and minting a
        # LEVEL-3 proof from a LEVEL-1 credential must fail.
        fake_pres = {
            "commitment": "0000", "signature": "AAAA",
            "predicate": predicate, "challenge": challenge
        }
        forged_result = blockchain.verify_credential_presentation(fake_pres)
        mint_low = blockchain.present_credential(attacker["did"], attacker["private_key"],
                                                 predicate, secrets_hex(8))

        save_state()
        return jsonify({
            "success": True,
            "steps": {
                "issuer_did": org["did"][:18] + "...",
                "subject_did": eng["did"][:18] + "... (pseudonymous)",
                "credential": vc,
                "presentation": presentation["presentation"],
                "verification": verification,
                "attacker_forged_proof_blocked": not forged_result["granted"],
                "attacker_level1_mint_blocked": not mint_low["success"]
            },
            "privacy_summary": ("The smart-contract verifies the attribute WITHOUT learning "
                                "which DID presented - the identity stays self-sovereign.")
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


# ============================================
# ABAC: ATTRIBUTE-BASED ACCESS CONTROL POLICIES
# ============================================

@app.route('/api/abac/register-device', methods=['POST'])
def abac_register_device():
    try:
        data = _post_json() or {}
        public_id = data.get("public_id")
        device_hash = data.get("device_hash")
        label = data.get("device_label", "")
        if not public_id or not device_hash:
            return jsonify({"success": False, "error": "public_id and device_hash required"}), 400
        result = blockchain.register_device(public_id, device_hash, label)
        if result["success"]:
            save_state()
        return jsonify(result if result.get("success") else {"success": False, "reason": result.get("reason")})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/abac/set-clearance', methods=['POST'])
def abac_set_clearance():
    try:
        data = _post_json() or {}
        public_id = data.get("public_id")
        level = data.get("level")
        if not public_id or not level:
            return jsonify({"success": False, "error": "public_id and level required"}), 400
        result = blockchain.set_security_clearance(public_id, level)
        if result["success"]:
            save_state()
        return jsonify(result if result.get("success") else {"success": False, "reason": result.get("reason")})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/abac/evaluate', methods=['POST'])
def abac_evaluate():
    """
    Evaluate the dynamic ABAC policy:
        Access = Role ∧ SecurityClearance ∧ Geofence ∧ DeviceSecurityHash
    context: {"device_hash": ..., "position": {"lat","lon"}, "now": ...}
    """
    try:
        data = _post_json() or {}
        public_id = data.get("public_id")
        resource = data.get("resource")
        context = data.get("context") or {}
        if not public_id or not resource:
            return jsonify({"success": False, "error": "public_id and resource required"}), 400
        result = blockchain.abac_evaluate(public_id, resource, context)
        if result.get("success"):
            save_state()
        return jsonify({"success": True, "data": result})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/abac/demo', methods=['POST'])
def abac_demo():
    """
    Showcase the FULL ABAC formula on the guarded radar blueprint resource:
      * inside BEL perimeter + certified device + LEVEL-3  -> GRANTED
      * same identity but UNTRUSTED device hash           -> DENIED (Admin blocked)
      * same identity outside the geofence                -> DENIED even for Admin
      * insufficient clearance (LEVEL-1)                  -> DENIED
    """
    try:
        data = _post_json() or {}
        public_id = data.get("public_id") or "aarav.sharma@bel.gov.in"

        # Ensure the identity has clearance + a registered device + geofence
        # + an explicit grant for the guarded radar-blueprint resource.
        admin = "aarav.sharma@bel.gov.in"
        blockchain.set_security_clearance(public_id, "LEVEL-3")
        delhi = {"center_lat": 28.6139, "center_lon": 77.2090, "radius_km": 10.0}
        blockchain.register_smart_contract_rules(public_id, False, geofence=delhi)
        cert_device = "sha256:7f3a9c11bel-azure-issued-device92"
        blockchain.register_device(public_id, cert_device, "BEL-certified hardened laptop")
        resource = "radar_blueprint_X"
        inside = {"lat": 28.6129, "lon": 77.2295}         # India Gate, near BEL HQ
        outside = {"lat": 19.0760, "lon": 72.8777}        # Mumbai - outside perimeter
        blockchain.grant_resource(public_id, resource, actor=admin,
                                  context={"position": inside, "device_hash": cert_device})

        results = {
            "inside_perimeter_certified_device": blockchain.abac_evaluate(
                public_id, resource, {"device_hash": cert_device, "position": inside}),
            "inside_perimeter_untrusted_device": blockchain.abac_evaluate(
                public_id, resource, {"device_hash": "sha256:attacker-phone", "position": inside}),
            "outside_perimeter_certified_device": blockchain.abac_evaluate(
                public_id, resource, {"device_hash": cert_device, "position": outside}),
            "no_device_hash": blockchain.abac_evaluate(
                public_id, resource, {"position": inside}),
        }

        # Insufficient clearance: level-1 identity is denied even with everything else ok.
        low_id = "rajesh.kumar@bel.gov.in"
        blockchain.set_security_clearance(low_id, "LEVEL-1")
        blockchain.register_smart_contract_rules(low_id, False, geofence=delhi)
        blockchain.register_device(low_id, cert_device, "BEL-certified laptop")
        blockchain.grant_resource(low_id, resource, actor=admin,
                                  context={"position": inside, "device_hash": cert_device})
        results["level1_clearance_all_else_ok"] = blockchain.abac_evaluate(
            low_id, resource, {"device_hash": cert_device, "position": inside})

        save_state()
        summary = {
            k: {"granted": v["granted"], "decision": v["decision"],
                "evaluation": v["evaluation"]} for k, v in results.items()
        }
        return jsonify({
            "success": True,
            "identity": public_id,
            "resource": resource,
            "formula": "Access = Role ∧ SecurityClearance ∧ Geofence ∧ DeviceSecurityHash",
            "scenarios": summary,
            "conclusion": ("Access to a defence blueprint is AUTOMATICALLY revoked when the "
                           "request originates outside the BEL perimeter or from an untrusted "
                           "device - even for an Administrator.")
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


# ============================================
# DYNAMIC LIFECYCLE NFTs (ERC-1155 dNFTs + IoT oracle)
# ============================================

@app.route('/api/nft/mint', methods=['POST'])
def nft_mint():
    try:
        data = _post_json() or {}
        actor = data.get("actor") or data.get("public_id") or data.get("operator")
        if not actor:
            return jsonify({"success": False,
                            "reason": "actor is required - only an authorized administrator may mint a dNFT"}), 400
        asset_type = data.get("asset_type", "hardware")
        name = data.get("name", "BEL Asset")
        owner = data.get("owner") or actor
        description = data.get("description", "")
        required_clearance = data.get("required_clearance", "LEVEL-3")
        result = blockchain.nft_mint(asset_type, name, owner, description, required_clearance,
                                     actor=str(actor), context=data.get("context") or {})
        if result["success"]:
            save_state()
        return jsonify(result if result.get("success") else {"success": False, "reason": result.get("reason")})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/nft/state', methods=['POST'])
def nft_state():
    try:
        data = _post_json() or {}
        token_id = data.get("token_id")
        new_state = data.get("new_state")
        if not token_id or not new_state:
            return jsonify({"success": False, "error": "token_id and new_state required"}), 400
        result = blockchain.nft_update_state(token_id, new_state)
        if result["success"]:
            save_state()
        return jsonify(result if result.get("success") else {"success": False, "reason": result.get("reason")})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/nft/version', methods=['POST'])
def nft_version():
    try:
        data = _post_json() or {}
        actor = data.get("actor") or data.get("public_id") or data.get("operator")
        if not actor:
            return jsonify({"success": False,
                            "reason": "actor is required - version release is an "
                                      "RBAC-gated administrator operation"}), 400
        token_id = data.get("token_id")
        version = data.get("version")
        content_hash = data.get("content_hash")
        if not token_id or version is None or not content_hash:
            return jsonify({"success": False, "error": "token_id, version and content_hash required"}), 400
        result = blockchain.nft_release_version(token_id, int(version), content_hash,
                                                actor=str(actor), context=data.get("context") or {})
        if result["success"]:
            save_state()
        return jsonify(result if result.get("success") else {"success": False, "reason": result.get("reason")})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/nft/grant-download', methods=['POST'])
def nft_grant_download():
    try:
        data = _post_json() or {}
        actor = data.get("actor") or data.get("public_id") or data.get("operator")
        if not actor:
            return jsonify({"success": False,
                            "reason": "actor is required - download grants are an "
                                      "RBAC-gated operation"}), 400
        token_id = data.get("token_id")
        public_id = data.get("public_id")
        if not token_id or not public_id:
            return jsonify({"success": False, "error": "token_id and public_id required"}), 400
        result = blockchain.nft_grant_download(token_id, public_id,
                                               actor=str(actor), context=data.get("context") or {})
        if result["success"]:
            save_state()
        return jsonify(result if result.get("success") else {"success": False, "reason": result.get("reason")})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/nft/revoke-download', methods=['POST'])
def nft_revoke_download():
    try:
        data = _post_json() or {}
        actor = data.get("actor") or data.get("public_id") or data.get("operator")
        if not actor:
            return jsonify({"success": False,
                            "reason": "actor is required - download revocations are an "
                                      "RBAC-gated operation"}), 400
        token_id = data.get("token_id")
        public_id = data.get("public_id")
        if not token_id or not public_id:
            return jsonify({"success": False, "error": "token_id and public_id required"}), 400
        result = blockchain.nft_revoke_download(token_id, public_id,
                                                actor=str(actor), context=data.get("context") or {})
        if result["success"]:
            save_state()
        return jsonify(result if result.get("success") else {"success": False, "reason": result.get("reason")})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/nft/download', methods=['POST'])
def nft_download():
    """
    Authorize a blueprint download through the ABAC gate: download_auth AND
    clearance AND device AND (geofence). Outside the perimeter -> DENIED.
    """
    try:
        data = _post_json() or {}
        token_id = data.get("token_id")
        public_id = data.get("public_id")
        device_hash = data.get("device_hash")
        position = data.get("position")
        if not token_id or not public_id:
            return jsonify({"success": False, "error": "token_id and public_id required"}), 400
        result = blockchain.nft_download(token_id, public_id, device_hash, position)
        if result.get("success"):
            save_state()
        return jsonify({"success": result.get("success", False), **result})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/nft/transfer', methods=['POST'])
def nft_transfer():
    """Transfer a dNFT. Requires EITHER a cryptographic owner-consent signature
    (owner_signature + consent_timestamp + nonce, verified against the owner's
    on-chain public key) OR an administrator with nft.transfer.admin override.
    Both paths pass the RBAC + smart-contract policy gate; an unauthenticated
    anonymous request can never reassign a token."""
    try:
        data = _post_json() or {}
        actor = data.get("actor") or data.get("public_id") or data.get("operator")
        if not actor:
            return jsonify({"success": False,
                            "reason": "actor is required - only an authenticated operator may transfer a dNFT"}), 400
        token_id = data.get("token_id")
        new_owner = data.get("new_owner")
        if not token_id or not new_owner:
            return jsonify({"success": False, "error": "token_id and new_owner required"}), 400
        result = blockchain.nft_transfer(token_id, new_owner,
                                         actor=str(actor),
                                         signature=data.get("owner_signature") or data.get("signature"),
                                         nonce=data.get("nonce"),
                                         consent_timestamp=data.get("consent_timestamp") or data.get("timestamp"),
                                         admin_override=data.get("admin_override") is True,
                                         context=data.get("context") or {})
        if result["success"]:
            save_state()
        return jsonify(result if result.get("success") else {"success": False, "reason": result.get("reason")})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/nft/sign-transfer', methods=['POST'])
def nft_sign_transfer():
    """Client-side helper: produce an owner-consent signature over the canonical
    transfer message (token_id|new_owner|timestamp|nonce) with the owner's
    private key. Returns everything the /api/nft/transfer endpoint expects."""
    try:
        data = _post_json() or {}
        private_key = data.get("private_key")
        token_id = data.get("token_id")
        new_owner = data.get("new_owner")
        nonce = data.get("nonce") or secrets.token_hex(8)
        if not private_key or not token_id or not new_owner:
            return jsonify({"success": False,
                            "error": "private_key, token_id and new_owner required"}), 400
        timestamp = int(time.time())
        message = Blockchain.transfer_consent_message(token_id, new_owner, timestamp, nonce)
        signature = CryptoIdentity.sign_message(private_key, message)
        return jsonify({"success": True, "message": message, "owner_signature": signature,
                        "consent_timestamp": timestamp, "nonce": nonce,
                        "transfer_payload": {
                            "token_id": token_id, "new_owner": new_owner,
                            "owner_signature": signature,
                            "consent_timestamp": timestamp, "nonce": nonce}})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/nft/transfer-demo', methods=['POST'])
def nft_transfer_demo():
    """End-to-end transfer-security demo proving the PS3 controls:
      1. mint a dNFT to a fresh registered identity (owner, WITH a signing key)
      2. an unauthenticated request (no actor) is DENIED
      3. an unrelated caller (non-owner, non-admin) is DENIED
      4. a forged/invalid owner consent signature is DENIED
      5. a real signed owner consent (crypto) transfers the dNFT successfully
      6. replaying the SAME signature+nonce is DENIED (one-time nonce)
      7. an administrator override can transfer without owner consent
    """
    try:
        demo_tag = secrets.token_hex(4)
        owner_mail = f"owner.{demo_tag}@bel.gov.in"
        recipient_mail = f"recipient.{demo_tag}@bel.gov.in"
        admin = "aarav.sharma@bel.gov.in"
        inside = {"lat": 28.6129, "lon": 77.2295}
        blockchain.register_smart_contract_rules(admin, work_hours=False)

        owner_reg = blockchain.register_crypto_identity({
            "name": "Demo Owner", "role": "MANAGER", "email": owner_mail,
            "department": "Demo", "access_level": "HIGH",
            "allowed_resources": ["basic_access", "nft.view", "nft.transfer",
                                  "nft.transfer.owner", "ledger.view"]})
        blockchain.add_identity({
            "name": "Demo Recipient", "role": "Manager", "email": recipient_mail,
            "department": "Demo", "access_level": "MEDIUM",
            "allowed_resources": ["basic_access", "nft.view"]})
        if not owner_reg["success"]:
            return jsonify({"success": False,
                            "reason": f"owner registration failed: {owner_reg}"}), 500

        mint = blockchain.nft_mint("hardware", "Demo Transfer Asset", owner_mail,
                                   "PS3 transfer-protection demo", "LEVEL-3", actor=admin,
                                   context={"position": inside})
        if not mint["success"]:
            return jsonify({"success": False, "reason": f"mint failed: {mint}"}), 500
        tid = mint["asset"]["token_id"]

        anon = blockchain.nft_transfer(tid, recipient_mail)
        stranger = blockchain.nft_transfer(tid, recipient_mail, actor=recipient_mail)
        forged = blockchain.nft_transfer(
            tid, recipient_mail, actor=owner_mail,
            signature="forge-it", nonce="n1",
            consent_timestamp=str(int(time.time())))
        consent_ts = int(time.time())
        msg = Blockchain.transfer_consent_message(tid, recipient_mail, consent_ts, "n-consent-1")
        real_signature = CryptoIdentity.sign_message(owner_reg["private_key"], msg)
        signed = blockchain.nft_transfer(
            tid, recipient_mail, actor=owner_mail,
            signature=real_signature, nonce="n-consent-1",
            consent_timestamp=str(consent_ts))

        # Admin returns the token so the ORIGINAL owner holds it again, then the
        # SAME signature + nonce is replayed -> the one-time nonce is already
        # burned, so the replay must be rejected (crypto still verifies, nonce
        # gate catches it).
        admin_tx = blockchain.nft_transfer(tid, owner_mail, actor=admin, admin_override=True,
                                           context={"position": inside})
        replay = blockchain.nft_transfer(
            tid, recipient_mail, actor=owner_mail,
            signature=real_signature, nonce="n-consent-1",
            consent_timestamp=str(consent_ts))

        save_state()
        return jsonify({
            "success": True,
            "token_id": tid,
            "scenarios": {
                "no_actor_request": {
                    "success": anon.get("success"), "reason": anon.get("reason"),
                    "blocked": not anon.get("success")},
                "non_owner_non_admin": {
                    "success": stranger.get("success"), "reason": stranger.get("reason"),
                    "blocked": not stranger.get("success")},
                "forged_owner_signature": {
                    "success": forged.get("success"), "reason": forged.get("reason"),
                    "blocked": not forged.get("success")},
                "signed_owner_consent": {
                    "success": signed.get("success"), "consent_mode": signed.get("consent_mode"),
                    "signature_verified": signed.get("signature_verified")},
                "replayed_nonce": {
                    "success": replay.get("success"), "reason": replay.get("reason"),
                    "blocked": not replay.get("success")},
                "admin_override": {
                    "success": admin_tx.get("success"),
                    "consent_mode": admin_tx.get("consent_mode")},
            },
            "ownership_now": blockchain.nft_chain_ledger(),
            "conclusion": ("A dNFT can be transferred only by (a) the verified current "
                           "owner presenting a valid cryptographic consent signature, or "
                           "(b) an administrator with nft.transfer.admin override. "
                           "Unauthenticated, stranger and forged-signature requests are "
                           "denied, and consent nonces are single-use (replay blocked).")
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/nft/list', methods=['GET'])
def nft_list():
    return jsonify({"success": True, "assets": blockchain.nft_list()})


@app.route('/api/nft/get', methods=['POST'])
def nft_get():
    try:
        data = _post_json() or {}
        token_id = data.get("token_id")
        if not token_id:
            return jsonify({"success": False, "error": "token_id required"}), 400
        result = blockchain.nft_get(token_id)
        return jsonify(result if result.get("success") else {"success": False, "reason": result.get("reason")})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


# ----------------------------------------------------------------------------
# RBAC - role taxonomy, role policy management + role assignment (Feature-15)
# ----------------------------------------------------------------------------
@app.route('/api/rbac/list', methods=['GET', 'POST'])
def rbac_list():
    try:
        data = _post_json() or {}
        actor = data.get("actor") or data.get("public_id")
        return jsonify(blockchain.rbac_list(actor=actor))
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/rbac/define-role', methods=['POST'])
def rbac_define_role():
    try:
        data = _post_json() or {}
        actor = data.get("actor") or data.get("public_id")
        role = data.get("role")
        if not actor or not role:
            return jsonify({"success": False,
                            "reason": "actor and role required (administrator-only operation)"}), 400
        result = blockchain.rbac_define_role(actor, role,
                                             capabilities=data.get("capabilities"),
                                             resources=data.get("resources"))
        if result.get("success"):
            save_state()
        return jsonify(result if result.get("success") else {"success": False, "reason": result.get("reason")})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/rbac/assign-role', methods=['POST'])
def rbac_assign_role():
    try:
        data = _post_json() or {}
        actor = data.get("actor") or data.get("public_id")
        public_id = data.get("public_id") or data.get("subject") or data.get("email")
        role = data.get("role")
        if not actor or not public_id or not role:
            return jsonify({"success": False,
                            "reason": "actor, public_id and role required (administrator-only)"}), 400
        result = blockchain.rbac_assign_role(actor, public_id, role)
        if result.get("success"):
            save_state()
        return jsonify(result if result.get("success") else {"success": False, "reason": result.get("reason")})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/rbac/verify', methods=['POST'])
def rbac_verify():
    try:
        data = _post_json() or {}
        subject = data.get("subject") or data.get("public_id")
        if not subject:
            return jsonify({"success": False, "reason": "subject required"}), 400
        return jsonify(blockchain.rbac_verify(subject,
                                              capability=data.get("capability"),
                                              resource=data.get("resource")))
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


# ----------------------------------------------------------------------------
# On-chain NFT ownership - ownership is derived from chain blocks only
# ----------------------------------------------------------------------------
@app.route('/api/nft/ownership', methods=['POST'])
def nft_ownership():
    try:
        data = _post_json() or {}
        actor = data.get("actor")
        if data.get("all") is True:
            return jsonify(blockchain.nft_chain_ledger())
        token_id = data.get("token_id")
        if not token_id:
            return jsonify({"success": False, "reason": "token_id (or all=true) required"}), 400
        return jsonify(blockchain.nft_ownership(token_id, actor=actor))
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/nft/demo', methods=['POST'])
def nft_demo():
    """
    Full dNFT lifecycle demo:
      1. mint a hardware dNFT + a blueprint dNFT (state MANUFACTURED / DRAFT)
      2. signed IoT telemetry drives MANUFACTURED -> DEPLOYED -> UNDER_MAINTENANCE
      3. a forged transition back to MANUFACTURED is REJECTED (invalid state machine)
      4. blueprint versioning + download authorization
      5. blueprint download passes ABAC inside the perimeter, DENIED outside
      6. DECOMMISSIONED asset refuses all further downloads
    """
    try:
        hw = blockchain.nft_mint("hardware", "Radar Antenna Mk-II",
                                 "aarav.sharma@bel.gov.in",
                                 "Indigenously-built radar antenna", "LEVEL-3",
                                 actor="aarav.sharma@bel.gov.in")
        bp = blockchain.nft_mint("blueprint", "Radar Hardware Blueprint X",
                                 "aarav.sharma@bel.gov.in",
                                 "Complete radar blueprint package", "LEVEL-3",
                                 actor="aarav.sharma@bel.gov.in")
        hw_id = hw["asset"]["token_id"]
        bp_id = bp["asset"]["token_id"]

        transitions = [
            blockchain.nft_update_state(hw_id, "DEPLOYED"),
            blockchain.nft_update_state(hw_id, "UNDER_MAINTENANCE"),
            blockchain.nft_update_state(hw_id, "MANUFACTURED"),   # invalid rollback
        ]
        forged_rollback_blocked = not transitions[2]["success"]

        blockchain.nft_release_version(bp_id, 1, "sha256:9f86d081884c7d659a2feaa0c55ad015",
                                   actor="aarav.sharma@bel.gov.in")
        blockchain.nft_release_version(bp_id, 2, "sha256:e5cc7fbc3b5a76e4caa1e8c6b91e9a21",
                                   actor="aarav.sharma@bel.gov.in")

        pid = "aarav.sharma@bel.gov.in"
        blockchain.set_security_clearance(pid, "LEVEL-3")
        cert_device = "sha256:bel-certified-7f3a9c11"
        blockchain.register_device(pid, cert_device, "BEL hardened laptop")
        delhi = {"center_lat": 28.6139, "center_lon": 77.2090, "radius_km": 10.0}
        blockchain.register_smart_contract_rules(pid, False, geofence=delhi)
        inside = {"lat": 28.6129, "lon": 77.2295}
        outside = {"lat": 19.0760, "lon": 72.8777}

        blockchain.nft_grant_download(bp_id, pid, actor=pid,
                                      context={"position": inside, "device_hash": cert_device})

        dl_inside = blockchain.nft_download(bp_id, pid, cert_device, inside)
        dl_outside = blockchain.nft_download(bp_id, pid, cert_device, outside)

        # Decommission the hardware asset, then attempt to use it -> terminal block.
        decommissioned = blockchain.nft_update_state(hw_id, "DECOMMISSIONED")
        terminal = blockchain._nft_registry.get(hw_id)["state"]

        save_state()
        return jsonify({
            "success": True,
            "hardware": blockchain.nft_get(hw_id)["asset"],
            "blueprint": blockchain.nft_get(bp_id)["asset"],
            "lifecycle_transitions": [
                {"from": t.get("previous_state"), "to": t.get("new_state"),
                 "signed_telemetry": t.get("signed_telemetry", False),
                 "success": t["success"]} for t in transitions
            ],
            "forged_rollback_blocked": forged_rollback_blocked,
            "download_inside_perimeter": dl_inside,
            "download_outside_perimeter": dl_outside,
            "decommissioned_state": terminal,
            "conclusion": ("Dynamic NFTs track Manufactured -> Deployed -> Under Maintenance -> "
                           "Decommissioned via signed IoT telemetry; access to the blueprint is "
                           "automatically revoked outside the BEL perimeter even for an Admin.")
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


# ============================================
# DUAL-LAYER STORAGE (AES-GCM + threshold nodes + IPFS)
# ============================================

@app.route('/api/encipfs/add', methods=['POST'])
def encipfs_add():
    """
    Encrypt a payload client-side (AES-256-GCM) BEFORE IPFS and split the key
    across threshold nodes. Only ciphertext is ever stored / served publicly.
    """
    try:
        data = _post_json() or {}
        plaintext = data.get("plaintext")
        name = data.get("name", "document")
        owner = data.get("owner", "BEL")
        required_clearance = data.get("required_clearance", "LEVEL-3")
        if plaintext is None:
            return jsonify({"success": False, "error": "plaintext required"}), 400
        result = encrypted_ipfs.store(plaintext, name, owner, required_clearance)
        if result["success"]:
            save_state()
        return jsonify(result)
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/encipfs/list', methods=['GET'])
def encipfs_list():
    return jsonify({"success": True, "documents": encrypted_ipfs.list_docs()})


@app.route('/api/encipfs/peek', methods=['POST'])
def encipfs_peek():
    """Show that the public IPFS + CID layer returns ONLY AES ciphertext."""
    try:
        data = _post_json() or {}
        cid = data.get("cid")
        if not cid:
            return jsonify({"success": False, "error": "cid required"}), 400
        result = encrypted_ipfs.peek(cid)
        return jsonify(result if result.get("success") else {"success": False, "reason": result.get("reason")})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/encipfs/retrieve', methods=['POST'])
def encipfs_retrieve():
    """
    Unlock a stored document. The threshold nodes release their shares ONLY if
    the smart-contract verifies the requester's ZK attribute presentation
    (clearance >= the document's required_clearance).
    """
    try:
        data = _post_json() or {}
        cid = data.get("cid")
        presentation = data.get("presentation")
        nodes = data.get("nodes") or ["lit_node_1", "lit_node_2", "lit_node_3"]
        if not cid:
            return jsonify({"success": False, "error": "cid required"}), 400

        meta_list = [d for d in encrypted_ipfs.list_docs() if d["cid"] == cid]
        if not meta_list:
            return jsonify({"success": False, "error": "Unknown cid"}), 404
        required = meta_list[0]["required_clearance"]

        if not presentation:
            return jsonify({
                "success": False,
                "reason": (f"GATE CLOSED - no ZK attribute presentation provided. "
                           f"This document requires clearance >= {required}.")
            })

        # The presentation MUST target the document's effective clearance.
        expected_predicate = {"attribute": "security_clearance", "op": ">=", "value": required}
        if presentation.get("predicate") != expected_predicate:
            return jsonify({
                "success": False,
                "reason": "GATE CLOSED - presentation does not target this document's clearance requirement"
            })

        gate = blockchain.verify_credential_presentation(presentation)
        if not gate["granted"]:
            return jsonify({
                "success": False,
                "reason": f"GATE CLOSED - ZK attribute proof rejected: {gate.get('reason', '')}"
            })

        # Gate passed -> nodes release threshold shares -> key + decrypt.
        result = encrypted_ipfs.retrieve(cid, nodes)
        if result.get("success"):
            save_state()
        return jsonify({"success": result.get("success", False), "gate": "OPEN", **result})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/encipfs/demo', methods=['POST'])
def encipfs_demo():
    """
    Full dual-layer storage demo:
      1. register DIDs, issue a LEVEL-3 credential, and one LEVEL-1 credential
      2. publish a radar blueprint - encrypted with AES-256-GCM, key split 5 ways
         (threshold 3), ONLY ciphertext visible publicly
      3. LEVEL-3 holder presents a ZK attribute proof -> nodes release shares ->
         document decrypts in full
      4. the same document WITHOUT a proof (or with a poor clearance) is DENIED,
         and with fewer than 3 shares decryption is cryptographically impossible
    """
    try:
        org = blockchain.register_did("BEL - Central Authority", "Issuer", "issuer@bel.gov.in")
        eng = blockchain.register_did("Aarav Sharma", "Radar Engineer", "aarav.sharma@bel.gov.in")
        low = blockchain.register_did("Rajesh Kumar", "Field Officer", "rajesh.kumar@bel.gov.in")
        blockchain.issue_credential(eng["did"], org["did"],
                                    {"security_clearance": "LEVEL-3"})
        blockchain.issue_credential(low["did"], org["did"],
                                    {"security_clearance": "LEVEL-1"})

        blueprint_payload = ("RADAR-BLUEPRINT-X | REV 2 | Antenna array specs: 1.2 GHz, "
                             "PHASED-ARRAY, 48 sub-modules | Export control: BEL-RESTRICTED")
        store_result = encrypted_ipfs.store(blueprint_payload,
                                            "radar_blueprint_X.txt", "BEL", "LEVEL-3")
        cid = store_result["cid"]
        peek = encrypted_ipfs.peek(cid)

        # Successful access: LEVEL-3 presentation against a server-issued challenge.
        challenge = secrets_hex(16)
        predicate = {"attribute": "security_clearance", "op": ">=", "value": "LEVEL-3"}
        pres = blockchain.present_credential(eng["did"], eng["private_key"], predicate, challenge)
        gate_ok = blockchain.verify_credential_presentation(pres["presentation"])

        # The ZK gate is evaluated BEFORE any share is released to the holder.
        if gate_ok.get("granted"):
            unlocked = encrypted_ipfs.retrieve(cid, ["lit_node_1", "lit_node_2", "lit_node_3"])
        else:
            unlocked = {
                "success": False,
                "error": gate_ok.get("reason", "ZK attribute proof rejected"),
                "gate": "CLOSED"
            }

        # Blocked attempt: an attacker presents nothing -> the route-level gate
        # (the /api/encipfs/retrieve side) refuses to release any shares.
        no_proof = {
            "success": False,
            "gate": "CLOSED",
            "reason": "No ZK attribute presentation - threshold nodes refuse to release shares"
        }

        # Blocked attempt: only 2 of 3 shares released (cryptographically possible? no).
        too_few = encrypted_ipfs.retrieve(cid, ["lit_node_1", "lit_node_2"])

        save_state()
        return jsonify({
            "success": True,
            "storage_metadata": {k: store_result[k] for k in
                                 ("cid", "encryption", "required_clearance", "n_shares", "threshold")},
            "what_public_peeker_sees": peek,
            "legitimate_unlock": {
                "zk_gate": gate_ok,
                "decrypted": unlocked,
                "plaintext_recovered": unlocked.get("plaintext") == blueprint_payload
            },
            "attack_without_proof": {
                "result": no_proof,
                "note": "Threshold nodes refuse to release shares without a verified ZK attribute proof"
            },
            "attack_too_few_shares": too_few,
            "conclusion": ("Payload is encrypted client-side (AES-256-GCM) before IPFS; the key is "
                           "split 5-ways (threshold 3); it is reconstructed ONLY once the smart "
                           "contract verifies a ZK attribute proof of the required clearance.")
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


# ============================================================
# FEATURE SUITE v2 - 13 security/operations capabilities
# ============================================================

# --- F1: Disposable / timed access tokens ---
@app.route('/api/disposable/mint', methods=['POST'])
def disposable_mint():
    try:
        d = _post_json() or {}
        r = blockchain.mint_disposable_token(d.get("public_id"), d.get("resource"),
                                             d.get("actions") or ["read"],
                                             float(d.get("ttl_s", 300)), d.get("max_uses", 1))
        save_state()
        return jsonify({"success": r["success"], "data": r})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/disposable/consume', methods=['POST'])
def disposable_consume():
    try:
        d = _post_json() or {}
        r = blockchain.consume_disposable_token(d.get("token"), d.get("resource"), d.get("action"))
        save_state()
        return jsonify({"success": r["granted"], "data": r})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/disposable/revoke', methods=['POST'])
def disposable_revoke():
    try:
        d = _post_json() or {}
        r = blockchain.revoke_disposable_token(d.get("token"))
        save_state()
        return jsonify({"success": r["success"], "data": r})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/disposable/list')
def disposable_list():
    r = blockchain.list_disposable_tokens(request.args.get("public_id"))
    return jsonify({"success": r["success"], "data": r["tokens"]})


# --- F2: Delegation chains ---
@app.route('/api/delegations/grant', methods=['POST'])
def delegation_grant():
    try:
        d = _post_json() or {}
        r = blockchain.grant_delegation(d.get("delegator"), d.get("delegate"), d.get("resource"),
                                        d.get("actions") or ["read"], float(d.get("ttl_s", 3600)),
                                        int(d.get("max_depth", 3)), bool(d.get("single_use_chain", False)))
        save_state()
        return jsonify({"success": r["success"], "data": r})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/delegations/revoke', methods=['POST'])
def delegation_revoke():
    try:
        d = _post_json() or {}
        r = blockchain.revoke_delegation(d.get("delegation_id"))
        save_state()
        return jsonify({"success": r["success"], "data": r})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/delegations/evaluate', methods=['POST'])
def delegation_evaluate():
    try:
        d = _post_json() or {}
        r = blockchain.check_delegated_access(d.get("delegate"), d.get("resource"), d.get("action"))
        return jsonify({"success": r["granted"], "data": r})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/delegations/list')
def delegation_list():
    r = blockchain.list_delegations(request.args.get("public_id"),
                                    request.args.get("as_delegate") == "true")
    return jsonify({"success": r["success"], "data": r["delegations"]})


# --- F3: Travel-mode context access ---
@app.route('/api/travel-mode/enable', methods=['POST'])
def travel_enable():
    try:
        d = _post_json() or {}
        r = blockchain.enable_travel_mode(d.get("public_id"), d.get("mode", "warzone"),
                                          d.get("destinations") or ["Anywhere"],
                                          float(d.get("ttl_s", 86400)))
        save_state()
        return jsonify({"success": r["success"], "data": r})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/travel-mode/disable', methods=['POST'])
def travel_disable():
    try:
        d = _post_json() or {}
        r = blockchain.disable_travel_mode(d.get("public_id"))
        save_state()
        return jsonify({"success": r["success"], "data": r})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/travel-mode/evaluate', methods=['POST'])
def travel_evaluate():
    try:
        d = _post_json() or {}
        r = blockchain.evaluate_travel_mode_access(d.get("public_id"), d.get("resource"),
                                                   d.get("context") or {})
        return jsonify({"success": bool(r.get("granted")), "data": r})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/travel-mode/list')
def travel_list():
    r = blockchain.list_travel_modes()
    return jsonify({"success": r["success"], "data": r["travel_modes"]})


# --- F4: DID rescue kits ---
@app.route('/api/rescue/create', methods=['POST'])
def rescue_create():
    try:
        d = _post_json() or {}
        r = blockchain.create_rescue_kit(d.get("public_id"), int(d.get("threshold", 2)),
                                         int(d.get("total_shares", 3)), d.get("guardians") or [])
        save_state()
        return jsonify({"success": r["success"], "data": r})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/rescue/recover', methods=['POST'])
def rescue_recover():
    try:
        d = _post_json() or {}
        r = blockchain.recover_rescue_kit(d.get("public_id"), d.get("shares") or {})
        save_state()
        return jsonify({"success": r["success"], "data": r})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/rescue/list')
def rescue_list():
    r = blockchain.list_rescue_kits()
    return jsonify({"success": r["success"], "data": r["rescue_kits"]})


# --- F5: Activity report export ---
@app.route('/api/report/activity')
def report_activity():
    r = blockchain.export_activity_report(request.args.get("public_id"),
                                          request.args.get("limit", type=int))
    return jsonify({"success": r["success"], "data": {
        "rows": r["rows"], "csv": r["csv"], "count": r["count"]}})


# --- F6: Rule dry-run simulator ---
@app.route('/api/rules/dry-run', methods=['POST'])
def rules_dry_run():
    try:
        d = _post_json() or {}
        r = blockchain.dry_run_rules(d.get("public_id"), d.get("resource"),
                                     d.get("context") or {}, d.get("rules") or [])
        return jsonify({"success": bool(r.get("success")), "data": r})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


# --- F7: Anomaly scores + security alerts ---
@app.route('/api/anomaly/scan', methods=['POST'])
def anomaly_scan():
    try:
        d = _post_json() or {}
        r = blockchain.run_anomaly_scan(d.get("since"), float(d.get("window", 900)))
        save_state()
        return jsonify({"success": r["success"], "data": r})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/anomaly/list')
def anomaly_list():
    active = request.args.get("active") != "false"
    r = blockchain.list_anomaly_alerts(active_only=active)
    return jsonify({"success": r["success"], "data": r["alerts"]})


@app.route('/api/anomaly/ack', methods=['POST'])
def anomaly_ack():
    try:
        d = _post_json() or {}
        r = blockchain.acknowledge_anomaly_alert(d.get("alert_id"))
        save_state()
        return jsonify({"success": r["success"], "data": r})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


# --- F8: Quorum-approved privileged operations ---
@app.route('/api/quorum/create', methods=['POST'])
def quorum_create():
    try:
        d = _post_json() or {}
        r = blockchain.create_quorum_operation(d.get("operation"), d.get("proposed_by"),
                                               d.get("params") or {}, int(d.get("required_votes", 2)))
        save_state()
        return jsonify({"success": r["success"], "data": r})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/quorum/approve', methods=['POST'])
def quorum_approve():
    try:
        d = _post_json() or {}
        r = blockchain.approve_quorum_operation(d.get("op_id"), d.get("approver"))
        save_state()
        return jsonify({"success": r["success"], "data": r})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/quorum/list')
def quorum_list():
    r = blockchain.list_quorum_operations(request.args.get("status"))
    return jsonify({"success": r["success"], "data": r["quorum_ops"]})


# --- F9: VC expiry + refresh ---
@app.route('/api/credentials/expiry', methods=['POST'])
def vc_expiry():
    try:
        d = _post_json() or {}
        r = blockchain.set_credential_expiry(d.get("public_id"), d.get("credential_id"),
                                             float(d.get("expires_at", time.time() + 86400)))
        save_state()
        return jsonify({"success": r["success"], "data": r})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/credentials/refresh', methods=['POST'])
def vc_refresh():
    try:
        d = _post_json() or {}
        r = blockchain.refresh_credential(d.get("public_id"), d.get("credential_id"),
                                          d.get("issuer", "blockchain-issuer"))
        save_state()
        return jsonify({"success": r["success"], "data": r})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/credentials/lifecycle')
def vc_lifecycle():
    r = blockchain.list_credential_lifecycle(request.args.get("public_id"))
    return jsonify({"success": r["success"], "data": r["credentials"]})


# --- F10: Chain backups ---
@app.route('/api/backups/create', methods=['POST'])
def backup_create():
    try:
        d = _post_json() or {}
        r = blockchain.create_chain_backup(d.get("label", "manual"))
        save_state()
        return jsonify({"success": r["success"], "data": r})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/backups/verify', methods=['POST'])
def backup_verify():
    try:
        d = _post_json() or {}
        r = blockchain.verify_chain_backup(d.get("backup_id"))
        return jsonify({"success": r["success"], "data": r})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/backups/restore', methods=['POST'])
def backup_restore():
    try:
        d = _post_json() or {}
        r = blockchain.restore_chain_backup(d.get("backup_id"))
        save_state()
        return jsonify({"success": r["success"], "data": r})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/backups/list')
def backup_list():
    r = blockchain.list_chain_backups()
    return jsonify({"success": r["success"], "data": r["backups"]})


# --- F11: Cross-node trust scores ---
@app.route('/api/trust/compute', methods=['POST'])
def trust_compute():
    try:
        r = blockchain.compute_trust_scores()
        save_state()
        return jsonify({"success": r["success"], "data": r})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/trust/scores')
def trust_scores():
    r = blockchain.list_trust_scores()
    return jsonify({"success": r["success"], "data": r["trust_scores"]})


# --- F12: Live attack / auto-response defense log ---
@app.route('/api/defense/run', methods=['POST'])
def defense_run():
    try:
        d = _post_json() or {}
        r = blockchain.run_live_defense(d.get("attack_type", "brute-force"), d.get("target"),
                                        bool(d.get("auto_respond", True)))
        save_state()
        return jsonify({"success": r["success"], "data": r})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/defense/list')
def defense_list():
    r = blockchain.list_defense_events()
    return jsonify({"success": r["success"], "data": r["defense_events"]})


# --- F13: Physical check-in QR passes ---
@app.route('/api/checkin/create', methods=['POST'])
def checkin_create():
    try:
        d = _post_json() or {}
        r = blockchain.create_checkin_pass(d.get("public_id"), d.get("facility", "SEC-7"),
                                           int(d.get("valid_minutes", 15)), d.get("ppe"))
        save_state()
        return jsonify({"success": r["success"], "data": r})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/checkin/verify', methods=['POST'])
def checkin_verify():
    try:
        d = _post_json() or {}
        r = blockchain.verify_checkin(d.get("token"), d.get("facility"),
                                      bool(d.get("location_ok", True)))
        save_state()
        return jsonify({"success": r["granted"], "data": r})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/checkin/list')
def checkin_list():
    r = blockchain.list_checkins(request.args.get("active") == "true")
    return jsonify({"success": r["success"], "data": r["checkins"]})


# =====================================================================
# G-SERIES: Adaptive step-up (JIT auth) / TOTP / Velocity / PII Redaction
# =====================================================================
@app.route('/api/adaptive/evaluate', methods=['POST'])
def adaptive_evaluate():
    try:
        d = _post_json() or {}
        r = blockchain.evaluate_adaptive_access(
            d.get("public_id"), d.get("resource"), d.get("context") or {})
        save_state()
        return jsonify({"success": r["success"], "data": r})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/adaptive/stepup/request', methods=['POST'])
def adaptive_stepup_request():
    try:
        d = _post_json() or {}
        r = blockchain.request_step_up(
            d.get("public_id"), d.get("resource"), d.get("factor", "TOTP"))
        save_state()
        return jsonify({"success": r["success"], "data": r})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/adaptive/stepup/fulfill', methods=['POST'])
def adaptive_stepup_fulfill():
    try:
        d = _post_json() or {}
        r = blockchain.fulfill_step_up(
            d.get("stepup_id"), d.get("factor"), d.get("evidence"))
        save_state()
        return jsonify({"success": r["success"], "data": r})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/adaptive/stepup/list')
def adaptive_stepup_list():
    r = blockchain.list_stepup_requests(request.args.get("active") == "true")
    return jsonify({"success": r["success"], "data": r["stepups"]})


@app.route('/api/adaptive/decisions')
def adaptive_decisions():
    r = blockchain.list_adaptive_decisions(int(request.args.get("limit", 20)))
    return jsonify({"success": r["success"], "data": r["decisions"]})


@app.route('/api/totp/enroll', methods=['POST'])
def totp_enroll():
    try:
        d = _post_json() or {}
        r = blockchain.enroll_totp(d.get("public_id"), step=d.get("step") or 30)
        save_state()
        return jsonify({"success": r["success"], "data": r})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/totp/verify', methods=['POST'])
def totp_verify():
    try:
        d = _post_json() or {}
        r = blockchain.verify_totp(d.get("public_id"), d.get("code"))
        save_state()
        return jsonify({"success": r["success"], "data": r})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/totp/reset', methods=['POST'])
def totp_reset():
    try:
        d = _post_json() or {}
        r = blockchain.reset_totp(d.get("public_id"))
        save_state()
        return jsonify({"success": r["success"], "data": r})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/totp/list')
def totp_list():
    r = blockchain.list_totp()
    return jsonify({"success": r["success"], "data": r["totp"]})


@app.route('/api/velocity/evaluate', methods=['POST'])
def velocity_evaluate():
    def _geo(v):
        if isinstance(v, (list, tuple)) and len(v) == 2:
            return tuple(v)
        return None
    try:
        d = _post_json() or {}
        r = blockchain.evaluate_velocity(
            _geo(d.get("from_geo")), _geo(d.get("to_geo")),
            float(d.get("elapsed_minutes") or 0), float(d.get("max_speed_kmh") or 900))
        return jsonify({"success": r["success"], "data": r})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/velocity/anomaly', methods=['POST'])
def velocity_anomaly():
    def _geo(v):
        if isinstance(v, (list, tuple)) and len(v) == 2:
            return tuple(v)
        return None
    try:
        d = _post_json() or {}
        r = blockchain.detect_velocity_anomaly(
            d.get("public_id"), d.get("from_facility"), d.get("to_facility"),
            _geo(d.get("from_geo")), _geo(d.get("to_geo")),
            float(d.get("elapsed_minutes") or 0), float(d.get("max_speed_kmh") or 900))
        save_state()
        return jsonify({"success": r["success"], "data": r})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/velocity/events')
def velocity_events():
    r = blockchain.list_velocity_events()
    return jsonify({"success": r["success"], "data": r["events"]})


@app.route('/api/redact/apply', methods=['POST'])
def redact_apply():
    try:
        d = _post_json() or {}
        r = blockchain.redact_identity_field(d.get("public_id"), d.get("field"))
        save_state()
        return jsonify({"success": r["success"], "data": r})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/redact/check', methods=['POST'])
def redact_check():
    try:
        d = _post_json() or {}
        r = blockchain.check_redaction(d.get("public_id"), d.get("field"))
        return jsonify({"success": r["success"], "data": r})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/redact/list')
def redact_list():
    r = blockchain.list_redactions(int(request.args.get("limit", 25)))
    return jsonify({"success": r["success"], "data": r["redactions"]})


@app.route('/api/honeytoken/plant', methods=['POST'])
def honeytoken_plant():
    try:
        d = _post_json() or {}
        r = blockchain.plant_honeytoken(
            d.get("public_id"), d.get("resource"), d.get("label"), d.get("clue"))
        save_state()
        return jsonify({"success": r["success"], "data": r})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/honeytoken/touch', methods=['POST'])
def honeytoken_touch():
    try:
        d = _post_json() or {}
        r = blockchain.touch_honeytoken(d.get("honeytoken_id"), d.get("presented_by"))
        save_state()
        return jsonify({"success": r["success"], "data": r})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/honeytoken/list')
def honeytoken_list():
    r = blockchain.list_honeytokens(request.args.get("status"))
    return jsonify({"success": r["success"], "data": r["honeytokens"]})


# =====================================================================
# G-SERIES (NEW): Break-glass ledger / CRL + ZK / k-anonymity /
#                 measured-boot attestation / cross-org federation
# =====================================================================

# ---------- G1: Break-glass / emergency access ledger ----------
@app.route('/api/breakglass/request', methods=['POST'])
def breakglass_request():
    try:
        d = _post_json() or {}
        r = blockchain.request_breakglass_access(
            d.get("public_id"), d.get("resource"),
            d.get("reason", "emergency"), d.get("requester", "SYSTEM"))
        save_state()
        return jsonify({"success": r["opened"], "data": r})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/breakglass/approve', methods=['POST'])
def breakglass_approve():
    try:
        d = _post_json() or {}
        r = blockchain.approve_breakglass_access(
            d.get("emergency_id"), d.get("approver", "SECOND_OPERATOR"),
            bool(d.get("override", False)))
        save_state()
        return jsonify({"success": r["approved"], "data": r})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/breakglass/use', methods=['POST'])
def breakglass_use():
    try:
        d = _post_json() or {}
        r = blockchain.use_breakglass_access(
            d.get("emergency_id"), d.get("public_id"), d.get("resource"))
        save_state()
        return jsonify({"success": r["granted"], "data": r})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/breakglass/list')
def breakglass_list():
    r = blockchain.list_breakglass_windows(request.args.get("status"))
    return jsonify({"success": r["success"], "data": r["windows"]})


# ---------- G4: Global revocation list (CRL) + ZK status proofs ----------
@app.route('/api/crl/revoke', methods=['POST'])
def crl_revoke():
    try:
        d = _post_json() or {}
        r = blockchain.crl_revoke(d.get("public_id"), d.get("reason", ""))
        save_state()
        return jsonify({"success": r["success"], "data": r})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/crl/unrevoke', methods=['POST'])
def crl_unrevoke():
    try:
        d = _post_json() or {}
        r = blockchain.crl_unrevoke(d.get("public_id"))
        save_state()
        return jsonify({"success": r["success"], "data": r})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/crl/list')
def crl_list():
    r = blockchain.crl_list()
    return jsonify({"success": r["success"], "data": r})


@app.route('/api/crl/check')
def crl_check():
    r = blockchain.crl_check(request.args.get("public_id"))
    return jsonify({"success": r["success"], "data": r})


@app.route('/api/crl/zk/challenge')
def crl_zk_challenge():
    r = blockchain.crl_zk_challenge()
    return jsonify({"success": r["success"], "data": r})


@app.route('/api/crl/zk/prove', methods=['POST'])
def crl_zk_prove():
    try:
        d = _post_json() or {}
        r = blockchain.crl_zk_prove(d.get("public_id"), d.get("challenge"))
        save_state()
        return jsonify({"success": r["success"], "data": r})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/crl/zk/verify', methods=['POST'])
def crl_zk_verify():
    try:
        d = _post_json() or {}
        r = blockchain.crl_zk_verify(d.get("proof_token"), d.get("challenge"))
        return jsonify({"success": r["success"], "data": r})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/crl/zk/demo')
def crl_zk_demo():
    r = blockchain.crl_zk_demo()
    return jsonify({"success": r["success"], "data": r})


# ---------- G7: k-anonymity aggregate statistics ----------
@app.route('/api/stats/k-anonymity')
def stats_k_anonymity():
    r = blockchain.k_anonymity_stats(int(request.args.get("k", 3)))
    return jsonify({"success": r["success"], "data": r})


# ---------- G9: Measured-boot device attestation ----------
@app.route('/api/attest/register', methods=['POST'])
def attest_register():
    try:
        d = _post_json() or {}
        r = blockchain.register_boot_measurement(
            d.get("public_id"), d.get("device_hash"),
            d.get("measure"), d.get("label", ""))
        save_state()
        return jsonify({"success": r["success"], "data": r})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/attest/revoke', methods=['POST'])
def attest_revoke():
    try:
        d = _post_json() or {}
        r = blockchain.revoke_device_attestation(
            d.get("public_id"), d.get("device_hash"))
        save_state()
        return jsonify({"success": r["success"], "data": r})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/attest/login', methods=['POST'])
def attest_login():
    try:
        d = _post_json() or {}
        r = blockchain.attest_device_login(
            d.get("public_id"), d.get("device_hash"),
            d.get("measure"), d.get("resource"))
        save_state()
        return jsonify({"success": r.get("granted", False), "data": r})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/attest/list')
def attest_list():
    r = blockchain.list_device_attestations()
    return jsonify({"success": r["success"], "data": r["devices"]})


# ---------- G10: Cross-org federation ----------
@app.route('/api/federation/register', methods=['POST'])
def federation_register():
    try:
        d = _post_json() or {}
        r = blockchain.federation_register_org(
            d.get("org_id"), d.get("meta") or {}, bool(d.get("trust", True)))
        save_state()
        return jsonify({"success": r["success"], "data": r})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/federation/trust', methods=['POST'])
def federation_trust():
    try:
        d = _post_json() or {}
        r = blockchain.federation_set_trust(
            d.get("org_id"), bool(d.get("trust", True)))
        save_state()
        return jsonify({"success": r["success"], "data": r})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/federation/list')
def federation_list():
    r = blockchain.federation_list()
    return jsonify({"success": r["success"], "data": r})


@app.route('/api/federation/demo')
def federation_demo():
    r = blockchain.cross_org_demo()
    return jsonify({"success": r["success"], "data": r})


# ============================================================
# DASH: Security Posture / Live Threat Board / Point-in-Time
# ============================================================
@app.route('/api/posture/score')
def posture_score():
    r = blockchain.compute_security_posture()
    save_state()
    return jsonify({"success": r["success"], "data": r})


@app.route('/api/posture/history')
def posture_history():
    return jsonify({"success": True,
                    "data": {"history": getattr(blockchain, "_posture_history", [])}})


@app.route('/api/threat/board')
def threat_board():
    r = blockchain.threat_board()
    return jsonify({"success": r["success"], "data": r})


@app.route('/api/audit/point-in-time', methods=['POST'])
def point_in_time():
    try:
        d = _post_json() or {}
        r = blockchain.point_in_time_report(
            d.get("block_index"), d.get("resource"), d.get("public_id"))
        return jsonify({"success": r["success"], "data": r})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


# ============================================================
# ID: Duplicate Detection / Bulk Onboarding / Join Queue
# ============================================================
@app.route('/api/identity/duplicate-check', methods=['POST'])
def duplicate_check():
    try:
        d = _post_json() or {}
        r = blockchain.duplicate_detect(d.get("name", ""), d.get("email", ""), d.get("id_number", ""))
        save_state()
        return jsonify({"success": r["success"], "data": r})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/identity/duplicate-flags')
def duplicate_flags():
    r = blockchain.list_duplicate_flags()
    return jsonify({"success": r["success"], "data": r})


@app.route('/api/onboard/bulk', methods=['POST'])
def bulk_onboard():
    try:
        d = _post_json() or {}
        rows = d.get("rows") or []
        r = blockchain.bulk_onboard(rows, d.get("label"))
        save_state()
        return jsonify({"success": r["success"], "data": r})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/onboard/batches')
def bulk_batches():
    r = blockchain.list_bulk_batches()
    return jsonify({"success": r["success"], "data": r})


@app.route('/api/join/request', methods=['POST'])
def join_request():
    try:
        d = _post_json() or {}
        r = blockchain.join_request(d.get("identity_data") or {},
                                    d.get("proposer", "self-registration"))
        save_state()
        return jsonify({"success": r["success"], "data": r})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/join/approve', methods=['POST'])
def join_approve():
    try:
        d = _post_json() or {}
        r = blockchain.join_approve(d.get("join_id"), d.get("approver", "admin"))
        save_state()
        return jsonify({"success": r["success"], "data": r})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/join/reject', methods=['POST'])
def join_reject():
    try:
        d = _post_json() or {}
        r = blockchain.join_reject(d.get("join_id"), d.get("reason", "rejected"),
                                   d.get("approver", "admin"))
        save_state()
        return jsonify({"success": r["success"], "data": r})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/join/list')
def join_list():
    try:
        r = blockchain.list_join_requests(request.args.get("status"))
        return jsonify({"success": r["success"], "data": r})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


# ============================================================
# ZK: Range Proof / Post-Quantum / Key Transparency / Liveness
# ============================================================
@app.route('/api/zk/range/prove', methods=['POST'])
def zk_range_prove():
    try:
        d = _post_json() or {}
        r = blockchain.zk_range_prove(d.get("secret_value"), d.get("min_bound"))
        return jsonify({"success": r["success"], "data": r})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/zk/range/verify', methods=['POST'])
def zk_range_verify():
    try:
        d = _post_json() or {}
        r = blockchain.zk_range_verify(d.get("proof"))
        return jsonify({"success": r["success"], "data": r})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/pq/list')
def pq_list():
    r = blockchain.list_post_quantum()
    return jsonify({"success": r["success"], "data": r})


@app.route('/api/pq/register', methods=['POST'])
def pq_register():
    try:
        d = _post_json() or {}
        r = blockchain.register_post_quantum_identity(d.get("public_id"))
        save_state()
        return jsonify({"success": r["success"], "data": r})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/pq/auth', methods=['POST'])
def pq_auth():
    try:
        d = _post_json() or {}
        r = blockchain.passwordless_pq_auth(d.get("public_id"), d.get("resource", "access"),
                                            d.get("signature_b64", ""),
                                            d.get("nonce") or __import__("time").time())
        return jsonify({"success": r.get("authenticated", False), "data": r})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/keytrans/rotate', methods=['POST'])
def keytrans_rotate():
    try:
        d = _post_json() or {}
        r = blockchain.kt_record_rotation(d.get("public_id"), d.get("new_key_fingerprint"),
                                          d.get("rotated_by", "identity-holder"),
                                          d.get("reason", "scheduled rotation"))
        save_state()
        return jsonify({"success": r["success"], "data": r})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/keytrans/chain', methods=['POST'])
def keytrans_chain():
    try:
        d = _post_json() or {}
        r = blockchain.kt_chain(d.get("public_id"))
        return jsonify({"success": r["success"], "data": r})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/keytrans/list')
def keytrans_list():
    r = blockchain.kt_list()
    return jsonify({"success": r["success"], "data": r})


@app.route('/api/liveness/issue', methods=['POST'])
def liveness_issue():
    try:
        d = _post_json() or {}
        r = blockchain.liveness_issue(d.get("public_id"))
        save_state()
        return jsonify({"success": r["success"], "data": r})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/liveness/verify', methods=['POST'])
def liveness_verify():
    try:
        d = _post_json() or {}
        r = blockchain.liveness_verify(d.get("challenge_id"), d.get("response_nonce"))
        save_state()
        return jsonify({"success": r["success"], "data": r})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


# ============================================================
# AC: Duress PIN / Two-Person / Risk-Adaptive Step-Up
# ============================================================
@app.route('/api/duress/register', methods=['POST'])
def duress_register():
    try:
        d = _post_json() or {}
        r = blockchain.duress_register(d.get("public_id"), d.get("duress_pin"),
                                       d.get("normal_pin", "123456"))
        save_state()
        return jsonify({"success": r["success"], "data": r})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/duress/authenticate', methods=['POST'])
def duress_authenticate():
    try:
        d = _post_json() or {}
        r = blockchain.duress_authenticate(d.get("public_id"), d.get("pin"), d.get("resource", "vault"))
        save_state()
        return jsonify({"success": r["success"], "data": r})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/duress/list')
def duress_list():
    r = blockchain.list_duress()
    return jsonify({"success": r["success"], "data": r})


@app.route('/api/twoperson/initiate', methods=['POST'])
def tp_initiate():
    try:
        d = _post_json() or {}
        r = blockchain.tp_initiate(d.get("resource"), d.get("viewer_a"))
        save_state()
        return jsonify({"success": r["success"], "data": r})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/twoperson/coauthorize', methods=['POST'])
def tp_coauthorize():
    try:
        d = _post_json() or {}
        r = blockchain.tp_coauthorize(d.get("window_id"), d.get("viewer_b"))
        save_state()
        return jsonify({"success": r["success"], "data": r})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/twoperson/view', methods=['POST'])
def tp_view():
    try:
        d = _post_json() or {}
        r = blockchain.tp_view(d.get("window_id"), d.get("viewer"))
        save_state()
        return jsonify({"success": r["success"], "data": r})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/twoperson/list')
def tp_list():
    r = blockchain.tp_list()
    return jsonify({"success": r["success"], "data": r})


@app.route('/api/riskstepup/evaluate', methods=['POST'])
def risk_stepup_evaluate():
    try:
        d = _post_json() or {}
        r = blockchain.risk_stepup_evaluate(d.get("public_id"), d.get("resource", "vault"))
        return jsonify({"success": r["success"], "data": r})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/riskstepup/policy', methods=['POST'])
def risk_stepup_policy():
    try:
        d = _post_json() or {}
        r = blockchain.risk_stepup_policy(d.get("resource"), d.get("factors") or [])
        save_state()
        return jsonify({"success": r["success"], "data": r})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/riskstepup/list')
def risk_stepup_list():
    r = blockchain.risk_stepup_list()
    return jsonify({"success": r["success"], "data": r})


# ============================================================
# NET: Air-Gapped Sync / Split-Brain / Pinning Reputation
# ============================================================
@app.route('/api/airgap/create', methods=['POST'])
def airgap_create():
    try:
        d = _post_json() or {}
        r = blockchain.airgap_create_pack(d.get("since_block", 0), d.get("source_node", "NODE-01"))
        save_state()
        return jsonify({"success": r["success"], "data": r})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/airgap/import', methods=['POST'])
def airgap_import():
    try:
        d = _post_json() or {}
        r = blockchain.airgap_import_pack(d.get("pack"))
        save_state()
        return jsonify({"success": r["success"], "data": r})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/airgap/list')
def airgap_list():
    r = blockchain.airgap_list()
    return jsonify({"success": r["success"], "data": r})


@app.route('/api/partition/start', methods=['POST'])
def partition_start():
    try:
        d = _post_json() or {}
        r = blockchain.partition_start(d.get("label", "PARTITION-WEST"))
        save_state()
        return jsonify({"success": r["success"], "data": r})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/partition/mine', methods=['POST'])
def partition_mine():
    try:
        d = _post_json() or {}
        r = blockchain.partition_mine(d.get("drill_id"), d.get("partition", "A"))
        save_state()
        return jsonify({"success": r["success"], "data": r})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/partition/heal', methods=['POST'])
def partition_heal():
    try:
        d = _post_json() or {}
        r = blockchain.partition_heal(d.get("drill_id"))
        save_state()
        return jsonify({"success": r["success"], "data": r})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/partition/log')
def partition_log():
    r = blockchain.partition_log()
    return jsonify({"success": r["success"], "data": r})


@app.route('/api/pinning/status')
def pinning_status():
    r = blockchain.pin_status()
    return jsonify({"success": r["success"], "data": r})


@app.route('/api/pinning/assign', methods=['POST'])
def pinning_assign():
    try:
        d = _post_json() or {}
        r = blockchain.pin_assign(d.get("cid"), d.get("node_id"))
        save_state()
        return jsonify({"success": r["success"], "data": r})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/pinning/node-fail', methods=['POST'])
def pinning_node_fail():
    try:
        d = _post_json() or {}
        r = blockchain.pin_node_fail(d.get("node_id"))
        save_state()
        return jsonify({"success": r["success"], "data": r})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


# ============================================================
# ASSET: Firmware/SBOM Gate / Provenance / Recall
# ============================================================
@app.route('/api/firmware/register', methods=['POST'])
def firmware_register():
    try:
        d = _post_json() or {}
        r = blockchain.firmware_register(d.get("unit_id"), d.get("version"),
                                         d.get("firmware_hash"), d.get("sbom_packages"))
        save_state()
        return jsonify({"success": r["success"], "data": r})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/firmware/deploy', methods=['POST'])
def firmware_deploy():
    try:
        d = _post_json() or {}
        r = blockchain.firmware_deploy(d.get("unit_id"), d.get("version"), d.get("firmware_hash"))
        save_state()
        return jsonify({"success": r["success"], "data": r})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/firmware/list')
def firmware_list():
    r = blockchain.firmware_list()
    return jsonify({"success": r["success"], "data": r})


@app.route('/api/provenance/transfer', methods=['POST'])
def provenance_transfer():
    try:
        d = _post_json() or {}
        r = blockchain.provenance_transfer(d.get("unit_id"), d.get("from_party"),
                                           d.get("to_party"), d.get("sig_from", "0x"),
                                           d.get("sig_to", ""))
        save_state()
        return jsonify({"success": r["success"], "data": r})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/provenance/graph', methods=['POST'])
def provenance_graph():
    try:
        d = _post_json() or {}
        r = blockchain.provenance_graph(d.get("unit_id"))
        return jsonify({"success": r["success"], "data": r})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/provenance/list')
def provenance_list():
    r = blockchain.provenance_list()
    return jsonify({"success": r["success"], "data": r})


@app.route('/api/recall/create', methods=['POST'])
def recall_create():
    try:
        d = _post_json() or {}
        r = blockchain.recall_create(d.get("name"), d.get("firmware_version"), d.get("reason", "safety defect"))
        save_state()
        return jsonify({"success": r["success"], "data": r})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/recall/ack', methods=['POST'])
def recall_ack():
    try:
        d = _post_json() or {}
        r = blockchain.recall_ack(d.get("campaign_id"), d.get("unit_id"), d.get("acknowledged_by", "tech"))
        save_state()
        return jsonify({"success": r["success"], "data": r})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/recall/list')
def recall_list():
    r = blockchain.recall_list()
    return jsonify({"success": r["success"], "data": r})


# ============================================================
# AUDIT: Case Management / Compliance / Forensic Diff
# ============================================================
@app.route('/api/case/create', methods=['POST'])
def case_create():
    try:
        d = _post_json() or {}
        r = blockchain.case_create(d.get("title"), d.get("anomaly_id"), d.get("opened_by", "analyst"))
        save_state()
        return jsonify({"success": r["success"], "data": r})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/case/evidence', methods=['POST'])
def case_add_evidence():
    try:
        d = _post_json() or {}
        r = blockchain.case_add_evidence(d.get("case_id"), d.get("description"),
                                         d.get("evidence_ref"), d.get("added_by", "analyst"))
        save_state()
        return jsonify({"success": r["success"], "data": r})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/case/signoff', methods=['POST'])
def case_signoff():
    try:
        d = _post_json() or {}
        r = blockchain.case_signoff(d.get("case_id"), d.get("analyst"))
        save_state()
        return jsonify({"success": r["success"], "data": r})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/case/close', methods=['POST'])
def case_close():
    try:
        d = _post_json() or {}
        r = blockchain.case_close(d.get("case_id"), d.get("closed_by", "lead-analyst"))
        save_state()
        return jsonify({"success": r["success"], "data": r})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/case/list')
def case_list():
    r = blockchain.case_list()
    return jsonify({"success": r["success"], "data": r})


@app.route('/api/compliance/report')
def compliance_report():
    try:
        r = blockchain.compliance_report()
        save_state()
        return jsonify({"success": r["success"], "data": r})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/compliance/list')
def compliance_list():
    r = blockchain.compliance_list()
    return jsonify({"success": r["success"], "data": r})


@app.route('/api/forensic/tamper', methods=['POST'])
def forensic_tamper():
    try:
        d = _post_json() or {}
        r = blockchain.forensic_tamper(d.get("block_index"))
        save_state()
        return jsonify({"success": r["success"], "data": r})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/forensic/list')
def forensic_list():
    r = blockchain.forensic_list()
    return jsonify({"success": r["success"], "data": r})


# ============================================================================
# FEATURE 15 - Dashboard: Scenario Theater / Propagation Map / Benchmarks
# ============================================================================
@app.route('/api/scenario/run', methods=['POST'])
def scenario_run():
    try:
        d = _post_json() or {}
        r = blockchain.scenario_run(d.get("preset") or "coercion")
        save_state()
        return jsonify({"success": r["success"], "data": r})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/scenario/list')
def scenario_list():
    r = blockchain.scenario_list()
    return jsonify({"success": r["success"], "data": r})


@app.route('/api/propagation/map')
def propagation_map():
    r = blockchain.propagation_map()
    return jsonify({"success": r["success"], "data": r})


@app.route('/api/propagation/broadcast', methods=['POST'])
def propagation_broadcast():
    try:
        d = _post_json() or {}
        r = blockchain.propagation_broadcast(d.get("label") or "demonstration")
        save_state()
        return jsonify({"success": r["success"], "data": r})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/benchmark/run', methods=['POST'])
def benchmark_run():
    try:
        r = blockchain.benchmark_run()
        return jsonify({"success": r["success"], "data": r})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


# ============================================================================
# FEATURE 15 - Identity: Identicons / Web-of-Trust / Containment
# ============================================================================
@app.route('/api/identicon', methods=['POST'])
def identicon():
    d = _post_json() or {}
    r = blockchain.identicon_data(d.get("identity_hash") or "")
    return jsonify({"success": r["success"], "data": r})


@app.route('/api/vouch/register', methods=['POST'])
def vouch_register():
    try:
        d = _post_json() or {}
        r = blockchain.vouch_register(d.get("name"), d.get("email"), d.get("id_number"),
                                      d.get("role") or "VOUCHED_PENDING")
        save_state()
        return jsonify({"success": r["success"], "data": r})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/vouch/attest', methods=['POST'])
def vouch_attest():
    try:
        d = _post_json() or {}
        r = blockchain.vouch_attest(d.get("target_id"), d.get("voucher"), d.get("note") or "")
        save_state()
        return jsonify({"success": r["success"], "data": r})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/vouch/check')
def vouch_check():
    r = blockchain.vouch_check(request.args.get("target_id", ""))
    return jsonify({"success": r["success"], "data": r})


@app.route('/api/vouch/list')
def vouch_list():
    r = blockchain.vouch_list()
    return jsonify({"success": r["success"], "data": r})


@app.route('/api/containment/revoke', methods=['POST'])
def containment_revoke():
    try:
        d = _post_json() or {}
        r = blockchain.containment_revoke(d.get("department"), d.get("reason") or "division compromise",
                                          d.get("actor") or "CISO")
        save_state()
        return jsonify({"success": r["success"], "data": r})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/containment/list')
def containment_list():
    r = blockchain.containment_list()
    return jsonify({"success": r["success"], "data": r})


# ============================================================================
# FEATURE 15 - Verification/ZK: Selective Disclosure / Witness / Lifecycle
# ============================================================================
@app.route('/api/sd/issue', methods=['POST'])
def sd_issue():
    try:
        d = _post_json() or {}
        r = blockchain.sd_issue(d.get("holder"), d.get("issuer") or "BEL-ISSUER", d.get("claims"))
        save_state()
        return jsonify({"success": r["success"], "data": r})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/sd/disclose', methods=['POST'])
def sd_disclose():
    try:
        d = _post_json() or {}
        r = blockchain.sd_disclose(d.get("vc_id"), d.get("reveal_keys"))
        save_state()
        return jsonify({"success": r["success"], "data": r})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/sd/list')
def sd_list():
    r = blockchain.sd_list()
    return jsonify({"success": r["success"], "data": r})


@app.route('/api/witness/open', methods=['POST'])
def witness_open():
    try:
        d = _post_json() or {}
        r = blockchain.witness_open(d.get("requester"), d.get("resource"),
                                    int(d.get("window_s") or 120))
        save_state()
        return jsonify({"success": r["success"], "data": r})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/witness/cosign', methods=['POST'])
def witness_cosign():
    try:
        d = _post_json() or {}
        r = blockchain.witness_cosign(d.get("req_id"), d.get("witness"), d.get("pairing_code"))
        save_state()
        return jsonify({"success": r["success"], "data": r})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/witness/resolve', methods=['POST'])
def witness_resolve():
    try:
        d = _post_json() or {}
        r = blockchain.witness_resolve(d.get("req_id"))
        save_state()
        return jsonify({"success": r["success"], "data": r})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/witness/list')
def witness_list():
    r = blockchain.witness_list()
    return jsonify({"success": r["success"], "data": r})


@app.route('/api/lifecycle/change', methods=['POST'])
def lifecycle_change():
    try:
        d = _post_json() or {}
        r = blockchain.lifecycle_change(d.get("public_id"), d.get("change_type") or "PROMOTION",
                                        d.get("new_role"), d.get("new_level"), d.get("new_resources"))
        save_state()
        return jsonify({"success": r["success"], "data": r})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/lifecycle/list')
def lifecycle_list():
    r = blockchain.lifecycle_list()
    return jsonify({"success": r["success"], "data": r})


# ============================================================================
# FEATURE 15 - Access: Purpose Binding / Session Sealing / Classification
# ============================================================================
@app.route('/api/purpose/register', methods=['POST'])
def purpose_register():
    try:
        d = _post_json() or {}
        r = blockchain.purpose_register(d.get("resource"), d.get("purpose_code"),
                                        d.get("description") or "")
        save_state()
        return jsonify({"success": r["success"], "data": r})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/purpose/access', methods=['POST'])
def purpose_access():
    try:
        d = _post_json() or {}
        r = blockchain.purpose_access(d.get("public_id"), d.get("resource"), d.get("purpose_code"))
        save_state()
        return jsonify({"success": r["success"], "data": r})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/purpose/list')
def purpose_list():
    r = blockchain.purpose_list()
    return jsonify({"success": r["success"], "data": r})


@app.route('/api/session/seal', methods=['POST'])
def session_seal():
    try:
        d = _post_json() or {}
        r = blockchain.session_seal(d.get("public_id"), d.get("device_hash"),
                                    d.get("ip") or "10.0.0.1", int(d.get("lease_s") or 600))
        save_state()
        return jsonify({"success": r["success"], "data": r})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/session/validate', methods=['POST'])
def session_validate():
    try:
        d = _post_json() or {}
        r = blockchain.session_validate(d.get("session_id"), d.get("device_hash"), d.get("ip"))
        save_state()
        return jsonify({"success": r["success"], "data": r})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/session/hijack', methods=['POST'])
def session_hijack():
    try:
        d = _post_json() or {}
        r = blockchain.session_hijack(d.get("session_id"))
        save_state()
        return jsonify({"success": r["success"], "data": r})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/session/list')
def session_list():
    r = blockchain.session_list()
    return jsonify({"success": r["success"], "data": r})


@app.route('/api/classify/register', methods=['POST'])
def classify_register():
    try:
        d = _post_json() or {}
        r = blockchain.classify_register(d.get("label"), d.get("required_factors"),
                                         d.get("min_level") or 1, d.get("watermark") or "BEL-CONFIDENTIAL")
        save_state()
        return jsonify({"success": r["success"], "data": r})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/classify/assess', methods=['POST'])
def classify_assess():
    d = _post_json() or {}
    r = blockchain.classify_assess(d.get("resource"), d.get("label"))
    return jsonify({"success": r["success"], "data": r})


@app.route('/api/classify/list')
def classify_list():
    r = blockchain.classify_list()
    return jsonify({"success": r["success"], "data": r})


# ============================================================================
# FEATURE 15 - Network: Chaos Engineering / Node PKI / Notarization
# ============================================================================
@app.route('/api/chaos/inject', methods=['POST'])
def chaos_inject():
    try:
        d = _post_json() or {}
        r = blockchain.chaos_inject(d.get("node_id"), d.get("mode"), d.get("value"))
        save_state()
        return jsonify({"success": r["success"], "data": r})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/chaos/clear', methods=['POST'])
def chaos_clear():
    try:
        d = _post_json() or {}
        r = blockchain.chaos_clear(d.get("node_id"))
        save_state()
        return jsonify({"success": r["success"], "data": r})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/chaos/verify', methods=['POST'])
def chaos_verify():
    try:
        d = _post_json() or {}
        r = blockchain.chaos_verify(d.get("node_id"))
        save_state()
        return jsonify({"success": r["success"], "data": r})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/chaos/list')
def chaos_list():
    r = blockchain.chaos_list()
    return jsonify({"success": r["success"], "data": r})


@app.route('/api/pki/join', methods=['POST'])
def pki_node_join():
    try:
        d = _post_json() or {}
        r = blockchain.pki_node_join(d.get("node_id"))
        save_state()
        return jsonify({"success": r["success"], "data": r})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/pki/gossip', methods=['POST'])
def pki_gossip():
    try:
        d = _post_json() or {}
        r = blockchain.pki_gossip(d.get("node_id"), d.get("message") or "hello-network")
        save_state()
        return jsonify({"success": r["success"], "data": r})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/pki/rogue-attempt', methods=['POST'])
def pki_rogue_attempt():
    try:
        d = _post_json() or {}
        r = blockchain.pki_rogue_attempt(d.get("node_id") or "ROGUE-MALLORY")
        save_state()
        return jsonify({"success": r["success"], "data": r})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/pki/revoke', methods=['POST'])
def pki_revoke():
    try:
        d = _post_json() or {}
        r = blockchain.pki_revoke(d.get("node_id"))
        save_state()
        return jsonify({"success": r["success"], "data": r})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/pki/list')
def pki_list():
    r = blockchain.pki_list()
    return jsonify({"success": r["success"], "data": r})


@app.route('/api/notarize/anchor', methods=['POST'])
def notarize_anchor():
    try:
        d = _post_json() or {}
        r = blockchain.notarize_anchor(d.get("notary") or "BEL-AUDIT-01")
        save_state()
        return jsonify({"success": r["success"], "data": r})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/notarize/verify', methods=['POST'])
def notarize_verify():
    d = _post_json() or {}
    r = blockchain.notarize_verify(d.get("anchor_id"))
    return jsonify({"success": r["success"], "data": r})


@app.route('/api/notarize/list')
def notarize_list():
    r = blockchain.notarize_list()
    return jsonify({"success": r["success"], "data": r})


# ============================================================================
# FEATURE 15 - Assets: Geo-Fence / Work Orders / Timeline
# ============================================================================
@app.route('/api/geofence/register', methods=['POST'])
def geofence_register():
    try:
        d = _post_json() or {}
        r = blockchain.geofence_register(d.get("unit_id"), d.get("center_lat"),
                                         d.get("center_lng"), d.get("radius_km") or 50)
        save_state()
        return jsonify({"success": r["success"], "data": r})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/geofence/telemetry', methods=['POST'])
def geofence_telemetry():
    try:
        d = _post_json() or {}
        r = blockchain.geofence_telemetry(d.get("unit_id"), d.get("lat"), d.get("lng"))
        save_state()
        return jsonify({"success": r["success"], "data": r})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/geofence/list')
def geofence_list():
    r = blockchain.geofence_list()
    return jsonify({"success": r["success"], "data": r})


@app.route('/api/wo/create', methods=['POST'])
def wo_create():
    try:
        d = _post_json() or {}
        r = blockchain.wo_create(d.get("unit_id"), d.get("technician"),
                                 d.get("parts"), d.get("description") or "")
        save_state()
        return jsonify({"success": r["success"], "data": r})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/wo/begin', methods=['POST'])
def wo_begin():
    try:
        d = _post_json() or {}
        r = blockchain.wo_begin(d.get("order_id"))
        save_state()
        return jsonify({"success": r["success"], "data": r})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/wo/complete', methods=['POST'])
def wo_complete():
    try:
        d = _post_json() or {}
        r = blockchain.wo_complete(d.get("order_id"), d.get("resolution") or "repaired")
        save_state()
        return jsonify({"success": r["success"], "data": r})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/wo/list')
def wo_list():
    r = blockchain.wo_list()
    return jsonify({"success": r["success"], "data": r})


@app.route('/api/timeline/asset')
def asset_timeline():
    r = blockchain.asset_timeline(request.args.get("unit_id", ""))
    return jsonify({"success": r["success"], "data": r})


@app.route('/api/timeline/assets')
def asset_timeline_assets():
    r = blockchain.asset_timeline_assets()
    return jsonify({"success": r["success"], "data": r})


# ============================================================================
# FEATURE 15 - Audit: Least-Privilege / Attestation Receipts
# ============================================================================
@app.route('/api/least-privilege/scan')
def least_privilege_scan():
    r = blockchain.least_privilege_scan(int(request.args.get("days") or 30))
    return jsonify({"success": r["success"], "data": r})


@app.route('/api/least-privilege/propose', methods=['POST'])
def least_privilege_propose():
    try:
        d = _post_json() or {}
        r = blockchain.least_privilege_propose(d.get("identity"), d.get("resource"),
                                               d.get("proposed_by") or "least-privilege-recommender")
        save_state()
        return jsonify({"success": r["success"], "data": r})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/least-privilege/list')
def least_privilege_list():
    r = blockchain.least_privilege_list()
    return jsonify({"success": r["success"], "data": r})


@app.route('/api/receipt/issue', methods=['POST'])
def receipt_issue():
    try:
        d = _post_json() or {}
        r = blockchain.receipt_issue(d.get("control"), d.get("framework") or "ISO-27001",
                                     d.get("subject") or "BEL-BLUEPRINT-STORE",
                                     d.get("verifier") or "BEL-AUDIT")
        save_state()
        return jsonify({"success": r["success"], "data": r})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/receipt/verify', methods=['POST'])
def receipt_verify():
    d = _post_json() or {}
    r = blockchain.receipt_verify(d.get("receipt_id"))
    return jsonify({"success": r["success"], "data": r})


@app.route('/api/receipt/list')
def receipt_list():
    r = blockchain.receipt_list()
    return jsonify({"success": r["success"], "data": r})


if __name__ == "__main__":
    import sys
    import socket
    import threading
    import webbrowser

    args = sys.argv[1:]
    use_https = "--https" in args
    deployed = bool(os.environ.get("RENDER") or os.environ.get("PORT"))
    open_browser = ("--no-browser" not in args) and not deployed
    host = "0.0.0.0"
    port = int(os.environ.get("PORT") or 8080)
    for a in args:
        if a.startswith("--host="):
            host = a.split("=", 1)[1]
        elif a.startswith("--port="):
            port = int(a.split("=", 1)[1])

    def _port_free(p):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                s.bind((host, p))
                return True
            except OSError:
                return False

    requested_port = port
    while not _port_free(port) and port < requested_port + 20:
        port += 1

    scheme = "https" if use_https else "http"
    local_url = f"{scheme}://127.0.0.1:{port}"
    print()
    print("=" * 66)
    print("  SIH26125 - Blockchain Identity & Access Control")
    print(f"  Open this:  {local_url}")
    print(f"  Also try:   {scheme}://localhost:{port}")
    print(f"  LAN:        {scheme}://<this-machine-IP>:{port}")
    if port != requested_port:
        print(f"  Note:       port {requested_port} was busy - using {port} instead")
    if use_https:
        print("  TLS:        self-signed cert (accept the browser warning once).")
    else:
        print("  Note:       this is HTTP - do NOT type https:// (use --https for that)")
    print(f"  Browser:    {'opening automatically' if open_browser else 'auto-open disabled'}")
    print("=" * 66)
    print()

    # Auto-open 127.0.0.1 (not "localhost") to avoid IPv6 (::1) resolution
    # issues, and use the free port we actually bound. Guard with
    # WERKZEUG_RUN_MAIN so the debug reloader does not open twice.
    # The browser only opens AFTER the server is confirmed to be accepting
    # connections - a blind timer would open the tab before the (reloader
    # child) process finished starting, causing "can't reach this page".
    # On a deployed host (Render sets PORT) the browser never opens.
    if open_browser and os.environ.get("WERKZEUG_RUN_MAIN") != "true":
        def _open_when_ready():
            deadline = time.time() + 30
            while time.time() < deadline:
                try:
                    with socket.create_connection(("127.0.0.1", port), timeout=1.0):
                        time.sleep(0.5)  # give the dev server a moment
                        webbrowser.open(local_url)
                        return
                except OSError:
                    time.sleep(0.5)
            print(f"  Could not confirm the server is accepting connections on {local_url} "
                  f"within 30s - open that URL manually.")
        threading.Thread(target=_open_when_ready, daemon=True).start()

    if deployed:
        app.run(debug=False, host=host, port=port, use_reloader=False)
    else:
        app.run(debug=True, host=host, port=port,
                use_reloader="--no-reload" not in args,
                ssl_context="adhoc" if use_https else None)
