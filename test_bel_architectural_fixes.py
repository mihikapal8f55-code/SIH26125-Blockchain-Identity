"""
Automated Test Suite for the 4 Core BEL Defense Architectural Fixes:
  Issue A: Identity Disconnect (Emails vs. DIDs)
  Issue B: Smart Contract Execution vs. Procedural Python Methods
  Issue C: NFT Ownership Binding & On-Chain State (verify_nft_provenance)
  Issue D: Blockchain Type Realism (Authorized Validator Node Consortium)
"""
import unittest
import json
import time
from blockchain import Blockchain, SmartContract, CONSORTIUM_METADATA
from app import app, network_nodes


class TestBELArchitecturalFixes(unittest.TestCase):

    def setUp(self):
        self.bc = Blockchain()
        self.client = app.test_client()

    # =========================================================================
    # Issue A: Identity Disconnect (Emails vs. DIDs)
    # =========================================================================
    def test_issue_a_auto_did_generation_and_anchoring(self):
        # 1. Register identity without providing a DID
        identity_data = {
            "name": "Vikram Sarabhai",
            "email": "vikram.sarabhai@bel.gov.in",
            "role": "MANAGER",
            "department": "Radar Systems",
            "id_number": "BEL-RAD-001"
        }
        res = self.bc.add_identity(identity_data)
        self.assertIn("did", res)
        did = res["did"]
        self.assertTrue(did.startswith("did:bel:"), f"Expected DID starting with 'did:bel:', got {did}")

        # 2. Check DID anchored in _did_store
        self.assertIn(did, self.bc._did_store)
        self.assertEqual(self.bc._did_store[did]["email"], "vikram.sarabhai@bel.gov.in")

        # 3. Check role assigned directly to DID
        self.assertEqual(self.bc.identity_role(did), "MANAGER")
        self.assertEqual(self.bc.identity_role("vikram.sarabhai@bel.gov.in"), "MANAGER")

        # 4. Bidirectional lookup
        lookup_by_did = self.bc.find_identity_by_public_id(did)
        self.assertTrue(lookup_by_did["found"])
        self.assertEqual(lookup_by_did["data"]["name"], "Vikram Sarabhai")

        lookup_by_email = self.bc.find_identity_by_public_id("vikram.sarabhai@bel.gov.in")
        self.assertTrue(lookup_by_email["found"])
        self.assertEqual(lookup_by_email["data"]["did"], did)

        # 5. Check API registration returns DID
        api_res = self.client.post('/api/identity/register', json={
            "name": "Kiran Bedi",
            "email": "kiran.bedi@bel.gov.in",
            "role": "Field Officer",
            "department": "Security"
        })
        self.assertEqual(api_res.status_code, 201)
        api_data = api_res.get_json()
        self.assertTrue(api_data["success"])
        self.assertIn("did", api_data)
        self.assertTrue(api_data["did"].startswith("did:bel:"))

    # =========================================================================
    # Issue B: Smart Contract Execution vs. Procedural Python Methods
    # =========================================================================
    def test_issue_b_smart_contract_execution_and_receipts(self):
        # 1. Check Canonical Contract Registry
        registry = self.bc.get_smart_contract_registry()
        self.assertIn("BEL-SC-IAM-01", registry)
        self.assertIn("BEL-SC-ASSET-01", registry)
        self.assertIn("BEL-SC-ACCESS-01", registry)

        # 2. Setup administrator identity
        admin_data = {
            "name": "Admin Officer",
            "email": "admin.officer@bel.gov.in",
            "role": "ADMINISTRATOR",
            "department": "IT Security"
        }
        res_admin = self.bc.add_identity(admin_data)
        admin_did = res_admin["did"]

        user_data = {
            "name": "Target User",
            "email": "target.user@bel.gov.in",
            "role": "USER",
            "department": "Field"
        }
        res_user = self.bc.add_identity(user_data)
        user_did = res_user["did"]

        # 3. Execute BEL-SC-IAM-01: assignRole
        receipt_iam = self.bc.execute_smart_contract(
            contract_id="BEL-SC-IAM-01",
            method="assignRole",
            caller_did=admin_did,
            params={"target_did": user_did, "role": "MANAGER"}
        )
        self.assertTrue(receipt_iam["success"])
        self.assertEqual(receipt_iam["execution_status"], "SUCCESS")
        self.assertEqual(receipt_iam["contract_id"], "BEL-SC-IAM-01")
        self.assertIn("tx_hash", receipt_iam)
        self.assertEqual(self.bc.identity_role(user_did), "MANAGER")

        # 4. Check on-chain SMART_CONTRACT_EXECUTION audit block
        last_block = self.bc.last_block
        self.assertEqual(last_block.data.get("type"), "SMART_CONTRACT_EXECUTION")
        self.assertEqual(last_block.data.get("contract_id"), "BEL-SC-IAM-01")

        # 5. Execute BEL-SC-ASSET-01: mintAsset
        receipt_mint = self.bc.execute_smart_contract(
            contract_id="BEL-SC-ASSET-01",
            method="mintAsset",
            caller_did=admin_did,
            params={
                "asset_type": "blueprint",
                "name": "Naval Sonar Mk-I",
                "owner": user_did,
                "required_clearance": "LEVEL-3"
            }
        )
        self.assertTrue(receipt_mint["success"])
        self.assertEqual(receipt_mint["execution_status"], "SUCCESS")
        token_id = receipt_mint["result"]["asset"]["token_id"]

        # 6. Execute via API endpoint POST /api/smartcontract/execute
        api_sc_res = self.client.post('/api/smartcontract/execute', json={
            "contract_id": "BEL-SC-ACCESS-01",
            "method": "validateWorkHours",
            "caller_did": admin_did,
            "params": {"now_dt": "2026-09-28T10:00:00"}  # Monday 10:00 AM
        })
        self.assertEqual(api_sc_res.status_code, 200)
        sc_data = api_sc_res.get_json()
        self.assertTrue(sc_data["success"])
        self.assertEqual(sc_data["execution_status"], "SUCCESS")

    # =========================================================================
    # Issue C: NFT Ownership Binding & On-Chain State (verify_nft_provenance)
    # =========================================================================
    def test_issue_c_nft_provenance_genesis_to_head(self):
        # 1. Setup identities
        admin_res = self.bc.add_identity({
            "name": "Commander Roy",
            "email": "roy@bel.gov.in",
            "role": "ADMINISTRATOR"
        })
        admin_did = admin_res["did"]

        tech_res = self.bc.add_identity({
            "name": "Technician Maya",
            "email": "maya@bel.gov.in",
            "role": "USER"
        })
        tech_did = tech_res["did"]

        officer_res = self.bc.add_identity({
            "name": "Officer Arjun",
            "email": "arjun@bel.gov.in",
            "role": "MANAGER"
        })
        officer_did = officer_res["did"]

        # 2. Mint NFT to Technician Maya
        mint_res = self.bc.nft_mint(
            asset_type="hardware",
            name="Tactical SDR Transceiver",
            owner=tech_did,
            actor=admin_did
        )
        self.assertTrue(mint_res["success"])
        token_id = mint_res["asset"]["token_id"]

        # 3. Transfer from Maya to Arjun (Admin override)
        xfer_res = self.bc.nft_transfer(
            token_id=token_id,
            new_owner=officer_did,
            actor=admin_did,
            admin_override=True
        )
        self.assertTrue(xfer_res["success"])

        # 4. Verify on-chain provenance
        prov = self.bc.verify_nft_provenance(token_id)
        self.assertTrue(prov["success"])
        self.assertTrue(prov["found"])
        self.assertEqual(prov["token_id"], token_id)
        self.assertEqual(prov["current_owner"], officer_did)
        self.assertEqual(prov["current_owner_kind"], "did")
        self.assertTrue(prov["unbroken_chain"])
        self.assertTrue(prov["cryptographically_verified"])
        self.assertEqual(len(prov["provenance_trail"]), 2)
        self.assertEqual(prov["provenance_trail"][0]["event_type"], "NFT_MINT")
        self.assertEqual(prov["provenance_trail"][1]["event_type"], "NFT_TRANSFER")

        # 5. Check API GET /api/nft/provenance/<token_id>
        import app as flask_app
        mint_app = flask_app.blockchain.nft_mint(
            asset_type="hardware",
            name="Tactical SDR Transceiver App",
            owner="rajesh.kumar@bel.gov.in",
            actor="aarav.sharma@bel.gov.in"
        )
        self.assertTrue(mint_app.get("success"), str(mint_app))
        token_id_app = mint_app["asset"]["token_id"]
        xfer_app = flask_app.blockchain.nft_transfer(
            token_id=token_id_app,
            new_owner="priya.patel@bel.gov.in",
            actor="aarav.sharma@bel.gov.in",
            admin_override=True
        )
        self.assertTrue(xfer_app.get("success"), str(xfer_app))
        api_prov = self.client.get(f'/api/nft/provenance/{token_id_app}')
        self.assertEqual(api_prov.status_code, 200)
        api_prov_data = api_prov.get_json()
        self.assertTrue(api_prov_data["success"])
        self.assertTrue(api_prov_data["unbroken_chain"])
        self.assertEqual(api_prov_data["current_owner"], "priya.patel@bel.gov.in")

    # =========================================================================
    # Issue D: Blockchain Type Realism (Authorized Validator Node Consortium)
    # =========================================================================
    def test_issue_d_consortium_status_and_nodes(self):
        # 1. Check consortium metadata definition
        self.assertIn("node_1", CONSORTIUM_METADATA)
        self.assertIn("node_2", CONSORTIUM_METADATA)
        self.assertIn("node_3", CONSORTIUM_METADATA)
        self.assertEqual(CONSORTIUM_METADATA["node_1"]["key_id"], "BEL-VAL-BLR-01")
        self.assertEqual(CONSORTIUM_METADATA["node_2"]["key_id"], "BEL-VAL-GZB-02")
        self.assertEqual(CONSORTIUM_METADATA["node_3"]["key_id"], "BEL-VAL-AUD-03")

        # 2. Check Blockchain.get_consortium_status()
        status = self.bc.get_consortium_status(network_nodes)
        self.assertTrue(status["success"])
        self.assertEqual(status["consortium_name"], "Bharat Electronics Limited (BEL) Defense Consortium")
        self.assertEqual(status["quorum_status"], "QUORUM_SATISFIED")
        self.assertEqual(status["active_validators"], 3)
        self.assertEqual(status["total_validators"], 3)
        self.assertEqual(len(status["validators"]), 3)

        # 3. Check API GET /api/consortium/status
        api_res = self.client.get('/api/consortium/status')
        self.assertEqual(api_res.status_code, 200)
        api_data = api_res.get_json()
        self.assertTrue(api_data["success"])
        self.assertIn("Permissioned Proof-of-Authority", api_data["consortium_model"])
        self.assertEqual(api_data["quorum_requirement"], "2-of-3 Authorized Signers (Supermajority Quorum)")

        # 4. Check API GET /api/network/status includes consortium and node metadata
        api_net = self.client.get('/api/network/status')
        self.assertEqual(api_net.status_code, 200)
        net_data = api_net.get_json()
        self.assertTrue(net_data["success"])
        self.assertIn("consortium", net_data)
        self.assertEqual(net_data["nodes"][0]["key_id"], "BEL-VAL-BLR-01")


if __name__ == '__main__':
    unittest.main()
