"""
Automated Test Suite for:
1. BEL Unified 7-Step Defense Showcase Runner
2. RBAC Permissions Matrix & Policy Simulator
3. Auditor Portal & Cryptographic Verification Hub
"""

import unittest
import json
from app import app
from blockchain import Blockchain

class TestShowcaseAndAuditor(unittest.TestCase):
    def setUp(self):
        self.client = app.test_client()

    def test_e2e_showcase_runner(self):
        """Test the 7-step BEL defense story flow"""
        payload = {
            "applicant_name": "Major Vikram Rao",
            "role": "MANAGER",
            "asset_name": "BEL Coastal Surveillance Radar Mk-IV Blueprint"
        }
        resp = self.client.post('/api/showcase/e2e-run',
                                data=json.dumps(payload),
                                content_type='application/json')
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertTrue(data.get("success"))
        self.assertEqual(data.get("applicant_name"), "Major Vikram Rao")
        self.assertEqual(data.get("role"), "MANAGER")
        self.assertTrue(data.get("did", "").startswith("did:"))
        self.assertIsNotNone(data.get("token_id"))
        self.assertIsNotNone(data.get("audit_root"))

        # Verify all 7 steps are present and completed
        steps = data.get("steps", [])
        self.assertEqual(len(steps), 7)
        step_nums = [s["step"] for s in steps]
        self.assertEqual(step_nums, [1, 2, 3, 4, 5, 6, 7])

        # Step 1: Identity Registration
        self.assertEqual(steps[0]["title"], "Identity Registration")
        self.assertEqual(steps[0]["status"], "COMPLETED")

        # Step 2: DID Anchoring
        self.assertEqual(steps[1]["title"], "Decentralized Identifier (DID) Anchoring")
        self.assertEqual(steps[1]["status"], "COMPLETED")

        # Step 3: RBAC Role Assignment
        self.assertEqual(steps[2]["title"], "Smart Contract RBAC Role Assignment")
        self.assertEqual(steps[2]["status"], "COMPLETED")

        # Step 4: Defense NFT Minting
        self.assertEqual(steps[3]["title"], "Defense Digital Asset (dNFT) Minted")
        self.assertEqual(steps[3]["status"], "COMPLETED")

        # Step 5: Asset Binding to DID
        self.assertEqual(steps[4]["title"], "Asset Binding to Verified DID")
        self.assertEqual(steps[4]["status"], "COMPLETED")

        # Step 6: Cryptographic Access Request
        self.assertEqual(steps[5]["title"], "Cryptographic Access Request & Evaluation")
        self.assertEqual(steps[5]["status"], "GRANTED")

        # Step 7: Immutable Audit Sealed
        self.assertEqual(steps[6]["title"], "Immutable Audit Block Sealed & Merkle Root Generated")
        self.assertEqual(steps[6]["status"], "COMPLETED")

    def test_rbac_matrix_endpoints(self):
        """Test RBAC Permissions Matrix and Simulation"""
        # GET matrix
        resp = self.client.get('/api/rbac/matrix')
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertTrue(data.get("success"))
        self.assertIn("ADMINISTRATOR", data.get("roles", []))
        self.assertIn("USER", data.get("roles", []))
        self.assertIn("MANAGER", data.get("roles", []))
        self.assertIn("AUDITOR", data.get("roles", []))
        matrix = data.get("matrix", {})
        self.assertTrue(matrix["ADMINISTRATOR"]["nft.mint"]["granted"])
        self.assertFalse(matrix["USER"]["nft.mint"]["granted"])

        # POST simulate: MANAGER -> nft.view (GRANTED)
        resp_sim = self.client.post('/api/rbac/matrix/simulate',
                                    data=json.dumps({"role": "MANAGER", "capability": "nft.view", "resource": "BEL-RADAR"}),
                                    content_type='application/json')
        self.assertEqual(resp_sim.status_code, 200)
        sim_data = resp_sim.get_json()
        self.assertEqual(sim_data.get("decision"), "GRANTED")

        # POST simulate: USER -> nft.mint (DENIED)
        resp_sim_deny = self.client.post('/api/rbac/matrix/simulate',
                                         data=json.dumps({"role": "USER", "capability": "nft.mint", "resource": "BEL-RADAR"}),
                                         content_type='application/json')
        self.assertEqual(resp_sim_deny.status_code, 200)
        deny_data = resp_sim_deny.get_json()
        self.assertEqual(deny_data.get("decision"), "DENIED")

    def test_auditor_portal_endpoints(self):
        """Test Deep Chain Scan, Merkle Proof Generation/Verification, and Certificate"""
        # 1. Chain scan
        scan_resp = self.client.get('/api/auditor/chain-scan')
        self.assertEqual(scan_resp.status_code, 200)
        scan = scan_resp.get_json()
        self.assertTrue(scan.get("success"))
        self.assertTrue(scan.get("valid"))
        self.assertEqual(scan.get("integrity_score"), 100)
        self.assertFalse(scan.get("tamper_detected"))

        # 2. Merkle proof generation
        proof_resp = self.client.post('/api/auditor/merkle-proof',
                                      data=json.dumps({"target_type": "audit"}),
                                      content_type='application/json')
        self.assertEqual(proof_resp.status_code, 200)
        proof = proof_resp.get_json()
        self.assertTrue(proof.get("success"))
        leaf_hash = proof.get("leaf_hash")
        proof_path = proof.get("proof_path")
        expected_root = proof.get("merkle_root")
        self.assertIsNotNone(leaf_hash)
        self.assertIsNotNone(expected_root)

        # 3. Merkle proof verification (valid)
        v_resp = self.client.post('/api/auditor/verify-proof',
                                  data=json.dumps({
                                      "leaf_hash": leaf_hash,
                                      "proof_path": proof_path,
                                      "expected_root": expected_root
                                  }),
                                  content_type='application/json')
        self.assertEqual(v_resp.status_code, 200)
        v_data = v_resp.get_json()
        self.assertTrue(v_data.get("verified"))
        self.assertEqual(v_data.get("verdict"), "VERIFIED")

        # 4. Merkle proof verification (tampered leaf)
        tampered_leaf = "0" * 64
        v_bad_resp = self.client.post('/api/auditor/verify-proof',
                                      data=json.dumps({
                                          "leaf_hash": tampered_leaf,
                                          "proof_path": proof_path,
                                          "expected_root": expected_root
                                      }),
                                      content_type='application/json')
        self.assertEqual(v_bad_resp.status_code, 200)
        v_bad_data = v_bad_resp.get_json()
        self.assertFalse(v_bad_data.get("verified"))
        self.assertEqual(v_bad_data.get("verdict"), "TAMPERED / MISMATCH")

        # 5. Certificate generation
        cert_resp = self.client.post('/api/auditor/certificate',
                                     data=json.dumps({"auditor_id": "BEL-LEAD-AUDITOR-99"}),
                                     content_type='application/json')
        self.assertEqual(cert_resp.status_code, 200)
        cert_data = cert_resp.get_json()
        self.assertTrue(cert_data.get("success"))
        cert = cert_data.get("certificate", {})
        self.assertEqual(cert.get("auditor_id"), "BEL-LEAD-AUDITOR-99")
        self.assertEqual(cert.get("compliance_status"), "CERTIFIED_SECURE")
        self.assertTrue(cert.get("certificate_id", "").startswith("BEL-SEC-CERT-"))
        self.assertIsNotNone(cert.get("signature"))

if __name__ == '__main__':
    unittest.main()
