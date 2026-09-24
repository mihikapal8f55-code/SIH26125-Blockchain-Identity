import io, sys, copy, json, os, unittest

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from blockchain import Blockchain

# Register the canonical seed identities the Feature-15 demo uses so mint
# ownership/transfer consent can be resolved against a *registered* identity.
def seed(blockchain):
    demos = [
        {"name": "Aarav Sharma", "role": "Administrator", "access_level": "HIGH",
         "email": "aarav.sharma@bel.gov.in", "id_number": "BEL-ADM-001",
         "department": "Digital Transformation", "allowed_resources": ["admin_dashboard", "sensitive_data", "user_management", "network_access"]},
        {"name": "Priya Patel", "role": "Data Analyst", "access_level": "MEDIUM",
         "email": "priya.patel@bel.gov.in", "id_number": "BEL-DA-004",
         "department": "Data Analytics", "allowed_resources": ["analytics_dashboard", "reporting"]},
        {"name": "Rajesh Kumar", "role": "Field Officer", "access_level": "LOW",
         "email": "rajesh.kumar@bel.gov.in", "id_number": "BEL-FO-007",
         "department": "Field Operations", "allowed_resources": ["basic_access"]},
        {"name": "Auditor Reviewer", "role": "Auditor", "access_level": "MEDIUM",
         "email": "auditor.review@bel.gov.in", "id_number": "AUD-001-2025",
         "department": "Audit & Assurance", "allowed_resources": ["audit.trail", "ledger.view"]},
    ]
    out = []
    for d in demos:
        out.append(blockchain.add_identity(d))
    return out

checks = []

def T(name, cond, detail=""):
    checks.append((name, cond, detail))

blockchain = Blockchain()
r = blockchain.rbac_list()
T("rbac_list has 4 canonical roles", r["success"] and len(r["canonical_roles"]) == 4, json.dumps(r)[:120])
T("rbac_list exposes role policy", any(x["role"] == "ADMINISTRATOR" and "nft.mint" in x["capabilities"] for x in r["roles"]),
  json.dumps(r["roles"])[:200])

# --- RBAC verify: non-registered subject denied ---
v = blockchain.rbac_verify("noone@example.com", capability="nft.mint")
T("rbac_verify unknown subject -> not granted", v["success"] and not v["granted"], json.dumps(v)[:120])

# --- seed an admin + a normal user ---
seed(blockchain)
adm = blockchain.identity_role("aarav.sharma@bel.gov.in")
T("admin role resolves to ADMINISTRATOR", adm == "ADMINISTRATOR", f"got {adm}")
usr = blockchain.identity_role("rajesh.kumar@bel.gov.in")
T("user role resolves to USER", usr == "USER", f"got {usr}")

# --- operator gate: administrator may mint, USER may not ---
g1 = blockchain.require_operator("aarav.sharma@bel.gov.in", "nft.mint", resource="nft.mint")
T("ADMINISTRATOR granted nft.mint", g1["granted"], json.dumps(g1)[:150])
g2 = blockchain.require_operator("rajesh.kumar@bel.gov.in", "nft.mint", resource="nft.mint")
T("USER denied nft.mint", not g2["granted"], json.dumps(g2)[:150])

# --- define/assign role is administrator-only ---
d1 = blockchain.rbac_define_role("rajesh.kumar@bel.gov.in", "AUDITOR", capabilities=["audit.view"], resources=[])
T("non-admin cannot define role", not d1["success"], json.dumps(d1)[:120])
d2 = blockchain.rbac_define_role("aarav.sharma@bel.gov.in", "AUDITOR", capabilities=["audit.view", "ledger.view"], resources=["audit.trail"])
T("admin can define AUDITOR role", d2["success"], json.dumps(d2)[:120])

# assign rahul to AUDITOR, then verify capability becomes granted
a1 = blockchain.rbac_assign_role("aarav.sharma@bel.gov.in", "priya.patel@bel.gov.in", "AUDITOR")
T("admin assigns priya -> AUDITOR", a1["success"], json.dumps(a1)[:120])
g3 = blockchain.rbac_verify("priya.patel@bel.gov.in", capability="audit.view")
T("priya [AUDITOR] granted audit.view after assignment", g3["granted"], json.dumps(g3)[:120])
a2 = blockchain.rbac_assign_role("rajesh.kumar@bel.gov.in", "priya.patel@bel.gov.in", "AUDITOR")
T("non-admin cannot assign role", not a2["success"], json.dumps(a2)[:120])

# --- ensure_auditor seeds the canonical AUDITOR identity + assignment ---
ea = blockchain.ensure_auditor()
T("ensure_auditor returns auditor", ea["success"] and ea["auditor"] == "auditor.review@bel.gov.in", json.dumps(ea)[:120])
g4 = blockchain.rbac_verify("auditor.review@bel.gov.in", capability="audit.view")
T("seeded auditor holds audit.view", g4["granted"], json.dumps(g4)[:120])

# --- NFT mint gating (PS2: admin-only mint) ---
m0 = blockchain.nft_mint("hardware", "Denied Antenna", "rajesh.kumar@bel.gov.in", "x", "LEVEL-3", actor="rajesh.kumar@bel.gov.in")
T("USER cannot mint dNFT", not m0["success"], json.dumps(m0)[:120])
m1 = blockchain.nft_mint("hardware", "Authorized Antenna", "aarav.sharma@bel.gov.in", "admin-minted", "LEVEL-3", actor="aarav.sharma@bel.gov.in")
T("ADMINISTRATOR can mint dNFT", m1["success"], json.dumps(m1)[:120])

# --- PS1: NFTs allocated to verified identities only ---
m2 = blockchain.nft_mint("hardware", "Ghost Owner", "ghost.owner@nowhere.in", "x", "LEVEL-3", actor="aarav.sharma@bel.gov.in")
T("mint to unregistered owner rejected", not m2["success"] and "registered identity" in m2.get("reason","").lower(), json.dumps(m2)[:140])

# --- PS3: transfer requires owner consent (or admin) ---
tid = m1["asset"]["token_id"]
t1 = blockchain.nft_transfer(tid, "priya.patel@bel.gov.in", actor="priya.patel@bel.gov.in")
T("non-owner non-admin transfer denied (consent required)", not t1["success"], json.dumps(t1)[:130])
t2 = blockchain.nft_transfer(tid, "priya.patel@bel.gov.in", actor="aarav.sharma@bel.gov.in", admin_override=True)
T("admin override transfer succeeds", t2["success"], json.dumps(t2)[:140])
o1 = blockchain.nft_chain_ledger()
found = [a for a in o1["assets"] if a["token_id"] == tid]
T("on-chain ledger shows priya as owner", found and found[0]["chain_owner"] == "priya.patel@bel.gov.in", json.dumps(o1)[:160])

fails = sum(1 for _, cond, _ in checks if not cond)

class TestRBACOwnership15(unittest.TestCase):
    def test_all_rbac_ownership_checks(self):
        self.assertEqual(fails, 0, f"{fails} out of {len(checks)} checks failed")

if __name__ == "__main__":
    print("\n=== TARGETED RBAC + NFT-OWNERSHIP ON-CHAIN TEST ===")
    for name, cond, detail in checks:
        print(("  PASS  " if cond else "  FAIL  ") + name + (f"  :: {detail}" if not cond else ""))
    print(f"\nRESULT: {len(checks)-fails}/{len(checks)} passed", "-> ALL GREEN" if fails == 0 else f"-> {fails} FAILED")
    sys.exit(1 if fails else 0)
