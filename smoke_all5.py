# -*- coding: utf-8 -*-
"""Instance-based smoke of all 5 features after the blockchain.py repair.
Fresh text; no fragments. Only reads + executes, writes nothing back."""
import importlib.util
import sys
import time

P = r"E:\SIH26125-Blockchain-Identity\blockchain.py"
spec = importlib.util.spec_from_file_location("bc_smoke", P)
bc = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bc)

Chain = bc.Blockchain
b = Chain()

def show(tag, ok, extra=""):
    print(("  [PASS] " if ok else "  [FAIL] ") + tag + "  " + extra)

print("== smoke: blockchain.py imports OK ==")
print("  PQ module classes:", [n for n in dir(bc) if n in (
    "WinternitzOneTimeSignature", "MerkleKeyTree", "SPHINCSReview",
    "pq_native_backend_probe")])

print("\n--- FEATURE 5: POST-QUANTUM IDENTITY ---")
try:
    r = b.register_post_quantum_identity("sara.pq@example.gov")
    show("PQ register on-chain", bool(r.get("success")), str(r)[:90])
    sig = r.get("signature_b64") or r.get("pq_signature_b64") or ""
    rec = r
    sig = rec.get("signature_b64") or rec.get("pq_signature_b64") or ""
    a = b.passwordless_pq_auth("sara.pq@example.gov", "grant.e-wallet", sig,
                               "nonce-001")
    show("PQ passwordless auth", bool(a.get("authenticated")), str(a)[:90])
    # replay: same nonce again must fail
    a2 = b.passwordless_pq_auth("sara.pq@example.gov", "grant.e-wallet", sig,
                                "nonce-001")
    show("PQ replay blocked", not bool(a2.get("authenticated")), str(a2)[:90])
except Exception as e:
    show("PQ", False, f"{type(e).__name__}: {e}")

print("\n--- FEATURE 1: BREAK-GLASS ---")
try:
    r = b.request_breakglass_access("alice@corp.gov", "warroom.db",
                                    reason="ICU emergency",
                                    requester="dr.who@corp.gov")
    eid = r.get("emergency_id") or r.get("request_id") or ""
    show("break-glass request", bool(r.get("opened") or eid), str(r)[:90])
    ap = b.approve_breakglass_access(eid, "second.op@corp.gov")
    show("break-glass approve", bool(ap.get("approved")), str(ap)[:90])
    u = b.use_breakglass_access(eid, "alice@corp.gov", "warroom.db")
    show("break-glass use", bool(u.get("granted") or u.get("opened")), str(u)[:90])
except Exception as e:
    show("break-glass", False, f"{type(e).__name__}: {e}")

print("\n--- FEATURE 2: TWO-PERSON RULE ---")
try:
    r = b.register_two_person_rule("vault@corp.gov", "e-wallet", "Kim", "Jordan")
    show("two-person register", bool(r.get("success") or r.get("rule_id")), str(r)[:90])
    v = b.verify_two_person_rule("vault@corp.gov", "e-wallet", "Kim", "Jordan",
                                 "kim-sig", "jordan-sig")
    show("two-person verify", bool(v.get("granted") or v.get("success")), str(v)[:90])
except Exception as e:
    show("two-person", False, f"{type(e).__name__}: {e}")

print("\n--- FEATURE 3: CAPABILITY TOKENS ---")
try:
    r = b.mint_capability_token("ops@corp.gov", "grant.e-wallet",
                                actions=("read", "sign"), ttl_s=120, single_use=True)
    tok = r.get("token", "")
    show("capability mint", bool(r.get("success") or tok), str(r)[:90])
    c1 = b.consume_capability_token(tok, "grant.e-wallet", "read")
    show("capability consume#1", bool(c1.get("granted") or c1.get("success")), str(c1)[:90])
    c2 = b.consume_capability_token(tok, "grant.e-wallet", "read")
    show("capability consume#2 single-use blocks", not bool(c2.get("granted") or c2.get("success")),
         str(c2)[:90])
    rv = b.revoke_capability_token(tok)
    show("capability revoke", bool(rv.get("success") or rv.get("revoked")), str(rv)[:90])
except Exception as e:
    show("capability", False, f"{type(e).__name__}: {e}")

print("\n--- FEATURE 4: AIR-GAP OFFLINE PACK ---")
try:
    r = b.build_offline_verification_pack("kim@corp.gov", "kpi.dashboard")
    pid = r.get("pack_id", "")
    show("offline pack build", bool(r.get("success") or pid), str(r)[:90])
    v = b.verify_offline_verification_pack(pid if pid else r)
    show("offline pack verify", bool(v.get("verified") or v.get("success")), str(v)[:90])
except Exception as e:
    show("offline pack", False, f"{type(e).__name__}: {e}")

print("\n=== SUMMARY ===")
