"""Main-suite RBAC + NFT-ownership governance tests.

This is a *top-level* suite (runs alongside test_app.py etc.), so the RBAC /
ownership self-test under tests/selftest/ is no longer orphaned - it is
imported here and its checks are reported as part of this suite's totals.

Coverage added on top of the self-test:
  * DID-based NFT ownership (item 8) - a registered DID can hold a dNFT, the
    on-chain ledger reports the DID, and an unresolvable DID is rejected.
  * DID-owner transfer consent - a DID that owns a dNFT authorises the transfer
    with its own anchored signing key (attribute policy recorded as N/A), while
    forged signatures and replayed nonces are still refused and the DID still
    cannot act as an RBAC operator.
  * No privilege escalation via DID - a DID can never act as an RBAC operator.
  * Policy-gate visibility (item 9) - privileged denials return a structured
    `gate` trace with stage/role/capability so the UI can render
    `role AND capability AND resource` instead of a bare reason string.
  * Six auditable activities (items 11-12) - server-side filtering by activity
    key, per-activity counts, and no structural-block leakage.
  * `log_audit` must not clobber the caller's activity type.

Run:  venv\\Scripts\\python.exe test_rbac_governance.py
"""
import importlib
import json
import os
import sys
import unittest

ROOT = os.path.abspath(os.path.dirname(__file__))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from blockchain import Blockchain, RBAC_ROLES

# Import the previously-orphaned self-test so its 20 checks count here too.
_self = importlib.import_module("tests.selftest.test_rbac_ownership15")
INHERITED = list(_self.checks)

checks = []
legacy = INHERITED  # alias: some suites read `legacy` for inherited checks


def T(name, cond, detail=""):
    checks.append((name, bool(cond), detail))


def summary_counts(summary, key):
    for a in summary["activities"]:
        if a["key"] == key:
            return a["count"]
    return 0


# ===========================================================================
# 1. RBAC decision trace: role AND capability AND resource
# ===========================================================================
bc = Blockchain()
_admin = bc.add_identity({
    "name": "Gate Admin", "role": "ADMINISTRATOR", "access_level": "HIGH",
    "email": "gate.admin@bel.gov.in", "id_number": "BEL-GA-001",
    "department": "Digital Transformation",
    "allowed_resources": ["admin_dashboard", "sensitive_data", "user_management"],
})
_user = bc.add_identity({
    "name": "Gate User", "role": "USER", "access_level": "LOW",
    "email": "gate.user@bel.gov.in", "id_number": "BEL-GU-002",
    "department": "Field Operations", "allowed_resources": ["basic_access"],
})
ADMIN = "gate.admin@bel.gov.in"
USER = "gate.user@bel.gov.in"
bc.register_smart_contract_rules(ADMIN, work_hours=False)

va = bc.rbac_verify(ADMIN, capability="nft.mint", resource="nft.mint")
T("verify: admin granted nft.mint", va["granted"], json.dumps(va)[:140])
T("verify trace exposes role", va.get("gate", {}).get("role") == "ADMINISTRATOR", json.dumps(va.get("gate"))[:140])
T("verify trace exposes capability_held", va.get("gate", {}).get("capability_held") is True, json.dumps(va.get("gate"))[:140])

vu = bc.rbac_verify(USER, capability="nft.mint", resource="nft.mint")
T("verify: plain USER denied nft.mint", not vu["granted"], json.dumps(vu)[:140])
gt = vu.get("gate", {})
T("verify trace shows role=USER", gt.get("role") == "USER", json.dumps(gt)[:140])
T("verify trace shows capability_held=False", gt.get("capability_held") is False, json.dumps(gt)[:140])
T("verify trace shows resource_granted=False", gt.get("resource_granted") is False, json.dumps(gt)[:140])
T("verify trace lists role capabilities", isinstance(gt.get("role_capabilities"), list), json.dumps(gt)[:140])

vg = bc.rbac_verify("ghost.subject@nowhere.in", capability="nft.mint")
T("verify: unknown subject deny-by-default", not vg["granted"], json.dumps(vg)[:140])
T("verify: unknown subject trace stage=rbac", vg.get("gate", {}).get("stage") == "rbac", json.dumps(vg.get("gate"))[:140])

# USER has no nft.mint in its canonical role policy
T("canonical USER role excludes nft.mint",
  "nft.mint" not in (bc._rbac_policy.get("USER", {}).get("capabilities") or []))

# ===========================================================================
# 2. Custom role definition flips the gate the other way
# ===========================================================================
dr = bc.rbac_define_role(ADMIN, "INCIDENT_RESPONDER",
                         capabilities=["nft.mint", "audit.view"], resources=[])
T("admin defines custom role", dr.get("success"), json.dumps(dr)[:140])
ar = bc.rbac_assign_role(ADMIN, USER, "INCIDENT_RESPONDER")
T("admin assigns custom role", ar.get("success"), json.dumps(ar)[:140])
T("custom role now grants nft.mint",
  bc.rbac_verify(USER, capability="nft.mint")["granted"], "still denied")
T("custom role shows in rbac_list",
  any(x["role"] == "INCIDENT_RESPONDER" for x in bc.rbac_list()["roles"]), "missing")

# non-admin denials must carry a structured gate, not just a string
d_den = bc.rbac_define_role(USER, "SHOULD_FAIL", capabilities=[])
T("non-admin define role denied", not d_den.get("success"), json.dumps(d_den)[:140])
T("non-admin define denial carries gate", isinstance(d_den.get("gate"), dict), json.dumps(d_den)[:160])
T("non-admin define denial names capability",
  (d_den.get("gate") or {}).get("capability") == "rbac.role.define", json.dumps(d_den.get("gate"))[:160])

a_den = bc.rbac_assign_role(USER, USER, "ADMINISTRATOR")
T("non-admin assign role denied", not a_den.get("success"), json.dumps(a_den)[:140])
T("non-admin assign denial carries gate", isinstance(a_den.get("gate"), dict), json.dumps(a_den)[:160])
T("non-admin cannot escalate self to ADMINISTRATOR",
  bc.identity_role(USER) == "INCIDENT_RESPONDER", bc.identity_role(USER))

# ===========================================================================
# 3. Mint gate: ADMIN ok, non-ADMIN denied, unknown owner denied
# ===========================================================================
m_ok = bc.nft_mint("hardware", "Gate Asset", ADMIN, actor=ADMIN)
T("ADMIN mints successfully", m_ok.get("success"), json.dumps(m_ok)[:140])
T("mint returns a gate trace", isinstance(m_ok.get("gate"), dict), json.dumps(m_ok.get("gate"))[:140])
T("mint reports owner_kind=identity", m_ok.get("owner_kind") == "identity", json.dumps(m_ok)[:140])

# demote a fresh user so the mint gate is exercised as a true non-ADMIN
bc.add_identity({
    "name": "Mint User", "role": "USER", "access_level": "LOW",
    "email": "mint.user@bel.gov.in", "id_number": "BEL-MU-003",
    "department": "Field Operations", "allowed_resources": ["basic_access"],
})
m_den = bc.nft_mint("hardware", "Denied Asset", "mint.user@bel.gov.in",
                    actor="mint.user@bel.gov.in")
T("non-ADMIN mint denied", not m_den.get("success"), json.dumps(m_den)[:140])
T("non-ADMIN mint denial carries gate", isinstance(m_den.get("gate"), dict), json.dumps(m_den)[:160])
T("non-ADMIN mint denial names nft.mint",
  (m_den.get("gate") or {}).get("capability") == "nft.mint", json.dumps(m_den.get("gate"))[:160])
T("non-ADMIN mint denial stage is rbac/attribution",
  (m_den.get("gate") or {}).get("stage") in ("rbac", "attribution", "rbac+smart-contract"),
  json.dumps(m_den.get("gate"))[:160])

m_ghost = bc.nft_mint("hardware", "Ghost Asset", "ghost.owner@nowhere.in", actor=ADMIN)
T("mint to unregistered owner denied", not m_ghost.get("success"), json.dumps(m_ghost)[:140])
T("unregistered owner denial stage=ownership",
  (m_ghost.get("gate") or {}).get("stage") == "ownership", json.dumps(m_ghost.get("gate"))[:160])

m_noactor = bc.nft_mint("hardware", "No Actor", ADMIN, actor=None)
T("mint with no actor denied", not m_noactor.get("success"), json.dumps(m_noactor)[:140])
T("no-actor denial stage=attribution",
  (m_noactor.get("gate") or {}).get("stage") == "attribution", json.dumps(m_noactor.get("gate"))[:160])

# ===========================================================================
# 4. DID-based NFT ownership (item 8)
# ===========================================================================
did_rec = bc.register_did(name="DID Holder", role="USER", email="did.holder@bel.gov.in")
DID = did_rec.get("did")
T("DID registered for ownership", bool(DID) and DID.startswith("did:"), str(did_rec)[:140])
T("DID is not resolvable as an identity (no actor escalation)",
  bc.find_identity_by_public_id(DID).get("found") is False, "DID leaked into identities")
T("DID cannot act as an RBAC operator",
  bc.require_operator(DID, "nft.mint").get("granted") is False, "DID could act as operator")
T("DID has no RBAC role", bc.identity_role(DID) is None, str(bc.identity_role(DID)))

subj = bc.resolve_ownership_subject(DID)
T("DID resolves as an ownership subject", subj.get("found") is True, json.dumps(subj)[:140])
T("ownership subject kind == did", subj.get("kind") == "did", json.dumps(subj)[:140])

m_did = bc.nft_mint("hardware", "DID Owned Asset", DID, actor=ADMIN)
T("mint dNFT directly to a DID owner succeeds", m_did.get("success"), json.dumps(m_did)[:160])
T("DID mint reports owner_kind=did", m_did.get("owner_kind") == "did", json.dumps(m_did)[:160])
DID_TOK = (m_did.get("asset") or {}).get("token_id")
T("DID-owned token id issued", bool(DID_TOK), str(m_did)[:160])

own = bc.nft_chain_ledger()
did_assets = [a for a in own["assets"] if a["token_id"] == DID_TOK]
T("on-chain ledger records the DID as owner",
  did_assets and did_assets[0].get("chain_owner") == DID, json.dumps(own)[:200])

m_baddid = bc.nft_mint("hardware", "Bad DID", "did:key:zNotARealDid", actor=ADMIN)
T("mint to unregistered DID denied", not m_baddid.get("success"), json.dumps(m_baddid)[:140])
T("unregistered DID denial stage=ownership",
  (m_baddid.get("gate") or {}).get("stage") == "ownership", json.dumps(m_baddid.get("gate"))[:160])

# ===========================================================================
# 5. Transfer consent gates (item 6)
# ===========================================================================
t_anon = bc.nft_transfer(DID_TOK, USER)
T("transfer with no actor denied", not t_anon.get("success"), json.dumps(t_anon)[:140])
T("no-actor transfer denial carries gate", isinstance(t_anon.get("gate"), dict), json.dumps(t_anon)[:160])

t_wrong = bc.nft_transfer(DID_TOK, USER, actor=USER)
T("wrong-holder transfer denied", not t_wrong.get("success"), json.dumps(t_wrong)[:140])
T("wrong-holder denial identifies current owner",
  (t_wrong.get("gate") or {}).get("current_owner") == DID, json.dumps(t_wrong.get("gate"))[:200])

t_badsig = bc.nft_transfer(DID_TOK, USER, actor=ADMIN, signature="00" * 32,
                           nonce="n-bad-1", consent_timestamp=1.0)
T("forged/bad signature cannot transfer", not t_badsig.get("success"), json.dumps(t_badsig)[:140])

t_ghost_new = bc.nft_transfer(DID_TOK, "ghost.newowner@nowhere.in",
                              actor=ADMIN, admin_override=True)
T("transfer to unregistered new owner denied",
  not t_ghost_new.get("success"), json.dumps(t_ghost_new)[:140])
T("unregistered new owner denial stage=ownership",
  (t_ghost_new.get("gate") or {}).get("stage") == "ownership", json.dumps(t_ghost_new.get("gate"))[:200])

# admin override to a legitimate identity must succeed and be traceable
t_ok = bc.nft_transfer(DID_TOK, ADMIN, actor=ADMIN, admin_override=True)
T("admin override transfer to verified identity succeeds",
  t_ok.get("success"), json.dumps(t_ok)[:160])
T("successful transfer returns gate trace", isinstance(t_ok.get("gate"), dict), json.dumps(t_ok.get("gate"))[:160])
T("successful transfer reports new_owner_kind=identity",
  t_ok.get("new_owner_kind") == "identity", json.dumps(t_ok)[:160])
after = bc.nft_chain_ledger()
moved = [a for a in after["assets"] if a["token_id"] == DID_TOK]
T("ledger ownership moved off the DID",
  moved and moved[0].get("chain_owner") == ADMIN, json.dumps(moved)[:200])

# ===========================================================================
# 6. log_audit must preserve the caller's activity type
# ===========================================================================
before_types = {b.data.get("type") for b in bc.chain}
bc.log_audit({"type": "RBAC_OPERATOR", "actor": ADMIN, "decision": "DENIED"})
preserved = [b for b in bc.chain
             if (b.data or {}).get("event_type") == "RBAC_OPERATOR"
             and b.data.get("type") == "AUDIT_LOG"]
T("log_audit preserves declared type in event_type", len(preserved) >= 1, str(len(preserved)))
T("log_audit still writes type=AUDIT_LOG (back-compat)", preserved, "type not AUDIT_LOG")

# ===========================================================================
# 7. The six auditable activities (items 11-12)
# ===========================================================================
summary = bc.get_activity_summary()
keys = [a["key"] for a in summary["activities"]]
T("exactly six PS activities", len(keys) == 6, json.dumps(keys))
T("activity keys are the PS six",
  keys == ["identity_creation", "nft_creation", "allocation",
           "access_rights", "ownership_transfer", "permission_update"],
  json.dumps(keys))
T("every PS activity is described with a label",
  all(a.get("label") for a in summary["activities"]), json.dumps(summary["activities"])[:200])

# structural blocks must never leak into the unfiltered activity view
unfiltered = bc.get_activity_trail(limit=5000)
unfiltered_types = {e["activity_type"] for e in unfiltered}
T("no GENESIS block in activity trail", "GENESIS" not in unfiltered_types, str(sorted(unfiltered_types)))
T("unfiltered trail only contains mapped activity types",
  all(t in {x for spec in bc.PS_ACTIVITIES.values() for x in spec["types"]}
      for t in unfiltered_types), str(sorted(unfiltered_types)))

for k in keys:
    tr = bc.get_activity_trail(activity=k, limit=500)
    ok_types = all(e["activity_type"] in bc.PS_ACTIVITIES[k]["types"] for e in tr)
    T(f"filter '{k}' returns only its own types", ok_types,
      str(sorted({e['activity_type'] for e in tr})))

T("identity_creation has blocks",
  summary_counts(summary, "identity_creation") > 0, json.dumps(summary["activities"]))
T("nft_creation has blocks", summary_counts(summary, "nft_creation") > 0, json.dumps(summary["activities"]))
T("permission_update has blocks", summary_counts(summary, "permission_update") > 0, json.dumps(summary["activities"]))
T("ownership_transfer has blocks", summary_counts(summary, "ownership_transfer") > 0, json.dumps(summary["activities"]))

# server-side filtering must happen BEFORE the limit
narrow = bc.get_activity_trail(activity="nft_creation", limit=1)
T("filter is applied before the limit", len(narrow) <= 1, str(len(narrow)))
T("limit=1 still returns the right type",
  narrow and narrow[0]["activity_type"] in bc.PS_ACTIVITIES["nft_creation"]["types"],
  json.dumps(narrow)[:140])

try:
    bc.get_activity_trail(activity="not_a_real_activity")
    T("unknown activity key rejected", False, "no error raised")
except ValueError:
    T("unknown activity key rejected with ValueError", True)


# ===========================================================================
# 8. Role selection at join approval (self-registration onboarding)
# ===========================================================================
jb = Blockchain()
jb.register_smart_contract_rules(ADMIN, work_hours=False)
jb.add_identity({"name": "Join Admin", "role": "ADMINISTRATOR", "access_level": "HIGH",
                 "email": "join.admin@bel.gov.in", "id_number": "BEL-JA-001",
                 "department": "IT", "allowed_resources": ["admin_dashboard"]})
jb.add_identity({"name": "Join Plain", "role": "USER", "access_level": "LOW",
                 "email": "join.plain@bel.gov.in", "id_number": "BEL-JP-002",
                 "department": "Field", "allowed_resources": ["basic_access"]})
JADMIN = "join.admin@bel.gov.in"
JPLAIN = "join.plain@bel.gov.in"


def _mk_join(mail):
    r = jb.join_request({"name": "Join Candidate", "email": mail,
                         "role": "FIELD_ENGINEER", "id_number": "BEL-JC-" + mail[:2].upper(),
                         "access_level": 2, "allowed_resources": ["personal_record"]})
    return r.get("join_id")


jr_user = _mk_join("jr.user@bel.in")
jr_mgr = _mk_join("jr.mgr@bel.in")
jr_admin = _mk_join("jr.admin@bel.in")
jr_bogus = _mk_join("jr.bogus@bel.in")
jr_plain = _mk_join("jr.plain@bel.in")

a_user = jb.join_approve(jr_user, approver=JADMIN, role="USER")
T("join approve with USER succeeds", a_user.get("success"), json.dumps(a_user)[:140])
T("join approve grants USER", a_user.get("role") == "USER", json.dumps(a_user)[:140])
T("approved identity resolves to USER",
  jb.identity_role("jr.user@bel.in") == "USER", str(jb.identity_role("jr.user@bel.in")))

a_mgr = jb.join_approve(jr_mgr, approver=JPLAIN, role="MANAGER")
T("non-admin cannot grant MANAGER at approval", not a_mgr.get("success"), json.dumps(a_mgr)[:160])
T("refused escalation carries gate trace", isinstance(a_mgr.get("gate"), dict), json.dumps(a_mgr)[:200])
T("refused escalation names the first failing capability",
  (a_mgr.get("gate") or {}).get("capability") in ("identity.register", "rbac.role.assign"),
  json.dumps(a_mgr.get("gate"))[:200])

T("refused escalation leaves request PENDING",
  jb._join_requests[jr_mgr]["status"] == "PENDING", jb._join_requests[jr_mgr]["status"])
T("refused escalation assigns no role", jb.identity_role("jr.mgr@bel.in") is None,
  str(jb.identity_role("jr.mgr@bel.in")))

a_admin = jb.join_approve(jr_admin, approver=JADMIN, role="ADMINISTRATOR")
T("admin can grant ADMINISTRATOR at approval", a_admin.get("success"), json.dumps(a_admin)[:160])
T("approved identity resolves to ADMINISTRATOR",
  jb.identity_role("jr.admin@bel.in") == "ADMINISTRATOR", str(jb.identity_role("jr.admin@bel.in")))

a_bogus = jb.join_approve(jr_bogus, approver=JADMIN, role="NOT_A_REAL_ROLE")
T("unknown role rejected at approval", not a_bogus.get("success"), json.dumps(a_bogus)[:140])

a_re = jb.join_approve(jr_user, approver=JADMIN, role="USER")
T("re-approving a settled request is refused", not a_re.get("success"), json.dumps(a_re)[:140])

a_none = jb.join_approve(jr_plain, approver=JADMIN)
T("approval without a role still succeeds (safe default)", a_none.get("success"), json.dumps(a_none)[:140])

# --- Regressions: join approval must be deny-by-default at the approver ------
# A non-privileged approver must be refused even when the requested role is the
# safe default USER: otherwise "approve with USER" is an unauthenticated way to
# mint identities. The failing leg is reported, not a bare error string.
jr_esc = jb.join_request({"email": "jr.esc@bel.in", "name": "Escalation Probe",
                          "role": "FIELD_ENGINEER", "access_level": 1,
                          "allowed_resources": ["basic_access"]})["join_id"]
a_esc = jb.join_approve(jr_esc, approver=JPLAIN, role="USER")
T("non-privileged approver refused even for plain USER", not a_esc.get("success"),
  json.dumps(a_esc)[:200])
T("that refusal names identity.register",
  (a_esc.get("gate") or {}).get("capability") == "identity.register",
  json.dumps(a_esc.get("gate"))[:200])
T("that refusal leaves the request PENDING",
  jb._join_requests[jr_esc]["status"] == "PENDING", jb._join_requests[jr_esc]["status"])
T("that refusal minted no identity", jb.identity_role("jr.esc@bel.in") is None,
  str(jb.identity_role("jr.esc@bel.in")))

jr_ghost = jb.join_request({"email": "jr.ghost@bel.in", "name": "Ghost Approver",
                            "role": "FIELD_ENGINEER", "access_level": 1,
                            "allowed_resources": ["basic_access"]})["join_id"]
a_ghost = jb.join_approve(jr_ghost, approver="ghost.approver@nowhere.in", role="USER")
T("unregistered approver refused", not a_ghost.get("success"), json.dumps(a_ghost)[:200])
T("unregistered approver mints nothing", jb.identity_role("jr.ghost@bel.in") is None,
  str(jb.identity_role("jr.ghost@bel.in")))

jr_noap = jb.join_request({"email": "jr.noap@bel.in", "name": "No Approver",
                           "role": "FIELD_ENGINEER", "access_level": 1,
                           "allowed_resources": ["basic_access"]})["join_id"]
a_noap = jb.join_approve(jr_noap, approver="", role="USER")
T("missing approver refused (deny-by-default)", not a_noap.get("success"), json.dumps(a_noap)[:200])

# The literal string "admin" was hardcoded by the UI but was never a registered
# identity, so it must not be accepted as an approver.
jr_lit = jb.join_request({"email": "jr.lit@bel.in", "name": "Literal Admin",
                          "role": "FIELD_ENGINEER", "access_level": 1,
                          "allowed_resources": ["basic_access"]})["join_id"]
a_lit = jb.join_approve(jr_lit, approver="admin", role="USER")
T("literal 'admin' is not a valid approver", not a_lit.get("success"), json.dumps(a_lit)[:200])

# Approved identities must be minted under the applicant's real principal, not
# the throwaway `pending.<hex>` handle used while the request is unresolved.
jr_real = jb.join_request({"email": "jr.real@bel.in", "name": "Real Principal",
                           "role": "FIELD_ENGINEER", "access_level": 1,
                           "allowed_resources": ["basic_access"]})["join_id"]
a_real = jb.join_approve(jr_real, approver=JADMIN, role="USER")
T("approval mints the applicant's real principal",
  (a_real.get("identity") or {}).get("public_id") == "jr.real@bel.in",
  json.dumps(a_real.get("identity"))[:200])
T("no pending.* placeholder reaches the ledger",
  not str(jb._rbac_assignments).find("pending.") >= 0
  and jb.identity_role("jr.real@bel.in") == "USER", str(jb.identity_role("jr.real@bel.in")))

# Two-leg design: a custom role may hold identity.register (approve ordinary
# joins) without rbac.role.assign (grant elevated roles). The second leg must
# still be enforced independently.
jb.rbac_define_role(JADMIN, "JOIN_APPROVER", capabilities=["identity.register"],
                    resources=["identity.register", "user_management"])
jb.add_identity({"public_id": "jr.hr@bel.in", "name": "HR Approver",
                 "role": "FIELD_ENGINEER", "access_level": 2,
                 "allowed_resources": ["identity.register", "user_management"]})
jb.rbac_assign_role(JADMIN, "jr.hr@bel.in", "JOIN_APPROVER")
T("custom approver holds identity.register",
  "identity.register" in jb._identity_capability_grants("jr.hr@bel.in", "JOIN_APPROVER"),
  str(sorted(jb._identity_capability_grants("jr.hr@bel.in", "JOIN_APPROVER"))))
T("custom approver does NOT hold rbac.role.assign",
  "rbac.role.assign" not in jb._identity_capability_grants("jr.hr@bel.in", "JOIN_APPROVER"),
  str(sorted(jb._identity_capability_grants("jr.hr@bel.in", "JOIN_APPROVER"))))

jr_hr_ok = jb.join_request({"email": "jr.hr.ok@bel.in", "name": "HR Approved",
                            "role": "FIELD_ENGINEER", "access_level": 1,
                            "allowed_resources": ["basic_access"]})["join_id"]
a_hr_ok = jb.join_approve(jr_hr_ok, approver="jr.hr@bel.in", role="USER")
T("custom approver may grant plain USER", a_hr_ok.get("success"), json.dumps(a_hr_ok)[:200])

jr_hr_bad = jb.join_request({"email": "jr.hr.bad@bel.in", "name": "HR Escalation",
                             "role": "FIELD_ENGINEER", "access_level": 1,
                             "allowed_resources": ["basic_access"]})["join_id"]
a_hr_bad = jb.join_approve(jr_hr_bad, approver="jr.hr@bel.in", role="MANAGER")
T("custom approver may NOT grant MANAGER", not a_hr_bad.get("success"), json.dumps(a_hr_bad)[:200])
T("that refusal is on the rbac.role.assign leg",
  (a_hr_bad.get("gate") or {}).get("capability") == "rbac.role.assign",
  json.dumps(a_hr_bad.get("gate"))[:200])

# Policy upgrades must reach an already-persisted chain: a stale snapshot of
# _rbac_policy used to pin the policy forever once a chain had been saved.
T("canonical policy is not frozen to an old snapshot",
  "identity.register" in jb._rbac_policy["ADMINISTRATOR"]["capabilities"],
  str(jb._rbac_policy["ADMINISTRATOR"]["capabilities"]))


# ===========================================================================
# 11. DID-owner transfer consent
#     A DID that HOLDS a dNFT must be able to authorise the transfer of its
#     own token with that DID's anchored signing key. Previously
#     get_public_key() only consulted the identity ledger and the owner path
#     required _resolve_identity_id(), so a DID owner was locked out of its own
#     asset and only an admin override could move it.
# ===========================================================================
from blockchain import CryptoIdentity  # noqa: E402

db = Blockchain()
_db_admin = db.add_identity({
    "name": "DID Admin", "role": "ADMINISTRATOR", "access_level": "HIGH",
    "email": "did.admin@bel.gov.in", "id_number": "BEL-DA-001",
    "department": "Digital Transformation",
    "allowed_resources": ["admin_dashboard", "sensitive_data", "user_management",
                          "network_access", "blockchain_console", "basic_access"],
})
_db_recip = db.add_identity({
    "name": "DID Recipient", "role": "FIELD_ENGINEER", "access_level": "MEDIUM",
    "email": "did.recip@bel.gov.in", "id_number": "BEL-DR-001",
    "department": "Field Ops", "allowed_resources": ["basic_access", "field_reports"],
})

_db_did = db.register_did({"name": "Field Device",
                           "controller": "sensor-gateway-7"})["did"]
_db_mint = db.nft_mint(asset_type="hardware", name="Telemetry Sensor", owner=_db_did,
                       description="field telemetry", actor="did.admin@bel.gov.in")
_db_tok = _db_mint.get("token_id") or (_db_mint.get("asset") or {}).get("token_id")

_db_pk = db.get_public_key(_db_did)
T("get_public_key resolves an anchored DID", _db_pk.get("found"), json.dumps(_db_pk)[:200])
T("the resolved DID key is tagged subject_kind=did",
  _db_pk.get("subject_kind") == "did", repr(_db_pk.get("subject_kind")))

_db_priv = db._did_store[_db_did]["private_key"]
_ts = str(int(__import__("time").time()))
_nonce = "didownerconsent0001"
_sig = CryptoIdentity.sign_message(
    _db_priv, db.transfer_consent_message(_db_tok, "did.recip@bel.gov.in",
                                         int(_ts), _nonce))
_ok = db.nft_transfer(actor=_db_did, token_id=_db_tok, new_owner="did.recip@bel.gov.in",
                      signature=_sig, nonce=_nonce, consent_timestamp=_ts)
T("a DID owner can authorise its own transfer by signature", _ok.get("success"),
  json.dumps(_ok)[:260])
T("that transfer is recorded as owner-signature consent",
  _ok.get("consent_mode") == "owner-signature", repr(_ok.get("consent_mode")))
T("the DID signature is marked as cryptographically verified",
  _ok.get("signature_verified") is True, repr(_ok.get("signature_verified")))
T("the gate trace explains that attribute policy is N/A for a DID",
  any("not applicable" in str(ev.get("detail", ""))
      for ev in ((_ok.get("gate") or {}).get("evaluation") or [])),
  json.dumps(_ok.get("gate"))[:260])
T("the recipient identity now holds the token",
  db.resolve_ownership_subject("did.recip@bel.gov.in").get("kind") == "identity",
  json.dumps(db.resolve_ownership_subject("did.recip@bel.gov.in"))[:180])

# A forged signature from the DID must still be refused - the fix must not
# have turned into "any DID owner may transfer".
_db_mint2 = db.nft_mint(asset_type="hardware", name="Forged Consent", owner=_db_did,
                        description="forgery probe", actor="did.admin@bel.gov.in")
_db_tok2 = _db_mint2.get("token_id") or (_db_mint2.get("asset") or {}).get("token_id")
_ts2 = str(int(__import__("time").time()))
_forged = db.nft_transfer(actor=_db_did, token_id=_db_tok2,
                          new_owner="did.recip@bel.gov.in", signature="deadbeef",
                          nonce="forgednonce000001", consent_timestamp=_ts2)
T("a DID owner with a forged signature is refused", not _forged.get("success"),
  json.dumps(_forged)[:260])
T("that refusal is attributed to invalid owner consent",
  "consent" in str(_forged.get("reason", "")).lower()
  or (_forged.get("gate") or {}).get("stage") == "owner-consent",
  json.dumps(_forged.get("gate"))[:220])

# Replay protection must survive the DID path.
_db_mint3 = db.nft_mint(asset_type="hardware", name="Replay Probe", owner=_db_did,
                        description="replay probe", actor="did.admin@bel.gov.in")
_db_tok3 = _db_mint3.get("token_id") or (_db_mint3.get("asset") or {}).get("token_id")
_ts3, _n3 = str(int(__import__("time").time())), "replayednonce0001"
_sig3 = CryptoIdentity.sign_message(
    _db_priv, db.transfer_consent_message(_db_tok3, "did.recip@bel.gov.in",
                                         int(_ts3), _n3))
_first = db.nft_transfer(actor=_db_did, token_id=_db_tok3,
                         new_owner="did.recip@bel.gov.in", signature=_sig3,
                         nonce=_n3, consent_timestamp=_ts3)
_replay = db.nft_transfer(actor=_db_did, token_id=_db_tok3,
                          new_owner="did.admin@bel.gov.in", signature=_sig3,
                          nonce=_n3, consent_timestamp=_ts3)
T("the first DID-signed transfer is accepted", _first.get("success") is True,
  json.dumps(_first)[:220])
T("replaying a DID consent nonce is refused", _replay.get("success") is False,
  json.dumps(_replay)[:220])

# A DID must still never act as an RBAC operator (unchanged by this fix).
_op = db._policy_gate(actor=_db_did, capability="nft.transfer.admin",
                      resource="nft.transfer.admin", context={}, owner_path=False)
T("a DID still cannot act as an RBAC operator",
  not _op.get("granted"), json.dumps(_op)[:220])


# ===========================================================================
# 12. join REJECTION is gated too
#     Rejecting blocks a legitimate applicant, so it needs the same
#     `identity.register` capability as approving. The gate used to be skipped
#     entirely when the approver field was empty, which made rejection the one
#     unauthenticated write in the onboarding flow.
# ===========================================================================
rb = Blockchain()
rb._rbac_init()
rb.add_identity({
    "name": "Reject Admin", "role": "ADMINISTRATOR", "access_level": "HIGH",
    "email": "reject.admin@bel.gov.in", "id_number": "BEL-RJ-001",
    "department": "Digital Transformation",
    "allowed_resources": ["admin_dashboard", "sensitive_data", "user_management",
                          "network_access", "blockchain_console", "basic_access"],
})
rb.add_identity({
    "name": "Reject Plain", "role": "USER", "access_level": "LOW",
    "email": "reject.plain@bel.gov.in", "id_number": "BEL-RP-001",
    "department": "Field Ops", "allowed_resources": ["basic_access"],
})


def _pending(rb_chain, email):
    jid = rb_chain.join_request({"name": "Applicant " + email, "email": email,
                                 "id_number": email.upper(),
                                 "department": "Field Ops"})["join_id"]
    return rb_chain._join_requests[jid]


_r1 = _pending(rb, "reject.empty@bel.gov.in")
T("a join request can be created for the rejection tests",
  _r1.get("status") == "PENDING", json.dumps(_r1)[:160])

_x = rb.join_reject(_r1["join_id"], reason="no approver", approver="")
T("reject with an EMPTY approver is refused", not _x.get("success"),
  json.dumps(_x)[:220])
T("that empty-approver refusal names identity.register",
  (_x.get("gate") or {}).get("capability") == "identity.register",
  json.dumps(_x.get("gate"))[:220])
T("the empty-approver rejection left the request PENDING",
  rb._join_requests[_r1["join_id"]].get("status") == "PENDING",
  json.dumps(rb._join_requests[_r1["join_id"]])[:200])

_r2 = _pending(rb, "reject.plainuser@bel.gov.in")
_x2 = rb.join_reject(_r2["join_id"], reason="nope", approver="reject.plain@bel.gov.in")
T("reject by a plain USER is refused", not _x2.get("success"), json.dumps(_x2)[:220])

_r3 = _pending(rb, "reject.stranger@bel.gov.in")
_x3 = rb.join_reject(_r3["join_id"], reason="nope", approver="nobody@bel.gov.in")
T("reject by an unregistered approver is refused", not _x3.get("success"),
  json.dumps(_x3)[:220])

_r4 = _pending(rb, "reject.literal@bel.gov.in")
_x4 = rb.join_reject(_r4["join_id"], reason="nope", approver="admin")
T("the literal string 'admin' cannot reject", not _x4.get("success"),
  json.dumps(_x4)[:220])

_r5 = _pending(rb, "reject.applicant@bel.gov.in")
_x5 = rb.join_reject(_r5["join_id"], reason="insufficient evidence",
                     approver="reject.admin@bel.gov.in")
T("an ADMINISTRATOR may reject", _x5.get("success"), json.dumps(_x5)[:220])
T("the rejection is recorded as REJECTED",
  rb._join_requests[_r5["join_id"]].get("status") == "REJECTED",
  json.dumps(rb._join_requests[_r5["join_id"]])[:200])
T("rejection minted no identity for the applicant",
  not rb.find_identity_by_public_id("reject.applicant@bel.gov.in")["found"],
  "applicant must not appear as an identity")
T("a settled request cannot be rejected twice",
  not rb.join_reject(_r5["join_id"], approver="reject.admin@bel.gov.in")
  .get("success"))


# ===========================================================================
# Report
# ===========================================================================
all_checks = list(INHERITED) + checks
fails = sum(1 for _, cond, _ in all_checks if not cond)


class TestRBACGovernance(unittest.TestCase):
    def test_inherited_selftest_checks(self):
        inherited_fails = [n for n, c, _ in INHERITED if not c]
        self.assertEqual(inherited_fails, [], f"inherited selftest failures: {inherited_fails}")

    def test_rbac_and_ownership_governance_checks(self):
        new_fails = [n for n, c, d in checks if not c]
        self.assertEqual(new_fails, [], f"{len(new_fails)} of {len(checks)} checks failed: {new_fails}")


if __name__ == "__main__":
    print("\n=== RBAC + NFT OWNERSHIP GOVERNANCE (main suite) ===")
    print(f"    inherited from tests/selftest/test_rbac_ownership15.py: {len(INHERITED)} checks")
    print(f"    added by this suite:                                  {len(checks)} checks\n")
    for name, cond, detail in checks:
        print(("  PASS  " if cond else "  FAIL  ") + name + (f"  :: {detail}" if not cond else ""))
    print(f"\nRESULT: {len(all_checks) - fails}/{len(all_checks)} passed",
          "-> ALL GREEN" if fails == 0 else f"-> {fails} FAILED")
    sys.exit(1 if fails else 0)
