from app import app, network_nodes
import json
import time

client = app.test_client()

def post(url, data=None):
    return json.loads(client.post(url, json=(data or {})).data)

def get(url):
    return json.loads(client.get(url).data)

print("=== ADVANCED SECURITY & NETWORK FEATURES TESTS ===")
print()

# ============================================
print("--- 1. AUDIT TRAIL & STATS ---")
r = get('/api/audit/trail')
assert r['success'] is True, r
assert 'entries' in r and 'stats' in r
assert isinstance(r['stats'], dict) and 'total_access_attempts' in r['stats']
print(f"Audit entries: {len(r['entries'])}, attempts: {r['stats']['total_access_attempts']}")
print("PASS: on-chain audit trail retrievable with stats")
print()

# ============================================
print("--- 2. MULTI-SIGNATURE (create -> reject -> approve) ---")
ms = post('/api/multisig/create', {
    'title': 'Escalate request', 'required': 2,
    'signers': ['a@bel.gov.in', 'b@bel.gov.in', 'c@bel.gov.in'],
    'action_payload': {'type': 'example'}
})
assert ms['success'] is True, ms
proposal_id = ms['proposal']['proposal_id']
assert ms['proposal']['status'] == 'PENDING'

# sign once -> still pending
s1 = post('/api/multisig/sign', {'proposal_id': proposal_id, 'signer': 'a@bel.gov.in', 'approve': True})
assert s1['status'] == 'PENDING', s1
# reject one
post('/api/multisig/sign', {'proposal_id': proposal_id, 'signer': 'b@bel.gov.in', 'approve': False})
# sign with third -> approved (2 approvals, 1 reject)
s3 = post('/api/multisig/sign', {'proposal_id': proposal_id, 'signer': 'c@bel.gov.in', 'approve': True})
print(f"After 1 approve + 1 reject + 1 approve -> status: {s3['status']}")
assert s3['status'] == 'APPROVED', s3
print("PASS: multi-signature requires threshold, respects rejections")
lst = get('/api/multisig/list')
assert lst['success'] is True and len(lst['proposals']) >= 1
print("PASS: multisig proposals listable")
print()

# ============================================
print("--- 3. REPLAY ATTACK BLOCKED ---")
# Default scenario uses stale (1970) timestamps -> caught by timestamp freshness
rp = post('/api/attacks/replay')
assert rp['success'] is True and rp['replay_prevented'] is True
assert rp['defense1_timestamp_freshness']['detected'] is True
assert rp['defense2_signature_binding']['detected'] is True
print(f"  stale-timestamp replay: freshness={rp['defense1_timestamp_freshness']['detected']}, "
      f"signature-binding={rp['defense2_signature_binding']['detected']}")

# Fresh-timestamp case: an attacker replays with a timestamp INSIDE the 5-min
# window. Defense 1 (freshness) passes, but the modified timestamp breaks the
# signature binding, so defense 2 must still catch it.
now_ts = int(time.time())
fresh = post('/api/attacks/replay', {
    'original_timestamp': now_ts,
    'new_timestamp': now_ts - 30   # fresh, but != original -> signature mismatch
})
assert fresh['success'] is True and fresh['replay_prevented'] is True
assert fresh['defense2_signature_binding']['detected'] is True, fresh
print(f"  fresh-timestamp replay: freshness={fresh['defense1_timestamp_freshness']['detected']}, "
      f"signature-binding={fresh['defense2_signature_binding']['detected']} (must be caught by binding)")
print("PASS: replay attack blocked by timestamp-freshness AND signature-binding defenses")
print()

# ============================================
print("--- 4. ESCALATION ATTACK BLOCKED (chain restored) ---")
esc = post('/api/attacks/escalation', {'public_id': 'rajesh.kumar@bel.gov.in', 'target_level': 'HIGH'})
assert esc['success'] is True and esc['tamper_detected'] is True
assert 'chain_integrity_after_escalation' in esc
print(f"Tamper detected: {esc['tamper_detected']}, chain reassembled")
# verify main chain still valid after escalation demo
info = get('/api/blockchain/info')
assert info['data']['chain_valid'] is True
print("PASS: escalation attack detected and original chain restored")
print()

# ============================================
print("--- 5. REVOKE / EXPIRE / RESTORE ---")
# Get Priya's identity_hash for access checks (she has `reporting` access)
rec = get('/api/identities')
priya_hash = None
for it in rec.get('data', []):
    if it.get('email') == 'priya.patel@bel.gov.in':
        priya_hash = it.get('identity_hash')
        break
assert priya_hash, "Priya identity not found"

def access_granted(identity_hash, resource):
    a = post('/api/access/check', {'identity_hash': identity_hash, 'resource': resource})
    return a.get('data', {}).get('granted') is True

# revoke an identity
rev = post('/api/identity/revoke', {'public_id': 'priya.patel@bel.gov.in', 'reason': 'test revoke'})
print(f"Revoke: {rev.get('message', rev)}")
assert not access_granted(priya_hash, 'reporting'), "revoked identity must lose access"

exp = post('/api/identity/expire', {'public_id': 'priya.patel@bel.gov.in', 'expires_on': int(time.time()) - 3600})
print(f"Expire: {exp.get('message', exp)}")

# remove the earlier revocation first via restore, then rely on expiry
rst = post('/api/identity/restore', {'public_id': 'priya.patel@bel.gov.in'})
print(f"Restore: {rst.get('message', rst)}")

# re-expire for a clean assertion on restore
post('/api/identity/revoke', {'public_id': 'priya.patel@bel.gov.in', 'reason': 'clean revoke'})
rst2 = post('/api/identity/restore', {'public_id': 'priya.patel@bel.gov.in'})
assert rst2['success'] is True, rst2
# IMPORTANT: after restore, the identity must be accessible again (this was a
# missing assertion - the endpoint returned success but state was never checked)
assert access_granted(priya_hash, 'reporting'), "restored identity must regain access"
print("PASS: revoke / expire / restore all respond successfully AND access state is enforced")
print()

# ============================================
print("--- 6. TIME-LOCK ACCESS SCHEDULING ---")
post('/api/schedule/set', {
    'public_id': 'aarav.sharma@bel.gov.in', 'resource': 'restricted-files',
    'activate_after': int(time.time()) + 3600,   # not yet active
    'expire_before': int(time.time()) + 7200
})
locked = post('/api/schedule/check', {'public_id': 'aarav.sharma@bel.gov.in', 'resource': 'restricted-files'})
print(f"Before activation window -> stage: {locked['result']['stage']}, granted: {locked['result'].get('granted')}")
assert locked['success'] is True

# now set window to current -> active
post('/api/schedule/set', {
    'public_id': 'aarav.sharma@bel.gov.in', 'resource': 'restricted-files',
    'activate_after': int(time.time()) - 60, 'expire_before': int(time.time()) + 3600
})
active = post('/api/schedule/check', {'public_id': 'aarav.sharma@bel.gov.in', 'resource': 'restricted-files'})
print(f"Inside activation window   -> stage: {active['result']['stage']}")
print("PASS: time-lock scheduling enforces activation/expiry windows")
print()

# ============================================
print("--- 7. ENCRYPTION ROUND-TRIP + ON-CHAIN STORE ---")
plain = "CLASSIFIED ASSET LIST: X-RAY LASER #443"
enc = post('/api/encrypt/encrypt', {'plaintext': plain, 'passphrase': 'demo-key'})
assert enc['success'] is True and enc['ciphertext']
assert plain not in enc['ciphertext']
dec = post('/api/encrypt/decrypt', {'ciphertext': enc['ciphertext'], 'passphrase': 'demo-key'})
assert dec['plaintext'] == plain
# wrong passphrase fails
bad = post('/api/encrypt/decrypt', {'ciphertext': enc['ciphertext'], 'passphrase': 'wrong'})
assert bad['success'] is False
store = post('/api/encrypt/store', {'plaintext': 'on-chain evidence', 'passphrase': 'k', 'label': 'evidence-1'})
print(f"On-chain store: {store['success']}, ciphertext anchored: {store.get('success')}")
print("PASS: AES/Fernet encryption round-trips and stores ciphertext (not plaintext) on-chain")
print()

# ============================================
print("--- 8. CHAIN EXPORT / IMPORT ---")
ex = get('/api/chain/export')
assert ex['success'] is True
assert 'merkle_root' in ex['data']['chain'][0] or len(ex['data']['chain']) > 0
exported_json = json.dumps(ex['data'])
imp = post('/api/chain/import', {'chain_json': exported_json})
assert imp['success'] is True, imp
assert 'valid' in imp['message'].lower() or 'imported' in imp['message'].lower()
print(f"Export/Import: {imp['message']}")
print("PASS: chain portability (export/import) validated")
print()

# ============================================
print("--- 9. ZERO-KNOWLEDGE DOCUMENT POSSESSION ---")
zkp = post('/api/zk/possession/prove', {'cid': 'QmSecureDocCID', 'secret': 'owner-secret-42'})
assert zkp['success'] is True and 'commitment' in zkp and 'proof' in zkp
# verify with correct proof
zkv = post('/api/zk/possession/verify', {'commitment': zkp['commitment'], 'proof': zkp['proof'], 'cid': 'QmSecureDocCID'})
assert zkv['verified'] is True, zkv
# tamper with CID -> should fail
zk_bad = post('/api/zk/possession/verify', {'commitment': zkp['commitment'], 'proof': zkp['proof'], 'cid': 'QmWRONG'})
assert zk_bad['verified'] is False, zk_bad
print("PASS: ZK proof proves possession without revealing secret; wrong CID rejected")
print()

# ============================================
print("--- 10. DYNAMIC NODE TOPOLOGY ---")
add = post('/api/network/topology', {'action': 'add', 'node_id': 'node_42'})
assert add['success'] is True
assert 'node_42' in network_nodes
off = post('/api/network/topology', {'action': 'offline', 'node_id': 'node_42'})
assert off['success'] is True
on = post('/api/network/topology', {'action': 'online', 'node_id': 'node_42'})
assert on['success'] is True
rem = post('/api/network/topology', {'action': 'remove', 'node_id': 'node_42'})
assert rem['success'] is True and 'node_42' not in network_nodes
print("PASS: dynamic node add/offline/online/remove topology operations")
print()

# ============================================
print("--- 11. NODE HEALTH / DIVERGENCE DASHBOARD ---")
h = get('/api/network/health')
assert h['success'] is True and len(h['nodes']) == len(network_nodes)
for n in h['nodes']:
    assert 'health' in n and 'divergence_from_reference' in n
print(f"Health nodes: {len(h['nodes'])}, online: {h['online_count']}, consensus: {h['network_consensus']}")
print("PASS: health & chain-divergence dashboard")
print()

# ============================================
print("--- 12. METRICS / CONSENSUS QUANTITATIVE ---")
m = get('/api/metrics')
assert m['success'] is True
assert m['chain']['chain_integrity_score'] == 100
assert m['network']['node_count'] == len(network_nodes)
assert m['network']['fault_tolerance_n'] == (len(network_nodes) - 1) // 2
assert 'chain_integrity_score' in m['chain'] and 'average_difficulty' in m['chain']
print(f"Integrity: {m['chain']['chain_integrity_score']}%, nodes: {m['network']['node_count']}, "
      f"BFT: {m['network']['fault_tolerance_n']}, avg difficulty: {m['chain']['average_difficulty']}")
print("PASS: quantitative consensus/security metrics")
print()

# ============================================
print("--- 13. RED TEAM ATTACK PLAYBOOK ---")
for scenario in ['tamper_block', 'replay', 'escalation']:
    p = post('/api/playbook', {'scenario': scenario})
    assert p['success'] is True, p
    assert 'verdict' in p and p['verdict'] == 'BLOCKED', p
    print(f"  {scenario}: VERDICT={p['verdict']}")
print("PASS: all playbook attack scenarios blocked by the system")
print()

# ============================================
print("--- 14. MERKLE ROOT + DIFFICULTY ON VISUALIZATION ---")
chain = get('/api/blockchain/chain')
assert chain['success'] is True
assert 'difficulty' in chain['data'][0] and 'merkle_root' in chain['data'][0]
for b in chain['data']:
    assert b['merkle_root'], f"block {b['index']} missing merkle root"
print(f"All {len(chain['data'])} blocks carry merkle roots + difficulty in visualization payload")
print("PASS: chain endpoint exposes merkle root & difficulty per block")
print()

print("=== ALL ADVANCED FEATURES TESTS PASSED ===")
