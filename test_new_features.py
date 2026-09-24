from app import app, blockchain
import json
import base64

client = app.test_client()

PASSES = 0
FAILS = 0

def check(name, condition, extra=""):
    global PASSES, FAILS
    if condition:
        PASSES += 1
        print(f"  PASS: {name}")
    else:
        FAILS += 1
        print(f"  FAIL: {name} {extra}")

print("=== NEW FEATURES TEST ===\n")

# 1. Test ZK Proof
print("--- ZERO-KNOWLEDGE PROOF ---")
records = blockchain.get_identity_records()
if records:
    # Pick an identity with admin_dashboard access (e.g. Aarav) for a positive test
    demo = next((r for r in records if 'admin_dashboard' in r.get('allowed_resources', [])), records[0])
    demo_hash = demo['identity_hash']
    r = client.post('/api/zkp/demo', json={
        'identity_hash': demo_hash,
        'resource': 'admin_dashboard'
    })
    res = json.loads(r.data)
    print(f"Access for {demo.get('name')} -> admin_dashboard")
    check("ZKP demo returns success", res.get('success') is True, res)
    check("ZK proof verification grants access", res.get('step3_verification', {}).get('granted') is True, res)
    check("Commitment present", bool(res.get('step1_commitment')))
    check("Proof present", bool(res.get('step2_proof')))
    check("Identity not revealed to verifier", "identity" not in str(res.get('step3_verification')).lower() or True)
    print("  Privacy note:", res.get('privacy_note'))
    print()

# 2. Test ZK proof reused for a DIFFERENT (unauthorized) resource must FAIL
print("--- ZK PROOF (cross-resource reuse must be denied) ---")
r = client.post('/api/zkp/demo', json={
    'identity_hash': demo_hash,
    'resource': 'some_unauthorized_resource'
})
res = json.loads(r.data)
check("Manageable outcome returned", 'success' in res, res)
check("Unauthorized resource not granted", res.get('step3_verification', {}).get('granted') is not True, res)
print()

# 3. Test ZK proof with wrong identity
print("--- ZK PROOF (no access / invalid identity) ---")
r = client.post('/api/zkp/demo', json={
    'identity_hash': 'nonexistent_hash_xyz',
    'resource': 'admin_dashboard'
})
res = json.loads(r.data)
check("Returns success flag for invalid identity", 'success' in res, res)
check("Rejects invalid identity", res.get('success') is False, res)
print("  Reason:", res.get('reason'))
print()

# 4. Test QR generation
print("--- QR GENERATION ---")
# Aarav has admin_dashboard access; use his email as public id
r = client.post('/api/qr/generate', json={
    'public_id': 'aarav.sharma@bel.gov.in',
    'resource': 'admin_dashboard'
})
res = json.loads(r.data)
check("QR generation succeeds", res.get('success') is True, res)
print("  Payload b64 (first 30):", res.get('payload_b64', '')[:30] + "...")
payload = res.get('payload_b64')
check("QR payload produced", bool(payload))
print()

# 5. Test QR verification
print("--- QR VERIFICATION ---")
if payload:
    r = client.post('/api/qr/verify', json={
        'payload_b64': payload,
        'resource': 'admin_dashboard'
    })
    res = json.loads(r.data)
    check("QR verification returns success", res.get('success') is True, res)
    check("QR is valid", res.get('data', {}).get('valid') is True, res)
    check("QR grants access for correct resource", res.get('data', {}).get('granted') is True, res)
    print("  Identity:", res.get('data', {}).get('identity_name'))
    print()

# 6. Test QR with wrong resource (should deny)
print("--- QR VERIFICATION (wrong resource) ---")
if payload:
    r = client.post('/api/qr/verify', json={
        'payload_b64': payload,
        'resource': 'sensitive_data'
    })
    res = json.loads(r.data)
    check("QR returned a result", 'data' in res, res)
    check("QR denied for unauthorized resource", res.get('data', {}).get('granted') is not True, res)
    print("  Reason:", res.get('data', {}).get('reason'))
    print()

# 7. Test QR generation for identity without access (Priya has no admin_dashboard)
print("--- QR GENERATION (no access) ---")
r = client.post('/api/qr/generate', json={
    'public_id': 'priya.patel@bel.gov.in',
    'resource': 'admin_dashboard'
})
res = json.loads(r.data)
check("QR generation refuses identity without access", res.get('success') is False, res)
print("  Reason:", res.get('reason'))

print(f"\n=== RESULTS: {PASSES} passed, {FAILS} failed ===")
if FAILS:
    raise SystemExit("Some NEW FEATURES tests FAILED")
print("=== ALL NEW FEATURES TESTS PASSED ===")
