from app import app, blockchain
import json

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

records = blockchain.get_identity_records()
print('=== REGISTERED IDENTITIES ===')
for rec in records:
    print(f"  #{rec['block_index']}: {rec['name']} ({rec['role']}) - hash: {rec['identity_hash'][:12]}...")

check("Demo identities are seeded on-chain", len(records) >= 3)

verify_me = records[0]['identity_hash']
print()
r = client.post('/api/identities/verify', json={'identity_hash': verify_me})
print('=== VERIFY TEST ===')
res = json.loads(r.data)
check("Authenticated identity is found", res['data']['found'] is True, res)
check("Found in a valid block", res['data']['block_index'] >= 1, res)

# verify a missing identity returns found=False (not an error)
r = client.post('/api/identities/verify', json={'identity_hash': 'no_such_hash'})
res2 = json.loads(r.data)
check("Unknown identity reported as not found", res2['data']['found'] is False, res2)

print()
print('=== ACCESS CONTROL TEST ===')
# Aarav (HIGH) has access to admin_dashboard and sensitive_data
r = client.post('/api/access/check', json={'identity_hash': verify_me, 'resource': 'admin_dashboard'})
admin = json.loads(r.data)
print('Admin access:', admin['data'])
check("Granted access to admin_dashboard", admin['data']['granted'] is True, admin)

r = client.post('/api/access/check', json={'identity_hash': verify_me, 'resource': 'sensitive_data'})
sensitive = json.loads(r.data)
print('Sensitive access:', sensitive['data'])
check("Granted access to sensitive_data", sensitive['data']['granted'] is True, sensitive)

print()
print('=== TAMPER TEST ===')
r = client.post('/api/blockchain/tamper', json={'block_index': 1})
res = json.loads(r.data)
print('Tampered:', res['tampered'], '| Chain valid now:', res['chain_valid'])
check("Tampering flagged as tampered", res['tampered'] is True, res)
check("Chain marked invalid after tamper", res['chain_valid'] is False, res)

r = client.get('/api/blockchain/validate')
res = json.loads(r.data)
print('Validation:', res['message'])
check("Chain integrity validation detects tampering", res['valid'] is False, res)

print()
print('=== RESET TEST ===')
r = client.post('/api/blockchain/reset')
res = json.loads(r.data)
print(res.get('message'))
check("Blockchain resets successfully", res.get('success') is True, res)

print(f"\n=== RESULTS: {PASSES} passed, {FAILS} failed ===")
if FAILS:
    raise SystemExit("Some CORE tests FAILED")
print("=== ALL CORE TESTS PASSED ===")
