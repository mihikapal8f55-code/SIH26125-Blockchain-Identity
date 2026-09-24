from app import app, blockchain
from blockchain import CryptoIdentity
import json
import time
import secrets as sec

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

print("=== PASSWORDLESS CRYPTO AUTH TESTS ===\n")

# 1. Register a crypto identity
print("--- 1. REGISTER CRYPTO IDENTITY ---")
reg = client.post('/api/crypto/register', json={
    'name': 'Crypto Admin',
    'role': 'Administrator',
    'email': 'crypto.admin@bel.gov.in',
    'department': 'Security',
    'access_level': 'HIGH',
    'allowed_resources': ['admin_dashboard', 'sensitive_data', 'network_access']
})
res = json.loads(reg.data)
print("Register success:", res.get('success'))
check("Crypto identity registers successfully", res.get('success') is True, res)
check("Public fingerprint generated", bool(res.get('identity', {}).get('fingerprint')))
private_key = res.get('private_key')
check("Private key issued", bool(private_key))
print()

# 2. Sign an access request with the private key
print("--- 2. SIGN ACCESS REQUEST ---")
timestamp = int(time.time())
nonce = sec.token_hex(8)
resource = 'admin_dashboard'
sign = client.post('/api/crypto/sign', json={
    'private_key': private_key,
    'resource': resource,
    'timestamp': str(timestamp),
    'nonce': nonce
})
sig = json.loads(sign.data)
print("Sign success:", sig.get('success'))
check("Signature generation succeeds", sig.get('success') is True, sig)
signature = sig.get('signature')
check("Signature is non-empty", bool(signature))
print()

# 3. Authenticate (verify signature server-side)
print("--- 3. PASSWORDLESS AUTHENTICATION ---")
auth = client.post('/api/crypto/auth', json={
    'public_id': 'crypto.admin@bel.gov.in',
    'resource': resource,
    'timestamp': str(timestamp),
    'nonce': nonce,
    'signature': signature
})
auth_res = json.loads(auth.data)
print("Auth success:", auth_res.get('success'))
check("Passwordless auth endpoint succeeds", auth_res.get('success') is True, auth_res)
check("Authenticated with valid signature", auth_res.get('data', {}).get('authenticated') is True, auth_res)
check("Identified user name", auth_res.get('data', {}).get('identity_name') == 'Crypto Admin', auth_res)
print("  Reason:", auth_res.get('data', {}).get('reason'))
print()

# 4. Negative test - wrong signature should fail
print("--- 4. WRONG SIGNATURE (should fail) ---")
wrong_private, _ = CryptoIdentity.generate_keypair()
wrong_sign = client.post('/api/crypto/sign', json={
    'private_key': wrong_private,
    'resource': resource,
    'timestamp': str(timestamp),
    'nonce': nonce
})
wrong_sig = json.loads(wrong_sign.data)
auth2 = client.post('/api/crypto/auth', json={
    'public_id': 'crypto.admin@bel.gov.in',
    'resource': resource,
    'timestamp': str(timestamp),
    'nonce': nonce,
    'signature': wrong_sig.get('signature')
})
auth2_res = json.loads(auth2.data)
print("Authenticated (should be False):", auth2_res.get('data', {}).get('authenticated'))
check("Wrong signature is REJECTED", auth2_res.get('data', {}).get('authenticated') is False, auth2_res)
check("Rejection reason reported", 'reason' in auth2_res.get('data', {}), auth2_res)
print("  Reason:", auth2_res.get('data', {}).get('reason'))
print()

# 5. Full demo (auto-registers + signs + verifies in one shot)
print("--- 5. FULL PASSWORDLESS DEMO ---")
demo = client.post('/api/crypto/demo', json={
    'public_id': 'demo.user@bel.gov.in',
    'resource': 'sensitive_data'
})
demo_res = json.loads(demo.data)
print("Demo success:", demo_res.get('success'))
check("Passwordless demo succeeds", demo_res.get('success') is True, demo_res)
check("Demo authenticates", demo_res.get('authentication', {}).get('authenticated') is True, demo_res)
print()

print(f"\n=== RESULTS: {PASSES} passed, {FAILS} failed ===")
if FAILS:
    raise SystemExit("Some PASSWORDLESS tests FAILED")
print("=== ALL PASSWORDLESS TESTS PASSED ===")
