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

print("=== BIOMETRIC & SMART CONTRACT TESTS ===\n")

# ---- BIOMETRIC ----
print("--- 1. BIOMETRIC ENROLL ---")
r = client.post('/api/biometric/enroll', json={
    'public_id': 'aarav.sharma@bel.gov.in',
    'biometric_type': 'face'
})
enroll = json.loads(r.data)
check("Biometric enrollment succeeds", enroll.get('success') is True, enroll)
check("Template committed as a HASH (not plaintext)", bool(enroll.get('template_hash')) and '000111' not in str(enroll.get('template_hash', '')), enroll)
print("  template_hash:", str(enroll.get('template_hash', ''))[:16] + "...")
print()

print("--- 2. BIOMETRIC VERIFY (match) ---")
r = client.post('/api/biometric/verify', json={
    'public_id': 'aarav.sharma@bel.gov.in',
    'biometric_type': 'face',
    'noise': 0.10
})
res = json.loads(r.data)
print(f"Matched: {res.get('matched')}, Similarity: {res.get('similarity')}")
check("Low-noise capture matches", res.get('matched') is True, res)
print()

print("--- 3. BIOMETRIC VERIFY (too much noise = reject) ---")
r = client.post('/api/biometric/verify', json={
    'public_id': 'aarav.sharma@bel.gov.in',
    'biometric_type': 'face',
    'noise': 0.30  # > threshold, should reject
})
res = json.loads(r.data)
print(f"Matched (should be False): {res.get('matched')}, Similarity: {res.get('similarity')}")
check("High-noise capture is rejected", res.get('matched') is False, res)
check("Similarity below threshold", res.get('similarity') < 0.78, res)
print()

print("--- 4. BIOMETRIC FULL DEMO ---")
r = client.post('/api/biometric/demo', json={
    'public_id': 'priya.patel@bel.gov.in',
    'biometric_type': 'fingerprint',
    'resource': 'reporting'
})
res = json.loads(r.data)
print("Final access:", res.get('final_access'))
check("Biometric demo completes", res.get('success') is True, res)
check("Authorized resource granted after biometric match", res.get('final_access') is True, res)
print()

# ---- SMART CONTRACT ----
print("--- 5. SMART CONTRACT TIME WINDOW DEMO ---")
r = client.post('/api/smartcontract/window-demo', json={
    'public_id': 'rajesh.kumar@bel.gov.in',
    'resource': 'field_reports'
})
res = json.loads(r.data)
scenarios = res.get('scenarios', {})
print("  early_monday_8am:", scenarios.get('early_monday_8am', {}).get('granted'))
print("  weekend_saturday:", scenarios.get('weekend_saturday', {}).get('granted'))
check("Denied before 09:00 on Monday", scenarios.get('early_monday_8am', {}).get('granted') is False, scenarios)
check("Denied on the weekend", scenarios.get('weekend_saturday', {}).get('granted') is False, scenarios)
print()

print("--- 6. SMART CONTRACT GEO-FENCE DEMO ---")
r = client.post('/api/smartcontract/geo-demo', json={
    'public_id': 'rajesh.kumar@bel.gov.in',
    'resource': 'field_reports'
})
res = json.loads(r.data)
scenarios = res.get('scenarios', {})
print("  inside_delhi:", scenarios.get('inside_delhi', {}).get('granted'))
print("  outside_mumbai:", scenarios.get('outside_mumbai', {}).get('granted'))
check("Granted inside the geofence", scenarios.get('inside_delhi', {}).get('granted') is True, scenarios)
check("Denied outside the geofence", scenarios.get('outside_mumbai', {}).get('granted') is False, scenarios)
print()

print("--- 7. SMART CONTRACT EVALUATE (direct) ---")
r = client.post('/api/smartcontract/evaluate', json={
    'public_id': 'aarav.sharma@bel.gov.in',
    'resource': 'sensitive_data',
    'context': {'position': {'lat': 28.6129, 'lon': 77.2295},
                'now': '2026-09-17T10:00:00'}
})
res = json.loads(r.data)
print("Granted:", res.get('data', {}).get('granted'))
check("Aarav granted access to sensitive_data", res.get('data', {}).get('granted') is True, res)
check("Final decision reflects access", res.get('data', {}).get('final_decision') == 'ACCESS GRANTED', res)
print()

print(f"\n=== RESULTS: {PASSES} passed, {FAILS} failed ===")
if FAILS:
    raise SystemExit("Some BIOMETRIC/SMARTCONTRACT tests FAILED")
print("=== ALL BIOMETRIC & SMART CONTRACT TESTS PASSED ===")
