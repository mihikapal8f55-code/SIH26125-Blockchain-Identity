# -*- coding: utf-8 -*-
"""
SIH26125 - Unified Test Suite Runner
Runs all test modules across the repository and verifies status codes.
"""
import os
import subprocess
import sys

TEST_FILES = [
    'test_app.py',
    'test_new_features.py',
    'test_crypto.py',
    'test_biometric_smartcontract.py',
    'test_advanced_features.py',
    'test_network_ipfs.py',
    'test_frontend.py',
    os.path.join('tests', 'selftest', 'test_rbac_ownership15.py'),
    'smoke_all5.py',
]

def main():
    root = os.path.dirname(os.path.abspath(__file__))
    passed = 0
    failed = 0
    results = []

    print('=' * 65)
    print('  RUNNING COMPLETE SIH26125 TEST SUITE')
    print('=' * 65)

    for tf in TEST_FILES:
        target_path = os.path.join(root, tf)
        if not os.path.exists(target_path):
            print(f'[-] {tf}: FILE NOT FOUND')
            failed += 1
            results.append((tf, 'NOT FOUND', 1))
            continue

        res = subprocess.run([sys.executable, target_path], cwd=root, capture_output=True, text=True)
        if res.returncode == 0:
            passed += 1
            print(f'  [PASS] {tf}')
            results.append((tf, 'PASS', 0))
        else:
            failed += 1
            print(f'  [FAIL] {tf} (exit code {res.returncode})')
            if res.stderr:
                print('    STDERR:', res.stderr[-500:].strip())
            results.append((tf, 'FAIL', res.returncode))

    print('=' * 65)
    print(f'TOTAL: {passed + failed} suites | PASSED: {passed} | FAILED: {failed}')
    print('=' * 65)

    return 1 if failed > 0 else 0

if __name__ == '__main__':
    sys.exit(main())
