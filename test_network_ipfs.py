from app import app, network_nodes
from blockchain import Node, Blockchain, IPFSDocumentStore
import json

client = app.test_client()
print("=== MULTI-NODE NETWORK & IPFS TESTS ===")
print()

# ============================================
print("--- 1. NETWORK STATUS ---")
r = json.loads(client.get('/api/network/status').data)
nodes = r['nodes']
print(f"Nodes online: {len(nodes)}")
for n in nodes:
    print(f"  {n['node_id']}: {n['blocks']} blocks, chain_valid={n['chain_valid']}")
assert len(nodes) == 3
assert all(n['chain_valid'] for n in nodes)
print("PASS: all 3 nodes have valid seeded chains")
print()

# ============================================
print("--- 2. CHAIN SYNC (node_1 -> node_2) ---")
# node_1 gains a new block, making its chain longer
n1 = network_nodes['node_1']
import time as _t
n1.blockchain.add_audit_block({'type': 'AUDIT_LOG', 'action': 'SYNC_TEST', 'timestamp': _t.time()})
n1_length = len(n1.blockchain.chain)
chain = json.loads(client.get('/api/network/node/node_1/chain').data)['chain']
r = json.loads(client.post('/api/network/sync', json={
    'sender': 'node_1', 'receiver': 'node_2', 'chain': chain
}).data)
print(f"node_1 length: {n1_length}, sync accepted: {r['result']['accepted']}")
print(f"  reason: {r['result']['reason']}")
assert r['result']['accepted'] is True
assert len(network_nodes['node_2'].blockchain.chain) == n1_length
print("PASS: node_2 adopted the longer valid chain (longest-chain-wins)")
print()

# ============================================
print("--- 3. MALICIOUS FORK REJECTION ---")
r = json.loads(client.post('/api/network/malicious-fork', json={
    'attacker': 'node_3',
    'block_index': 1,
    'fake_data': {'type': 'GENESIS', 'message': 'MALICIOUS FORK - fake block'}
}).data)
print(f"attacker chain valid: {r['attacker_chain_valid']}")
print(f"fork rejected: {r['consensus_result']['fork_rejected']}")
print(f"rejected by: {r['consensus_result']['rejected_by']}")
assert r['attacker_chain_valid'] is False
assert r['consensus_result']['fork_rejected'] is True
assert set(r['consensus_result']['rejected_by']) == {'node_1', 'node_2'}
print("PASS: honest nodes rejected the malicious fork")
print()

# ============================================
print("--- 4. DIRECT NODE CONSENSUS CLASS ---")
a = Node('a'); b = Node('b'); c = Node('c')
# Give each node at least 2 blocks so tampering index 1 is valid
for nd in (a, b, c):
    nd.blockchain.add_audit_block({'type': 'AUDIT_LOG', 'action': 'SEED'})
# b tampers its chain -> invalid candidate
assert b.blockchain.tamper_with_block(1, {'type': 'GENESIS', 'message': 'FAKE'})
candidates = {'a': a.get_chain(), 'b': b.get_chain(), 'c': c.get_chain()}
res = a.consensus_check(candidates)
print(f"winner: {res['consensus_winner']}, length: {res['consensus_length']}")
# b's chain is tainted (tampered) so it must NOT be the consensus winner
print(f"results: {[(r['node_id'], r['valid']) for r in res['results']]}")
assert res['consensus_winner'] == 'a'
assert [r for r in res['results'] if r['node_id'] == 'b'][0]['valid'] is False
print("PASS: consensus picks longest VALID chain, tampered node b is not elected")
print()

# ============================================
print("--- 5. IPFS ADD DOCUMENT ---")
r = json.loads(client.post('/api/ipfs/add', json={
    'content': 'This is a secure classified BEL document version 1.',
    'name': 'classified-report',
    'owner': 'aarav.sharma@bel.gov.in',
    'id_number': 'EMP-1001'
}).data)
cid = r['cid']
print(f"CID: {cid[:12]}...")
print(f"on-chain anchor present: {bool(r.get('on_chain_anchor'))}")
print(f"size: {r['size']} bytes")
assert r['success'] is True
assert cid.startswith('Qm')  # base58-encoded sha2-256 CID
print("PASS: document added to IPFS, CID returned")
print()

# ============================================
print("--- 6. IPFS VERIFY (authentic) ---")
r = json.loads(client.get('/api/ipfs/get/' + cid).data)
print(f"verified: {r['verified']}")
print(f"message: {r['message']}")
assert r['verified'] is True
print("PASS: authentic document verified against CID")
print()

# ============================================
print("--- 7. IPFS TAMPER DETECTION ---")
client.post('/api/ipfs/tamper', json={'cid': cid, 'new_content': 'I have been modified illegally!'})
r = json.loads(client.get('/api/ipfs/get/' + cid).data)
print(f"verified after tamper: {r['verified']}")
print(f"message: {r['message']}")
assert r['verified'] is False
print("PASS: tampering detected via CID re-hash")
print()

# ============================================
print("--- 8. IPFS CID COMPUTATION MATCHES ---")
store = IPFSDocumentStore()  # note: verify_document is an instance method
content = "verifiable test document"
computed = IPFSDocumentStore.compute_cid(content.encode())
assert store.verify_document(content.encode(), computed) is True
assert store.verify_document((content + "x").encode(), computed) is False
print("PASS: CID computation & verification correct")
print()

print()
print("=== ALL MULTI-NODE & IPFS TESTS PASSED ===")
