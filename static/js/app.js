// Load blockchain info and visualization
        async function loadBlockchainData() {
            const info = await fetchAPI('/api/blockchain/info');
            if (info.success) {
                document.getElementById('totalBlocks').textContent = info.data.total_blocks;
                document.getElementById('totalIdentities').textContent = info.data.total_identities;
                document.getElementById('genesisTime').textContent = info.data.genesis_created;
                
                const statusEl = document.getElementById('chainStatus');
                if (info.data.chain_valid) {
                    statusEl.textContent = 'VALID ✓';
                    statusEl.style.color = 'var(--success)';
                } else {
                    statusEl.textContent = 'TAMPERED ✗';
                    statusEl.style.color = 'var(--danger)';
                }
            }

            // Load chain visualization
            const chain = await fetchAPI('/api/blockchain/chain');
            if (chain.success) {
                const container = document.getElementById('chainVisualization');
                container.innerHTML = '';
                
                chain.data.forEach(block => {
                    const blockDiv = document.createElement('div');
                    const identity0 = block.data ? block.data.identity_data : null;
                    const tamperedBlock = !!identity0 && (identity0.hacked || identity0.tamper_flags);
                    blockDiv.className = `chain-block ${block.index === 0 ? 'genesis' : ''} ${tamperedBlock ? 'tampered' : ''}`;
                    
                    let blockContent = '';
                    if (block.index === 0) {
                        blockContent = `<div class="block-index">GENESIS</div>
                            <div class="block-hash" title="${block.merkle_root || ''}">M:${(block.merkle_root || '').slice(0, 8)}...</div>`;
                    } else {
                        const identity = block.data.identity_data;
                        const identityName = identity ? identity.name : null;
                        const dataType = block.data.type || '';
                        const name = identityName || (dataType ? dataType.replace(/_/g, ' ') : 'Data Block');
                        const isTampered = identity && identity.hacked;
                        blockContent = `
                            <div class="block-index">Block #${block.index}</div>
                            <div class="block-hash" title="Hash: ${block.hash}\nMerkle: ${block.merkle_root || ''}\nDifficulty: ${block.difficulty}">${block.hash.slice(0, 16)}...</div>
                            <div style="margin-top:0.3rem; font-size:0.75rem;">
                                ${isTampered ? '⚠️ TAMPERED' : (name || 'Data')}
                            </div>
                            ${isTampered ? `<div style="color:var(--danger); font-size:0.7rem;">!!! ALERT !!!</div>` : ''}
                        `;
                    }
                    
                    blockDiv.innerHTML = blockContent;
                    
                    // Click to show full details
                    blockDiv.onclick = () => showAlert(
                        `<b>Block #${block.index}</b><br>
                         <b>Hash:</b> <code>${block.hash}</code><br>
                         <b>Prev Hash:</b> <code>${block.previous_hash}</code><br>
                         <b>Merkle Root:</b> <code>${block.merkle_root || 'n/a'}</code><br>
                         <b>Difficulty:</b> ${block.difficulty}<br>
                         <b>Timestamp:</b> ${block.timestamp}<br>
                         <b>Nonce:</b> ${block.nonce}`, 
                        'info', 6000
                    );
                    
                    container.appendChild(blockDiv);
                });
            }

            // Load metrics
            loadMetrics();
            loadIdentities();
        }

        async function loadMetrics() {
            const response = await fetchAPI('/api/metrics');
            const container = document.getElementById('metricsContainer');
            if (!response.success) { container.innerHTML = `<div class="alert alert-error show">${response.error}</div>`; return; }
            const c = response.chain;
            const n = response.network;
            container.innerHTML = `
                <div class="stats-grid">
                    <div class="stat-card"><div class="stat-value">${c.total_blocks}</div><div class="stat-label">BLOCKS</div></div>
                    <div class="stat-card"><div class="stat-value">${c.identity_blocks}</div><div class="stat-label">IDENTITY TX</div></div>
                    <div class="stat-card"><div class="stat-value">${c.audit_blocks}</div><div class="stat-label">AUDIT TX</div></div>
                    <div class="stat-card"><div class="stat-value">${c.chain_integrity_score}%</div><div class="stat-label">INTEGRITY</div></div>
                    <div class="stat-card"><div class="stat-value">${c.average_difficulty}</div><div class="stat-label">AVG DIFFICULTY</div></div>
                    <div class="stat-card"><div class="stat-value">${c.total_nonce_work}</div><div class="stat-label">NONCE WORK</div></div>
                    <div class="stat-card"><div class="stat-value">${n.node_count}</div><div class="stat-label">NODES</div></div>
                    <div class="stat-card"><div class="stat-value">${n.fault_tolerance_n}</div><div class="stat-label">BYZANTINE FAULT TOLERANCE</div></div>
                </div>
                <div style="font-size:0.72rem;margin-top:0.3rem;">${n.fault_tolerance_label} | Merkle roots verified: ${c.merkle_roots_verified === true ? 'YES' : 'NO'} | Last block: <code>${c.last_block_hash}</code></div>`;
            renderSparkline(container);
        }

        // Sparkline: per-block Proof-of-Work difficulty, red bars = tampered blocks
        async function renderSparkline(container) {
            if (!container) return;
            const ch = await fetchAPI('/api/blockchain/chain');
            if (!ch.success || !Array.isArray(ch.data) || ch.data.length === 0) return;
            const max = Math.max(...ch.data.map(b => (b.difficulty || 1)), 1);
            const bars = ch.data.map(b => {
                const d = b.data ? (b.data.identity_data || {}) : {};
                const bad = !!(d.hacked || d.tamper_flags);
                const h = 6 + Math.round(((b.difficulty || 1) / max) * 34);
                return `<div class="spark-bar ${bad ? 'spark-bad' : ''}" style="height:${h}px" title="Block #${b.index} · difficulty ${b.difficulty}${bad ? ' · TAMPERED' : ''}"></div>`;
            }).join('');
            container.insertAdjacentHTML('beforeend', `
                <div class="spark-wrap">
                    <div class="spark-title"><i class="fas fa-wave-square"></i> Proof-of-Work difficulty per block</div>
                    <div class="spark">${bars}</div>
                </div>`);
        }

        async function loadIdentities() {
            const result = await fetchAPI('/api/identities');
            if (result.success) {
                const tbody = document.getElementById('identityTable');
                tbody.innerHTML = '';
                
                if (result.count === 0) {
                    tbody.innerHTML = '<tr><td colspan="5" style="text-align:center;">No identities registered yet</td></tr>';
                    return;
                }
                
                result.data.forEach(identity => {
                    const accessBadge = identity.access_level === 'HIGH' 
                        ? '<span class="badge badge-high">HIGH</span>' 
                        : identity.access_level === 'MEDIUM' 
                            ? '<span class="badge badge-medium">MEDIUM</span>' 
                            : '<span class="badge badge-low">LOW</span>';
                    
                    const row = document.createElement('tr');
                    row.innerHTML = `
                        <td>#${identity.block_index}</td>
                        <td>${escapeHtml(identity.name)}<br><small style="color:var(--text-light)">${escapeHtml(identity.department)}</small></td>
                        <td>${escapeHtml(identity.role)}</td>
                        <td>${accessBadge}</td>
                        <td>
                            <div class="identity-hash-display" title="Click to copy" 
                                 onclick="copyToClipboard('${identity.identity_hash}')">
                                ${identity.identity_hash.slice(0, 20)}...
                            </div>
                        </td>
                    `;
                    tbody.appendChild(row);
                });
            }
        }

        // Register new identity
        async function registerIdentity() {
            const name = document.getElementById('name').value;
            const role = document.getElementById('role').value;
            const email = document.getElementById('email').value;
            const department = document.getElementById('department').value;
            const accessLevel = document.getElementById('accessLevel').value;
            const idNumber = document.getElementById('idNumber').value;
            const resourcesStr = document.getElementById('allowedResources').value;
            const metadata = document.getElementById('metadata').value;

            if (!name || !role || !email) {
                showAlert('Please fill in Name, Role, and Email at minimum', 'error');
                return;
            }

            const resources = resourcesStr.split(',').map(r => r.trim()).filter(r => r);

            const response = await fetchAPI('/api/identities/add', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    name, role, email, department,
                    access_level: accessLevel,
                    id_number: idNumber,
                    allowed_resources: resources,
                    metadata
                })
            });

            if (response.success) {
                // Auto-fill the Verify-Identity field so the user does NOT have
                // to manually copy/paste the hash (which is error-prone).
                const verifyInput = document.getElementById('verifyHash');
                if (verifyInput) {
                    verifyInput.value = response.identity_hash || '';
                }

                showAlert(`
                    <b>✓ Identity Registered Successfully!</b><br>
                    <b>Identity Hash:</b> 
                    <span class="identity-hash-display" onclick="copyToClipboard('${response.identity_hash}')">
                        ${response.identity_hash}
                    </span><br>
                    <b>Block:</b> #${response.block_index} | <b>Nonce:</b> ${response.nonce}<br>
                    <b>Mining Time:</b> ${response.mining_time}s
                    <div style="margin-top:0.6rem;">
                        <button class="btn btn-small btn-primary" onclick="verifyIdentity()">
                            <i class="fas fa-check-circle"></i> Verify Now
                        </button>
                    </div>
                `, 'success', 10000);
                
                // Clear form
                document.getElementById('name').value = '';
                document.getElementById('role').value = '';
                document.getElementById('email').value = '';
                document.getElementById('department').value = '';
                document.getElementById('idNumber').value = '';
                document.getElementById('allowedResources').value = '';
                document.getElementById('metadata').value = '';
                document.getElementById('accessLevel').value = 'LOW';
                
                // Refresh data
                loadBlockchainData();
                loadIdentities();
            } else {
                showAlert(`Error: ${response.error}`, 'error');
            }
        }

        // Verify identity
        async function verifyIdentity() {
            const hash = document.getElementById('verifyHash').value;
            if (!hash) {
                showAlert('Please enter an identity hash to verify', 'error');
                return;
            }

            const response = await fetchAPI('/api/identities/verify', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ identity_hash: hash })
            });

            const resultEl = document.getElementById('verifyResult');
            if (response.success && response.data.found) {
                resultEl.className = 'alert alert-success show';
                resultEl.innerHTML = `
                    <b>✓ Identity Verified!</b><br>
                    <b>Name:</b> ${escapeHtml(response.data.data.name)}<br>
                    <b>Role:</b> ${escapeHtml(response.data.data.role)}<br>
                    <b>Found in Block:</b> #${response.data.block_index}<br>
                    <b>Block Hash:</b> <code style="font-size:0.7rem;">${response.data.block_hash.slice(0, 30)}...</code>
                `;
            } else {
                resultEl.className = 'alert alert-error show';
                resultEl.innerHTML = `✗ Identity not found in the blockchain.`;
            }
        }

        // Check access
        async function checkAccess() {
            const hash = document.getElementById('accessHash').value;
            const resource = document.getElementById('resourceSelect').value;

            if (!hash) {
                showAlert('Please enter an identity hash', 'error');
                return;
            }

            const response = await fetchAPI('/api/access/check', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ identity_hash: hash, resource })
            });

            const resultEl = document.getElementById('accessResult');
            if (response.success && response.data.granted) {
                resultEl.className = 'alert alert-success show';
                resultEl.innerHTML = `
                    <b>✅ ACCESS GRANTED</b><br>
                    ${response.data.reason}<br>
                    <small><i class="fas fa-check-circle"></i> Verified in Block #${response.data.verified_in_block}</small>
                `;
            } else {
                resultEl.className = 'alert alert-error show';
                resultEl.innerHTML = `
                    <b>❌ ACCESS DENIED</b><br>
                    ${response.data ? response.data.reason : 'Unknown error'}
                `;
            }
        }

        // Reset blockchain
        async function resetBlockchain() {
            if (confirm('Are you sure you want to reset the entire blockchain? All custom identities will be removed.')) {
                const response = await fetchAPI('/api/blockchain/reset', {
                    method: 'POST'
                });
                if (response.success) {
                    showAlert('Blockchain has been reset. Demo identities restored.', 'success');
                    loadBlockchainData();
                }
            }
        }

        // ============================================
        // TAB SWITCHING
        // ============================================
        function switchTab(tabName, btn) {
            // Scope to this tab group only: `data-tab` buttons and `#panel-*`
            // panels belong to the verification feature here. The other groups
            // (data-tab2..data-tab6 / panel2-*..panel6-*) use their own switchers.
            document.querySelectorAll('[data-tab]').forEach(t => t.classList.remove('active'));
            btn.classList.add('active');

            document.querySelectorAll('.feature-panel[id^="panel-"]').forEach(p => p.classList.remove('active'));
            document.getElementById(`panel-${tabName}`).classList.add('active');
        }

        // ============================================
        // PASSWORDLESS CRYPTOGRAPHIC AUTH
        // ============================================
        async function runPasswordlessDemo() {
            const btn = document.getElementById('cryptoButton');
            btn.disabled = true;
            btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Running passwordless auth...';

            const response = await fetchAPI('/api/crypto/demo', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    public_id: 'demo.crypto@bel.gov.in',
                    resource: 'admin_dashboard'
                })
            });

            btn.disabled = false;
            btn.innerHTML = '<i class="fas fa-bolt"></i> Run Passwordless Auth Demo';

            const container = document.getElementById('cryptoResult');
            if (!response.success) {
                const reason = (response.reason
                    || response.error
                    || (response.authentication && response.authentication.reason)
                    || 'Unknown error');
                container.innerHTML = `
                    <div class="alert alert-error show">
                        <b>❌ Passwordless auth failed</b><br>
                        ${reason}
                    </div>
                `;
                return;
            }

            const auth = response.authentication || {};
            const authed = auth.authenticated;
            container.innerHTML = `
                <div class="alert ${authed ? 'alert-success' : 'alert-error'} show">
                    <b>${authed ? '🔐 PASSWORDLESS AUTHENTICATED' : '❌ Authentication Failed'}</b>
                    <div style="margin-top:0.3rem; font-size:0.85rem;">${auth.reason || ''}</div>
                </div>
                <div class="zk-steps">
                    <div class="step">
                        <div class="step-num">1</div>
                        <div>
                            <b>Identity Registered (crypto)</b>
                            <div style="font-size:0.8rem; margin-top:0.2rem;">
                                <span class="pill pill-purple">${response.demo_data.identity_email}</span>
                                <span class="pill pill-blue">FP: ${response.public_fingerprint.slice(0,12)}...</span>
                            </div>
                        </div>
                    </div>
                    <div class="step">
                        <div class="step-num">2</div>
                        <div>
                            <b>Signed Access Request</b>
                            <div class="code-display copyable" onclick="copyToClipboard(this.textContent)">${response.demo_data.signed_message}</div>
                            <div class="code-display" style="font-size:0.6rem;">Signature: ${JSON.stringify(auth)}</div>
                        </div>
                    </div>
                    <div class="step">
                        <div class="step-num">3</div>
                        <div>
                            <b>Private Key (shown once - SECRET)</b>
                            <details>
                                <summary style="cursor:pointer; font-size:0.8rem; color:var(--text-light);">View private key</summary>
                                <div class="code-display" style="max-height:80px;">${response.private_key || 'N/A'}</div>
                            </details>
                        </div>
                    </div>
                </div>
                <div style="margin-top:0.5rem;">
                    <span class="pill pill-green"><i class="fas fa-lock-open"></i> ${response.note}</span>
                </div>
            `;
        }

        // ============================================
        // ZERO-KNOWLEDGE PROOF
        // ============================================
        async function runZkpDemo() {
            const identityHash = document.getElementById('zkpHash').value.trim();
            const resource = document.getElementById('zkpResource').value;

            if (!identityHash) {
                showAlert('Please enter your identity hash to prove access', 'error');
                return;
            }

            const btn = document.getElementById('zkpButton');
            btn.disabled = true;
            btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Generating ZK proof...';

            const response = await fetchAPI('/api/zkp/demo', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ identity_hash: identityHash, resource })
            });

            btn.disabled = false;
            btn.innerHTML = '<i class="fas fa-user-secret"></i> Run ZK Proof Demo';

            const container = document.getElementById('zkpResult');
            if (!response.success) {
                container.innerHTML = `
                    <div class="alert alert-error show">
                        <b>❌ Could not generate proof</b><br>
                        ${response.reason || response.error}
                    </div>
                `;
                return;
            }

            const granted = response.step3_verification.granted;
            container.innerHTML = `
                <div class="alert ${granted ? 'alert-success' : 'alert-error'} show">
                    <b>${granted ? '✅ ACCESS PROVEN (Zero-Knowledge)' : '❌ Access Denied'}</b>
                    <div style="margin-top:0.5rem; font-size:0.85rem;">${response.step3_verification.reason}</div>
                </div>
                <div class="zk-steps">
                    <div class="step">
                        <div class="step-num">1</div>
                        <div>
                            <b>Commitment (public, hides secret)</b>
                            <div class="code-display copyable" onclick="copyToClipboard(this.textContent)">${response.step1_commitment}</div>
                        </div>
                    </div>
                    <div class="step">
                        <div class="step-num">2</div>
                        <div>
                            <b>Proof (verifies without revealing)</b>
                            <div class="code-display copyable" onclick="copyToClipboard(this.textContent)">${response.step2_proof}</div>
                        </div>
                    </div>
                    <div class="step">
                        <div class="step-num">3</div>
                        <div>
                            <b>Verification</b>
                            <div class="code-display">${JSON.stringify(response.step3_verification, null, 2)}</div>
                        </div>
                    </div>
                </div>
                <div style="margin-top:0.5rem;">
                    <span class="pill pill-purple"><i class="fas fa-eye-slash"></i> ${response.privacy_note}</span>
                </div>
            `;
        }

        // ============================================
        // QR CODE GENERATION & VERIFICATION
        // ============================================
        let currentQRPayloadB64 = null;

        async function generateQR() {
            const publicId = document.getElementById('qrPublicId').value.trim();
            const resource = document.getElementById('qrResource').value;

            if (!publicId) {
                showAlert('Please enter a public identifier (email or ID number)', 'error');
                return;
            }

            const response = await fetchAPI('/api/qr/generate', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ public_id: publicId, resource })
            });

            const payloadDisplay = document.getElementById('qrPayloadDisplay');
            const resultEl = document.getElementById('qrResult');

            if (!response.success) {
                resultEl.innerHTML = `
                    <div class="alert alert-error show">
                        <b>❌ ${response.reason || response.error}</b>
                    </div>
                `;
                payloadDisplay.innerHTML = '';
                return;
            }

            // Store the payload for later verification
            currentQRPayloadB64 = response.payload_b64;

            // Generate the QR code image using an external API
            const qrDataUrl = await generateQRImage(response.payload_b64);
            document.getElementById('qrPreview').innerHTML = `
                <img src="${qrDataUrl}" alt="QR Code" title="Blockchain Access QR">
                <div style="font-size:0.75rem; color:var(--text-light);">
                    <i class="fas fa-clock"></i> Expires in 5 min (anti-replay)
                </div>
            `;

            resultEl.innerHTML = `
                <div class="alert alert-success show">
                    <b>✅ QR Generated for ${publicId}</b><br>
                    <small>Resource: <span class="pill pill-blue">${response.resource}</span></small>
                    <div style="margin-top:0.5rem;">
                        <button class="btn btn-small btn-primary" onclick="copyToClipboard('${response.payload_b64}')">
                            <i class="fas fa-copy"></i> Copy Payload
                        </button>
                    </div>
                </div>
            `;

            payloadDisplay.innerHTML = `
                <details>
                    <summary style="cursor:pointer; font-size:0.8rem; color:var(--text-light);">View raw QR payload</summary>
                    <div class="code-display">${JSON.stringify(response.qr_payload, null, 2)}</div>
                </details>
            `;
        }

        async function generateQRImage(data) {
            // Use a public QR code generation API (no API key needed)
            return `https://api.qrserver.com/v1/create-qr-code/?size=180x180&data=${encodeURIComponent('SIH26125:' + data)}`;
        }

        async function verifyQR() {
            if (!currentQRPayloadB64) {
                showAlert('Please generate a QR code first, then verify it', 'error');
                return;
            }

            const resource = document.getElementById('qrResource').value;
            const resultEl = document.getElementById('qrResult');

            resultEl.innerHTML = `
                <div class="alert alert-info show">
                    <i class="fas fa-spinner fa-spin"></i> Scanning QR code against blockchain...
                </div>
            `;

            const response = await fetchAPI('/api/qr/verify', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ payload_b64: currentQRPayloadB64, resource })
            });

            if (response.success && response.data.valid) {
                const granted = response.data.granted;
                resultEl.innerHTML = `
                    <div class="alert ${granted ? 'alert-success' : 'alert-error'} show">
                        <b>${granted ? '✅ QR VERIFIED - ACCESS GRANTED' : '❌ QR Valid but Access Denied'}</b><br>
                        <span style="font-size:0.85rem;">${response.data.reason}</span><br>
                        <div style="margin-top:0.4rem; font-size:0.8rem;">
                            <span class="pill pill-blue">Block #${response.data.block_index}</span>
                            <span class="pill pill-green">Age: ${response.data.age_seconds}s</span>
                            <span class="pill pill-purple">Identity: ${response.data.identity_name}</span>
                        </div>
                    </div>
                `;
            } else {
                resultEl.innerHTML = `
                    <div class="alert alert-error show">
                        <b>❌ QR Verification Failed</b><br>
                        <span style="font-size:0.85rem;">${response.data ? response.data.reason : response.error || 'Invalid QR'}</span>
                    </div>
                `;
            }
        }

        // ============================================
        // SMART CONTRACT SUB-TAB SWITCHING
        // ============================================
        function switchTab2(tabName, btn) {
            document.querySelectorAll('[data-tab2]').forEach(t => t.classList.remove('active'));
            btn.classList.add('active');

            document.querySelectorAll('.feature-panel[id^="panel2-"]').forEach(p => p.classList.remove('active'));
            document.getElementById(`panel2-${tabName}`).classList.add('active');
        }

        // ============================================
        // BIOMETRIC VERIFICATION
        // ============================================
        async function runBiometricDemo() {
            const publicId = document.getElementById('bioPublicId').value.trim() || 'aarav.sharma@bel.gov.in';
            const bioType = document.getElementById('bioType').value;

            const btn = document.getElementById('bioButton');
            btn.disabled = true;
            btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Enrolling & capturing biometric...';

            const response = await fetchAPI('/api/biometric/demo', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ public_id: publicId, biometric_type: bioType, resource: 'admin_dashboard' })
            });

            btn.disabled = false;
            btn.innerHTML = '<i class="fas fa-user-check"></i> Run Biometric Verification Demo';

            const container = document.getElementById('bioResult');
            if (!response.success) {
                container.innerHTML = `
                    <div class="alert alert-error show">
                        <b>❌ Biometric demo failed</b><br>
                        ${response.reason || response.error}
                    </div>
                `;
                return;
            }

            const enroll = response.steps.enroll;
            const capture = response.steps.capture;
            const matched = capture.matched;

            container.innerHTML = `
                <div class="alert ${matched ? 'alert-success' : 'alert-error'} show">
                    <b>${matched ? '✅ BIOMETRIC MATCHED' : '❌ BIOMETRIC REJECTED'}</b><br>
                    <span style="font-size:0.85rem;">${capture.message}</span>
                </div>
                <div class="zk-steps">
                    <div class="step">
                        <div class="step-num">1</div>
                        <div>
                            <b>Enrollment (${response.biometric_type})</b><br>
                            <span style="font-size:0.75rem;">Template hash (on-chain):</span>
                            <div class="code-display copyable" onclick="copyToClipboard(this.textContent)">${enroll.template_hash}</div>
                        </div>
                    </div>
                    <div class="step">
                        <div class="step-num">2</div>
                        <div>
                            <b>Live Capture (${bioType})</b><br>
                            <span style="font-size:0.75rem;">Similarity: <span class="pill ${matched ? 'pill-green' : 'pill-red'}">${(capture.similarity * 100).toFixed(1)}%</span> (threshold ${(capture.threshold * 100).toFixed(0)}%)</span>
                        </div>
                    </div>
                </div>
                <div style="margin-top:0.5rem;">
                    <span class="pill pill-blue"><i class="fas fa-shield-alt"></i> Raw biometric NEVER stored - only the hash is on blockchain</span>
                </div>
            `;
        }

        // ============================================
        // SMART CONTRACT: TIME WINDOW
        // ============================================
        async function runTimeWindowDemo() {
            const btn = document.getElementById('timeButton');
            btn.disabled = true;
            btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Evaluating time rules...';

            const response = await fetchAPI('/api/smartcontract/window-demo', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    public_id: 'rajesh.kumar@bel.gov.in',
                    resource: 'field_reports'
                })
            });

            btn.disabled = false;
            btn.innerHTML = '<i class="fas fa-calendar-check"></i> Test Work-Hours Rule';

            const container = document.getElementById('timeResult');
            if (!response.success) {
                container.innerHTML = `<div class="alert alert-error show">${response.error}</div>`;
                return;
            }

            const scenarios = response.scenarios;
            const now = scenarios.now;
            const weekend = scenarios.weekend_saturday;
            const early = scenarios.early_monday_8am;

            container.innerHTML = `
                <div class="zk-steps">
                    <div class="step">
                        <div class="step-num">1</div>
                        <div>
                            <b>${now.time}</b><br>
                            <span class="pill ${now.granted ? 'pill-green' : 'pill-red'}">${now.granted ? 'GRANTED' : 'DENIED'}</span>
                            <div style="font-size:0.75rem; margin-top:0.3rem;">${statusLine(now.evaluation)}</div>
                        </div>
                    </div>
                    <div class="step">
                        <div class="step-num">2</div>
                        <div>
                            <b>${weekend.time}</b> (weekend)<br>
                            <span class="pill ${weekend.granted ? 'pill-green' : 'pill-red'}">${weekend.granted ? 'GRANTED' : 'DENIED'}</span>
                            <div style="font-size:0.75rem; margin-top:0.3rem;">${statusLine(weekend.evaluation)}</div>
                        </div>
                    </div>
                    <div class="step">
                        <div class="step-num">3</div>
                        <div>
                            <b>${early.time}</b> (before 9am)<br>
                            <span class="pill ${early.granted ? 'pill-green' : 'pill-red'}">${early.granted ? 'GRANTED' : 'DENIED'}</span>
                            <div style="font-size:0.75rem; margin-top:0.3rem;">${statusLine(early.evaluation)}</div>
                        </div>
                    </div>
                </div>
                <div style="margin-top:0.5rem;">
                    <span class="pill pill-purple"><i class="fas fa-file-contract"></i> Use case: field officers only within Mon-Fri 9:00-18:00</span>
                </div>
            `;
        }

        function statusLine(evaluation) {
            const workRule = (evaluation || []).find(e => e.rule.includes('Work Hours'));
            if (workRule) return workRule.detail;
            return '';
        }

        // ============================================
        // SMART CONTRACT: GEO-FENCING
        // ============================================
        async function runGeoDemo() {
            const btn = document.getElementById('geoButton');
            btn.disabled = true;
            btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Evaluating geo-fence...';

            const response = await fetchAPI('/api/smartcontract/geo-demo', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    public_id: 'rajesh.kumar@bel.gov.in',
                    resource: 'field_reports'
                })
            });

            btn.disabled = false;
            btn.innerHTML = '<i class="fas fa-map-marked-alt"></i> Test Geo-fence Rule';

            const container = document.getElementById('geoResult');
            if (!response.success) {
                container.innerHTML = `<div class="alert alert-error show">${response.error}</div>`;
                return;
            }

            const inside = response.scenarios.inside_delhi;
            const outside = response.scenarios.outside_mumbai;

            container.innerHTML = `
                <div style="margin-bottom:0.5rem;">
                    <span class="pill pill-blue"><i class="fas fa-map-marker-alt"></i> ${response.geofence}</span>
                    <span class="pill pill-green">${response.context_time}</span>
                </div>
                <div class="zk-steps">
                    <div class="step">
                        <div class="step-num">1</div>
                        <div>
                            <b>${inside.position}</b><br>
                            <span class="pill ${inside.granted ? 'pill-green' : 'pill-red'}">${inside.granted ? 'GRANTED' : 'DENIED'}</span>
                            <div style="font-size:0.75rem; margin-top:0.3rem;">${geoLine(inside.evaluation)}</div>
                        </div>
                    </div>
                    <div class="step">
                        <div class="step-num">2</div>
                        <div>
                            <b>${outside.position}</b><br>
                            <span class="pill ${outside.granted ? 'pill-green' : 'pill-red'}">${outside.granted ? 'GRANTED' : 'DENIED'}</span>
                            <div style="font-size:0.75rem; margin-top:0.3rem;">${geoLine(outside.evaluation)}</div>
                        </div>
                    </div>
                </div>
                <div style="margin-top:0.5rem;">
                    <span class="pill pill-purple"><i class="fas fa-file-contract"></i> Use case: workers only inside assigned operational zone</span>
                </div>
            `;
        }

        function geoLine(evaluation) {
            const geoRule = (evaluation || []).find(e => e.rule.includes('Geo-fencing'));
            if (geoRule) return geoRule.detail;
            return '';
        }

        // ============================================
        // MULTI-NODE DISTRIBUTED NETWORK
        // ============================================
        function switchTab3(tabName, btn) {
            document.querySelectorAll('[data-tab3]').forEach(t => t.classList.remove('active'));
            btn.classList.add('active');
            document.querySelectorAll('.feature-panel[id^="panel3-"]').forEach(p => p.classList.remove('active'));
            document.getElementById(`panel3-${tabName}`).classList.add('active');
        }

        async function loadNetworkStatus() {
            const btn = document.getElementById('netButton');
            btn.disabled = true;
            btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Checking nodes...';
            const response = await fetchAPI('/api/network/status');
            btn.disabled = false;
            btn.innerHTML = '<i class="fas fa-server"></i> Load Network Status';

            const container = document.getElementById('netStatusResult');
            if (!response.success) {
                container.innerHTML = `<div class="alert alert-error show">${response.error}</div>`;
                return;
            }
            container.innerHTML = response.nodes.map(n => `
                <div class="step">
                    <div class="step-num">${n.blocks}</div>
                    <div>
                        <b>${n.node_id}</b><br>
                        <span class="pill ${n.chain_valid ? 'pill-green' : 'pill-red'}">${n.chain_valid ? 'VALID' : 'INVALID'}</span>
                        <span class="pill pill-blue">${n.blocks} blocks</span><br>
                        <span style="font-size:0.75rem;">Last hash: <span class="code-display">${n.last_block_hash}</span></span>
                    </div>
                </div>
            `).join('');
        }

        async function runNetworkSync() {
            const btn = document.getElementById('syncButton');
            btn.disabled = true;
            btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Syncing chains...';
            const response = await fetchAPI('/api/network/status');
            btn.disabled = false;
            btn.innerHTML = '<i class="fas fa-sync-alt"></i> Simulate Chain Sync (node_1 -> node_2)';

            const container = document.getElementById('syncResult');
            if (!response.success) {
                container.innerHTML = `<div class="alert alert-error show">${response.error}</div>`;
                return;
            }
            const node1 = response.nodes.find(n => n.node_id === 'node_1');
            if (!node1) {
                container.innerHTML = `<div class="alert alert-error show">node_1 is not part of the current topology.</div>`;
                return;
            }
            // Fetch node_1's full chain and push to node_2 (simulated HTTP POST)
            const chainRes = await fetchAPI('/api/network/node/node_1/chain');
            if (!chainRes.success || !Array.isArray(chainRes.chain)) {
                container.innerHTML = `<div class="alert alert-error show">node_1 chain unavailable (offline?). ${chainRes.error || ''}</div>`;
                return;
            }
            const sync = await fetchAPI('/api/network/sync', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ sender: 'node_1', receiver: 'node_2', chain: chainRes.chain })
            });
            if (!sync.success || !sync.result) {
                container.innerHTML = `<div class="alert alert-error show">${sync.error || 'Sync failed'}</div>`;
                return;
            }
            container.innerHTML = `
                <div class="step">
                    <div class="step-num">1</div>
                    <div>
                        <b>node_1 broadcasts its chain</b><br>
                        <span class="pill pill-blue">${node1 ? node1.blocks : '?'} blocks</span> sent over HTTP (localhost port)
                    </div>
                </div>
                <div class="step">
                    <div class="step-num">2</div>
                    <div>
                        <b>node_2 validates & adopts</b><br>
                        <span class="pill ${sync.result.accepted ? 'pill-green' : 'pill-red'}">${sync.result.accepted ? 'ACCEPTED' : 'REJECTED'}</span>
                        <div style="font-size:0.75rem; margin-top:0.3rem;">${sync.result.reason}</div>
                    </div>
                </div>
                <div style="margin-top:0.5rem;">
                    <span class="pill pill-purple"><i class="fas fa-balance-scale"></i> Consensus: longest valid chain wins</span>
                </div>
            `;
        }

        async function runMaliciousFork() {
            const btn = document.getElementById('forkButton');
            btn.disabled = true;
            btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Launching malicious fork...';
            const response = await fetchAPI('/api/network/malicious-fork', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    attacker: 'node_3',
                    block_index: 1,
                    fake_data: { type: 'GENESIS', message: 'MALICIOUS FORK - fake block' }
                })
            });
            btn.disabled = false;
            btn.innerHTML = '<i class="fas fa-biohazard"></i> Attack with Malicious Fork (node_3)';

            const container = document.getElementById('forkResult');
            if (!response.success) {
                container.innerHTML = `<div class="alert alert-error show">${response.error}</div>`;
                return;
            }
            const cons = response.consensus_result;
            container.innerHTML = `
                <div class="step">
                    <div class="step-num">1</div>
                    <div>
                        <b>Malicious node 3 alters block #${response.tampered_block}</b><br>
                        <span style="font-size:0.75rem;">Tampers data WITHOUT recomputing the hash, then broadcasts a forged chain</span>
                    </div>
                </div>
                <div class="step">
                    <div class="step-num">2</div>
                    <div>
                        <b>Node 3's chain integrity</b><br>
                        <span class="pill ${response.attacker_chain_valid ? 'pill-green' : 'pill-red'}">${response.attacker_chain_valid ? 'VALID' : 'INVALID (tamper detected)'}</span>
                    </div>
                </div>
                <div class="step">
                    <div class="step-num">3</div>
                    <div>
                        <b>Consensus verdict</b><br>
                        <span class="pill ${cons.fork_rejected ? 'pill-green' : 'pill-red'}">${cons.fork_rejected ? 'FORK REJECTED' : 'FORK ACCEPTED'}</span>
                        <div style="font-size:0.75rem; margin-top:0.3rem;">Rejected by: ${cons.rejected_by.join(', ')}</div>
                    </div>
                </div>
                <div style="margin-top:0.5rem;">
                    <span class="pill pill-purple"><i class="fas fa-shield-alt"></i> ${response.message}</span>
                </div>
            `;
        }

        // ============================================
        // IPFS DOCUMENT STORAGE
        // ============================================
        function switchTab4(tabName, btn) {
            document.querySelectorAll('[data-tab4]').forEach(t => t.classList.remove('active'));
            btn.classList.add('active');
            document.querySelectorAll('.feature-panel[id^="panel4-"]').forEach(p => p.classList.remove('active'));
            document.getElementById(`panel4-${tabName}`).classList.add('active');
        }

        async function addIpfsDocument() {
            const name = document.getElementById('ipfsDocName').value.trim() || 'document';
            const content = document.getElementById('ipfsDocContent').value;
            const btn = document.getElementById('ipfsAddButton');
            btn.disabled = true;
            btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Storing on IPFS...';
            const response = await fetchAPI('/api/ipfs/add', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ content, name, owner: 'aarav.sharma@bel.gov.in' })
            });
            btn.disabled = false;
            btn.innerHTML = '<i class="fas fa-cloud-upload-alt"></i> Add to IPFS (store CID on-chain)';

            const container = document.getElementById('ipfsAddResult');
            if (!response.success) {
                container.innerHTML = `<div class="alert alert-error show">${response.error}</div>`;
                return;
            }
            document.getElementById('ipfsVerifyCid').value = response.cid;
            container.innerHTML = `
                <div class="step">
                    <div class="step-num">CID</div>
                    <div>
                        <b>Document stored on IPFS (off-chain)</b><br>
                        <span class="pill pill-blue">${response.size} bytes</span> ${response.content_type}<br>
                        <span style="font-size:0.75rem;">Only this hash is anchored on-chain:</span>
                        <div class="code-display copyable" onclick="copyToClipboard(this.textContent)">${response.cid}</div>
                    </div>
                </div>
                <div style="margin-top:0.5rem;">
                    <span class="pill pill-purple"><i class="fas fa-shield-alt"></i> ${response.message}</span>
                </div>
            `;
        }

        async function verifyIpfsDocument() {
            const cid = document.getElementById('ipfsVerifyCid').value.trim();
            const btn = document.getElementById('ipfsVerifyButton');
            if (!cid) {
                document.getElementById('ipfsVerifyResult').innerHTML = `<div class="alert alert-error show">Enter a CID first</div>`;
                return;
            }
            btn.disabled = true;
            btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Verifying...';
            const response = await fetchAPI('/api/ipfs/get/' + encodeURIComponent(cid));
            btn.disabled = false;
            btn.innerHTML = '<i class="fas fa-shield-alt"></i> Verify Content vs on-chain CID';

            const container = document.getElementById('ipfsVerifyResult');
            if (!response.success) {
                container.innerHTML = `<div class="alert alert-error show">${response.message || response.error}</div>`;
                return;
            }
            container.innerHTML = `
                <div class="step">
                    <div class="step-num">${response.verified ? 'OK' : 'X'}</div>
                    <div>
                        <b>${response.name}</b><br>
                        <span class="pill ${response.verified ? 'pill-green' : 'pill-red'}">${response.verified ? 'AUTHENTIC' : 'TAMPERED'}</span>
                        <div style="font-size:0.75rem; margin-top:0.3rem;">${response.message}</div>
                        <div class="code-display">${response.cid}</div>
                    </div>
                </div>
            `;
        }

        async function tamperIpfsDocument() {
            const cid = document.getElementById('ipfsVerifyCid').value.trim();
            const btn = document.getElementById('ipfsTamperButton');
            if (!cid) {
                document.getElementById('ipfsVerifyResult').innerHTML = `<div class="alert alert-error show">Enter a CID first</div>`;
                return;
            }
            btn.disabled = true;
            btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Tampering...';
            const response = await fetchAPI('/api/ipfs/tamper', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ cid, new_content: 'TAMPERED: Illegal content modification!' })
            });
            btn.disabled = false;
            btn.innerHTML = '<i class="fas fa-exclamation-triangle"></i> Simulate Tampering';
            if (!response.success || !response.tampered) {
                document.getElementById('ipfsVerifyResult').innerHTML =
                    `<div class="alert alert-error show">${response.error || 'Tampering failed'}</div>`;
                return;
            }
            document.getElementById('ipfsVerifyResult').innerHTML = `
                <div class="step">
                    <div class="step-num">!</div>
                    <div>
                        <b>Document content tampered on IPFS</b><br>
                        <span class="pill pill-red">The PKI hash no longer matches the on-chain CID</span><br>
                        <span style="font-size:0.75rem;">Click "Verify Content vs on-chain CID" again to detect it.</span>
                    </div>
                </div>
            `;
        }

        // --- Dynamic Node Topology ---
        async function topo(action) {
            const nodeId = document.getElementById('topoNodeId').value.trim();
            const container = document.getElementById('topoResult');
            const response = await fetchAPI('/api/network/topology', {
                method: 'POST', headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ action, node_id: nodeId })
            });
            container.innerHTML = response.success
                ? `<div class="alert alert-success show">${response.message}</div>`
                : `<div class="alert alert-error show">${response.error}</div>`;
            loadNetworkStatus();
        }

        // --- Node Health / Divergence Dashboard ---
        async function loadNetworkHealth() {
            const response = await fetchAPI('/api/network/health');
            const container = document.getElementById('healthResult');
            if (!response.success) { container.innerHTML = `<div class="alert alert-error show">${response.error}</div>`; return; }
            container.innerHTML = `
                <div style="margin-bottom:0.5rem;display:flex;gap:0.5rem;flex-wrap:wrap;">
                    <span class="pill pill-blue">Online: ${response.online_count}</span>
                    <span class="pill ${response.offline_count ? 'pill-red' : 'pill-green'}">Offline: ${response.offline_count}</span>
                    <span class="pill pill-purple">Consensus: ${response.network_consensus}</span>
                </div>
                <div class="table-container" style="max-height:280px;overflow:auto;">
                    <table><thead><tr><th>Node</th><th>Status</th><th>Blocks</th><th>Divergence</th><th>Health</th></tr></thead><tbody>
                        ${response.nodes.map(n => `
                            <tr>
                                <td>${n.node_id}</td>
                                <td><span class="pill ${n.online !== undefined && n.online !== null ? (n.chain_valid ? 'pill-green' : 'pill-red') : ''}">${n.chain_valid ? 'VALID' : 'INVALID'}</span></td>
                                <td>${n.blocks}</td>
                                <td>${n.divergence_from_reference !== undefined ? n.divergence_from_reference : '--'}</td>
                                <td><span class="pill ${n.health === 'HEALTHY' ? 'pill-green' : (n.health === 'SYNCING' ? 'pill-blue' : 'pill-red')}">${n.health}</span></td>
                            </tr>`).join('')}
                    </tbody></table>
                </div>`;
        }

        // ============================================
        // AUDIT TRAIL & ADVANCED SECURITY
        // ============================================
        function switchTab5(tabName, btn) {
            document.querySelectorAll('[data-tab5]').forEach(t => t.classList.remove('active'));
            btn.classList.add('active');
            document.querySelectorAll('.feature-panel[id^="panel5-"]').forEach(p => p.classList.remove('active'));
            document.getElementById(`panel5-${tabName}`).classList.add('active');
        }

        function switchTab6(tabName, btn) {
            document.querySelectorAll('[data-tab6]').forEach(t => t.classList.remove('active'));
            btn.classList.add('active');
            document.querySelectorAll('.feature-panel[id^="panel6-"]').forEach(p => p.classList.remove('active'));
            document.getElementById(`panel6-${tabName}`).classList.add('active');
        }

        // --- Audit Trail ---
        async function loadAuditTrail() {
            const btn = document.getElementById('auditButton');
            btn.disabled = true;
            btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Loading audit trail...';
            const response = await fetchAPI('/api/audit/trail');
            btn.disabled = false;
            btn.innerHTML = '<i class="fas fa-list-alt"></i> Load On-Chain Audit Trail';

            const statsEl = document.getElementById('auditStats');
            const container = document.getElementById('auditResult');
            if (!response.success) {
                container.innerHTML = `<div class="alert alert-error show">${response.error}</div>`;
                return;
            }
            const s = response.stats || {};
            statsEl.innerHTML = `
                <div class="stats-grid" style="margin:0.5rem 0;">
                    <div class="stat-card"><div class="stat-value">${s.granted || 0}</div><div class="stat-label">GRANTED</div></div>
                    <div class="stat-card"><div class="stat-value">${s.denied || 0}</div><div class="stat-label">DENIED</div></div>
                    <div class="stat-card"><div class="stat-value">${s.total_access_attempts || 0}</div><div class="stat-label">ATTEMPTS</div></div>
                    <div class="stat-card"><div class="stat-value">${s.audit_blocks || 0}</div><div class="stat-label">AUDIT BLOCKS</div></div>
                </div>
            `;
            if (!response.entries || response.entries.length === 0) {
                container.innerHTML = `<div class="alert alert-info show">No audit entries yet. Perform an access check to populate the trail.</div>`;
                return;
            }
            container.innerHTML = '<div class="table-container" style="max-height:300px;overflow:auto;">' +
                '<table><thead><tr><th>Block</th><th>Time</th><th>Identity</th><th>Resource</th><th>Decision</th><th>Reason</th></tr></thead><tbody>' +
                response.entries.map(e => `
                    <tr>
                        <td>#${e.block_index}</td>
                        <td>${e.timestamp_display || '--'}</td>
                        <td>${e.identity_name || e.public_id || '--'}</td>
                        <td>${e.resource || '--'}</td>
                        <td><span class="pill ${(e.decision === 'GRANTED' || e.decision === 'APPROVED') ? 'pill-green' : 'pill-red'}">${e.decision || e.action || '--'}</span></td>
                        <td style="font-size:0.72rem;">${e.reason || ''}</td>
                    </tr>`).join('') +
                '</tbody></table></div>';
        }

        // --- Revoke / Expire / Restore ---
        async function revokeIdentity() {
            const pid = document.getElementById('revokePublicId').value.trim();
            const response = await fetchAPI('/api/identity/revoke', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ public_id: pid, reason: 'Manual revocation via dashboard' })
            });
            renderRevokeResult(response);
        }
        async function expireIdentity() {
            const pid = document.getElementById('revokePublicId').value.trim();
            const response = await fetchAPI('/api/identity/expire', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ public_id: pid, expires_on: Math.floor(Date.now() / 1000) - 60 })
            });
            renderRevokeResult(response);
        }
        async function restoreIdentity() {
            const pid = document.getElementById('revokePublicId').value.trim();
            const response = await fetchAPI('/api/identity/restore', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ public_id: pid })
            });
            renderRevokeResult(response);
        }
        function renderRevokeResult(response) {
            const container = document.getElementById('revokeResult');
            if (!response.success) {
                container.innerHTML = `<div class="alert alert-error show">${response.error || 'Operation failed'}</div>`;
                return;
            }
            container.innerHTML = `<div class="alert alert-success show">${response.message}</div>`;
        }

        // --- Multi-Signature ---
        async function createMultisig() {
            const signers = document.getElementById('msSigners').value.split(',').map(s => s.trim()).filter(Boolean);
            const required = parseInt(document.getElementById('msRequired').value) || 2;
            const response = await fetchAPI('/api/multisig/create', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ title: 'High-security action', required, signers, action_payload: { type: 'example' } })
            });
            if (!response.success) {
                document.getElementById('msResult').innerHTML = `<div class="alert alert-error show">${response.error}</div>`;
                return;
            }
            document.getElementById('msResult').innerHTML = `
                <div class="alert alert-success show">Proposal created (ID: ${response.proposal.proposal_id}) - requires ${response.proposal.required} of ${response.proposal.signers.length} signers.</div>
            `;
        }
        async function loadMultisig() {
            const response = await fetchAPI('/api/multisig/list');
            const container = document.getElementById('msResult');
            if (!response.success) {
                container.innerHTML = `<div class="alert alert-error show">${response.error}</div>`;
                return;
            }
            if (!response.proposals.length) {
                container.innerHTML = `<div class="alert alert-info show">No proposals yet. Create one first.</div>`;
                return;
            }
            container.innerHTML = response.proposals.map(p => `
                <div class="step">
                    <div class="step-num">${Object.keys(p.approvals || {}).length}/${p.required}</div>
                    <div>
                        <b>${p.title}</b>
                        <span class="pill ${p.status === 'APPROVED' ? 'pill-green' : (p.status === 'REJECTED' ? 'pill-red' : 'pill-blue')}">${p.status}</span><br>
                        <div style="display:flex;gap:0.3rem;margin-top:0.3rem;flex-wrap:wrap;">
                            ${p.signers.map(sg => `<button class="btn btn-sm" onclick="signMultisig('${p.proposal_id}','${sg}')">${sg}</button>`).join('')}
                        </div>
                        <div style="font-size:0.72rem;">ID: ${p.proposal_id} | approved by: ${Object.keys(p.approvals || {}).filter(k => p.approvals[k]).join(', ') || 'none'}</div>
                    </div>
                </div>`).join('');
        }
        async function signMultisig(proposalId, signer) {
            const response = await fetchAPI('/api/multisig/sign', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ proposal_id: proposalId, signer, approve: true })
            });
            showAlert(response.message || (response.status ? `Signed! Status: ${response.status}` : 'Signed'), response.success ? 'success' : 'error');
            loadMultisig();
        }

        // --- Time-Lock Scheduling ---
        async function setAccessSchedule() {
            const pid = document.getElementById('schedPublicId').value.trim();
            const res = document.getElementById('schedResource').value.trim();
            const now = Math.floor(Date.now() / 1000);
            const response = await fetchAPI('/api/schedule/set', {
                method: 'POST', headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ public_id: pid, resource: res, activate_after: now - 100, expire_before: now + 3600 })
            });
            const container = document.getElementById('schedResult');
            container.innerHTML = response.success
                ? `<div class="alert alert-success show">${response.message}</div>`
                : `<div class="alert alert-error show">${response.error || 'failed'}</div>`;
        }
        async function checkAccessSchedule() {
            const pid = document.getElementById('schedPublicId').value.trim();
            const res = document.getElementById('schedResource').value.trim();
            const response = await fetchAPI('/api/schedule/check', {
                method: 'POST', headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ public_id: pid, resource: res })
            });
            const container = document.getElementById('schedResult');
            if (!response.success) { container.innerHTML = `<div class="alert alert-error show">${response.error}</div>`; return; }
            const r = response.result;
            const stage = r.granted ? r.stage : (r.stage || 'NO_SCHEDULE');
            container.innerHTML = `
                <div class="step"><div class="step-num">${r.granted ? 'OK' : 'X'}</div><div>
                    <b>Stage: <span class="pill ${r.granted ? 'pill-green' : 'pill-red'}">${stage}</span></b><br>
                    <span style="font-size:0.75rem;">${r.reason}</span>
                </div></div>`;
        }

        // --- Encryption ---
        async function encryptValue() {
            const plain = document.getElementById('encPlain').value;
            const pass = document.getElementById('encPass').value;
            const response = await fetchAPI('/api/encrypt/encrypt', {
                method: 'POST', headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ plaintext: plain, passphrase: pass })
            });
            const container = document.getElementById('encResult');
            if (!response.success) { container.innerHTML = `<div class="alert alert-error show">${response.error}</div>`; return; }
            container.innerHTML = `
                <div class="step"><div class="step-num">ENC</div><div>
                    <b>Ciphertext (stored on-chain):</b>
                    <div class="code-display copyable" onclick="copyToClipboard(this.textContent)">${response.ciphertext}</div>
                    <span style="font-size:0.75rem;">AES symmetric encryption (Fernet). Only decodable with the passphrase.</span>
                </div></div>`;
        }
        async function decryptValue() {
            const pass = document.getElementById('encPass').value;
            const container = document.getElementById('encResult');
            const cipherEl = container.querySelector('.code-display');
            const ciphertext = cipherEl ? cipherEl.textContent : '';
            if (!ciphertext) { container.innerHTML += `<div class="alert alert-error show">Encrypt a value first</div>`; return; }
            const response = await fetchAPI('/api/encrypt/decrypt', {
                method: 'POST', headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ ciphertext, passphrase: pass })
            });
            container.innerHTML += response.success
                ? `<div class="alert alert-success show">Decrypted: ${response.plaintext}</div>`
                : `<div class="alert alert-error show">Decryption failed (wrong passphrase): ${response.error}</div>`;
        }

        // --- ZK Document Possession ---
        async function proveZkDocument() {
            const cid = document.getElementById('zkDocCid').value.trim();
            const response = await fetchAPI('/api/zk/possession/prove', {
                method: 'POST', headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ cid, secret: 'document-owner-secret' })
            });
            const container = document.getElementById('zkDocResult');
            if (!response.success) { container.innerHTML = `<div class="alert alert-error show">${response.error}</div>`; return; }
            container.innerHTML = `
                <div class="step"><div class="step-num">ZK</div><div>
                    <b>Commitment (public, reveals nothing):</b>
                    <div class="code-display copyable" onclick="copyToClipboard(this.textContent)">${response.commitment}</div>
                    <b style="display:block;margin-top:0.4rem;">Proof secret (shown here for demo):</b>
                    <div class="code-display copyable" onclick="copyToClipboard(this.textContent)">${response.proof}</div>
                </div></div>`;
        }
        async function verifyZkDocument() {
            const cid = document.getElementById('zkDocCid').value.trim();
            const container = document.getElementById('zkDocResult');
            const codes = container.querySelectorAll('.code-display');
            const commitment = codes[0] ? codes[0].textContent : '';
            const proof = codes[1] ? codes[1].textContent : '';
            if (!commitment || !proof) { container.innerHTML = `<div class="alert alert-error show">Generate a proof first</div>`; return; }
            const response = await fetchAPI('/api/zk/possession/verify', {
                method: 'POST', headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ commitment, proof, cid })
            });
            container.innerHTML += `<div class="alert ${response.verified ? 'alert-success' : 'alert-error'} show">${response.message}</div>`;
        }

        // --- Export / Import ---
        async function exportChain() {
            const response = await fetchAPI('/api/chain/export');
            if (!response.success) { showAlert(response.error, 'error'); return; }
            document.getElementById('exportOutput').value = JSON.stringify(response.data);
            showAlert(`Exported chain (${response.data.chain.length} blocks)`, 'success');
        }
        async function importChain() {
            const chainJson = document.getElementById('importInput').value;
            const container = document.getElementById('importResult');
            if (!chainJson.trim()) { container.innerHTML = `<div class="alert alert-error show">Paste chain JSON first</div>`; return; }
            const response = await fetchAPI('/api/chain/import', {
                method: 'POST', headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ chain_json: chainJson })
            });
            container.innerHTML = response.success
                ? `<div class="alert alert-success show">${response.message}</div>`
                : `<div class="alert alert-error show">${response.error}</div>`;
            loadBlockchainData();
        }

        // ============================================
        // RED TEAM ATTACK PLAYBOOK
        // ============================================
        async function runPlaybook(scenario) {
            const container = document.getElementById('playbookResult');
            container.innerHTML = `<div class="alert alert-info show"><i class="fas fa-spinner fa-spin"></i> Running attack scenario...</div>`;
            const response = await fetchAPI('/api/playbook', {
                method: 'POST', headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ scenario })
            });
            if (!response.success) { container.innerHTML = `<div class="alert alert-error show">${response.error}</div>`; return; }
            container.innerHTML = `
                <div class="step"><div class="step-num">${response.verdict === 'BLOCKED' ? 'X' : '!'}</div><div>
                    <b>${response.scenario}</b><br>
                    <span style="font-size:0.75rem;">${response.attack}</span><br>
                    <span class="pill ${response.verdict === 'BLOCKED' ? 'pill-green' : 'pill-red'}" style="margin-top:0.3rem;">SYSTEM: ${response.verdict}</span>
                    <div style="font-size:0.75rem;margin-top:0.3rem;">${response.detail || response.system_response || response.conclusion || ''}</div>
                </div></div>`;
        }

        // ============================================
        // FEATURE 1: ZK SELF-SOVEREIGN IDENTITY (DID + VC)
        // ============================================
        async function runZkSsiDemo() {
            const btn = document.getElementById('zkSsiButton');
            btn.disabled = true;
            btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Running ZK-SSI demo...';
            const response = await fetchAPI('/api/did/full-demo', {
                method: 'POST', headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ subject_name: 'Aarav Sharma', subject_email: 'aarav.sharma@bel.gov.in' })
            });
            btn.disabled = false;
            btn.innerHTML = '<i class="fas fa-user-secret"></i> Run ZK-SSI Demo (prove attribute, not identity)';
            const c = document.getElementById('zkSsiResult');
            if (!response.success) { c.innerHTML = `<div class="alert alert-error show">${response.error}</div>`; return; }
            const s = response.steps || {};
            const v = s.verification || {};
            c.innerHTML = `
                <div class="alert ${v.granted ? 'alert-success' : 'alert-error'} show">
                    <b>${v.granted ? 'ATTRIBUTE PROVEN - identity stays hidden' : 'PROOF REJECTED'}</b>
                    <div style="font-size:0.82rem;margin-top:0.3rem;">${v.reason || v.detail || response.privacy_summary || ''}</div>
                </div>
                <div class="zk-steps">
                    <div class="step"><div class="step-num">I</div><div><b>Issuer DID</b>
                        <div class="code-display" style="font-size:0.65rem;">${s.issuer_did}</div></div></div>
                    <div class="step"><div class="step-num">S</div><div><b>Subject DID (pseudonymous)</b>
                        <div class="code-display" style="font-size:0.65rem;">${s.subject_did}</div></div></div>
                    <div class="step"><div class="step-num">C</div><div><b>Verifiable Credential (commitment anchored on-chain)</b>
                        <div class="code-display" style="font-size:0.6rem;max-height:100px;">${JSON.stringify(s.credential, null, 1)}</div></div></div>
                    <div class="step"><div class="step-num">P</div><div><b>ZK presentation (predicate &gt;= LEVEL-3)</b>
                        <div class="code-display" style="font-size:0.6rem;max-height:100px;">${JSON.stringify(s.presentation, null, 1)}</div></div></div>
                </div>
                <div style="margin-top:0.5rem;">
                    <span class="pill ${s.attacker_forged_proof_blocked ? 'pill-green' : 'pill-red'}">Forged proof: ${s.attacker_forged_proof_blocked ? 'BLOCKED' : 'ACCEPTED'}</span>
                    <span class="pill ${s.attacker_level1_mint_blocked ? 'pill-green' : 'pill-red'}">LEVEL-1 mint attempt: ${s.attacker_level1_mint_blocked ? 'BLOCKED' : 'ACCEPTED'}</span>
                </div>`;
        }

        async function listDids() {
            const response = await fetchAPI('/api/did/list');
            const c = document.getElementById('zkSsiResult');
            if (!response.success) { c.innerHTML = `<div class="alert alert-error show">${response.error || 'Failed to load DIDs'}</div>`; return; }
            const dids = response.dids || [];
            if (!dids.length) { c.innerHTML = '<div class="alert alert-info show">No DIDs registered yet - run the demo above.</div>'; return; }
            c.innerHTML = `<div class="alert alert-info show"><b>${dids.length} DID(s) on-chain</b> (public verification methods only)</div>` +
                dids.slice(-6).map(d => `<div class="code-display copyable" style="font-size:0.65rem;" onclick="copyToClipboard('${d.did}')">${d.did} • block #${d.anchored_in_block} • ${d.credentials_issued} credential(s)</div>`).join('');
        }

        // ============================================
        // FEATURE 2: ATTRIBUTE-BASED ACCESS CONTROL (ABAC)
        // ============================================
        const ABAC_LABELS = {
            inside_perimeter_certified_device: 'Inside perimeter + certified device',
            inside_perimeter_untrusted_device: 'Inside perimeter + UNTRUSTED device',
            outside_perimeter_certified_device: 'OUTSIDE perimeter + certified device',
            no_device_hash: 'Inside perimeter + NO device hash',
            level1_clearance_all_else_ok: 'LEVEL-1 clearance, everything else OK'
        };

        async function runAbacDemo() {
            const publicId = document.getElementById('abacPublicId').value.trim() || 'aarav.sharma@bel.gov.in';
            const btn = document.getElementById('abacButton');
            btn.disabled = true;
            btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Evaluating policy...';
            const response = await fetchAPI('/api/abac/demo', {
                method: 'POST', headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ public_id: publicId })
            });
            btn.disabled = false;
            btn.innerHTML = '<i class="fas fa-shield-alt"></i> Run ABAC Demo (ALL 4 attributes)';
            const c = document.getElementById('abacResult');
            if (!response.success) { c.innerHTML = `<div class="alert alert-error show">${response.error}</div>`; return; }
            const rows = Object.entries(response.scenarios || {}).map(([k, v]) => {
                const badge = v.granted
                    ? '<span class="pill pill-green">GRANTED</span>'
                    : '<span class="pill pill-red">DENIED</span>';
                return `<div class="step">
                    <div class="step-num">${v.granted ? 'OK' : 'X'}</div>
                    <div><b>${ABAC_LABELS[k] || k}</b> ${badge}
                        <div style="font-size:0.72rem;margin-top:0.25rem;color:var(--text-light);">
                            ${(v.evaluation || []).map(r => `${r.allowed ? '✓' : '✗'} ${r.rule}: ${r.detail}`).join('<br>')}
                        </div>
                    </div></div>`;
            }).join('');
            c.innerHTML = `
                <div class="alert alert-info show"><b>Policy:</b> <code>${response.formula}</code><br>
                    <span style="font-size:0.8rem;">Resource: <code>${response.resource}</code></span></div>
                <div class="zk-steps">${rows}</div>
                <div class="alert alert-success show" style="margin-top:0.5rem;font-size:0.82rem;">${response.conclusion}</div>`;
        }

        // ============================================
        // FEATURE 3: DYNAMIC LIFECYCLE NFTs (dNFTs)
        // ============================================
        async function runNftDemo() {
            const btn = document.getElementById('nftButton');
            btn.disabled = true;
            btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Running dNFT lifecycle...';
            const response = await fetchAPI('/api/nft/demo', {
                method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({})
            });
            btn.disabled = false;
            btn.innerHTML = '<i class="fas fa-bolt"></i> Run dNFT Lifecycle Demo';
            const c = document.getElementById('nftResult');
            if (!response.success) { c.innerHTML = `<div class="alert alert-error show">${response.error}</div>`; return; }
            const hw = response.hardware || {}, bp = response.blueprint || {};
            const trans = (response.lifecycle_transitions || []).map(t =>
                `<div class="step"><div class="step-num">${t.success ? '→' : 'X'}</div>
                    <div>${t.from || '?'} → <b>${t.to || '?'}</b>
                    <span class="pill ${t.success ? 'pill-green' : 'pill-red'}">${t.success ? 'ACCEPTED' : 'REJECTED'}</span>
                    ${t.signed_telemetry ? '<span class="pill pill-purple">signed IoT telemetry</span>' : ''}</div></div>`).join('');
            const dl = (r) => `<span class="pill ${r && r.success ? 'pill-green' : 'pill-red'}">${r && r.success ? 'DOWNLOAD OK' : 'DENIED'}</span>`;
            c.innerHTML = `
                <div class="alert alert-info show">
                    <b>${hw.token_id}</b> • ${hw.name} → state <b>${hw.state}</b><br>
                    <b>${bp.token_id}</b> • ${bp.name} → v${bp.version} (${bp.state})
                </div>
                <div class="zk-steps">${trans}</div>
                <div style="margin-top:0.5rem;">
                    <span class="pill ${response.forged_rollback_blocked ? 'pill-green' : 'pill-red'}">Forged rollback: ${response.forged_rollback_blocked ? 'BLOCKED' : 'ACCEPTED'}</span>
                    ${dl(response.download_inside_perimeter)} inside perimeter
                    ${dl(response.download_outside_perimeter)} outside perimeter
                    <span class="pill pill-blue">terminal state: ${response.decommissioned_state}</span>
                </div>
                <div class="alert alert-success show" style="margin-top:0.5rem;font-size:0.82rem;">${response.conclusion}</div>`;
        }

        async function listNfts() {
            const response = await fetchAPI('/api/nft/list');
            const c = document.getElementById('nftResult');
            if (!response.success) { c.innerHTML = `<div class="alert alert-error show">${response.error || 'Failed'}</div>`; return; }
            const assets = response.assets || [];
            if (!assets.length) { c.innerHTML = '<div class="alert alert-info show">No dNFTs minted yet - run the demo above.</div>'; return; }
            c.innerHTML = `<div class="alert alert-info show"><b>${assets.length} dynamic NFT(s)</b></div>` +
                assets.slice(-6).map(a => `<div class="code-display" style="font-size:0.68rem;">${a.token_id} • ${a.asset_type} • ${a.name} • state=${a.state}${a.version ? ' v' + a.version : ''} • owner=${a.owner}</div>`).join('');
        }

        // ============================================
        // FEATURE 4: DUAL-LAYER ENCRYPTED STORAGE
        // ============================================
        async function encipfsStore() {
            const plaintext = document.getElementById('encipfsPlaintext').value;
            const btn = document.getElementById('encipfsStoreButton');
            btn.disabled = true;
            btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Encrypting...';
            const response = await fetchAPI('/api/encipfs/add', {
                method: 'POST', headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ plaintext, name: 'radar_blueprint_X.txt', owner: 'BEL', required_clearance: 'LEVEL-3' })
            });
            btn.disabled = false;
            btn.innerHTML = '<i class="fas fa-user-lock"></i> Encrypt &amp; Publish to IPFS';
            const c = document.getElementById('encipfsResult');
            if (!response.success) { c.innerHTML = `<div class="alert alert-error show">${response.error || response.reason}</div>`; return; }
            c.innerHTML = `
                <div class="alert alert-success show"><b>Encrypted &amp; anchored</b><br>
                    <span style="font-size:0.78rem;">Only the CID + ciphertext are public. The AES key is split across ${response.n_shares} nodes (threshold ${response.threshold}).</span></div>
                <div class="zk-steps">
                    <div class="step"><div class="step-num">1</div><div><b>CID</b>
                        <div class="code-display copyable" style="font-size:0.65rem;" onclick="copyToClipboard('${response.cid}')">${response.cid}</div></div></div>
                    <div class="step"><div class="step-num">2</div><div><b>Cipher</b>
                        <span class="pill pill-purple">${response.encryption}</span>
                        <span class="pill pill-blue">needs ${response.required_clearance}</span></div></div>
                    <div class="step"><div class="step-num">3</div><div><b>Share holders</b>
                        <div style="font-size:0.72rem;">${(response.nodes_holding_shares || []).join(', ')}</div></div></div>
                </div>
                <div style="font-size:0.75rem;margin-top:0.3rem;">To decrypt, run the full demo below (it presents a ZK attribute proof to release threshold shares).</div>`;
        }

        async function runEncipfsDemo() {
            const btn = document.getElementById('encipfsButton');
            btn.disabled = true;
            btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Running dual-layer demo...';
            const response = await fetchAPI('/api/encipfs/demo', {
                method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({})
            });
            btn.disabled = false;
            btn.innerHTML = '<i class="fas fa-bolt"></i> Run Full Dual-Layer Demo';
            const c = document.getElementById('encipfsResult');
            if (!response.success) { c.innerHTML = `<div class="alert alert-error show">${response.error}</div>`; return; }
            const sm = response.storage_metadata || {};
            const peek = response.what_public_peeker_sees || {};
            const unlock = response.legitimate_unlock || {};
            const noProof = (response.attack_without_proof || {}).result || {};
            const tooFew = response.attack_too_few_shares || {};
            const dec = unlock.decrypted || {};
            c.innerHTML = `
                <div class="alert alert-info show">
                    <b>${sm.encryption}</b> • CID <code>${sm.cid}</code><br>
                    <span style="font-size:0.78rem;">${sm.n_shares} threshold nodes • reconstruction needs ${sm.threshold} • requires ${sm.required_clearance}</span>
                </div>
                <div class="zk-steps">
                    <div class="step"><div class="step-num">1</div><div><b>What a public peeker sees (only ciphertext)</b>
                        <div class="code-display" style="font-size:0.62rem;max-height:70px;">${peek.what_a_strager_sees || 'ciphertext'}</div></div></div>
                    <div class="step"><div class="step-num">2</div><div><b>Legitimate unlock via ZK proof ${unlock.zk_gate && unlock.zk_gate.granted ? '<span class="pill pill-green">GATE OPEN</span>' : '<span class="pill pill-red">GATE CLOSED</span>'}</b>
                        <div class="code-display" style="font-size:0.66rem;">recovered: ${dec.plaintext || unlock.plaintext_recovered ? (dec.plaintext || 'YES') : 'N/A'}</div></div></div>
                    <div class="step"><div class="step-num">3</div><div><b>Attack - no ZK proof</b> ${noProof.success === false || !noProof.success ? '<span class="pill pill-green">BLOCKED</span>' : '<span class="pill pill-red">LEAKED</span>'}
                        <div style="font-size:0.72rem;">${noProof.reason || (response.attack_without_proof || {}).note || ''}</div></div></div>
                    <div class="step"><div class="step-num">4</div><div><b>Attack - only 2 of 3 shares</b> <span class="pill pill-green">IMPOSSIBLE</span>
                        <div style="font-size:0.72rem;">${tooFew.reason || ''}</div></div></div>
                </div>
                <div class="alert alert-success show" style="margin-top:0.5rem;font-size:0.82rem;">${response.conclusion}</div>`;
        }

        // ============================================================
        // FEATURE SUITE v2 - 13 security/operations capabilities
        // ============================================================
        function renderRaw(elId, data) {
            const el = document.getElementById(elId);
            if (!el) return;
            if (data && data.success === false) {
                el.innerHTML = `<div class="alert alert-error show">${data.error || data.data && data.data.reason || 'Operation failed'}</div>`;
                return;
            }
            const inner = data && data.data !== undefined ? data.data : data;
            el.innerHTML = `<pre class="code-display" style="font-size:0.72rem;max-height:320px;overflow:auto;white-space:pre-wrap;">${escapeHtml(JSON.stringify(inner, null, 2))}</pre>`;
        }
        function postJSON(url, body) {
            return fetchAPI(url, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
        }
        function splitCsv(id) {
            return document.getElementById(id).value.split(',').map(s => s.trim()).filter(Boolean);
        }

        // --- F1: Disposable tokens ---
        async function disposeMint() {
            const r = await postJSON('/api/disposable/mint', {
                public_id: document.getElementById('dspPublicId').value.trim(),
                resource: document.getElementById('dspResource').value.trim(),
                actions: splitCsv('dspActions'),
                ttl_s: 300, max_uses: parseInt(document.getElementById('dspMaxUses').value) || 1
            });
            const el = document.getElementById('dspResult');
            if (r.success) {
                el.innerHTML = `<div class="alert alert-success show"><b>Token minted</b> — copy it:<br>
                    <span style="font-size:0.78rem;">${r.data.token}</span></div>`;
            } else { renderRaw('dspResult', r); }
        }
        async function disposeConsume() {
            const last = (document.querySelector('#dspResult .alert-success') || { innerHTML: '' }).innerHTML;
            const token = (last.match(/token minted<\/b>\s*—\s*copy it:<br>\s*<span[^>]*>(.*?)<\/span>/i) || [])[1] || prompt('Disposable token?');
            const r = await postJSON('/api/disposable/consume', {
                token, resource: document.getElementById('dspResource').value.trim(), action: 'enter'
            });
            renderRaw('dspResult', r);
        }
        async function disposeRevoke() {
            const token = prompt('Disposable token to revoke?');
            if (!token) return;
            renderRaw('dspResult', await postJSON('/api/disposable/revoke', { token }));
        }
        async function disposeList() {
            renderRaw('dspResult', { success: true, data: (await fetchAPI('/api/disposable/list')).data });
        }

        // --- F2: Delegation chains ---
        async function delegationGrant() {
            const r = await postJSON('/api/delegations/grant', {
                delegator: document.getElementById('dlgDelegator').value.trim(),
                delegate: document.getElementById('dlgDelegate').value.trim(),
                resource: document.getElementById('dlgResource').value.trim(),
                actions: [document.getElementById('dlgAction').value.trim() || 'read'],
                ttl_s: 3600, max_depth: 3
            });
            const el = document.getElementById('dlgResult');
            if (r.success) {
                el.innerHTML = `<div class="alert alert-success show"><b>Delegation granted</b> (ID: <code>${r.data.delegation_id}</code>) — delegate may now be evaluated.</div>`;
            } else { renderRaw('dlgResult', r); }
        }
        async function delegationRevoke() {
            const id = prompt('Delegation ID to revoke?');
            if (!id) return;
            renderRaw('dlgResult', await postJSON('/api/delegations/revoke', { delegation_id: id }));
        }
        async function delegationEvaluate() {
            const r = await postJSON('/api/delegations/evaluate', {
                delegate: document.getElementById('dlgDelegate').value.trim(),
                resource: document.getElementById('dlgResource').value.trim(),
                action: document.getElementById('dlgAction').value.trim() || 'read'
            });
            const el = document.getElementById('dlgResult');
            if (r.success) {
                el.innerHTML = `<div class="alert alert-success show"><b>Delegated access GRANTED</b> via delegation <code>${r.data.delegation_id}</code> (chain depth ${r.data.chain_depth})</div>`;
            } else {
                el.innerHTML = `<div class="alert alert-warning show">Delegate ${r.data && r.data.reason || 'denied'}</div>`;
            }
        }
        async function delegationList() {
            renderRaw('dlgResult', { success: true, data: (await fetchAPI('/api/delegations/list')).data });
        }

        // --- F3: Travel-mode context access ---
        async function travelEnable() {
            const r = await postJSON('/api/travel-mode/enable', {
                public_id: document.getElementById('trvPublicId').value.trim(),
                mode: document.getElementById('trvMode').value.trim() || 'warzone',
                destinations: splitCsv('trvDest'), ttl_s: 86400
            });
            const el = document.getElementById('trvResult');
            if (r.success) {
                el.innerHTML = `<div class="alert alert-success show"><b>Travel mode enabled</b> — expires ${new Date(r.data.expires_at * 1000).toLocaleString()}</div>`;
            } else { renderRaw('trvResult', r); }
        }
        async function travelDisable() {
            renderRaw('trvResult', await postJSON('/api/travel-mode/disable', {
                public_id: document.getElementById('trvPublicId').value.trim()
            }));
        }
        async function travelEvaluate() {
            const r = await postJSON('/api/travel-mode/evaluate', {
                public_id: document.getElementById('trvPublicId').value.trim(),
                resource: document.getElementById('dspResource').value.trim() || 'armory',
                context: { destination: (splitCsv('trvDest')[0] || 'Zone-A') }
            });
            const el = document.getElementById('trvResult');
            if (r.data && r.data.travel_override) {
                el.innerHTML = `<div class="alert alert-success show"><b>GRANTED by travel-mode override</b> — ${r.data.reason}</div>`;
            } else {
                el.innerHTML = `<div class="alert alert-warning show">${r.data && r.data.reason || 'No travel-mode grant'}</div>`;
            }
        }
        async function travelList() {
            renderRaw('trvResult', { success: true, data: (await fetchAPI('/api/travel-mode/list')).data });
        }

        // --- F4: DID rescue kits ---
        async function rescueCreate() {
            const r = await postJSON('/api/rescue/create', {
                public_id: document.getElementById('kitPublicId').value.trim(),
                threshold: parseInt(document.getElementById('kitThreshold').value) || 2,
                total_shares: parseInt(document.getElementById('kitShares').value) || 3
            });
            const el = document.getElementById('kitResult');
            if (r.success) {
                el.innerHTML = `<div class="alert alert-success show"><b>Rescue kit created</b> (${r.data.threshold} of ${r.data.total_shares} shares). Shares are held by guardians — recovery below requires the share hexes.</div>
                    <pre class="code-display" style="font-size:0.7rem;">${escapeHtml(JSON.stringify(r.data, null, 2))}</pre>`;
            } else { renderRaw('kitResult', r); }
        }
        async function rescueRecover() {
            const el = document.getElementById('kitResult');
            const raw = prompt('Paste guardian shares as JSON e.g. {"1":"hexshare1","2":"hexshare2"}');
            if (!raw) return;
            let shares = {};
            try { shares = JSON.parse(raw); } catch (e) { el.innerHTML = `<div class="alert alert-error show">Invalid JSON</div>`; return; }
            const pid = document.getElementById('kitPublicId').value.trim();
            const r = await postJSON('/api/rescue/recover', { public_id: pid, shares });
            el.innerHTML = r.success
                ? `<div class="alert alert-success show"><b>Identity recovered!</b> recovered key: ${r.data.recovered_key_hint}</div>`
                : `<div class="alert alert-warning show">${r.data && r.data.reason || r.error || 'Recovery failed'}</div>`;
        }

        // --- F5: Activity report ---
        async function reportActivity() {
            const pid = document.getElementById('repPublicId').value.trim();
            const q = pid ? `?public_id=${encodeURIComponent(pid)}` : '';
            const r = await fetchAPI('/api/report/activity' + q);
            const el = document.getElementById('repResult');
            if (r.success) {
                const rows = r.data.rows || [];
                el.innerHTML = `<div class="alert alert-success show"><b>${r.data.count} rows exported</b></div>
                    <div style="display:flex;gap:0.4rem;margin-top:0.4rem;">
                        <button class="btn btn-sm" onclick="downloadCsv()"><i class="fas fa-download"></i> Download CSV</button>
                    </div>
                    <div class="table-container" style="max-height:220px;overflow:auto;margin-top:0.4rem;">
                        <table><thead><tr><th>Time</th><th>Type</th><th>Actor</th><th>Resource</th></tr></thead><tbody>
                        ${rows.slice(0, 40).map(x => `<tr><td>${x.timestamp}</td><td>${x.type}</td><td>${x.actor}</td><td>${x.resource}</td></tr>`).join('')}
                        </tbody></table></div>`;
                window.__activityCsv = r.data.csv;
            } else { renderRaw('repResult', r); }
        }
        function downloadCsv() {
            const blob = new Blob([window.__activityCsv || ''], { type: 'text/csv' });
            const a = document.createElement('a');
            a.href = URL.createObjectURL(blob);
            a.download = 'activity-report.csv';
            a.click();
        }

        // --- F6: Rule dry-run ---
        async function dryRunRules() {
            const r = await postJSON('/api/rules/dry-run', {
                public_id: document.getElementById('dryPublicId').value.trim(),
                resource: document.getElementById('dryResource').value.trim() || 'armory',
                context: { hour: Math.floor(Date.now() / 3600000) % 24 },
                rules: [{ field: document.getElementById('dryField').value.trim() || 'access_level',
                          op: document.getElementById('dryOp').value,
                          value: document.getElementById('dryValue').value.trim() }]
            });
            const el = document.getElementById('dryResult');
            if (r.success) {
                const d = r.data;
                el.innerHTML = `<div class="alert ${d.decision === 'GRANTED' ? 'alert-success' : 'alert-warning'} show">
                    <b>DRY-RUN verdict: ${d.decision}</b> (recommendation: ${d.recommendation}) — NO audit block written</div>
                    <pre class="code-display" style="font-size:0.7rem;">${escapeHtml(JSON.stringify({ base: d.abac_rules, smart_contract: d.smart_contract_hits, optional_rules: d.optional_rules }, null, 2))}</pre>`;
            } else { renderRaw('dryResult', r); }
        }

        // --- F7: Anomaly scan ---
        async function anomalyScan() {
            const r = await postJSON('/api/anomaly/scan', { window: 900 });
            const el = document.getElementById('anomalyResult');
            el.innerHTML = (r.success && r.data)
                ? `<div class="alert alert-info show">Triaged ${r.data.alerts_scanned} entries — <b>${r.data.new_alerts}</b> new alert(s), ${r.data.active_alerts} active.</div>`
                : `<div class="alert alert-error show">${r.error || 'Anomaly scan failed'}</div>`;
        }
        async function anomalyList() {
            const r = await fetchAPI('/api/anomaly/list?active=true');
            const el = document.getElementById('anomalyResult');
            if (!r.success || !(r.data || []).length) { el.innerHTML = `<div class="alert alert-info show">No active anomaly alerts.</div>`; return; }
            el.innerHTML = `<div class="table-container" style="max-height:220px;overflow:auto;">
                <table><thead><tr><th>Score</th><th>Severity</th><th>Type</th><th>Identity</th><th>Resource</th><th></th></tr></thead><tbody>
                ${r.data.map(a => `<tr>
                    <td><b>${a.score}</b></td><td><span class="pill ${a.severity === 'HIGH' ? 'pill-red' : 'pill-blue'}">${a.severity}</span></td>
                    <td>${a.type}</td><td>${a.public_id || '--'}</td><td>${a.resource || '--'}</td>
                    <td><button class="btn btn-sm" onclick="anomalyAck('${a.alert_id}')">Ack</button></td></tr>`).join('')}
                </tbody></table></div>`;
        }
        async function anomalyAck(id) {
            await postJSON('/api/anomaly/ack', { alert_id: id });
            anomalyList();
        }

        // --- F8: Quorum ops ---
        async function quorumCreate() {
            const op = document.getElementById('qOp').value;
            const params = op === 'GRANT_RESOURCE'
                ? { public_id: document.getElementById('qTarget').value.trim(), resource: document.getElementById('qResource').value.trim() || 'armory' }
                : { public_id: document.getElementById('qTarget').value.trim() };
            const r = await postJSON('/api/quorum/create', {
                operation: op, proposed_by: document.getElementById('qApprover').value.trim(),
                params, required_votes: 2
            });
            const el = document.getElementById('quorumResult');
            el.innerHTML = r.success
                ? `<div class="alert alert-success show">Proposed <code>${op}</code> — <b>${r.data.op_id}</b> needs ${r.data.required_votes} votes. Click "Show Ops + Vote" to approve.</div>`
                : `<div class="alert alert-error show">${r.error || r.data && r.data.reason}</div>`;
        }
        async function quorumList() {
            const r = await fetchAPI('/api/quorum/list');
            const el = document.getElementById('quorumResult');
            if (!(r.data || []).length) { el.innerHTML = `<div class="alert alert-info show">No quorum ops yet.</div>`; return; }
            el.innerHTML = r.data.map(q => `
                <div class="step">
                    <div class="step-num">${q.approved_by.length}/${q.required_votes}</div>
                    <div><b>${q.operation}</b> <span class="pill ${q.status === 'EXECUTED' ? 'pill-green' : (q.status === 'PENDING' ? 'pill-blue' : 'pill-purple')}">${q.status}</span><br>
                    <span style="font-size:0.72rem;">${q.op_id} • proposed by ${q.proposed_by} • approvers: ${q.approved_by.join(', ') || 'none'}</span><br>
                    ${q.status !== 'EXECUTED' ? `<button class="btn btn-sm" onclick="quorumApprove('${q.op_id}')">Approve</button>` : ''}
                    ${q.result ? `<div class="alert alert-info show" style="margin-top:0.3rem;font-size:0.72rem;">result: ${escapeHtml(JSON.stringify(q.result))}</div>` : ''}</div>
                </div>`).join('');
        }
        async function quorumApprove(id) {
            const r = await postJSON('/api/quorum/approve', {
                op_id: id, approver: document.getElementById('qApprover').value.trim()
            });
            const el = document.getElementById('quorumResult');
            if (r.data && r.data.status === 'EXECUTED') {
                el.innerHTML = `<div class="alert alert-success show"><b>Quorum met — OPERATION EXECUTED.</b><br><pre class="code-display" style="font-size:0.7rem;">${escapeHtml(JSON.stringify(r.data.result, null, 2))}</pre></div>`;
            } else if (r.data && r.data.status) {
                el.innerHTML = `<div class="alert alert-info show">Vote cast: ${r.data.votes}/${r.data.required_votes} (${r.data.status}).</div>`;
            } else {
                el.innerHTML = `<div class="alert alert-error show">${r.error || (r.data && r.data.reason) || 'Vote failed'}</div>`;
            }
        }

        // --- F9: VC lifecycle ---
        async function vcExpiry() {
            const r = await postJSON('/api/credentials/expiry', {
                public_id: document.getElementById('vcPublicId').value.trim(),
                credential_id: document.getElementById('vcCredId').value.trim(),
                expires_at: Math.floor(Date.now() / 1000) - 60
            });
            const el = document.getElementById('vcResult');
            el.innerHTML = r.success
                ? `<div class="alert alert-info show">Expiry set — credential is now <b>${r.data.status}</b>.</div>`
                : `<div class="alert alert-error show">${r.error || r.data && r.data.reason}</div>`;
        }
        async function vcRefresh() {
            const r = await postJSON('/api/credentials/refresh', {
                public_id: document.getElementById('vcPublicId').value.trim(),
                credential_id: document.getElementById('vcCredId').value.trim()
            });
            const el = document.getElementById('vcResult');
            el.innerHTML = r.success
                ? `<div class="alert alert-success show">Credential refreshed (count ${r.data.refresh_count}) — expires ${new Date(r.data.expires_at * 1000).toLocaleString()}</div>`
                : `<div class="alert alert-warning show">${r.data && r.data.reason || 'Refresh failed — credential missing'}</div>`;
        }
        async function vcLifecycle() {
            renderRaw('vcResult', { success: true, data: (await fetchAPI('/api/credentials/lifecycle')).data });
        }

        // --- F10: Chain backups ---
        async function backupCreate() {
            const r = await postJSON('/api/backups/create', { label: 'manual' });
            const el = document.getElementById('bkResult');
            if (r.success) {
                el.innerHTML = `<div class="alert alert-success show"><b>Backup created</b> — CID <code>${r.data.cid}</code> anchored (${r.data.block_count} blocks)</div>`;
            } else { renderRaw('bkResult', r); }
        }
        async function backupList() {
            renderRaw('bkResult', { success: true, data: (await fetchAPI('/api/backups/list')).data });
        }
        async function backupVerify() {
            renderRaw('bkResult', (await postJSON('/api/backups/verify', { backup_id: document.getElementById('bkId').value.trim() })));
        }
        async function backupRestore() {
            const r = await postJSON('/api/backups/restore', { backup_id: document.getElementById('bkId').value.trim() });
            const el = document.getElementById('bkResult');
            el.innerHTML = r.success
                ? `<div class="alert alert-success show">${r.data.message}</div>`
                : `<div class="alert alert-error show">${r.data && r.data.reason || r.error}</div>`;
            if (typeof loadBlockchainData === 'function') loadBlockchainData();
        }

        // --- F11: Trust scores ---
        async function trustCompute() {
            const r = await postJSON('/api/trust/compute', {});
            const el = document.getElementById('trustResult');
            if (r.success) {
                const scores = r.data.trust_scores || {};
                const rows = Object.entries(scores).map(([pid, s]) => ({
                    pid, s, bar: Math.round((s / 999) * 100)
                })).sort((a, b) => b.s - a.s);
                el.innerHTML = `<div class="alert alert-success show"><b>${rows.length} identities scored</b></div>
                    <div class="table-container" style="max-height:260px;overflow:auto;">
                    <table><thead><tr><th>Identity</th><th>Score</th><th>Trust</th></tr></thead><tbody>
                    ${rows.map(x => `<tr><td>${x.pid}</td><td><b>${x.s}</b></td>
                        <td><div style="position:relative;background:#eee;border-radius:4px;height:8px;width:100%;">
                            <div style="position:absolute;left:0;top:0;height:8px;border-radius:4px;width:${x.bar}%;background:${x.s >= 700 ? '#16a34a' : (x.s >= 400 ? '#d97706' : '#dc2626')};"></div>
                        </div></td></tr>`).join('')}
                    </tbody></table></div>`;
            } else { renderRaw('trustResult', r); }
        }
        async function trustList() {
            renderRaw('trustResult', { success: true, data: (await fetchAPI('/api/trust/scores')).data });
        }

        // --- F12: Live defense ---
        async function defenseRun() {
            const r = await postJSON('/api/defense/run', {
                attack_type: document.getElementById('dfAttack').value,
                target: document.getElementById('dfTarget').value.trim(), auto_respond: true
            });
            const el = document.getElementById('defenseResult');
            el.innerHTML = r.success
                ? `<div class="alert alert-danger show"><b>Attack ${r.data.attack} detected</b> (severity ${r.data.severity}) — auto-response: ${r.data.auto_response}. Status: ${r.data.status}</div>`
                : `<div class="alert alert-error show">${r.error}</div>`;
        }
        async function defenseList() {
            const r = await fetchAPI('/api/defense/list');
            const el = document.getElementById('defenseResult');
            if (!(r.data || []).length) { el.innerHTML = `<div class="alert alert-info show">No defense events yet.</div>`; return; }
            el.innerHTML = `<div class="table-container" style="max-height:220px;overflow:auto;">
                <table><thead><tr><th>Severity</th><th>Attack</th><th>Target</th><th>Auto-response</th><th>Status</th><th>ID</th></tr></thead><tbody>
                ${r.data.map(e => `<tr><td><b>${e.severity}</b></td><td>${e.attack}</td><td>${e.target || 'all'}</td>
                    <td>${e.auto_response}</td><td><span class="pill ${e.status === 'CONTAINED' ? 'pill-green' : 'pill-blue'}">${e.status}</span></td>
                    <td style="font-size:0.7rem;">${e.detection_id}</td></tr>`).join('')}
                </tbody></table></div>`;
        }

        // --- F13: Physical check-in QR ---
        async function checkinCreate() {
            const r = await postJSON('/api/checkin/create', {
                public_id: document.getElementById('ckPublicId').value.trim(),
                facility: document.getElementById('ckFacility').value.trim() || 'SEC-7',
                valid_minutes: parseInt(document.getElementById('ckMinutes').value) || 15,
                ppe: ['helmet', 'vest']
            });
            const el = document.getElementById('ckResult');
            if (r.success) {
                el.innerHTML = `<div class="alert alert-success show"><b>Check-in pass issued</b> (facility ${r.data.facility}, expires ${new Date(r.data.expires_at * 1000).toLocaleTimeString()})<br>
                    <span style="font-size:0.78rem;">token: ${r.data.token}</span><br>
                    <span style="font-size:0.7rem;">QR payload: <code>${r.data.qr_payload}</code></span></div>`;
                document.getElementById('ckToken').value = r.data.token;
            } else { renderRaw('ckResult', r); }
        }
        async function checkinVerify() {
            const r = await postJSON('/api/checkin/verify', {
                token: document.getElementById('ckToken').value.trim(),
                facility: document.getElementById('ckFacility').value.trim() || 'SEC-7',
                location_ok: true
            });
            const el = document.getElementById('ckResult');
            el.innerHTML = r.success && r.data && r.data.granted
                ? `<div class="alert alert-success show"><b>GATE OPEN</b> — ${r.data.public_id} admitted to ${r.data.facility}. PPE required: ${r.data.ppe_required.join(', ')}.</div>`
                : `<div class="alert alert-warning show">${r.data && r.data.reason || 'Verification failed'}</div>`;
        }
        async function checkinList() {
            renderRaw('ckResult', { success: true, data: (await fetchAPI('/api/checkin/list')).data });
        }

        // ============================================================
        // FEATURE SUITE v3 - G-series: Break-glass / Adaptive step-up /
        //   TOTP / CRL+ZK / honeytoken / velocity / k-ANON /
        //   attestation / PII redaction / federation
        // ============================================================
        function _gid(id) { return document.getElementById(id); }

        // --- G1: Break-glass emergency access ledger ---
        let __bgCurrent = null;
        async function bgRequest() {
            const r = await postJSON('/api/breakglass/request', {
                public_id: _gid('bgPublicId').value.trim(),
                resource: _gid('bgResource').value.trim(),
                reason: 'incident-response',
                requester: _gid('bgRequester').value.trim() || 'SYSTEM'
            });
            const el = _gid('bgResult');
            if (r.success) {
                const d = r.data;
                __bgCurrent = d.emergency_id;
                el.innerHTML = `<div class="alert alert-danger show"><b>EMERGENCY WINDOW OPEN</b> <code>${d.emergency_id}</code><br>` +
                    `Requester <b>${escapeHtml(d.record.requester)}</b> opened high-privilege access to <b>${escapeHtml(d.record.resource)}</b>. ` +
                    `Auto-expires in ${d.window_s}s. A second operator MUST approve before use.</div>`;
            } else { renderRaw('bgResult', r); }
        }
        async function bgApprove() {
            if (!__bgCurrent) __bgCurrent = prompt('Emergency window id to approve?');
            if (!__bgCurrent) return;
            const r = await postJSON('/api/breakglass/approve', {
                emergency_id: __bgCurrent, approver: 'CO.OPERATOR', override: false
            });
            const el = _gid('bgResult');
            el.innerHTML = r.success
                ? `<div class="alert alert-success show">Window <code>${__bgCurrent}</code> <b>APPROVED</b> by second operator CO.OPERATOR.</div>`
                : `<div class="alert alert-error show">${escapeHtml(r.error || (r.data && r.data.reason) || 'Approval failed')}</div>`;
        }
        async function bgUse() {
            if (!__bgCurrent) __bgCurrent = prompt('Emergency window id to use?');
            if (!__bgCurrent) return;
            const r = await postJSON('/api/breakglass/use', {
                emergency_id: __bgCurrent,
                public_id: _gid('bgPublicId').value.trim(),
                resource: _gid('bgResource').value.trim()
            });
            const el = _gid('bgResult');
            el.innerHTML = r.success
                ? `<div class="alert alert-danger show"><b>BREAK-GLASS ACCESS USED</b> <code>${__bgCurrent}</code> - audited on-chain and fed to the anomaly scorer.</div>`
                : `<div class="alert alert-error show">${escapeHtml(r.error || (r.data && r.data.reason) || 'Use failed')}</div>`;
        }
        async function bgList() {
            renderRaw('bgResult', { success: true, data: (await fetchAPI('/api/breakglass/list')).data });
        }

        // --- G2: Adaptive (JIT) step-up authentication ---
        let __adCurrent = null;
        async function adEvaluate() {
            const r = await postJSON('/api/adaptive/evaluate', {
                public_id: _gid('adPublicId').value.trim(),
                resource: _gid('adResource').value.trim(),
                context: { source: 'ui' }
            });
            const el = _gid('adResult');
            if (!r.success) { renderRaw('adResult', r); return; }
            const d = r.data;
            const cls = d.decision === 'GRANTED' ? 'alert-success'
                : d.decision === 'STEP_UP' ? 'alert-warning' : 'alert-danger';
            el.innerHTML = `<div class="alert ${cls} show"><b>${escapeHtml(d.decision)}</b> - risk score ${d.risk}/100<br>` +
                `<span style="font-size:0.75rem;">${escapeHtml((d.reasons || []).join('; ') || 'no risk factors')}</span></div>`;
        }
        async function adStepup() {
            const r = await postJSON('/api/adaptive/stepup/request', {
                public_id: _gid('adPublicId').value.trim(),
                resource: _gid('adResource').value.trim(),
                factor: 'TOTP'
            });
            const el = _gid('adResult');
            if (!r.success) { renderRaw('adResult', r); return; }
            __adCurrent = r.data.stepup_id;
            el.innerHTML = `<div class="alert alert-warning show"><b>STEP-UP CHALLENGE OPENED</b> <code>${escapeHtml(r.data.stepup_id)}</code><br>` +
                `<span style="font-size:0.75rem;">required factor: ${escapeHtml(r.data.required_factor)}. Nothing is granted until it is fulfilled.</span></div>`;
        }
        async function adFulfill() {
            if (!__adCurrent) __adCurrent = prompt('Step-up challenge id?');
            if (!__adCurrent) return;
            const r = await postJSON('/api/adaptive/stepup/fulfill', {
                stepup_id: __adCurrent, factor: 'TOTP', evidence: 'ok'
            });
            const el = _gid('adResult');
            el.innerHTML = r.success
                ? `<div class="alert alert-success show"><b>JIT GRANT ISSUED</b> <code>${escapeHtml(r.data.grant_id)}</code> for challenge ${escapeHtml(__adCurrent)}<br>` +
                  `<span style="font-size:0.75rem;">expires_at: ${escapeHtml(String(r.data.expires_at))} - time-boxed on-chain.</span></div>`
                : `<div class="alert alert-error show">${escapeHtml(r.error || (r.data && r.data.reason) || 'Fulfill failed')}</div>`;
        }
        async function adList() {
            renderRaw('adResult', {
                success: true,
                data: {
                    stepups: (await fetchAPI('/api/adaptive/stepup/list')).data,
                    decisions: (await fetchAPI('/api/adaptive/decisions')).data
                }
            });
        }

        // --- G3: TOTP second factor (RFC 6238) ---
        async function tpEnroll() {
            const r = await postJSON('/api/totp/enroll', { public_id: _gid('tpPublicId').value.trim() });
            const el = _gid('tpResult');
            if (!r.success) { renderRaw('tpResult', r); return; }
            const d = r.data;
            el.innerHTML = `<div class="alert alert-info show"><b>TOTP ENROLLED</b> - secret revealed below (scan or type it into an authenticator)<br>` +
                `<span style="font-size:0.72rem;">digits: ${d.digits} - period: ${d.step}s</span></div>` +
                `<div class="code-display copyable" style="font-size:0.8rem;word-break:break-all;" onclick="copyToClipboard('${d.secret_b32}')">${escapeHtml(d.secret_b32)}</div>` +
                `<div style="font-size:0.68rem;color:var(--text-light);word-break:break-all;margin-top:0.3rem;">${escapeHtml(d.otpauth_uri)}</div>` +
                `<div class="alert alert-warning show" style="margin-top:0.5rem;">current code: <b>${escapeHtml(d.current_code)}</b></div>`;
        }
        async function tpVerify() {
            const r = await postJSON('/api/totp/verify', {
                public_id: _gid('tpPublicId').value.trim(),
                code: _gid('tpCode').value.trim()
            });
            const el = _gid('tpResult');
            el.innerHTML = r.success
                ? `<div class="alert alert-success show"><b>CODE VERIFIED</b> (matched window: ${r.data.matched_window})</div>`
                : `<div class="alert alert-error show">${escapeHtml(r.error || (r.data && r.data.error) || 'Verification failed')}</div>`;
        }
        async function tpReset() {
            const r = await postJSON('/api/totp/reset', { public_id: _gid('tpPublicId').value.trim() });
            const el = _gid('tpResult');
            el.innerHTML = r.success
                ? `<div class="alert alert-warning show"><b>SEED REVOKED</b> - ${escapeHtml(r.data.public_id)}'s authenticator is now dead on-chain.</div>`
                : `<div class="alert alert-error show">${escapeHtml(r.error || (r.data && r.data.error) || 'Reset failed')}</div>`;
        }
        async function tpList() {
            renderRaw('tpResult', { success: true, data: (await fetchAPI('/api/totp/list')).data });
        }

        // --- G6: Physical velocity / teleport detection ---
        function _geo(id) {
            const p = _gid(id).value.split(',').map(function (s) { return parseFloat(s.trim()); });
            return (p.length === 2 && p.every(function (n) { return !isNaN(n); })) ? p : null;
        }
        async function vlAnomaly() {
            const fromGeo = _geo('vlFromGeo'), toGeo = _geo('vlToGeo');
            if (!fromGeo || !toGeo) { _gid('vlResult').innerHTML = '<div class="alert alert-error show">Both geo fields must be "lat,lng".</div>'; return; }
            const r = await postJSON('/api/velocity/anomaly', {
                public_id: _gid('vlPublicId').value.trim(),
                from_facility: _gid('vlFrom').value.trim(),
                to_facility: _gid('vlTo').value.trim(),
                from_geo: fromGeo, to_geo: toGeo,
                elapsed_minutes: parseFloat(_gid('vlMinutes').value) || 0,
                max_speed_kmh: 900
            });
            const el = _gid('vlResult');
            if (!r.success) { renderRaw('vlResult', r); return; }
            const d = r.data;
            const cls = d.flag === 'NORMAL' ? 'alert-success' : d.flag === 'SUSPICIOUS' ? 'alert-warning' : 'alert-danger';
            el.innerHTML = `<div class="alert ${cls} show"><b>${escapeHtml(d.flag)}</b> - ${escapeHtml(d.reason)}<br>` +
                `<span style="font-size:0.75rem;">${d.distance_km} km in ${d.elapsed_minutes} min = ${d.speed_kmh} km/h (ceiling ${d.max_speed_kmh} km/h). action: ${escapeHtml(d.action)}</span></div>`;
        }
        async function vlPlausible() {
            const fromGeo = _geo('vlFromGeo'), toGeo = _geo('vlToGeo');
            if (!fromGeo || !toGeo) { _gid('vlResult').innerHTML = '<div class="alert alert-error show">Both geo fields must be "lat,lng".</div>'; return; }
            const r = await postJSON('/api/velocity/evaluate', {
                from_geo: fromGeo, to_geo: toGeo,
                elapsed_minutes: 45, max_speed_kmh: 900
            });
            renderRaw('vlResult', r);
        }
        async function vlList() {
            renderRaw('vlResult', { success: true, data: (await fetchAPI('/api/velocity/events')).data });
        }

        // --- G8: PII redaction / right-to-erasure ---
        async function rdApply() {
            const r = await postJSON('/api/redact/apply', {
                public_id: _gid('rdPublicId').value.trim(),
                field: _gid('rdField').value.trim()
            });
            const el = _gid('rdResult');
            el.innerHTML = r.success
                ? `<div class="alert alert-success show"><b>FIELD REDACTED</b> - ${escapeHtml(r.data.field)} of ${escapeHtml(r.data.public_id)}<br>` +
                  `<span style="font-size:0.75rem;">tombstone hash: ${escapeHtml(r.data.value_hash)} (plaintext not stored)</span></div>`
                : `<div class="alert alert-error show">${escapeHtml(r.error || (r.data && r.data.error) || 'Redaction failed')}</div>`;
        }
        async function rdCheck() {
            const r = await postJSON('/api/redact/check', {
                public_id: _gid('rdPublicId').value.trim(),
                field: _gid('rdField').value.trim()
            });
            const el = _gid('rdResult');
            if (!r.success) { renderRaw('rdResult', r); return; }
            const d = r.data;
            el.innerHTML = d.redacted
                ? `<div class="alert alert-success show"><b>REDACTED</b> - ${escapeHtml(d.field)} of ${escapeHtml(d.public_id)} was tombstoned.<br>` +
                  `<span style="font-size:0.75rem;">redacted_at: ${escapeHtml(String(d.redacted_at))}</span></div>`
                : `<div class="alert alert-warning show"><b>NOT REDACTED</b> - ${escapeHtml(d.field)} of ${escapeHtml(d.public_id)} is still in plaintext.</div>`;
        }
        async function rdList() {
            renderRaw('rdResult', { success: true, data: (await fetchAPI('/api/redact/list')).data });
        }

        // --- G4: Global revocation list + ZK status proof ---
        async function crlRevoke() {
            const r = await postJSON('/api/crl/revoke', {
                public_id: _gid('crlPublicId').value.trim(),
                reason: _gid('crlReason').value.trim() || 'Revoked by administrator'
            });
            const el = _gid('crlResult');
            el.innerHTML = r.success
                ? `<div class="alert alert-danger show"><b>ADDED TO CRL</b> - ${escapeHtml(r.data.public_id)} is now <b>REVOKED</b><br><span style="font-size:0.7rem;">commit: ${r.data.commit}</span></div>`
                : `<div class="alert alert-error show">${escapeHtml(r.error || (r.data && r.data.reason))}</div>`;
        }
        async function crlUnrevoke() {
            const r = await postJSON('/api/crl/unrevoke', { public_id: _gid('crlPublicId').value.trim() });
            const el = _gid('crlResult');
            el.innerHTML = r.success
                ? `<div class="alert alert-success show"><b>REMOVED FROM CRL</b> - ${escapeHtml(r.data.public_id)} back to <b>ACTIVE</b>.</div>`
                : `<div class="alert alert-error show">${escapeHtml(r.error || (r.data && r.data.reason))}</div>`;
        }
        async function crlCheck() {
            const r = await fetchAPI('/api/crl/check?public_id=' + encodeURIComponent(_gid('crlPublicId').value.trim()));
            renderRaw('crlResult', r);
        }
        async function crlList() {
            renderRaw('crlResult', { success: true, data: (await fetchAPI('/api/crl/list')).data });
        }
        async function crlZkProveVerify() {
            const pid = _gid('crlPublicId').value.trim() || prompt('Identity for ZK status proof?');
            if (!pid) return;
            const el = _gid('crlResult');
            const ch = await fetchAPI('/api/crl/zk/challenge');
            const proved = await postJSON('/api/crl/zk/prove', { public_id: pid, challenge: ch.data.challenge });
            if (!proved.success) { renderRaw('crlResult', proved); return; }
            const verdict = await postJSON('/api/crl/zk/verify', { proof_token: proved.data.proof_token, challenge: ch.data.challenge });
            el.innerHTML = `<div class="alert ${verdict.data.revoked ? 'alert-danger' : 'alert-success'} show">` +
                `<b>ZK STATUS PROOF</b> - the (hidden) identity is <b>${verdict.data.status}</b><br>` +
                `<span style="font-size:0.7rem;">proof_token ${String(proved.data.proof_token).slice(0, 16)}... &middot; challenge ${String(ch.data.challenge).slice(0, 16)}...</span><br>` +
                `${escapeHtml(verdict.data.message || '')}</div>`;
        }
        async function crlZkDemo() {
            renderRaw('crlResult', await fetchAPI('/api/crl/zk/demo'));
        }

        // --- G5: Honeytoken deception trap ---
        let __htCurrent = null;
        async function htPlant() {
            const r = await postJSON('/api/honeytoken/plant', {
                public_id: _gid('htPublicId').value.trim(),
                resource: _gid('htResource').value.trim() || 'protected_data',
                label: 'service-account-' + Math.random().toString(36).slice(2, 7)
            });
            const el = _gid('htResult');
            if (!r.success) { renderRaw('htResult', r); return; }
            __htCurrent = r.data.honeytoken_id;
            el.innerHTML = `<div class="alert alert-danger show"><b>HONEYTOKEN PLANTED</b> <code>${escapeHtml(r.data.honeytoken_id)}</code> on ${escapeHtml(r.data.resource)}<br>` +
                `<span style="font-size:0.75rem;">bait secret: <code>${escapeHtml(r.data.bait)}</code> - nothing legitimate ever uses it, so any touch is an attacker.</span></div>`;
        }
        async function htTouch() {
            if (!__htCurrent) __htCurrent = prompt('Honeytoken id to touch?');
            if (!__htCurrent) return;
            const r = await postJSON('/api/honeytoken/touch', {
                honeytoken_id: __htCurrent,
                presented_by: _gid('htPublicId').value.trim() || 'UNKNOWN'
            });
            const el = _gid('htResult');
            if (!r.success) { renderRaw('htResult', r); return; }
            const d = r.data;
            el.innerHTML = `<div class="alert alert-error show"><b>HONEYTOKEN TOUCHED - DECEPTION CONFIRMED</b> <code>${escapeHtml(d.alert_id)}</code><br>` +
                `Claimed identity <b>${escapeHtml(d.presented_by)}</b> presented the decoy. ` +
                `<span class="pill ${d.severity === 'HIGH' ? 'pill-red' : 'pill-yellow'}">${escapeHtml(d.severity)}</span> score ${d.score}.<br>` +
                `<span style="font-size:0.75rem;">status: ${escapeHtml(d.status)} - fed to the anomaly engine and anchored as HONEYTOKEN-TOUCH.</span></div>`;
        }
        async function htList() {
            renderRaw('htResult', { success: true, data: (await fetchAPI('/api/honeytoken/list')).data });
        }

        // --- G7: k-anonymity aggregate reports ---
        async function kaStats() {
            const k = parseInt(_gid('kaK').value) || 3;
            renderRaw('kaResult', await fetchAPI('/api/stats/k-anonymity?k=' + k));
        }

        // --- G9: Measured-boot device attestation ---
        function g9Measure() {
            const v = _gid('g9Measure').value.trim();
            if (!v) return [];
            return v.includes(',') ? v.split(',').map(function (s) { return s.trim(); }).filter(Boolean) : v;
        }
        async function g9Register() {
            const r = await postJSON('/api/attest/register', {
                public_id: _gid('g9PublicId').value.trim(),
                device_hash: _gid('g9Device').value.trim(),
                measure: g9Measure(),
                label: _gid('g9Label').value.trim()
            });
            const el = _gid('g9Result');
            el.innerHTML = r.success
                ? `<div class="alert alert-success show"><b>GOLDEN QUOTE ANCHORED</b> for ${escapeHtml(r.data.device_hash)}<br><span style="font-size:0.7rem;">on-chain sha256 digest: ${r.data.golden}</span></div>`
                : `<div class="alert alert-error show">${escapeHtml(r.error || (r.data && r.data.reason))}</div>`;
        }
        async function g9Login(tampered) {
            const measure = tampered ? 'TAMPERED-FIRMWARE-' + Date.now() : g9Measure();
            const r = await postJSON('/api/attest/login', {
                public_id: _gid('g9PublicId').value.trim(),
                device_hash: _gid('g9Device').value.trim(),
                measure: measure
            });
            const el = _gid('g9Result');
            const d = r.data || {};
            el.innerHTML = r.success && d.granted
                ? `<div class="alert alert-success show"><b>GATE OPEN - MEASURED-BOOT PASSED</b><br>${escapeHtml(d.reason || '')}</div>`
                : `<div class="alert alert-danger show"><b>ATTESTATION DENIED</b><br>${escapeHtml(d.reason || r.error || 'denied')}</div>`;
        }
        async function g9Revoke() {
            const r = await postJSON('/api/attest/revoke', {
                public_id: _gid('g9PublicId').value.trim(),
                device_hash: _gid('g9Device').value.trim()
            });
            const el = _gid('g9Result');
            el.innerHTML = r.success
                ? `<div class="alert alert-warning show"><b>DEVICE ATTESTATION REVOKED</b> - ${escapeHtml(r.data.device_hash)}'s quote is no longer trusted.</div>`
                : `<div class="alert alert-error show">${escapeHtml(r.error || (r.data && r.data.reason))}</div>`;
        }
        async function g9List() {
            renderRaw('g9Result', { success: true, data: (await fetchAPI('/api/attest/list')).data });
        }

        // --- G10: Cross-org federation ---
        async function fedDemo() {
            const r = await fetchAPI('/api/federation/demo');
            if (!r.success) { renderRaw('g10Result', r); return; }
            const d = r.data;
            const el = _gid('g10Result');
            el.innerHTML = `<div class="alert alert-info show">${escapeHtml(d.announce)}</div>` +
                `<div class="table-container" style="max-height:200px;overflow:auto;"><table><thead><tr><th>Issuer org</th><th>Trust anchor</th><th>Cross-org verdict</th></tr></thead><tbody>` +
                `<tr><td>${escapeHtml(d.trusted_org)}</td><td style="font-size:0.65rem;">${escapeHtml(d.trusted_anchor)}</td>` +
                `<td><span class="pill ${d.trusted_presentation.granted ? 'pill-green' : 'pill-red'}">${d.trusted_presentation.granted ? 'GRANTED' : 'DENIED'}</span></td></tr>` +
                `<tr><td>${escapeHtml(d.rogue_org)}</td><td style="font-size:0.65rem;">not federated (untrusted)</td>` +
                `<td><span class="pill ${d.rogue_presentation.granted ? 'pill-green' : 'pill-red'}">${d.rogue_presentation.granted ? 'GRANTED' : 'DENIED'}</span></td></tr>` +
                `</tbody></table></div>` +
                `<div class="alert ${d.rogue_presentation.granted ? 'alert-danger' : 'alert-success'} show" style="margin-top:0.4rem;">${escapeHtml(d.conclusion)}</div>`;
        }
        async function fedList() {
            renderRaw('g10Result', { success: true, data: (await fetchAPI('/api/federation/list')).data });
        }
        async function fedRegister() {
            const r = await postJSON('/api/federation/register', {
                org_id: _gid('fedOrgId').value.trim(),
                trust: !!_gid('fedTrust').checked
            });
            const el = _gid('g10Result');
            el.innerHTML = r.success
                ? `<div class="alert alert-success show"><b>ORG FEDERATED</b> - ${escapeHtml(r.data.org_id)}<br><span style="font-size:0.7rem;">anchored DID public key: ${r.data.anchor_fingerprint}</span></div>`
                : `<div class="alert alert-error show">${escapeHtml(r.error || (r.data && r.data.reason))}</div>`;
        }

        // ============================================================
        // FEATURE SUITE v3 - Dashboard posture / threat / point-in-time
        // ============================================================
        async function postureRefresh() {
            const r = await fetchAPI('/api/posture/score');
            const g = _gid('postureGauge');
            const b = _gid('postureBreakdown');
            const d = _gid('postureDetail');
            if (!r.success) { b.innerHTML = `<div class="alert alert-error show">${escapeHtml(r.error || 'failed')}</div>`; return; }
            const data = r.data;
            g.innerHTML = `<div class="posture-big"><span style="font-size:1.8rem;font-weight:700;color:${data.score >= 75 ? 'var(--success)' : data.score >= 50 ? 'var(--warning, #e8a33d)' : 'var(--danger)'};">${data.score}</span>/100
                <span class="pill ${data.grade === 'A' || data.grade === 'B' ? 'pill-green' : 'pill-red'}" style="vertical-align:middle;">GRADE ${data.grade}</span></div>
                <div style="font-size:0.72rem;color:var(--text-dim);margin-top:0.3rem;">${data.chain_valid ? 'chain VALID' : 'chain TAMPERED'} &middot; trend: ${(data.trend || []).join(' &rsaquo; ')}</div>`;
            b.innerHTML = `<table><tbody>` + Object.entries(data.breakdown || {}).map(([k, v]) =>
                `<tr><td style="font-size:0.75rem;">${escapeHtml(k.replace(/_/g, ' '))}</td>
                <td style="font-size:0.75rem;">${Number(v.score).toFixed(0)}</td>
                <td style="font-size:0.7rem;color:var(--text-dim);">${escapeHtml(v.detail || '')}</td></tr>`).join('') + `</tbody></table>`;
            d.innerHTML = Object.entries(data.breakdown || {}).map(([k, v]) =>
                `<div class="hint" style="margin-top:0.3rem;"><b>${escapeHtml(k.replace(/_/g, ' '))}</b> ${Number(v.score).toFixed(1)}/100 &middot; ${escapeHtml(v.detail || '')}</div>`).join('');
        }
        async function threatBoard() {
            const r = await fetchAPI('/api/threat/board');
            const el = _gid('threatResult');
            if (!r.success) { renderRaw('threatResult', r); return; }
            const ev = (r.data.events || []);
            if (!ev.length) { el.innerHTML = `<div class="alert alert-success show">No incidents on the board right now.</div>`; return; }
            const rankOrder = r.data.severity_rank || { HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4 };
            const pill = s => `pill pill-${(s === 'CRITICAL' || s === 'HIGH') ? 'red' : s === 'MEDIUM' ? 'orange' : 'green'}`;
            ev.sort((a, b) => (rankOrder[a.severity] ?? 9) - (rankOrder[b.severity] ?? 9));
            el.innerHTML = `<div class="table-container" style="max-height:340px;overflow:auto;"><table><thead><tr><th>Severity</th><th>Source</th><th>Event</th></tr></thead><tbody>` +
                ev.map(e => `<tr><td><span class="${pill(e.severity)}">${escapeHtml(e.severity)}</span></td>
                <td style="font-size:0.72rem;">${escapeHtml(e.source)}</td>
                <td style="font-size:0.72rem;">${escapeHtml(e.title)}<br><span style="color:var(--text-dim);">${escapeHtml(e.detail || '')}</span></td></tr>`).join('') +
                `</tbody></table></div><div class="hint">${ev.length} incident(s) on the SOC feed.</div>`;
        }
        async function pitLabel() {
            const maxB = parseInt(_gid('totalBlocks').textContent || '0', 10) - 1;
            const s = _gid('pitSlider');
            if (maxB > 0 && parseInt(s.max, 10) === 0) s.max = Math.max(1, maxB);
            _gid('pitSliderLabel').textContent = `block ${s.value}`;
        }
        async function pitQuery() {
            const r = await postJSON('/api/audit/point-in-time', {
                block_index: parseInt(_gid('pitSlider').value, 10),
                resource: _gid('pitResource').value.trim()
            });
            const el = _gid('pitResult');
            if (!r.success) { renderRaw('pitResult', r); return; }
            const s = r.data.snapshot;
            const rows = (s.matches || []).map(m => `<tr><td style="font-size:0.72rem;">${escapeHtml(m.public_id)}</td>
                <td style="font-size:0.72rem;">${escapeHtml(m.name)}</td>
                <td><span class="pill ${m.status === 'ACTIVE' ? 'pill-green' : 'pill-red'}">${escapeHtml(m.status)}</span></td>
                <td><span class="pill ${m.access === 'GRANTED' ? 'pill-green' : 'pill-red'}">${escapeHtml(m.access)}</span></td></tr>`).join('');
            el.innerHTML = `<div class="alert alert-info show">Snapshot at <b>block ${s.blocks_before}</b> (${escapeHtml(s.target_ts_display)}). Who could access <b>${escapeHtml(s.resource)}</b> then:</div>
                <div class="table-container" style="max-height:260px;overflow:auto;"><table><thead><tr><th>Identity</th><th>Name</th><th>Status</th><th>Access</th></tr></thead><tbody>${rows || '<tr><td colspan="4">no matches</td></tr>'}</tbody></table></div>`;
        }

        // ============================================================
        // FEATURE SUITE v3 - Identity: duplicate / bulk / join
        // ============================================================
        async function dupCheck() {
            const r = await postJSON('/api/identity/duplicate-check', {
                name: _gid('dupName').value.trim(),
                email: _gid('dupEmail').value.trim(),
                id_number: _gid('dupId').value.trim()
            });
            const el = _gid('dupResult');
            if (!r.success) { renderRaw('dupResult', r); return; }
            const d = r.data;
            const cands = (d.candidates || []).map(c => `<tr>
                <td style="font-size:0.72rem;">${escapeHtml(c.public_id)}</td>
                <td style="font-size:0.72rem;">${(c.flags || []).map(f => `<span class="pill pill-orange">${escapeHtml(f)}</span>`).join(' ')}</td>
                <td style="font-size:0.72rem;">sim ${c.name_similarity} / ${c.email_similarity}${c.id_match ? ' / ID match' : ''}</td>
                <td>${c.blocked ? '<span class="pill pill-red">BLOCKED</span>' : '<span class="pill pill-green">review</span>'}</td></tr>`).join('');
            el.innerHTML = `<div class="alert ${d.verdict === 'CLEAR' ? 'alert-success' : d.verdict === 'BLOCKED' ? 'alert-danger' : 'alert-warning'} show"><b>VERDICT: ${d.verdict}</b> - ${escapeHtml(d.heuristic)}</div>
                ${cands ? `<div class="table-container" style="max-height:200px;overflow:auto;"><table><thead><tr><th>Candidate</th><th>Flags</th><th>Similarity</th><th>Action</th></tr></thead><tbody>${cands}</tbody></table></div>` : '<div class="hint">No near-matches on-chain.</div>'}`;
        }
        async function dupFlags() { renderRaw('dupResult', { success: true, data: (await fetchAPI('/api/identity/duplicate-flags')).data }); }
        async function bulkOnboard() {
            const lines = _gid('bulkCsv').value.split(/\r?\n/).map(l => l.trim()).filter(Boolean);
            const rows = lines.map(l => {
                const p = l.split('|').map(s => s.trim());
                return { name: p[0] || 'Unnamed', id_number: p[1] || '', role: p[2] || 'EMPLOYEE',
                         email: p[3] || '', access_level: 1, allowed_resources: 'personal_record' };
            });
            const r = await postJSON('/api/onboard/bulk', { rows, label: _gid('bulkLabel').value.trim() });
            const el = _gid('bulkResult');
            if (!r.success) { renderRaw('bulkResult', r); return; }
            el.innerHTML = `<div class="alert alert-success show"><b>Batch ${escapeHtml(r.data.batch_id)}</b>: ${r.data.success_count}/${r.data.total} on-boarded</div>` +
                `<div class="table-container" style="max-height:220px;overflow:auto;"><table><thead><tr><th>#</th><th>Identity</th><th>Block Hash Receipt</th></tr></thead><tbody>` +
                r.data.receipts.map(x => `<tr><td style="font-size:0.7rem;">${x.row}</td><td style="font-size:0.7rem;">${escapeHtml(x.public_id)}</td><td style="font-size:0.7rem;font-family:monospace;">${escapeHtml(x.receipt || x.error || '')}</td></tr>`).join('') +
                `</tbody></table></div>`;
        }
        async function bulkBatches() { renderRaw('bulkResult', { success: true, data: (await fetchAPI('/api/onboard/batches')).data }); }
        async function joinSubmit() {
            let payload = {};
            try { payload = JSON.parse(_gid('joinPayload').value); }
            catch (e) { _gid('joinResult').innerHTML = `<div class="alert alert-error show">Invalid JSON payload</div>`; return; }
            const r = await postJSON('/api/join/request', { identity_data: payload });
            const el = _gid('joinResult');
            el.innerHTML = r.success
                ? `<div class="alert alert-success show"><b>JOIN ${r.data.join_id}</b> submitted as PENDING - awaiting admin approval.</div>`
                : `<div class="alert alert-error show">${escapeHtml(r.error || (r.data && r.data.reason))}</div>`;
        }
        async function joinApprove() {
            const r = await postJSON('/api/join/approve', { join_id: _gid('joinId').value.trim(), approver: 'admin' });
            const el = _gid('joinResult');
            el.innerHTML = r.success
                ? `<div class="alert alert-success show"><b>APPROVED ${r.data.join_id}</b> - minted identity ${escapeHtml(r.data.identity.public_id)} (block ${r.data.identity.block_index})</div>`
                : `<div class="alert alert-error show">${escapeHtml(r.error || (r.data && r.data.reason))}</div>`;
        }
        async function joinReject() {
            const r = await postJSON('/api/join/reject', { join_id: _gid('joinId').value.trim(), reason: 'declined', approver: 'admin' });
            const el = _gid('joinResult');
            el.innerHTML = r.success
                ? `<div class="alert alert-warning show">REJECTED ${r.data.join_id}</div>`
                : `<div class="alert alert-error show">${escapeHtml(r.error || (r.data && r.data.reason))}</div>`;
        }

        // ============================================================
        // FEATURE SUITE v3 - ZK range / post-quantum / key transparency / liveness
        // ============================================================
        let lastZkProof = null;
        let lastPqSignatureB64 = '';
        async function zrProve() {
            const r = await postJSON('/api/zk/range/prove', {
                secret_value: parseInt(_gid('zrSecret').value, 10),
                min_bound: parseInt(_gid('zrBound').value, 10)
            });
            const el = _gid('zrResult');
            if (!r.success) { renderRaw('zrResult', r); return; }
            lastZkProof = r.data.proof || null;
            const p = lastZkProof;
            el.innerHTML = `<div class="alert ${p.satisfies ? 'alert-success' : 'alert-danger'} show"><b>${p.satisfies ? 'PROOF SATISFIES' : 'PROOF REFUTED'}</b> - ${escapeHtml(p.statement)}</div>` +
                `<div class="hint">commit ${escapeHtml(p.commit.c.slice(0, 20))}... &middot; revealed high digits: ${escapeHtml(p.revealed_prefix || 'none')} &middot; lower digits concealed.</div>`;
        }
        async function zrVerify() {
            if (!lastZkProof) { _gid('zrResult').innerHTML = `<div class="alert alert-warning show">Generate a range proof first.</div>`; return; }
            const r = await postJSON('/api/zk/range/verify', { proof: lastZkProof });
            const el = _gid('zrResult');
            if (!r.success) { renderRaw('zrResult', r); return; }
            el.innerHTML = `<div class="alert ${r.data.valid ? 'alert-success' : 'alert-danger'} show"><b>VERIFICATION ${r.data.valid ? 'PASSED' : 'FAILED'}</b> - clearance >= ${r.data.bound} without revealing the value.</div>
                <div class="hint">${escapeHtml(r.data.verification)} &middot; observed high digits: ${r.data.revealed_high_digits}</div>`;
        }
        async function pqRegister() {
            const r = await postJSON('/api/pq/register', { public_id: _gid('pqPublicId').value.trim() });
            const el = _gid('pqResult');
            if (!r.success) { renderRaw('pqResult', r); return; }
            lastPqSignatureB64 = r.data.signature_b64 || '';
            el.innerHTML = `<div class="alert alert-success show"><b>PQ IDENTITY ANCHORED</b> ${escapeHtml(r.data.public_id)}<br>
                <span style="font-size:0.7rem;">scheme: ${escapeHtml(r.data.pq_backend)} &middot; on-chain root: ${escapeHtml(r.data.pq_root.slice(0, 24))}...</span></div>
                <div class="hint">${escapeHtml(r.data.message)}</div>`;
        }
        async function pqAuth() {
            const el = _gid('pqResult');
            if (!lastPqSignatureB64) { el.innerHTML = `<div class="alert alert-warning show">Register a PQ identity first - its attestation is needed for the auth demo.</div>`; return; }
            const r = await postJSON('/api/pq/auth', { public_id: _gid('pqPublicId').value.trim(), signature_b64: lastPqSignatureB64, nonce: 'nonce-' + Date.now() });
            if (!r.success || !r.data.authenticated) {
                el.innerHTML = `<div class="alert alert-danger show"><b>AUTH ${r.data && r.data.authenticated === false ? 'DENIED' : 'FAILED'}</b> - ${escapeHtml(r.error || (r.data && r.data.reason))}</div>`;
                return;
            }
            el.innerHTML = `<div class="alert alert-success show"><b>AUTH GRANTED (HASH-BASED)</b> - ${escapeHtml(r.data.reason)}</div>`;
        }
        async function pqList() { renderRaw('pqResult', { success: true, data: (await fetchAPI('/api/pq/list')).data }); }
        async function ktRotate() {
            const r = await postJSON('/api/keytrans/rotate', {
                public_id: _gid('ktPublicId').value.trim(),
                new_key_fingerprint: _gid('ktFingerprint').value.trim(),
                rotated_by: 'identity-holder', reason: 'scheduled rotation'
            });
            const el = _gid('ktResult');
            el.innerHTML = r.success
                ? `<div class="alert alert-success show"><b>ROTATION LOGGED</b> for ${escapeHtml(r.data.public_id)}<br><span style="font-size:0.7rem;">${escapeHtml(r.data.record.hash)}</span></div>
                   <div class="hint">${escapeHtml(r.data.confirmation)}</div>`
                : `<div class="alert alert-error show">${escapeHtml(r.error || (r.data && r.data.reason))}</div>`;
        }
        async function ktChain() {
            const r = await postJSON('/api/keytrans/chain', { public_id: _gid('ktPublicId').value.trim() });
            const el = _gid('ktResult');
            if (!r.success) { renderRaw('ktResult', r); return; }
            el.innerHTML = `<div class="alert ${r.data.chain_verified ? 'alert-success' : 'alert-danger'} show"><b>CHAIN ${r.data.chain_verified ? 'VERIFIED' : 'BROKEN'}</b> - ${r.data.length} rotation record(s) for ${escapeHtml(r.data.public_id)}</div>` +
                `<div class="table-container" style="max-height:200px;overflow:auto;"><table><thead><tr><th>Key</th><th>By</th><th>Previous</th><th>Hash</th></tr></thead><tbody>` +
                (r.data.records || []).map(x => `<tr><td style="font-size:0.7rem;">${escapeHtml(x.new_key_fingerprint)}</td><td style="font-size:0.7rem;">${escapeHtml(x.rotated_by)}</td><td style="font-size:0.65rem;">${escapeHtml(x.previous)}</td><td style="font-size:0.65rem;">${escapeHtml(x.hash)}</td></tr>`).join('') +
                `</tbody></table></div>`;
        }
        async function ktListAll() { renderRaw('ktResult', { success: true, data: (await fetchAPI('/api/keytrans/list')).data }); }
        async function lvIssue() {
            const r = await postJSON('/api/liveness/issue', { public_id: _gid('lvPublicId').value.trim() });
            const el = _gid('lvResult');
            if (!r.success) { renderRaw('lvResult', r); return; }
            _gid('lvChallengeId').value = r.data.challenge_id;
            _gid('lvNonce').value = r.data.nonce;
            el.innerHTML = `<div class="alert alert-info show"><b>LIVENESS CHALLENGE ${r.data.challenge_id}</b><br><span style="font-size:0.72rem;">${escapeHtml(r.data.instructions)}</span></div>`;
        }
        async function lvVerify() {
            const r = await postJSON('/api/liveness/verify', {
                challenge_id: _gid('lvChallengeId').value.trim(),
                response_nonce: _gid('lvNonce').value.trim()
            });
            const el = _gid('lvResult');
            el.innerHTML = r.success
                ? `<div class="alert alert-success show"><b>LIVENESS VERIFIED</b> - ${escapeHtml(r.data.result)}</div>`
                : `<div class="alert alert-danger show">${escapeHtml(r.error || (r.data && r.data.reason))}</div>`;
        }

        // ============================================================
        // FEATURE SUITE v3 - Access: duress / two-person / step-up
        // ============================================================
        async function dupEnroll() {
            const r = await postJSON('/api/duress/register', {
                public_id: _gid('dupPublicId').value.trim(),
                duress_pin: _gid('dupPanicPin').value.trim(),
                normal_pin: _gid('dupNormalPin').value.trim()
            });
            const el = _gid('dupResult');
            el.innerHTML = r.success
                ? `<div class="alert alert-success show"><b>DURESS ENROLLED</b> for ${escapeHtml(r.data.public_id)}<br><span style="font-size:0.7rem;">${escapeHtml(r.data.message)}</span></div>`
                : `<div class="alert alert-error show">${escapeHtml(r.error || (r.data && r.data.reason))}</div>`;
        }
        async function dupAuth() {
            const r = await postJSON('/api/duress/authenticate', {
                public_id: _gid('dupPublicId').value.trim(),
                pin: _gid('dupTestPin').value.trim(),
                resource: _gid('dupResource').value.trim()
            });
            const el = _gid('dupResult');
            if (!r.success) { renderRaw('dupResult', r); return; }
            if (r.data.scenario === 'duress') {
                el.innerHTML = `<div class="alert ${r.data.alert_raised ? 'alert-danger' : 'alert-warning'} show">
                    <b>LOOKS LIKE NORMAL SUCCESS</b> &middot; duress pin accepted (granted=${escapeHtml(String(r.data.granted))}) but a <b>CRITICAL "${escapeHtml(r.data.alert_id || '')}"</b> alert was raised silently.</div>
                    <div class="hint">${escapeHtml(r.data.note)}</div>`;
            } else {
                el.innerHTML = `<div class="alert alert-success show"><b>NORMAL PIN</b> - plain success, no alert.</div>`;
            }
        }
        async function tpOpen() {
            const r = await postJSON('/api/twoperson/initiate', {
                resource: _gid('tpResource').value.trim(),
                viewer_a: _gid('tpViewerA').value.trim()
            });
            const el = _gid('tpResult');
            if (!r.success) { renderRaw('tpResult', r); return; }
            _gid('tpWindowId').value = r.data.window_id;
            el.innerHTML = `<div class="alert alert-warning show"><b>WINDOW ${r.data.window_id}</b> - ${escapeHtml(r.data.view)}</div>`;
        }
        async function tpWindowList() { renderRaw('tpResult', { success: true, data: (await fetchAPI('/api/twoperson/list')).data }); }
        async function tpCoauthorize() {
            const r = await postJSON('/api/twoperson/coauthorize', {
                window_id: _gid('tpWindowId').value.trim(),
                viewer_b: _gid('tpViewerB').value.trim()
            });
            const el = _gid('tpResult');
            el.innerHTML = r.success
                ? `<div class="alert alert-success show">${escapeHtml(r.data.view)}</div>`
                : `<div class="alert alert-danger show">${escapeHtml(r.error || (r.data && r.data.reason))}</div>`;
        }
        async function tpView() {
            const r = await postJSON('/api/twoperson/view', {
                window_id: _gid('tpWindowId').value.trim(),
                viewer: _gid('tpViewerA').value.trim()
            });
            const el = _gid('tpResult');
            el.innerHTML = r.success
                ? `<div class="alert alert-success show"><b>VIEW GRANTED</b> - ${escapeHtml(r.data.view)}</div>`
                : `<div class="alert alert-danger show"><b>VIEW DENIED</b> - ${escapeHtml(r.error || (r.data && r.data.reason))}</div>`;
        }
        async function rsEvaluate() {
            const r = await postJSON('/api/riskstepup/evaluate', {
                public_id: _gid('rsPublicId').value.trim(),
                resource: _gid('rsResource').value.trim()
            });
            const el = _gid('rsResult');
            if (!r.success) { renderRaw('rsResult', r); return; }
            el.innerHTML = `<div class="alert ${r.data.outcome.startsWith('HIGH') ? 'alert-danger' : r.data.outcome.startsWith('MED') ? 'alert-warning' : 'alert-success'} show">
                <b>${escapeHtml(r.data.outcome)}</b> - anomaly score ${r.data.anomaly_score.toFixed(0)}</div>
                <div class="hint">Mandatory factors: ${(r.data.factors || []).map(f => `<span class="pill pill-purple" style="margin-right:0.2rem;">${escapeHtml(f)}</span>`).join('')}</div>
                <div class="hint">${escapeHtml(r.data.interpretation)}</div>`;
        }
        async function rsList() { renderRaw('rsResult', { success: true, data: (await fetchAPI('/api/riskstepup/list')).data }); }

        // ============================================================
        // FEATURE SUITE v3 - Network: air-gap / partition / pinning
        // ============================================================
        async function agCreate() {
            const r = await postJSON('/api/airgap/create', {
                since_block: parseInt(_gid('agSince').value, 10),
                source_node: _gid('agNode').value.trim()
            });
            const el = _gid('agResult');
            el.innerHTML = r.success
                ? `<div class="alert alert-success show"><b>SYNC PACK ${r.data.pack_id}</b> - ${r.data.blocks} blocks signed from ${escapeHtml(r.data.source_node)}<br>
                    <span style="font-size:0.7rem;">head RSA signature: ${escapeHtml(r.data.head_signature ? r.data.head_signature.slice(0, 32) + '...' : '(head signature simulated - no oracle keypair yet)')}</span></div>
                    <div class="hint">${escapeHtml(r.data.carry_instructions)}</div>`
                : `<div class="alert alert-error show">${escapeHtml(r.error || (r.data && r.data.reason))}</div>`;
        }
        async function agList() { renderRaw('agResult', { success: true, data: (await fetchAPI('/api/airgap/list')).data }); }
        async function partStart() {
            const r = await postJSON('/api/partition/start', { label: 'PARTITION-WEST' });
            const el = _gid('partResult');
            if (!r.success) { renderRaw('partResult', r); return; }
            _gid('partDrill').value = r.data.drill_id;
            el.innerHTML = `<div class="alert alert-warning show"><b>DRILL ${r.data.drill_id}</b> - ${escapeHtml(r.data.message)}</div>`;
        }
        async function partMine(p) {
            const r = await postJSON('/api/partition/mine', { drill_id: _gid('partDrill').value.trim(), partition: p });
            const el = _gid('partResult');
            el.innerHTML = r.success
                ? `<div class="alert alert-info show">Partition <b>${escapeHtml(r.data.partition)}</b> mined block <b>${r.data.mined_index}</b> (head ${escapeHtml(r.data.head_hash.slice(0, 14))}...)</div>`
                : `<div class="alert alert-error show">${escapeHtml(r.error || (r.data && r.data.reason))}</div>`;
        }
        async function partHeal() {
            const r = await postJSON('/api/partition/heal', { drill_id: _gid('partDrill').value.trim() });
            const el = _gid('partResult');
            el.innerHTML = r.success
                ? `<div class="alert alert-success show"><b>HEALED</b> - ${escapeHtml(r.data.resolved)}</div>`
                : `<div class="alert alert-error show">${escapeHtml(r.error || (r.data && r.data.reason))}</div>`;
        }
        async function partLog() { renderRaw('partResult', { success: true, data: (await fetchAPI('/api/partition/log')).data }); }
        async function pinStatus() { renderRaw('pinResult', { success: true, data: (await fetchAPI('/api/pinning/status')).data }); }
        async function pinAssign() {
            const r = await postJSON('/api/pinning/assign', { cid: _gid('pinCid').value.trim(), node_id: _gid('pinNode').value.trim() });
            const el = _gid('pinResult');
            el.innerHTML = r.success
                ? `<div class="alert alert-success show"><b>PINNED</b> ${escapeHtml(r.data.cid)} on ${(r.data.pinned_on || []).join(', ')} (${r.data.replicas} replica(s))</div>`
                : `<div class="alert alert-error show">${escapeHtml(r.error || (r.data && r.data.reason))}</div>`;
        }
        async function pinFail() {
            const r = await postJSON('/api/pinning/node-fail', { node_id: _gid('pinNode').value.trim() });
            const el = _gid('pinResult');
            el.innerHTML = r.success
                ? `<div class="alert alert-warning show"><b>NODE LOST</b> - ${r.data.documents_re_pinned} document(s) re-pinned: ${(r.data.moved || []).map(m => `${escapeHtml(m.cid)} -> ${escapeHtml(m['re-pinned_to'].join(','))}`).join('; ')}</div>`
                : `<div class="alert alert-error show">${escapeHtml(r.error || (r.data && r.data.reason))}</div>`;
        }

        // ============================================================
        // FEATURE SUITE v3 - Assets: firmware / provenance / recall
        // ============================================================
        async function fwAnchor() {
            const r = await postJSON('/api/firmware/register', {
                unit_id: _gid('fwUnit').value.trim(),
                version: _gid('fwVersion').value.trim(),
                firmware_hash: _gid('fwHash').value.trim(),
                sbom_packages: _gid('fwSbom').value
            });
            const el = _gid('fwResult');
            el.innerHTML = r.success
                ? `<div class="alert alert-success show"><b>FIRMWARE ANCHORED</b> ${escapeHtml(r.data.unit_id)} @ ${escapeHtml(r.data.version)}<br>
                    <span style="font-size:0.7rem;">SBOM: ${(r.data.sbom || []).join(', ')} &middot; ${escapeHtml(r.data.dNFT_authorized)}</span></div>`
                : `<div class="alert alert-error show">${escapeHtml(r.error || (r.data && r.data.reason))}</div>`;
        }
        async function fwDeploy() {
            const r = await postJSON('/api/firmware/deploy', {
                unit_id: _gid('fwUnit').value.trim(),
                version: _gid('fwVersion').value.trim(),
                firmware_hash: _gid('fwHash').value.trim()
            });
            const el = _gid('fwResult');
            el.innerHTML = r.success
                ? `<div class="alert alert-success show"><b>FLASH ${escapeHtml(r.data.flash)}</b> - ${escapeHtml(r.data.message)}</div>`
                : `<div class="alert ${r.data && r.data.flash === 'REFUSED' ? 'alert-danger' : 'alert-error'} show"><b>FLASH ${escapeHtml(r.data && r.data.flash || 'DENIED')}</b> - ${escapeHtml(r.data && r.data.reason || r.error)}</div>`;
        }
        async function fwList() { renderRaw('fwResult', { success: true, data: (await fetchAPI('/api/firmware/list')).data }); }
        async function prTransfer() {
            const r = await postJSON('/api/provenance/transfer', {
                unit_id: _gid('prUnit').value.trim(),
                from_party: _gid('prFrom').value.trim(),
                to_party: _gid('prTo').value.trim(),
                sig_from: 'sig-' + Date.now(), sig_to: 'rcv-' + Date.now()
            });
            const el = _gid('prResult');
            el.innerHTML = r.success
                ? `<div class="alert alert-success show"><b>CUSTODY ${escapeHtml(r.data.transfer.from)} -> ${escapeHtml(r.data.transfer.to)}</b> (step ${r.data.transfer.step})<br>
                    <span style="font-size:0.7rem;">hash ${escapeHtml(r.data.transfer.hash)}</span></div>`
                : `<div class="alert alert-error show">${escapeHtml(r.error || (r.data && r.data.reason))}</div>`;
        }
        async function prGraph() {
            const r = await postJSON('/api/provenance/graph', { unit_id: _gid('prUnit').value.trim() });
            const el = _gid('prResult');
            if (!r.success) { renderRaw('prResult', r); return; }
            el.innerHTML = `<div class="alert alert-info show"><b>${escapeHtml(r.data.unit_id)}</b> - ${r.data.hops} custody hop(s), current holder: <b>${escapeHtml(r.data.current_holder || 'none')}</b></div>` +
                `<div class="hint">${(r.data.graph || []).map(x => `<span class="pill pill-green" style="margin-right:0.2rem;">${escapeHtml(x.from)} &#8594; ${escapeHtml(x.to)}</span>`).join(' ')}</div>`;
        }
        async function prList() { renderRaw('prResult', { success: true, data: (await fetchAPI('/api/provenance/list')).data }); }
        async function rcCreate() {
            const r = await postJSON('/api/recall/create', {
                name: _gid('rcName').value.trim(),
                firmware_version: _gid('rcVersion').value.trim()
            });
            const el = _gid('rcResult');
            if (!r.success) { renderRaw('rcResult', r); return; }
            _gid('rcCampaign').value = r.data.campaign_id;
            el.innerHTML = `<div class="alert alert-warning show"><b>CAMPAIGN ${r.data.campaign_id}</b> - ${r.data.affected_units} unit(s) flagged. ${escapeHtml(r.data.message)}</div>`;
        }
        async function rcAck() {
            const r = await postJSON('/api/recall/ack', {
                campaign_id: _gid('rcCampaign').value.trim(),
                unit_id: _gid('rcUnit').value.trim(), acknowledged_by: 'tech'
            });
            const el = _gid('rcResult');
            el.innerHTML = r.success
                ? `<div class="alert alert-success show"><b>ACKNOWLEDGED</b> ${escapeHtml(r.data.unit_id)} - ${escapeHtml(r.data.progress)}</div>`
                : `<div class="alert alert-error show">${escapeHtml(r.error || (r.data && r.data.reason))}</div>`;
        }
        async function rcList() { renderRaw('rcResult', { success: true, data: (await fetchAPI('/api/recall/list')).data }); }

        // ============================================================
        // FEATURE SUITE v3 - Audit: cases / compliance / forensic
        // ============================================================
        async function caseOpen() {
            const r = await postJSON('/api/case/create', {
                title: _gid('caseTitle').value.trim(),
                opened_by: 'analyst'
            });
            const el = _gid('caseResult');
            if (!r.success) { renderRaw('caseResult', r); return; }
            _gid('caseId').value = r.data.case_id;
            el.innerHTML = `<div class="alert alert-success show"><b>CASE ${r.data.case_id}</b> opened (${escapeHtml(r.data.anomaly_ref)}).</div>`;
        }
        async function caseEvidence() {
            const r = await postJSON('/api/case/evidence', {
                case_id: _gid('caseId').value.trim(),
                description: _gid('caseEvidence').value.trim(),
                evidence_ref: 'audit-block-' + Date.now(), added_by: 'analyst'
            });
            const el = _gid('caseResult');
            el.innerHTML = r.success
                ? `<div class="alert alert-success show"><b>EVIDENCE ANCHORED</b> - ${escapeHtml(r.data.message)}</div>`
                : `<div class="alert alert-error show">${escapeHtml(r.error || (r.data && r.data.reason))}</div>`;
        }
        async function caseSignoff() {
            const r = await postJSON('/api/case/signoff', { case_id: _gid('caseId').value.trim(), analyst: 'analyst-1' });
            const el = _gid('caseResult');
            el.innerHTML = r.success
                ? `<div class="alert alert-success show"><b>SIGNED OFF</b> - ${r.data.analysts} analyst(s): ${(r.data.signoffs || []).join(', ')}</div>`
                : `<div class="alert alert-error show">${escapeHtml(r.error || (r.data && r.data.reason))}</div>`;
        }
        async function caseClose() {
            const r = await postJSON('/api/case/close', { case_id: _gid('caseId').value.trim(), closed_by: 'lead-analyst' });
            const el = _gid('caseResult');
            el.innerHTML = r.success
                ? `<div class="alert alert-success show">${escapeHtml(r.data.message)}</div>`
                : `<div class="alert alert-error show">${escapeHtml(r.error || (r.data && r.data.reason))}</div>`;
        }
        async function caseList() { renderRaw('caseResult', { success: true, data: (await fetchAPI('/api/case/list')).data }); }
        async function complianceRun() {
            const r = await fetchAPI('/api/compliance/report');
            const el = _gid('complianceResult');
            if (!r.success) { renderRaw('complianceResult', r); return; }
            const rep = r.data.report;
            let rows = '';
            for (const [fw, items] of Object.entries(rep.framework || {})) {
                rows += `<tr><td style="font-size:0.7rem;" rowspan="${items.length}"><b>${escapeHtml(fw.replace(/_/g, ' '))}</b></td>` +
                    items.map((it, i) => `${i ? '<tr>' : ''}<td style="font-size:0.7rem;">${escapeHtml(it.clause || it.ref)}</td><td style="font-size:0.7rem;">${escapeHtml(it.control)}</td><td><span class="pill pill-green">${escapeHtml(it.status)}</span></td><td style="font-size:0.65rem;color:var(--text-dim);">${escapeHtml(it.evidence)}</td></tr>`).join('');
            }
            el.innerHTML = `<div class="alert alert-success show"><b>COMPLIANCE ${escapeHtml(rep.org)}</b> - ${r.data.implemented}/${r.data.required_controls} controls (${r.data.compliance_pct}%) generated ${escapeHtml(rep.generated)}</div>
                <div class="table-container" style="max-height:300px;overflow:auto;"><table><thead><tr><th>Framework</th><th>Clause</th><th>Control</th><th>Status</th><th>Evidence</th></tr></thead><tbody>${rows}</tbody></table></div>`;
        }
        async function complianceList() { renderRaw('complianceResult', { success: true, data: (await fetchAPI('/api/compliance/list')).data }); }
        async function foTamper() {
            const r = await postJSON('/api/forensic/tamper', { block_index: parseInt(_gid('foIndex').value, 10) });
            const el = _gid('foResult');
            if (!r.success) { renderRaw('foResult', r); return; }
            const d = r.data.diff;
            el.innerHTML = `<div class="alert ${r.data.valid_after ? 'alert-warning' : 'alert-danger'} show"><b>TAMPER DETECTED</b> - chain now ${r.data.valid_after ? 'UNCHANGED?' : 'INVALID'} (affects all ≥ block ${d.target_index})</div>
                <div class="hint">before ${escapeHtml(d.hash_before.slice(0, 24))}... &middot; after ${escapeHtml(d.hash_after.slice(0, 24))}... &middot; recomputed ${escapeHtml(d.recomputed_hash.slice(0, 24))}... &middot; ${d.hashes_diverge ? 'hashes DIVERGE' : 'hashes match?'}</div>
                <div class="hint">defenses that would fire: ${(d.defenses_that_would_fire || []).map(x => `<span class="pill pill-orange">${escapeHtml(x)}</span>`).join(' ')}</div>`;
        }
        async function foScan() { renderRaw('foResult', { success: true, data: (await fetchAPI('/api/forensic/list')).data }); }

        // ============================================================
        // FEATURE 15 - Scenario Theater / Propagation / Benchmarks
        // ============================================================
        async function f15ScenarioRun() {
            const r = await postJSON('/api/scenario/run', { preset: _gid('f15scenPreset').value });
            const el = _gid('f15scenResult');
            if (!r.success) { renderRaw('f15scenResult', r); return; }
            const run = r.data.run;
            const steps = (run.steps || []).map(s => `
                <div class="hint" style="display:flex;align-items:center;gap:0.5rem;padding:0.25rem 0;">
                    <span class="pill ${s.ok ? 'pill-green' : 'pill-orange'}"><i class="fas fa-${s.icon}"></i> Step ${s.step}</span>
                    <div><b>${escapeHtml(s.caption)}</b><br><span style="font-size:0.7rem;color:var(--text-dim);">${escapeHtml(s.detail)}</span></div>
                </div>`).join('');
            el.innerHTML = `<div class="alert ${run.status === 'COMPLETE' ? 'alert-success' : 'alert-warning'} show">
                <b>Scenario <span style="font-size:0.72rem;">${escapeHtml(run.run_id)}</span> ${escapeHtml(run.preset)}</b>
                &middot; ${run.duration_ms} ms &middot; identity ${escapeHtml(run.identity)}</div>${steps}
                <button class="btn btn-secondary btn-full" onclick="f15ScenarioList()" style="margin-top:0.4rem;"><i class="fas fa-list"></i> Past Runs</button>
                <div id="f15scenPast" style="margin-top:0.4rem;"></div>`;
        }
        async function f15ScenarioList() {
            const r = await fetchAPI('/api/scenario/list');
            renderRaw('f15scenPast', { success: true, data: { runs: (r.data.runs || []).map(x => ({ run_id: x.run_id, preset: x.preset, status: x.status, duration_ms: x.duration_ms, identity: x.identity })) } });
        }
        function f15PropDrawNode(ctx, x, y, label, alive, head) {
            ctx.beginPath();
            ctx.arc(x, y, head ? 13 : 9, 0, Math.PI * 2);
            ctx.fillStyle = alive ? (head ? '#16a34a' : '#1d4ed8') : '#64748b';
            ctx.fill();
            ctx.strokeStyle = alive ? '#fff' : '#94a3b8';
            ctx.lineWidth = 2;
            ctx.stroke();
            ctx.fillStyle = '#fff';
            ctx.font = 'bold 11px sans-serif';
            ctx.textAlign = 'center';
            ctx.fillText(String(label).slice(0, 8), x, y + 3);
        }
        function f15PropDraw(data) {
            const cv = _gid('f15propCanvas');
            if (!cv) return;
            const ctx = cv.getContext('2d');
            const W = cv.width, H = cv.height;
            ctx.clearRect(0, 0, W, H);
            const nodes = data.nodes || [];
            if (!nodes.length) {
                ctx.fillStyle = '#94a3b8';
                ctx.font = '13px sans-serif';
                ctx.textAlign = 'center';
                ctx.fillText('No live nodes registered yet - add nodes in Network & IPFS, then Refresh Map.', W / 2, H / 2);
                return;
            }
            const R = Math.min(W, H) / 2 - 30;
            const cx = W / 2, cy = H / 2;
            nodes.forEach((n, i) => {
                const ang = (i / nodes.length) * Math.PI * 2 - Math.PI / 2;
                const x = cx + R * Math.cos(ang), y = cy + R * Math.sin(ang);
                n._x = x; n._y = y;
            });
            nodes.forEach(n => {
                ctx.beginPath();
                ctx.moveTo(cx, cy);
                ctx.lineTo(n._x, n._y);
                ctx.strokeStyle = n.alive ? 'rgba(29,78,216,0.35)' : 'rgba(100,116,139,0.25)';
                ctx.lineWidth = n.desynced ? 3 : 1;
                ctx.setLineDash(n.desynced ? [4, 4] : []);
                ctx.stroke();
                ctx.setLineDash([]);
            });
            ctx.save();
            ctx.translate(cx, cy);
            for (let i = 0; i < 6; i++) {
                ctx.globalAlpha = 1 - i / 6;
                ctx.beginPath();
                ctx.arc(0, 0, 12 + i * 3, 0, Math.PI * 2);
                ctx.globalAlpha = 0.25;
                ctx.strokeStyle = '#16a34a';
                ctx.stroke();
            }
            ctx.restore();
            nodes.forEach(n => f15PropDrawNode(ctx, n._x, n._y, n.node_id, n.alive, false));
            ctx.beginPath();
            ctx.arc(cx, cy, 14, 0, Math.PI * 2);
            ctx.fillStyle = '#16a34a';
            ctx.fill();
            ctx.strokeStyle = '#fff';
            ctx.lineWidth = 2;
            ctx.stroke();
            ctx.fillStyle = '#fff';
            ctx.font = 'bold 10px sans-serif';
            ctx.textAlign = 'center';
            ctx.fillText('L' + (data.canonical_head_index || 0), cx, cy + 3);
        }
        async function f15PropMap() {
            const r = await fetchAPI('/api/propagation/map');
            if (!r.success) { renderRaw('f15propResult', r); return; }
            f15PropDraw(r.data);
            _gid('f15propResult').innerHTML = `<div class="hint">Canonical head #${r.data.canonical_head_index} (${r.data.total_blocks} blocks). Alive nodes: ${(r.data.nodes || []).filter(n => n.alive).length}/${(r.data.nodes || []).length}. Dim = chaos-dead, dashed = desynced.</div>`;
        }
        async function f15PropBroadcast() {
            const r = await postJSON('/api/propagation/broadcast', { label: 'animation-demo' });
            const el = _gid('f15propResult');
            if (!r.success) { renderRaw('f15propResult', r); return; }
            el.innerHTML = `<div class="alert alert-success show">Block #${r.data.block_index} <b>${escapeHtml(r.data.block_hash.slice(0, 16))}...</b> broadcast to ${r.data.targets.length} live node(s): ${(r.data.targets || []).map(t => `<span class="pill pill-blue">${escapeHtml(t)}</span>`).join(' ')}</div>`;
            await f15PropMap();
        }
        async function f15BenchRun() {
            _gid('f15benchResult').innerHTML = '<div class="hint">Benchmarking... (PoW mine-time + auth + ZK percentiles)</div>';
            const r = await postJSON('/api/benchmark/run', {});
            renderRaw('f15benchResult', r);
        }

        // ============================================================
        // FEATURE 15 - Identicon / Web-of-Trust / Containment
        // ============================================================
        async function f15Identicon() {
            const r = await postJSON('/api/identicon', { identity_hash: _gid('f15idHash').value.trim() });
            const el = _gid('f15identiconResult');
            if (!r.success) { renderRaw('f15identiconResult', r); return; }
            const g = r.data.grid, cell = 20, pad = 6;
            let rects = '';
            g.forEach((row, i) => row.forEach((v, j) => {
                if (v) rects += `<rect x="${pad + j * cell}" y="${pad + i * cell}" width="${cell}" height="${cell}" fill="${r.data.fg}" rx="3"/>`;
            }));
            el.innerHTML = `<div class="alert alert-success show"><b>Identicon for ${escapeHtml(r.data.hash)}</b></div>
                <svg width="${pad * 2 + 5 * cell}" height="${pad * 2 + 5 * cell}" viewBox="0 0 ${pad * 2 + 5 * cell} ${pad * 2 + 5 * cell}" style="background:${r.data.bg};border-radius:8px;">
                    <rect width="100%" height="100%" fill="${r.data.bg}"/>${rects}
                </svg>
                <div class="hint">Deterministic 5x5 glyph + SHA-256 colour pair. Same hash &rarr; same avatar, always.</div>`;
        }
        async function f15VouchRegister() {
            const r = await postJSON('/api/vouch/register', {
                name: _gid('f15vName').value.trim(), email: _gid('f15vEmail').value.trim(),
                id_number: _gid('f15vId').value.trim()
            });
            const el = _gid('f15vouchResult');
            if (!r.success) { renderRaw('f15vouchResult', r); return; }
            el.innerHTML = `<div class="alert alert-success show"><b>${escapeHtml(r.data.message)}</b><br>target id: <span class="pill pill-blue">${escapeHtml(r.data.target_id)}</span> (requires ${r.data.required_vouches} HIGH vouchers)</div>`;
        }
        async function f15VouchAttest() {
            const r = await postJSON('/api/vouch/attest', {
                target_id: _gid('f15vTarget').value.trim(), voucher: _gid('f15vVoucher').value.trim()
            });
            const el = _gid('f15vouchResult');
            if (!r.success) { renderRaw('f15vouchResult', r); return; }
            const ob = r.data.onboarded || {};
            el.innerHTML = `<div class="alert ${r.data.status === 'VOUCHED' ? 'alert-success' : 'alert-warning'} show">
                <b>${r.data.status}</b> &middot; ${r.data.count}/${r.data.required} vouchers &middot; ${escapeHtml(r.data.message)}</div>
                ${ob.public_id ? `<div class="hint">Minted on-chain: ${escapeHtml(ob.public_id)} @ block ${ob.block}${ob.identity_hash ? ' &middot; ' + escapeHtml(ob.identity_hash.slice(0, 24)) + '...' : ''}</div>` : ''}`;
        }
        async function f15VouchList() {
            const r = await fetchAPI('/api/vouch/list');
            renderRaw('f15vouchResult', { success: true, data: { targets: (r.data.targets || []).map(t => ({ id: t.target_id, name: t.name, email: t.email, status: t.status, count: t.count, required: t.required, vouchers: t.vouchers })) } });
        }
        async function f15Containment() {
            const r = await postJSON('/api/containment/revoke', {
                department: _gid('f15cDept').value.trim(), reason: _gid('f15cReason').value.trim(),
                actor: _gid('f15cActor').value.trim()
            });
            const el = _gid('f15containResult');
            if (!r.success) { renderRaw('f15containResult', r); return; }
            const rows = (r.data.identities || []).map(i => `<tr><td>${escapeHtml(i.public_id)}</td><td>${escapeHtml(i.department)}</td><td><span class="pill pill-orange">REVOKED</span></td></tr>`).join('');
            el.innerHTML = `<div class="alert alert-danger show"><b>${escapeHtml(r.data.action_id)}</b> &middot; ${r.data.revoked_count} identities in ${escapeHtml(r.data.department)} revoked &middot; ${escapeHtml(r.data.message)}</div>
                <div class="table-container" style="max-height:200px;"><table><thead><tr><th>Public id</th><th>Department</th><th>State</th></tr></thead><tbody>${rows || '<tr><td colspan="3">(none)</td></tr>'}</tbody></table></div>`;
        }
        async function f15ContainmentList() { renderRaw('f15containResult', { success: true, data: (await fetchAPI('/api/containment/list')).data }); }

        // ============================================================
        // FEATURE 15 - Selective Disclosure / Witness / Lifecycle
        // ============================================================
        async function f15SdIssue() {
            let claims = [];
            try { claims = JSON.parse(_gid('f15sClaims').value); } catch (e) { renderRaw('f15sdResult', { success: false, error: 'claims JSON is invalid' }); return; }
            const r = await postJSON('/api/sd/issue', { holder: _gid('f15sHolder').value.trim(), claims });
            const el = _gid('f15sdResult');
            if (!r.success) { renderRaw('f15sdResult', r); return; }
            const rows = r.data.claims.map(c => `<span class="pill pill-blue">${escapeHtml(c.key)}=${escapeHtml(c.value)}</span>`).join(' ');
            el.innerHTML = `<div class="alert alert-success show"><b>${escapeHtml(r.data.vc_id)}</b> &middot; ${r.data.claims.length} claims &middot; ipfs ${escapeHtml(r.data.ipfs_cid.slice(0, 20))}... &middot; digest ${escapeHtml(r.data.digest.slice(0, 24))}...</div>
                <div class="hint" style="margin-bottom:0.4rem;">${rows}</div>
                <div class="hint">${escapeHtml(r.data.message)}</div>`;
        }
        async function f15SdDisclose() {
            const reveal = splitCsv('f15sReveal');
            const r = await postJSON('/api/sd/disclose', { vc_id: _gid('f15sVc').value.trim(), reveal_keys: reveal });
            const el = _gid('f15sdResult');
            if (!r.success) { renderRaw('f15sdResult', r); return; }
            const shown = r.data.revealed.map(c => `<span class="pill pill-green">${escapeHtml(c.key)}=${escapeHtml(c.value)}</span>`).join(' ');
            el.innerHTML = `<div class="alert alert-success show"><b>${escapeHtml(r.data.vc_id)}</b> &middot; revealed ${r.data.revealed.length}, withheld ${r.data.withheld_count} &middot; ${escapeHtml(r.data.message)}</div>
                <div class="hint" style="margin-bottom:0.4rem;">REVEALED: ${shown || '(none)'}</div>
                <div class="hint">WITHHELD: ${(r.data.withheld || []).map(escapeHtml).join(', ') || '(none)'} &middot; verifier sub-digest ${escapeHtml(r.data.sub_digest.slice(0, 24))}...</div>`;
        }
        async function f15SdList() { renderRaw('f15sdResult', { success: true, data: (await fetchAPI('/api/sd/list')).data }); }
        async function f15WitnessOpen() {
            const r = await postJSON('/api/witness/open', {
                requester: _gid('f15wRequester').value.trim(), resource: _gid('f15wResource').value.trim()
            });
            const el = _gid('f15witnessResult');
            if (!r.success) { renderRaw('f15witnessResult', r); return; }
            el.innerHTML = `<div class="alert alert-success show"><b>${escapeHtml(r.data.req_id)}</b> &middot; ${escapeHtml(r.data.message)}</div>
                <div class="hint">Pairing code (scan/QR to the nearby witness): <b>${escapeHtml(r.data.pairing_code)}</b></div>`;
        }
        async function f15WitnessCosign() {
            const r = await postJSON('/api/witness/cosign', {
                req_id: _gid('f15wReq').value.trim(), witness: _gid('f15wWitness').value.trim(),
                pairing_code: _gid('f15wCode').value.trim()
            });
            const el = _gid('f15witnessResult');
            if (!r.success) { renderRaw('f15witnessResult', r); return; }
            el.innerHTML = `<div class="alert alert-success show"><b>${r.data.status}</b> &middot; ${escapeHtml(r.data.message)}</div>`;
        }
        async function f15WitnessList() { renderRaw('f15witnessResult', { success: true, data: (await fetchAPI('/api/witness/list')).data }); }
        async function f15Lifecycle() {
            const r = await postJSON('/api/lifecycle/change', {
                public_id: _gid('f15lPid').value.trim(), change_type: _gid('f15lType').value,
                new_role: _gid('f15lRole').value.trim(), new_level: parseInt(_gid('f15lLevel').value) || 0,
                new_resources: splitCsv('f15lRes')
            });
            const el = _gid('f15lifecycleResult');
            if (!r.success) { renderRaw('f15lifecycleResult', r); return; }
            const rev = (r.data.cascade_revoked || []).map(x => `<span class="pill pill-orange">${escapeHtml(x)}</span>`).join(' ');
            const now = (r.data.resources_now || []).map(x => `<span class="pill pill-green">${escapeHtml(x)}</span>`).join(' ');
            el.innerHTML = `<div class="alert ${(r.data.cascade_revoked || []).length ? 'alert-warning' : 'alert-success'} show"><b>${escapeHtml(r.data.change_type)}</b> &middot; ${escapeHtml(r.data.message)}</div>
                <div class="hint">Cascade-revoked grants: ${rev || '<i>none</i>'}</div>
                <div class="hint">Grants now: ${now || '<i>none</i>'}</div>`;
        }
        async function f15LifecycleList() { renderRaw('f15lifecycleResult', { success: true, data: (await fetchAPI('/api/lifecycle/list')).data }); }

        // ============================================================
        // FEATURE 15 - Purpose Binding / Session Sealing / Classification
        // ============================================================
        async function f15PurposeRegister() {
            const r = await postJSON('/api/purpose/register', {
                resource: _gid('f15pRes').value.trim(), purpose_code: _gid('f15pCode').value.trim()
            });
            _gid('f15purposeResult').innerHTML = r.success
                ? `<div class="alert alert-success show">${escapeHtml(r.data.message)}</div>`
                : `<div class="alert alert-error show">${escapeHtml(r.data.reason || 'failed')}</div>`;
        }
        async function f15PurposeAccess() {
            const r = await postJSON('/api/purpose/access', {
                public_id: _gid('f15aPid').value.trim(), resource: _gid('f15aRes').value.trim(),
                purpose_code: _gid('f15aCode').value.trim()
            });
            const el = _gid('f15purposeResult');
            if (!r.success) { renderRaw('f15purposeResult', r); return; }
            el.innerHTML = `<div class="alert ${r.data.granted ? 'alert-success' : 'alert-danger'} show"><b>${r.data.granted ? 'GRANTED' : 'DENIED'}</b> &middot; ${escapeHtml(r.data.reason)}</div>
                <div class="hint">role_permitted: ${r.data.role_permitted} &middot; purpose_registered: ${r.data.purpose_registered}</div>`;
        }
        async function f15PurposeList() { renderRaw('f15purposeResult', { success: true, data: (await fetchAPI('/api/purpose/list')).data }); }
        async function f15SessionSeal() {
            const r = await postJSON('/api/session/seal', {
                public_id: _gid('f15ssPid').value.trim(), device_hash: _gid('f15ssDev').value.trim(),
                ip: _gid('f15ssIp').value.trim(), lease_s: parseInt(_gid('f15ssLease').value) || 600
            });
            const el = _gid('f15sessionResult');
            if (!r.success) { renderRaw('f15sessionResult', r); return; }
            el.innerHTML = `<div class="alert alert-success show"><b>${escapeHtml(r.data.session_id)}</b> &middot; token ${escapeHtml(r.data.token)} &middot; ${escapeHtml(r.data.message)}</div>`;
        }
        async function f15SessionValidate() {
            const r = await postJSON('/api/session/validate', {
                session_id: _gid('f15ssSid').value.trim(), device_hash: _gid('f15ssDev').value.trim(),
                ip: _gid('f15ssIp').value.trim()
            });
            const el = _gid('f15sessionResult');
            if (!r.success) { renderRaw('f15sessionResult', r); return; }
            el.innerHTML = `<div class="alert ${r.data.valid ? 'alert-success' : 'alert-danger'} show"><b>${r.data.valid ? 'VALID' : 'INVALID'}</b> &middot; ${escapeHtml(r.data.reason)}</div>`;
        }
        async function f15SessionHijack() {
            const r = await postJSON('/api/session/hijack', { session_id: _gid('f15ssSid').value.trim() });
            const el = _gid('f15sessionResult');
            if (!r.success) { renderRaw('f15sessionResult', r); return; }
            el.innerHTML = `<div class="alert ${r.data.attack_blocked ? 'alert-danger' : 'alert-warning'} show"><b>Hijack ${r.data.attack_blocked ? 'BLOCKED' : 'NOT BLOCKED'}</b> &middot; ${escapeHtml(r.data.countermeasure)}</div>
                <div class="hint">${escapeHtml(r.data.reason)}</div>`;
        }
        async function f15SessionList() { renderRaw('f15sessionResult', { success: true, data: (await fetchAPI('/api/session/list')).data }); }
        async function f15ClassifyRegister() {
            const r = await postJSON('/api/classify/register', {
                label: _gid('f15clLabel').value.trim(), required_factors: splitCsv('f15clFactors'),
                min_level: parseInt(_gid('f15clLevel').value) || 1, watermark: _gid('f15clMark').value.trim()
            });
            _gid('f15classifyResult').innerHTML = r.success
                ? `<div class="alert alert-success show">${escapeHtml(r.data.message)}</div>`
                : `<div class="alert alert-error show">${escapeHtml(r.data.reason || 'failed')}</div>`;
        }
        async function f15ClassifyAssess() {
            const r = await postJSON('/api/classify/assess', {
                resource: _gid('f15cRes').value.trim(), label: _gid('f15ccLabel').value.trim()
            });
            const el = _gid('f15classifyResult');
            if (!r.success) { renderRaw('f15classifyResult', r); return; }
            const rules = r.data.rules_inherited || {};
            el.innerHTML = `<div class="alert alert-success show"><b>${escapeHtml(r.data.label)}</b> &middot; ${escapeHtml(r.data.message)}</div>
                <div class="hint">factors: ${(rules.factors || []).map(x => `<span class="pill pill-blue">${escapeHtml(x)}</span>`).join(' ')} &middot; min_level ${rules.min_level} &middot; watermark ${escapeHtml(rules.watermark)}</div>`;
        }
        async function f15ClassifyList() { renderRaw('f15classifyResult', { success: true, data: (await fetchAPI('/api/classify/list')).data }); }

        // ============================================================
        // FEATURE 15 - Chaos / Node PKI / Audit-Root Notarization
        // ============================================================
        async function f15ChaosInject() {
            const r = await postJSON('/api/chaos/inject', {
                node_id: _gid('f15chNode').value.trim(), mode: _gid('f15chMode').value,
                value: _gid('f15chValue').value.trim()
            });
            const el = _gid('f15chaosResult');
            if (!r.success) { renderRaw('f15chaosResult', r); return; }
            el.innerHTML = `<div class="alert alert-danger show">${escapeHtml(r.data.message)}</div>
                <div class="hint">config: ${escapeHtml(JSON.stringify(r.data.config))}</div>`;
        }
        async function f15ChaosVerify() {
            const r = await postJSON('/api/chaos/verify', { node_id: _gid('f15chNode').value.trim() });
            const el = _gid('f15chaosResult');
            if (!r.success) { renderRaw('f15chaosResult', r); return; }
            el.innerHTML = `<div class="alert ${r.data.verdict === 'BLOCKED' ? 'alert-danger' : 'alert-success'} show"><b>${r.data.verdict}</b> on ${escapeHtml(r.data.node_id)} &middot; ${escapeHtml(r.data.reason)}</div>
                <div class="hint">stale_ts ${r.data.stale_request_ts} &middot; clock_skew ${r.data.clock_skew_s}s &middot; freshness_5min_window ${r.data.freshness_5min_window} &middot; monotonic_nonce_defense ${r.data.monotonic_nonce_defense}</div>`;
        }
        async function f15ChaosList() { renderRaw('f15chaosResult', { success: true, data: (await fetchAPI('/api/chaos/list')).data }); }
        async function f15PkiJoin() {
            const r = await postJSON('/api/pki/join', { node_id: _gid('f15pkiNode').value.trim() });
            _gid('f15pkiResult').innerHTML = r.success
                ? `<div class="alert alert-success show"><b>${escapeHtml(r.data.node_id)}</b> &middot; pubkey ${escapeHtml(r.data.public_key)} &middot; ${escapeHtml(r.data.message)}</div>`
                : `<div class="alert alert-warning show">${escapeHtml(r.data.reason || 'failed')}</div>`;
        }
        async function f15PkiGossip() {
            const r = await postJSON('/api/pki/gossip', {
                node_id: _gid('f15pkiNode').value.trim(), message: _gid('f15pkiMsg').value.trim()
            });
            const el = _gid('f15pkiResult');
            if (!r.success) { renderRaw('f15pkiResult', r); return; }
            el.innerHTML = `<div class="alert ${r.data.accepted ? 'alert-success' : 'alert-danger'} show"><b>${r.data.accepted ? 'ACCEPTED' : 'REJECTED'}</b> &middot; ${escapeHtml(r.data.message)}</div>
                <div class="hint">signature ${escapeHtml(r.data.signature || 'n/a')}</div>`;
        }
        async function f15PkiRogue() {
            const r = await postJSON('/api/pki/rogue-attempt', { node_id: 'rogue.mallory' });
            const el = _gid('f15pkiResult');
            if (!r.success) { renderRaw('f15pkiResult', r); return; }
            el.innerHTML = `<div class="alert alert-danger show">ROGUE NODE injected &middot; ${escapeHtml(r.data.reason)}</div>`;
        }
        async function f15PkiRevoke() {
            const r = await postJSON('/api/pki/revoke', { node_id: _gid('f15pkiNode').value.trim() });
            _gid('f15pkiResult').innerHTML = r.success
                ? `<div class="alert alert-warning show">${escapeHtml(r.data.message)}</div>`
                : `<div class="alert alert-warning show">${escapeHtml(r.data.reason || 'failed')}</div>`;
        }
        async function f15PkiList() { renderRaw('f15pkiResult', { success: true, data: (await fetchAPI('/api/pki/list')).data }); }
        async function f15NotarizeAnchor() {
            const r = await postJSON('/api/notarize/anchor', { notary: 'BEL-AUDIT-01' });
            _gid('f15notarizeResult').innerHTML = r.success
                ? `<div class="alert alert-success show"><b>${escapeHtml(r.data.anchor.anchor_id)}</b> &middot; root ${escapeHtml(r.data.anchor.audit_root).slice(0, 24)}... &middot; ipfs ${escapeHtml(r.data.anchor.ipfs_cid).slice(0, 20)}... &middot; ${r.data.anchor.audit_blocks} audit blocks</div>`
                : renderRaw('f15notarizeResult', r);
        }
        async function f15NotarizeVerify() {
            const r = await postJSON('/api/notarize/verify', { anchor_id: _gid('f15ntAnchor').value.trim() });
            const el = _gid('f15notarizeResult');
            if (!r.success) { renderRaw('f15notarizeResult', r); return; }
            el.innerHTML = `<div class="alert ${r.data.verdict === 'VERIFIED' ? 'alert-success' : 'alert-danger'} show"><b>${r.data.verdict}</b> &middot; trail matches anchor: ${r.data.audit_trail_matches_anchor} &middot; ipfs_retrievable ${r.data.ipfs_retrievable}</div>
                <div class="hint">${escapeHtml(r.data.message)}</div>`;
        }
        async function f15NotarizeList() { renderRaw('f15notarizeResult', { success: true, data: (await fetchAPI('/api/notarize/list')).data }); }

        // ============================================================
        // FEATURE 15 - Geo-Fence / Work Orders / Lifecycle Timeline
        // ============================================================
        async function f15GeofenceRegister() {
            const r = await postJSON('/api/geofence/register', {
                unit_id: _gid('f15gfUnit').value.trim(), center_lat: _gid('f15gfLat').value.trim(),
                center_lng: _gid('f15gfLng').value.trim(), radius_km: _gid('f15gfRad').value.trim()
            });
            _gid('f15geofenceResult').innerHTML = r.success
                ? `<div class="alert alert-success show">${escapeHtml(r.data.message)}</div>`
                : `<div class="alert alert-warning show">${escapeHtml(r.data.reason || 'failed')}</div>`;
        }
        async function f15GeofenceTelemetry() {
            const r = await postJSON('/api/geofence/telemetry', {
                unit_id: _gid('f15gfTUnit').value.trim(), lat: _gid('f15gfTLat').value.trim(),
                lng: _gid('f15gfTLng').value.trim()
            });
            const el = _gid('f15geofenceResult');
            if (!r.success) { renderRaw('f15geofenceResult', r); return; }
            el.innerHTML = `<div class="alert ${r.data.flagged ? 'alert-danger' : 'alert-success'} show"><b>${r.data.inside_perimeter ? 'INSIDE' : 'OUTSIDE PERIMETER'}</b> &middot; ${r.data.distance_km} km &middot; ${escapeHtml(r.data.message)}</div>`;
        }
        async function f15GeofenceList() { renderRaw('f15geofenceResult', { success: true, data: (await fetchAPI('/api/geofence/list')).data }); }
        async function f15WoCreate() {
            const r = await postJSON('/api/wo/create', {
                unit_id: _gid('f15woUnit').value.trim(), technician: _gid('f15woTech').value.trim(),
                parts: splitCsv('f15woParts')
            });
            _gid('f15woResult').innerHTML = r.success
                ? `<div class="alert alert-success show"><b>${escapeHtml(r.data.order_id)}</b> &middot; ${escapeHtml(r.data.message)}</div>`
                : `<div class="alert alert-warning show">${escapeHtml(r.data.reason || 'failed')}</div>`;
        }
        async function f15WoBegin() {
            const r = await postJSON('/api/wo/begin', { order_id: _gid('f15woId').value.trim() });
            _gid('f15woResult').innerHTML = r.success
                ? `<div class="alert alert-success show"><b>${escapeHtml(r.data.order_id)}</b> &middot; ${escapeHtml(r.data.message)}</div>`
                : `<div class="alert alert-warning show">${escapeHtml(r.data.reason || 'failed')}</div>`;
        }
        async function f15WoComplete() {
            const r = await postJSON('/api/wo/complete', { order_id: _gid('f15woId').value.trim() });
            _gid('f15woResult').innerHTML = r.success
                ? `<div class="alert alert-success show"><b>${escapeHtml(r.data.order_id)}</b> &middot; ${escapeHtml(r.data.message)}</div>`
                : `<div class="alert alert-warning show">${escapeHtml(r.data.reason || 'failed')}</div>`;
        }
        async function f15WoList() { renderRaw('f15woResult', { success: true, data: (await fetchAPI('/api/wo/list')).data }); }
        function f15Ts(ts) { return ts ? new Date(ts * 1000).toLocaleString('en-IN') : '?'; }
        async function f15Timeline() {
            const r = await fetchAPI('/api/timeline/asset?unit_id=' + encodeURIComponent(_gid('f15tlUnit').value.trim()));
            const el = _gid('f15timelineResult');
            if (!r.success) { renderRaw('f15timelineResult', r); return; }
            const ev = (r.data.events || []).map(e => `<div class="hint" style="display:flex;align-items:center;gap:0.5rem;padding:0.2rem 0;">
                <span class="pill ${e.event === 'GEOFENCE_BREACH' ? 'pill-orange' : 'pill-blue'}">${escapeHtml(e.event)}</span>
                <span style="font-size:0.68rem;color:var(--text-dim);">${escapeHtml(f15Ts(e.ts))} &middot; by ${escapeHtml(e.by || '?')} &middot; ${escapeHtml(e.note || '')}</span></div>`).join('');
            el.innerHTML = `<div class="alert alert-success show"><b>${escapeHtml(r.data.unit_id)}</b> &middot; ${r.data.count} events</div>${ev || '<div class="hint">No events recorded yet.</div>'}`;
        }
        async function f15TimelineAssets() { renderRaw('f15timelineResult', { success: true, data: (await fetchAPI('/api/timeline/assets')).data }); }

        // ============================================================
        // FEATURE 15 - Least-Privilege / Attestation Receipts
        // ============================================================
        async function f15LpScan() {
            _gid('f15lpResult').innerHTML = '<div class="hint">Scanning audit trail...</div>';
            const r = await fetchAPI('/api/least-privilege/scan?days=' + (parseInt(_gid('f15lpDays').value) || 30));
            const el = _gid('f15lpResult');
            if (!r.success) { renderRaw('f15lpResult', r); return; }
            const rows = (r.data.candidates || []).map(c => `<tr>
                <td>${escapeHtml(c.identity)}</td><td><span class="pill pill-blue">${escapeHtml(c.resource)}</span></td>
                <td>${escapeHtml(c.role || '')}</td><td><span class="pill ${c.resource ? 'pill-orange' : 'pill-green'}">${escapeHtml(c.last_use)}</span></td></tr>`).join('');
            el.innerHTML = `<div class="alert ${(r.data.candidates || []).length ? 'alert-warning' : 'alert-success'} show"><b>${(r.data.candidates || []).length} over-grants</b> in ${r.data.window_days} days</div>
                <div class="table-container" style="max-height:220px;"><table><thead><tr><th>Identity</th><th>Never-used grant</th><th>Role</th><th>Last use</th></tr></thead><tbody>${rows || '<tr><td colspan="4">No prune candidates - great least-privilege hygiene.</td></tr>'}</tbody></table></div>`;
        }
        async function f15LpPropose() {
            const r = await postJSON('/api/least-privilege/propose', {
                identity: _gid('f15lpId').value.trim(), resource: _gid('f15lpRes').value.trim()
            });
            _gid('f15lpResult').innerHTML = r.success
                ? `<div class="alert alert-success show">${escapeHtml(r.data.message)}</div>`
                : `<div class="alert alert-warning show">${escapeHtml(r.data.reason || 'failed')}</div>`;
        }
        async function f15LpList() { renderRaw('f15lpResult', { success: true, data: (await fetchAPI('/api/least-privilege/list')).data }); }
        async function f15ReceiptIssue() {
            const r = await postJSON('/api/receipt/issue', {
                control: _gid('f15rControl').value.trim(), framework: _gid('f15rFramework').value.trim(),
                subject: _gid('f15rSubject').value.trim(), verifier: _gid('f15rVerifier').value.trim()
            });
            const el = _gid('f15receiptResult');
            if (!r.success) { renderRaw('f15receiptResult', r); return; }
            const rec = r.data.receipt;
            el.innerHTML = `<div class="alert alert-success show"><b>${escapeHtml(rec.receipt_id)}</b> &middot; ${escapeHtml(r.data.message)}</div>
                <div class="hint">control ${escapeHtml(rec.control)} &middot; ${escapeHtml(rec.framework)} &middot; ${escapeHtml(rec.subject)} &middot; verifier ${escapeHtml(rec.verifier)} &middot; result ${escapeHtml(rec.result)}</div>
                <div class="hint">self-contained duty: dgst ${escapeHtml(rec.dgst.slice(0, 24))}... &middot; sig ${escapeHtml(rec.signature.slice(0, 24))}...</div>`;
        }
        async function f15ReceiptVerify() {
            const r = await postJSON('/api/receipt/verify', { receipt_id: _gid('f15rId').value.trim() });
            const el = _gid('f15receiptResult');
            if (!r.success) { renderRaw('f15receiptResult', r); return; }
            el.innerHTML = `<div class="alert ${r.data.verdict === 'VERIFIED' ? 'alert-success' : 'alert-danger'} show"><b>${r.data.verdict}</b> &middot; signature_valid ${r.data.signature_valid} &middot; digest_valid ${r.data.digest_valid} &middot; offline_verifiable ${r.data.offline_verifiable}</div>
                <div class="hint">${escapeHtml(r.data.message)}</div>`;
        }
        async function f15ReceiptList() { renderRaw('f15receiptResult', { success: true, data: (await fetchAPI('/api/receipt/list')).data }); }
