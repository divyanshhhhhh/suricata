// Suricata Rule Builder - Frontend Application Logic

// State management
let currentEditingSid = null;
let contentFieldCount = 0;

// Initialize the application when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    initializeForm();
    loadRules();
    setupEventListeners();
    setupProtocolListener();
});

/**
 * Setup protocol change listener to show/hide protocol-specific sections
 */
function setupProtocolListener() {
    const protocolSelect = document.getElementById('protocol');
    protocolSelect.addEventListener('change', handleProtocolChange);
    // Trigger initial setup
    handleProtocolChange();
}

/**
 * Handle protocol change to show/hide relevant sections
 */
function handleProtocolChange() {
    const protocol = document.getElementById('protocol').value;

    // Hide all protocol-specific sections
    document.querySelectorAll('.protocol-specific').forEach(section => {
        section.style.display = 'none';
    });

    // Show relevant protocol section
    if (protocol === 'http') {
        document.getElementById('httpKeywordsSection').style.display = 'block';
    } else if (protocol === 'tls') {
        document.getElementById('tlsKeywordsSection').style.display = 'block';
    } else if (protocol === 'dns') {
        document.getElementById('dnsKeywordsSection').style.display = 'block';
    }
}

/**
 * Toggle collapsible sections
 */
function toggleSection(sectionId) {
    const content = document.getElementById(sectionId);
    const header = content.previousElementSibling;
    const icon = header.querySelector('.toggle-icon');

    if (content.style.display === 'none' || content.style.display === '') {
        content.style.display = 'block';
        icon.textContent = '▼';
    } else {
        content.style.display = 'none';
        icon.textContent = '▶';
    }
}

/**
 * Initialize form with default values and event listeners
 */
function initializeForm() {
    // Set initial values
    getNextSid();

    // Add initial content field
    addContentField();

    // Update rule preview on any form change
    updateRulePreview();
}

/**
 * Setup event listeners for form inputs
 */
function setupEventListeners() {
    const form = document.getElementById('ruleForm');

    // Use event delegation on the form instead of individual inputs
    // This way new inputs (in protocol sections) will automatically work
    form.addEventListener('input', updateRulePreview);
    form.addEventListener('change', updateRulePreview);

    // Manual rule editor sync
    const manualEdit = document.getElementById('manualRuleEdit');
    manualEdit.addEventListener('input', () => {
        const preview = document.getElementById('rulePreview');
        preview.innerHTML = `<code>${escapeHtml(manualEdit.value)}</code>`;
    });
}

/**
 * Update the rule preview in real-time
 */
function updateRulePreview() {
    const rule = buildRuleFromForm();
    const preview = document.getElementById('rulePreview');
    const manualEdit = document.getElementById('manualRuleEdit');

    // Apply syntax highlighting
    preview.innerHTML = `<code>${syntaxHighlight(rule)}</code>`;
    manualEdit.value = rule;
}

/**
 * Build a Suricata rule string from form data
 */
function buildRuleFromForm() {
    // Get basic components
    const action = document.getElementById('action').value;
    const protocol = document.getElementById('protocol').value;
    const srcIp = document.getElementById('srcIp').value;
    const srcPort = document.getElementById('srcPort').value;
    const direction = document.querySelector('input[name="direction"]:checked').value;
    const dstIp = document.getElementById('dstIp').value;
    const dstPort = document.getElementById('dstPort').value;

    // Build options
    const options = [];

    // Message (required)
    const msg = document.getElementById('msg').value || 'Suricata Rule';
    options.push(`msg:"${msg}"`);

    // Content matches
    const contentFields = document.querySelectorAll('.content-field');
    contentFields.forEach(field => {
        const value = field.querySelector('.content-value').value;
        if (value) {
            options.push(`content:"${value}"`);

            // Add modifiers
            if (field.querySelector('.content-nocase').checked) {
                options.push('nocase');
            }

            const offset = field.querySelector('.content-offset').value;
            if (offset) {
                options.push(`offset:${offset}`);
            }

            const depth = field.querySelector('.content-depth').value;
            if (depth) {
                options.push(`depth:${depth}`);
            }
        }
    });

    // HTTP Keywords (protocol-specific)
    if (protocol === 'http') {
        const httpMethod = document.getElementById('httpMethod').value;
        if (httpMethod) options.push(`http.method; content:"${httpMethod}"`);

        const httpUri = document.getElementById('httpUri').value;
        if (httpUri) options.push(`http.uri; content:"${httpUri}"`);

        const httpUserAgent = document.getElementById('httpUserAgent').value;
        if (httpUserAgent) options.push(`http.user_agent; content:"${httpUserAgent}"`);

        const httpHost = document.getElementById('httpHost').value;
        if (httpHost) options.push(`http.host; content:"${httpHost}"`);

        const httpCookie = document.getElementById('httpCookie').value;
        if (httpCookie) options.push(`http.cookie; content:"${httpCookie}"`);

        const httpReferer = document.getElementById('httpReferer').value;
        if (httpReferer) options.push(`http.referer; content:"${httpReferer}"`);

        const httpContentType = document.getElementById('httpContentType').value;
        if (httpContentType) options.push(`http.content_type; content:"${httpContentType}"`);

        const httpStatCode = document.getElementById('httpStatCode').value;
        if (httpStatCode) options.push(`http.stat_code; content:"${httpStatCode}"`);

        // HTTP buffer modifiers
        if (document.getElementById('httpRequestBody').checked) {
            options.push('http.request_body');
        }
        if (document.getElementById('httpResponseBody').checked) {
            options.push('http.response_body');
        }
        if (document.getElementById('fileData').checked) {
            options.push('file.data');
        }
    }

    // TLS Keywords (protocol-specific)
    if (protocol === 'tls') {
        const tlsVersion = document.getElementById('tlsVersion').value;
        if (tlsVersion) options.push(`tls.version:"${tlsVersion}"`);

        const tlsSni = document.getElementById('tlsSni').value;
        if (tlsSni) options.push(`tls.sni; content:"${tlsSni}"`);

        const tlsSubject = document.getElementById('tlsSubject').value;
        if (tlsSubject) options.push(`tls.subject; content:"${tlsSubject}"`);

        const tlsIssuer = document.getElementById('tlsIssuer').value;
        if (tlsIssuer) options.push(`tls.issuer; content:"${tlsIssuer}"`);

        const tlsCertFingerprint = document.getElementById('tlsCertFingerprint').value;
        if (tlsCertFingerprint) options.push(`tls.cert_fingerprint; content:"${tlsCertFingerprint}"`);

        const ja3Hash = document.getElementById('ja3Hash').value;
        if (ja3Hash) options.push(`ja3.hash; content:"${ja3Hash}"`);

        const ja3sHash = document.getElementById('ja3sHash').value;
        if (ja3sHash) options.push(`ja3s.hash; content:"${ja3sHash}"`);
    }

    // DNS Keywords (protocol-specific)
    if (protocol === 'dns') {
        const dnsQuery = document.getElementById('dnsQuery').value;
        if (dnsQuery) options.push(`dns.query; content:"${dnsQuery}"`);

        const dnsQueryType = document.getElementById('dnsQueryType').value;
        if (dnsQueryType) options.push(`dns.query.type:${dnsQueryType}`);

        const dnsAnswer = document.getElementById('dnsAnswer').value;
        if (dnsAnswer) options.push(`dns.answer; content:"${dnsAnswer}"`);

        const dnsOpcode = document.getElementById('dnsOpcode').value;
        if (dnsOpcode) options.push(`dns.opcode:${dnsOpcode}`);
    }

    // Flow options
    const flowOpts = [];
    if (document.getElementById('flowEstablished').checked) flowOpts.push('established');
    if (document.getElementById('flowToServer').checked) flowOpts.push('to_server');
    if (document.getElementById('flowToClient').checked) flowOpts.push('to_client');
    if (document.getElementById('flowFromServer').checked) flowOpts.push('from_server');
    if (document.getElementById('flowFromClient').checked) flowOpts.push('from_client');

    if (flowOpts.length > 0) {
        options.push(`flow:${flowOpts.join(',')}`);
    }

    // Classification and priority
    const classtype = document.getElementById('classtype').value;
    if (classtype) {
        options.push(`classtype:${classtype}`);
    }

    const priority = document.getElementById('priority').value;
    if (priority) {
        options.push(`priority:${priority}`);
    }

    // Threshold
    const thresholdType = document.getElementById('thresholdType').value;
    if (thresholdType) {
        let threshold = `threshold:type ${thresholdType}`;

        const track = document.getElementById('thresholdTrack').value;
        if (track) threshold += `,track ${track}`;

        const count = document.getElementById('thresholdCount').value;
        if (count) threshold += `,count ${count}`;

        const seconds = document.getElementById('thresholdSeconds').value;
        if (seconds) threshold += `,seconds ${seconds}`;

        options.push(threshold);
    }

    // Reference
    const reference = document.getElementById('reference').value;
    if (reference) {
        options.push(`reference:${reference}`);
    }

    // SID and REV (required)
    const sid = document.getElementById('sid').value || '1000000';
    const rev = document.getElementById('rev').value || '1';
    options.push(`sid:${sid}`);
    options.push(`rev:${rev}`);

    // Build complete rule
    const optionsStr = options.join('; ') + ';';
    return `${action} ${protocol} ${srcIp} ${srcPort} ${direction} ${dstIp} ${dstPort} (${optionsStr})`;
}

/**
 * Add a content matching field
 */
function addContentField() {
    contentFieldCount++;
    const container = document.getElementById('contentFields');

    const fieldHtml = `
        <div class="content-field" id="content-${contentFieldCount}">
            <div class="content-field-header">
                <h4>Content Match #${contentFieldCount}</h4>
                <button type="button" class="btn btn-sm btn-danger" onclick="removeContentField(${contentFieldCount})">✕ Remove</button>
            </div>
            <div class="form-group">
                <label>Content to Match</label>
                <input type="text" class="content-value" placeholder="e.g., malware.exe, SELECT * FROM">
            </div>
            <div class="content-modifiers">
                <label>
                    <input type="checkbox" class="content-nocase"> Case Insensitive (nocase)
                </label>
            </div>
            <div class="content-modifier-inputs">
                <div class="form-group">
                    <label>Offset</label>
                    <input type="number" class="content-offset" min="0" placeholder="0">
                </div>
                <div class="form-group">
                    <label>Depth</label>
                    <input type="number" class="content-depth" min="1" placeholder="">
                </div>
            </div>
        </div>
    `;

    container.insertAdjacentHTML('beforeend', fieldHtml);

    // Add event listeners to new fields
    const newField = document.getElementById(`content-${contentFieldCount}`);
    const inputs = newField.querySelectorAll('input');
    inputs.forEach(input => {
        input.addEventListener('input', updateRulePreview);
        input.addEventListener('change', updateRulePreview);
    });
}

/**
 * Remove a content field
 */
function removeContentField(id) {
    const field = document.getElementById(`content-${id}`);
    if (field) {
        field.remove();
        updateRulePreview();
    }
}

/**
 * Get the next available SID from the server
 */
async function getNextSid() {
    try {
        const response = await fetch('/api/next-sid');
        const data = await response.json();

        if (data.success) {
            document.getElementById('sid').value = data.next_sid;
            updateRulePreview();
        }
    } catch (error) {
        console.error('Error getting next SID:', error);
    }
}

/**
 * Validate the current rule
 */
async function validateCurrentRule() {
    const manualEdit = document.getElementById('manualRuleEdit');
    const rule = manualEdit.value;
    const resultDiv = document.getElementById('validationResult');

    if (!rule.trim()) {
        showValidationResult('Please enter a rule to validate', false);
        return;
    }

    // Show loading state
    resultDiv.innerHTML = '<div class="spinner"></div> Validating rule...';
    resultDiv.className = 'validation-result';
    resultDiv.style.display = 'block';

    try {
        const response = await fetch('/api/validate', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ rule: rule })
        });

        const data = await response.json();

        if (data.valid) {
            showValidationResult(`✓ ${data.message || 'Rule syntax is valid!'}`, true);
        } else {
            showValidationResult(`✗ ${data.error || 'Invalid rule syntax'}`, false);
        }
    } catch (error) {
        showValidationResult(`Error validating rule: ${error.message}`, false);
    }
}

/**
 * Show validation result
 */
function showValidationResult(message, isValid) {
    const resultDiv = document.getElementById('validationResult');
    resultDiv.textContent = message;
    resultDiv.className = `validation-result ${isValid ? 'success' : 'error'}`;
    resultDiv.style.display = 'block';

    // Auto-hide after 5 seconds
    setTimeout(() => {
        resultDiv.style.display = 'none';
    }, 5000);
}

/**
 * Save the rule to the server
 */
async function saveRule() {
    const manualEdit = document.getElementById('manualRuleEdit');
    const rule = manualEdit.value;

    if (!rule.trim()) {
        alert('Please enter a rule to save');
        return;
    }

    // Validate first
    try {
        const validateResponse = await fetch('/api/validate', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ rule: rule })
        });

        const validateData = await validateResponse.json();

        if (!validateData.valid) {
            if (!confirm(`Rule validation failed: ${validateData.error}\n\nDo you want to save anyway?`)) {
                return;
            }
        }

        // Save the rule
        const endpoint = currentEditingSid ? `/api/rules/${currentEditingSid}` : '/api/rules';
        const method = currentEditingSid ? 'PUT' : 'POST';

        const response = await fetch(endpoint, {
            method: method,
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ raw_rule: rule })
        });

        const data = await response.json();

        if (data.success) {
            showValidationResult(`✓ Rule ${currentEditingSid ? 'updated' : 'saved'} successfully!`, true);
            loadRules();
            if (!currentEditingSid) {
                resetForm();
            }
            currentEditingSid = null;
        } else {
            showValidationResult(`✗ Failed to save rule: ${data.error}`, false);
        }
    } catch (error) {
        showValidationResult(`Error saving rule: ${error.message}`, false);
    }
}

/**
 * Load all rules from the server
 */
async function loadRules() {
    const tbody = document.getElementById('rulesTableBody');
    tbody.innerHTML = '<tr><td colspan="6" class="text-center">Loading rules...</td></tr>';

    try {
        const response = await fetch('/api/rules');
        const data = await response.json();

        if (data.success) {
            displayRules(data.rules);
        } else {
            tbody.innerHTML = `<tr><td colspan="6" class="text-center">Error loading rules: ${data.error}</td></tr>`;
        }
    } catch (error) {
        tbody.innerHTML = `<tr><td colspan="6" class="text-center">Error loading rules: ${error.message}</td></tr>`;
    }
}

/**
 * Display rules in the table
 */
function displayRules(rules) {
    const tbody = document.getElementById('rulesTableBody');

    if (rules.length === 0) {
        tbody.innerHTML = '<tr><td colspan="6" class="text-center">No rules found. Create your first rule above!</td></tr>';
        return;
    }

    tbody.innerHTML = '';

    rules.forEach(rule => {
        const row = document.createElement('tr');

        const actionBadge = getActionBadge(rule.action);

        row.innerHTML = `
            <td><strong>${rule.sid || 'N/A'}</strong></td>
            <td>${escapeHtml(rule.msg || 'No message')}</td>
            <td>${actionBadge}</td>
            <td><code>${escapeHtml(rule.protocol || 'N/A')}</code></td>
            <td class="rule-cell" title="${escapeHtml(rule.raw)}">${escapeHtml(rule.raw)}</td>
            <td>
                <div class="actions-cell">
                    <button class="btn btn-sm btn-primary" onclick="editRule(${rule.sid})">✎ Edit</button>
                    <button class="btn btn-sm btn-danger" onclick="deleteRule(${rule.sid})">✕ Delete</button>
                </div>
            </td>
        `;

        tbody.appendChild(row);
    });
}

/**
 * Get badge HTML for action type
 */
function getActionBadge(action) {
    const badges = {
        'alert': '<span class="badge badge-alert">ALERT</span>',
        'drop': '<span class="badge badge-drop">DROP</span>',
        'pass': '<span class="badge badge-pass">PASS</span>',
        'reject': '<span class="badge badge-reject">REJECT</span>',
        'rejectsrc': '<span class="badge badge-reject">REJECT SRC</span>',
        'rejectdst': '<span class="badge badge-reject">REJECT DST</span>',
        'rejectboth': '<span class="badge badge-reject">REJECT BOTH</span>'
    };
    return badges[action] || `<span class="badge">${escapeHtml(action)}</span>`;
}

/**
 * Edit a rule
 */
async function editRule(sid) {
    try {
        const response = await fetch('/api/rules');
        const data = await response.json();

        if (data.success) {
            const rule = data.rules.find(r => r.sid === sid);

            if (rule) {
                currentEditingSid = sid;

                // Load rule into manual editor
                const manualEdit = document.getElementById('manualRuleEdit');
                manualEdit.value = rule.raw;

                // Update preview
                const preview = document.getElementById('rulePreview');
                preview.innerHTML = `<code>${syntaxHighlight(rule.raw)}</code>`;

                // Scroll to top
                window.scrollTo({ top: 0, behavior: 'smooth' });

                // Highlight the editor
                manualEdit.focus();

                showValidationResult(`Editing rule SID ${sid}. Make changes and click Save Rule.`, true);
            }
        }
    } catch (error) {
        alert(`Error loading rule: ${error.message}`);
    }
}

/**
 * Delete a rule
 */
async function deleteRule(sid) {
    if (!confirm(`Are you sure you want to delete rule SID ${sid}?`)) {
        return;
    }

    try {
        const response = await fetch(`/api/rules/${sid}`, {
            method: 'DELETE'
        });

        const data = await response.json();

        if (data.success) {
            showValidationResult(`✓ Rule deleted successfully!`, true);
            loadRules();
        } else {
            alert(`Failed to delete rule: ${data.error}`);
        }
    } catch (error) {
        alert(`Error deleting rule: ${error.message}`);
    }
}

/**
 * Reset the form to default values
 */
function resetForm() {
    document.getElementById('ruleForm').reset();

    // Clear content fields
    document.getElementById('contentFields').innerHTML = '';
    contentFieldCount = 0;

    // Reset editing state
    currentEditingSid = null;

    // Re-initialize
    initializeForm();
}

/**
 * Parse manual rule and load into form (basic implementation)
 */
function parseManualRule() {
    alert('This feature loads the manual rule into the preview. Full form parsing is complex and would require extensive regex. The manual editor provides direct rule editing capability.');
    updateRulePreview();
}

/**
 * Copy rule to clipboard
 */
async function copyToClipboard() {
    const manualEdit = document.getElementById('manualRuleEdit');
    const rule = manualEdit.value;

    try {
        await navigator.clipboard.writeText(rule);
        showValidationResult('✓ Rule copied to clipboard!', true);
    } catch (error) {
        // Fallback for older browsers
        manualEdit.select();
        document.execCommand('copy');
        showValidationResult('✓ Rule copied to clipboard!', true);
    }
}

/**
 * Export all rules as JSON
 */
async function exportRules() {
    try {
        const response = await fetch('/api/export');
        const data = await response.json();

        if (data.success) {
            // Create download
            const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `suricata-rules-export-${new Date().toISOString().split('T')[0]}.json`;
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            URL.revokeObjectURL(url);

            showValidationResult(`✓ Exported ${data.total} rules successfully!`, true);
        } else {
            alert(`Failed to export rules: ${data.error}`);
        }
    } catch (error) {
        alert(`Error exporting rules: ${error.message}`);
    }
}

/**
 * Show import dialog
 */
function showImportDialog() {
    document.getElementById('importModal').style.display = 'block';
}

/**
 * Close import dialog
 */
function closeImportDialog() {
    document.getElementById('importModal').style.display = 'none';
    document.getElementById('importData').value = '';
}

/**
 * Import rules from JSON
 */
async function importRules() {
    const importData = document.getElementById('importData').value;

    if (!importData.trim()) {
        alert('Please enter JSON data to import');
        return;
    }

    try {
        const data = JSON.parse(importData);

        const response = await fetch('/api/import', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(data)
        });

        const result = await response.json();

        if (result.success) {
            alert(`Successfully imported ${result.imported} rules!\n${result.errors.length > 0 ? 'Errors: ' + result.errors.join('\n') : ''}`);
            closeImportDialog();
            loadRules();
        } else {
            alert(`Failed to import rules: ${result.error}`);
        }
    } catch (error) {
        alert(`Error importing rules: ${error.message}`);
    }
}

/**
 * Reload Suricata service
 */
async function reloadService() {
    if (!confirm('Are you sure you want to reload the Suricata service? This will apply all rule changes.')) {
        return;
    }

    try {
        const response = await fetch('/api/reload', {
            method: 'POST'
        });

        const data = await response.json();

        if (data.success) {
            alert('✓ Suricata service reload initiated successfully!');
        } else {
            alert(`⚠ ${data.message || data.error}\n\n${data.hint || ''}`);
        }
    } catch (error) {
        alert(`Error reloading service: ${error.message}`);
    }
}

/**
 * Show help modal
 */
function showHelp() {
    document.getElementById('helpModal').style.display = 'block';
}

/**
 * Close help modal
 */
function closeHelp() {
    document.getElementById('helpModal').style.display = 'none';
}

/**
 * Close modals when clicking outside
 */
window.onclick = function(event) {
    const helpModal = document.getElementById('helpModal');
    const importModal = document.getElementById('importModal');

    if (event.target === helpModal) {
        closeHelp();
    }
    if (event.target === importModal) {
        closeImportDialog();
    }
}

/**
 * Escape HTML to prevent XSS
 */
function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

/**
 * Simple syntax highlighting for Suricata rules
 */
function syntaxHighlight(rule) {
    let highlighted = escapeHtml(rule);

    // Highlight actions
    highlighted = highlighted.replace(
        /^(alert|pass|drop|reject|rejectsrc|rejectdst|rejectboth)\s+/,
        '<span class="action">$1</span> '
    );

    // Highlight protocol
    highlighted = highlighted.replace(
        /\s+(tcp|udp|icmp|ip|http|dns|tls|ssh|ftp|smtp|smb)\s+/,
        ' <span class="protocol">$1</span> '
    );

    // Highlight direction
    highlighted = highlighted.replace(
        /\s+(-&gt;|&lt;&gt;)\s+/g,
        ' <span class="direction">$1</span> '
    );

    return highlighted;
}

// Keyboard shortcuts
document.addEventListener('keydown', (e) => {
    // Ctrl+S / Cmd+S to save
    if ((e.ctrlKey || e.metaKey) && e.key === 's') {
        e.preventDefault();
        saveRule();
    }

    // Ctrl+Enter / Cmd+Enter to validate
    if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
        e.preventDefault();
        validateCurrentRule();
    }

    // Escape to close modals
    if (e.key === 'Escape') {
        closeHelp();
        closeImportDialog();
    }
});
