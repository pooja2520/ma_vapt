// ─── DOM Elements ───────────────────────────────────────────
const targetInput        = document.getElementById('targetInput');
const loginType          = document.getElementById('loginType');
const scanBtn            = document.getElementById('scanBtn');
const btnIcon            = document.getElementById('btnIcon');
const btnText            = document.getElementById('btnText');
const newScanBtn         = document.getElementById('newScanBtn');
const errorMessage       = document.getElementById('errorMessage');
const errorText          = document.getElementById('errorText');
const authSuccessMessage = document.getElementById('authSuccessMessage');
const authSuccessText    = document.getElementById('authSuccessText');
const progressMessage    = document.getElementById('progressMessage');
const progressText       = document.getElementById('progressText');
const testCoverageSection= document.getElementById('testCoverageSection');
const resultsSection     = document.getElementById('resultsSection');
const resultsContainer   = document.getElementById('resultsContainer');
const scanLog            = document.getElementById('scanLog');
const basicAuthFields    = document.getElementById('basicAuthFields');
const formAuthFields     = document.getElementById('formAuthFields');

// ─── State ──────────────────────────────────────────────────
let isScanning   = false;
let eventSource  = null;
let crawledPaths = [];
const PHASE_PCT  = { 1: 15, 2: 40, 3: 85, 4: 100 };

// ─── Init ────────────────────────────────────────────────────
loginType.addEventListener('change', handleLoginTypeChange);
targetInput.addEventListener('keypress', e => { if (e.key === 'Enter' && !isScanning) handleScan(); });

// New Scan button HIDDEN by default; appears only after scan completes
newScanBtn.style.display = 'none';

window.addEventListener('DOMContentLoaded', () => { restoreStateOnLoad(); });

// ─── On page load: reconnect if scanning, or auto-fill+start from URL params ─
async function restoreStateOnLoad() {
    // Scanning page has its own initScanPage — avoid duplicate reconnect logic
    if (window.location.pathname === '/scanning') return;

    // ── 1. Check for ?url= query param (came from targets page play button) ──
    const params   = new URLSearchParams(window.location.search);
    const autoUrl  = params.get('url');
    const autoStart= params.get('autostart') === '1';

    if (autoUrl) {
        // Fill in the target URL field
        targetInput.value = decodeURIComponent(autoUrl);
        // Clean URL bar so refreshing doesn't re-trigger
        window.history.replaceState({}, '', '/scanning');

        if (autoStart) {
            // Small delay so the UI is fully painted before scan starts
            setTimeout(() => {
                showProgress('🚀 Auto-starting scan for ' + targetInput.value + '…');
                handleScan();
            }, 600);
            return; // skip reconnect check below
        }
    }

    // ── 2. Reconnect if a scan is already actively running ──────────────────
    try {
        const r    = await fetch('/api/scan-logs');
        const data = await r.json();

        if (data.running) {
            // Scan still in progress — reconnect SSE and show live logs
            if (autoUrl) targetInput.value = data.target || autoUrl;
            isScanning = true;
            updateScanButton(true);
            newScanBtn.style.display = 'none';
            if (data.logs && data.logs.length > 0) {
                clearLog();
                data.logs.forEach(line => appendLog(line));
            }
            connectToProgressStream();
        }
        // If idle or complete — clean page
    } catch (_) {}
}

// ─── Auth type toggle ────────────────────────────────────────
function handleLoginTypeChange() {
    const type = loginType.value;
    basicAuthFields.style.display = 'none';
    formAuthFields.style.display  = 'none';
    hideAuthSuccess();
    if (type === 'basic') { basicAuthFields.style.display = 'block'; }
    if (type === 'form')  { formAuthFields.style.display  = 'block'; }
}

// ─── Test Auth (returns true on success, false on failure) ─────
async function runAuthTest() {
    const target = targetInput.value.trim();
    const type   = loginType.value;
    if (!target)         { showError('Please enter a target URL first'); return false; }
    if (type === 'none') { showError('Please select an authentication method'); return false; }
    hideError(); hideAuthSuccess(); showProgress('🔍 Testing authentication...');
    try {
        const res    = await fetch('/test-auth', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ target, auth_type: type, auth_data: collectAuthData() }) });
        const result = await res.json();
        hideProgress();
        if (result.status === 'success') {
            showAuthSuccess(result.message);
            return true;
        }
        showError(result.message);
        return false;
    } catch (e) { hideProgress(); showError('Authentication test failed: ' + e.message); return false; }
}

function collectAuthData() {
    const type = loginType.value;
    const d = {};
    if (type === 'basic') {
        d.username = document.getElementById('basicUsername').value.trim();
        d.password = document.getElementById('basicPassword').value.trim();
    } else if (type === 'form') {
        d.login_url         = document.getElementById('formLoginUrl').value.trim();
        d.username          = document.getElementById('formUsername').value.trim();
        d.password          = document.getElementById('formPassword').value.trim();
        d.username_field    = document.getElementById('formUsernameField').value.trim() || 'username';
        d.password_field    = document.getElementById('formPasswordField').value.trim() || 'password';
        d.success_indicator = document.getElementById('formSuccessIndicator').value.trim();
    }
    return d;
}

// ─── Start Scan (test auth first if basic/form, then scan) ─────
async function handleScan() {
    const target = targetInput.value.trim();
    const type  = loginType.value;
    if (!target) { showError('Please enter a target URL or IP address'); return; }
    hideError(); hideAuthSuccess();

    // If auth is basic or form, run auth test first
    if (type === 'basic' || type === 'form') {
        const passed = await runAuthTest();
        if (!passed) return;
        hideAuthSuccess();  // clear before scan starts
    }

    isScanning = true; crawledPaths = [];
    updateScanButton(true);
    newScanBtn.style.display = 'none';   // hide during scan

    resultsSection.style.display      = 'none';
    testCoverageSection.style.display = 'none';
    clearLog(); resetProgress();
    showProgress('🚀 Initializing scan...');
    appendLog('[--:--:--] 🚀 Scan initializing for ' + target);

    try {
        const res    = await fetch('/scan', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ target, auth_type: type, auth_data: collectAuthData(), owasp_enabled: true }) });
        const result = await res.json();
        if (result.status === 'started') connectToProgressStream();
        else handleScanError(result.message || 'Scan failed to start');
    } catch (e) { handleScanError('Scan request failed: ' + e.message); }
}

// ─── SSE Stream ──────────────────────────────────────────────
function connectToProgressStream() {
    if (eventSource) eventSource.close();
    eventSource = new EventSource('/scan-progress');
    eventSource.onmessage = e => {
        try { handleProgressUpdate(JSON.parse(e.data)); } catch (err) { console.error(err); }
    };
    eventSource.onerror = () => { eventSource.close(); setTimeout(pollScanStatus, 1000); };
}

// ─── Progress event handler ──────────────────────────────────
function handleProgressUpdate(data) {
    switch (data.type) {
        case 'log':
            appendLog(data.message); break;
        case 'phase':
            setProgress(PHASE_PCT[data.phase] || 0, `Phase ${data.phase}: ${data.name}`);
            setPhaseActive(data.phase);
            showProgress(`📋 Phase ${data.phase}: ${data.name}`);
            appendLog(`[--:--:--] 📋 Phase ${data.phase}: ${data.name}`); break;
        case 'crawl_start':
            showProgress(`🕷️ Starting crawler (max ${data.max_pages} pages)...`);
            appendLog(`[--:--:--] 🕷️ Crawler starting — max ${data.max_pages} pages`); break;
        case 'crawling':
            crawledPaths.push(data.url);
            showProgress(`🕷️ Crawling: ${data.url}<br><small>Page ${data.count} of ${data.total}</small>`);
            appendLog(`[--:--:--] 🕷️ [${data.count}/${data.total}] ${data.url}`); break;
        case 'crawl_complete':
            setProgress(75, 'Crawl complete');
            showProgress(`✅ Crawl complete! ${data.total_paths} paths from ${data.pages_crawled} pages`);
            appendLog(`[--:--:--] ✅ Crawl done — ${data.total_paths} paths / ${data.pages_crawled} pages`); break;
        case 'complete':
            eventSource.close(); fetchScanResults(); break;
        case 'heartbeat': break;
    }
}

// ─── Poll fallback ───────────────────────────────────────────
async function pollScanStatus() {
    if (!isScanning) return;
    try {
        const r = await fetch('/scan-status');
        const d = await r.json();
        if      (d.status === 'running') setTimeout(pollScanStatus, 2000);
        else if (d.status === 'success') handleScanComplete(d);
        else if (d.status === 'error')   handleScanError(d.message);
        else                             setTimeout(pollScanStatus, 2000);
    } catch (e) { setTimeout(pollScanStatus, 2000); }
}

async function fetchScanResults() {
    showProgress('📊 Fetching results...');
    try {
        const r = await fetch('/scan-status');
        const d = await r.json();
        if      (d.status === 'success') handleScanComplete(d);
        else if (d.status === 'error')   handleScanError(d.message);
        else                             setTimeout(fetchScanResults, 1000);
    } catch (e) { handleScanError('Failed to fetch results: ' + e.message); }
}

// ─── Scan Complete ───────────────────────────────────────────
function handleScanComplete(result) {
    isScanning = false;
    updateScanButton(false);
    hideProgress();
    setProgress(100, 'Scan complete ✅');
    setAllPhasesDone();
    testCoverageSection.style.display = 'block';
    displayResults(result.results);
    resultsSection.style.display = 'block';
    resultsSection.scrollIntoView({ behavior: 'smooth' });
    appendLog('[--:--:--] ✅ Scan complete. Results loaded below.');
    // ⭐ Show "New Scan" ONLY after scan is done
    newScanBtn.style.display = 'inline-flex';
}

function handleScanError(message) {
    isScanning = false;
    updateScanButton(false);
    hideProgress();
    showError(message);
    appendLog('[--:--:--] ❌ Error: ' + message);
    if (eventSource) eventSource.close();
    newScanBtn.style.display = 'inline-flex';
}

// ─── Results Rendering ───────────────────────────────────────
function displayResults(results) {
    resultsContainer.innerHTML = '';
    if (!results || results.length === 0) {
        resultsContainer.innerHTML = '<p style="padding:1rem;color:var(--text-muted)">No security issues found.</p>';
        return;
    }
    results.forEach((r, i) => resultsContainer.appendChild(createResultElement(r, i)));
}

function createResultElement(result, index) {
    const div = document.createElement('div');
    div.className = `result-item severity-${(result.Severity||'info').toLowerCase()}`;
    const hasDetails = result.Remediation && result.Remediation !== 'N/A';
    if (hasDetails) { div.style.cursor = 'pointer'; div.addEventListener('click', () => toggleDetails(div, result)); }
    const statusClass = (result.Status||'').toLowerCase().replace(/ /g, '-');
    div.innerHTML = `
        <div class="result-content">
            <div class="result-test">
                <span>${result.Test}</span>
                ${hasDetails ? '<span class="expand-icon">▼</span>' : ''}
                <span class="badge status-${statusClass} status-badge">${result.Status}</span>
            </div>
            <div class="result-finding">${result.Finding}</div>
            ${result['Vulnerable Path'] && result['Vulnerable Path'] !== 'N/A'
                ? `<div class="result-finding" style="margin-top:8px"><strong>Affected Path(s):</strong> ${result['Vulnerable Path']}</div>` : ''}
        </div>`;
    return div;
}

function toggleDetails(el, result) {
    const existing = el.querySelector('.result-details');
    if (existing) {
        existing.remove(); el.classList.remove('expanded');
        const ic = el.querySelector('.expand-icon'); if (ic) ic.textContent = '▼';
        return;
    }
    const d = document.createElement('div'); d.className = 'result-details';
    let html = '';
    if (result.Remediation && result.Remediation !== 'N/A')
        html += `<div class="detail-section"><div class="detail-header"><span class="detail-icon">🛠️</span><strong>Remediation</strong></div><div class="detail-content">${result.Remediation}</div></div>`;
    if (result['Resolution Steps'] && result['Resolution Steps'] !== 'N/A')
        html += `<div class="detail-section"><div class="detail-header"><span class="detail-icon">📋</span><strong>Resolution Steps</strong></div><div class="detail-content">${formatResolutionSteps(result['Resolution Steps'])}</div></div>`;
    d.innerHTML = html;
    el.querySelector('.result-content').appendChild(d);
    el.classList.add('expanded');
    const ic = el.querySelector('.expand-icon'); if (ic) ic.textContent = '▲';
}

function formatResolutionSteps(steps) {
    if (typeof steps === 'string' && steps.includes('\n')) {
        const arr = steps.split('\n').filter(s => s.trim());
        return '<ol class="resolution-steps">' + arr.map(s => `<li>${s.trim()}</li>`).join('') + '</ol>';
    }
    return steps || '';
}

// ─── Scan Log Panel ──────────────────────────────────────────
function clearLog() {
    if (scanLog) scanLog.innerHTML = '';
}

function appendLog(line) {
    if (!scanLog) return;
    const ph = scanLog.querySelector('.log-info');
    if (ph) ph.remove();
    const span = document.createElement('div');
    span.style.cssText = 'padding:1px 0;border-bottom:1px solid rgba(255,255,255,0.04);word-break:break-all;';
    if      (line.includes('❌') || line.includes('Error'))    span.style.color = '#f87171';
    else if (line.includes('✅') || line.includes('complete'))  span.style.color = '#4ade80';
    else if (line.includes('📋') || line.includes('Phase'))     span.style.color = '#60a5fa';
    else if (line.includes('🕷️') || line.includes('Crawl'))    span.style.color = '#facc15';
    else if (line.includes('🚀'))                               span.style.color = '#a78bfa';
    else                                                         span.style.color = '#94a3b8';
    span.textContent = line;
    scanLog.appendChild(span);
    scanLog.scrollTop = scanLog.scrollHeight;
}

// ─── Progress Bar ────────────────────────────────────────────
function setProgress(pct, label) {
    const fill  = document.getElementById('progFill');
    const pLbl  = document.getElementById('phaseLabel');
    const pPct  = document.getElementById('pctLabel');
    if (fill)  fill.style.width   = pct + '%';
    if (pLbl)  pLbl.textContent   = label || '';
    if (pPct)  pPct.textContent   = pct + '%';
}

function resetProgress() {
    setProgress(0, 'Ready');
    document.querySelectorAll('.phase').forEach(p => p.classList.remove('active','done'));
}

function setPhaseActive(phase) {
    for (let i = 1; i <= 4; i++) {
        const el = document.getElementById('ph' + i);
        if (!el) continue;
        if      (i < phase)  { el.classList.remove('active'); el.classList.add('done'); }
        else if (i === phase) { el.classList.add('active');   el.classList.remove('done'); }
        else                  { el.classList.remove('active','done'); }
    }
}

function setAllPhasesDone() {
    for (let i = 1; i <= 4; i++) {
        const el = document.getElementById('ph' + i);
        if (!el) continue;
        el.classList.remove('active');
        el.classList.add('done');
    }
}

// ─── Misc ────────────────────────────────────────────────────
async function handleNewScan() {
    // 1. Tell server to wipe scan_results + logs so a refresh won't restore them
    try { await fetch('/api/reset-scan', { method: 'POST' }); } catch(_) {}

    // 2. Close any open SSE stream
    if (eventSource) { eventSource.close(); eventSource = null; }
    isScanning   = false;
    crawledPaths = [];

    // 3. Reset UI — hide results, coverage, logs
    resultsSection.style.display      = 'none';
    testCoverageSection.style.display = 'none';
    resultsContainer.innerHTML        = '';
    clearLog();
    resetProgress();

    // 4. Restore log panel placeholder text
    if (scanLog) {
        const ph = document.createElement('span');
        ph.className   = 'log-info';
        ph.style.color = '#64748b';
        ph.textContent = 'No scan logs yet. Configure and start a scan.';
        scanLog.appendChild(ph);
    }

    // 5. Hide New Scan button, re-enable Start Scan
    newScanBtn.style.display = 'none';
    updateScanButton(false);
    hideError();
    hideProgress();
    hideAuthSuccess();

    // 6. Clear the target input & reset auth
    targetInput.value = '';
    loginType.value   = 'none';
    handleLoginTypeChange();

    // 7. Scroll back to top
    window.scrollTo({ top: 0, behavior: 'smooth' });
}
function handleDownload() { window.location.href = '/download'; }

function updateScanButton(scanning) {
    if (scanning) {
        btnIcon.innerHTML   = '<span class="loading">⚙️</span>';
        btnText.textContent = 'Scanning...';
        scanBtn.disabled    = true;
    } else {
        btnIcon.textContent = '🔍';
        btnText.textContent = 'Test Auth & Start Scan';
        scanBtn.disabled    = false;
    }
}

function showError(msg)       { errorText.textContent = msg; errorMessage.style.display = 'flex'; }
function hideError()          { errorMessage.style.display = 'none'; }
function showAuthSuccess(msg) { authSuccessText.textContent = msg; authSuccessMessage.style.display = 'flex'; }
function hideAuthSuccess()    { authSuccessMessage.style.display = 'none'; }
function showProgress(msg)    { progressText.innerHTML = msg; progressMessage.style.display = 'flex'; }
function hideProgress()       { progressMessage.style.display = 'none'; }