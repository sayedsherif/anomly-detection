/* ════════════════════════════════════
   ELWARDANI — app.js  (v3.1 Enhanced)
   Security & Video Intro Upgrade
════════════════════════════════════ */
'use strict';

/* ── ANTI-FRAME + CLICKJACKING GUARD ── */
if (window.top !== window.self) {
    try { window.top.location = window.self.location; }
    catch { document.body.innerHTML = ''; window.stop(); }
}
const API_BASE = window.location.protocol === 'file:'
    ? ''
    : window.location.origin;

/* ── VIDEO INTRO CONTROLLER ── */
function runVideoIntro() {
    const intro         = document.getElementById('videoIntro');
    const video         = document.getElementById('introVideo');
    const progressBar   = document.getElementById('viProgressBar');
    const progressLabel = document.getElementById('viProgressLabel');
    const enterBtn      = document.getElementById('viEnterBtn');
    if (!intro) return;

    const msgs = [
        'AUTHENTICATING SYSTEM...',
        'LOADING NEURAL NETWORKS...',
        'ACTIVATING THREAT SENSORS...',
        'ESTABLISHING SECURE TUNNEL...',
        'SYSTEM READY'
    ];
    let pct = 0, msgIdx = 0;
    const msgTimer = setInterval(() => {
        if (msgIdx < msgs.length && progressLabel) progressLabel.textContent = msgs[msgIdx++];
    }, 900);
    const barTimer = setInterval(() => {
        pct = Math.min(100, pct + Math.random() * 9 + 3);
        if (progressBar) progressBar.style.width = pct + '%';
        if (pct >= 100) { clearInterval(barTimer); clearInterval(msgTimer); if (progressLabel) progressLabel.textContent = 'SYSTEM READY'; }
    }, 200);

    function dismissIntro() {
        clearInterval(barTimer); clearInterval(msgTimer);
        intro.classList.add('vi-fade-out');
        setTimeout(() => { intro.classList.add('vi-hidden'); try { video.pause(); } catch {} }, 1200);
    }

    if (video) {
        video.addEventListener('ended', dismissIntro, { once: true });
        video.addEventListener('error', () => { intro.classList.add('vi-hidden'); }, { once: true });
    }
    setTimeout(dismissIntro, 13000);

    if (enterBtn) enterBtn.addEventListener('click', dismissIntro, { once: true });
    document.addEventListener('keydown', function skipKey(e) {
        if (e.key === 'Enter' || e.key === ' ' || e.key === 'Escape') {
            document.removeEventListener('keydown', skipKey);
            dismissIntro();
        }
    });
}

/* ── DEEP SANITIZE HELPER ── */
function deepSanitize(obj, depth) {
    depth = depth || 0;
    if (depth > 5) return {};
    if (typeof obj === 'string') return sanitize(obj);
    if (typeof obj === 'number') return isFinite(obj) ? obj : 0;
    if (typeof obj === 'boolean') return obj;
    if (Array.isArray(obj)) return obj.slice(0,100).map(function(v){ return deepSanitize(v, depth+1); });
    if (obj && typeof obj === 'object') {
        var safe = {}, k = 0;
        for (var key in obj) {
            if (!Object.prototype.hasOwnProperty.call(obj, key)) continue;
            if (k++ > 50) break;
            var sk = sanitize(String(key));
            if (sk) safe[sk] = deepSanitize(obj[key], depth+1);
        }
        return safe;
    }
    return '';
}

/* ── SPLASH ── */
function runSplash() {
    const splash = document.getElementById('splashScreen');
    const bar    = document.getElementById('splashBar');
    const status = document.getElementById('splashStatus');
    const steps  = [
        { pct:15,  msg:'Loading security modules...',    idx:0 },
        { pct:30,  msg:'Initializing ML engine...',      idx:1 },
        { pct:50,  msg:'Connecting to backend...',       idx:2 },
        { pct:70,  msg:'Loading threat signatures...',   idx:3 },
        { pct:88,  msg:'Establishing session...',        idx:4 },
        { pct:100, msg:'System ready.',                  idx:4 }
    ];
    let i = 0;
    const tick = () => {
        if (i >= steps.length) { setTimeout(() => splash.classList.add('hidden'), 400); return; }
        bar.style.width    = steps[i].pct + '%';
        status.textContent = steps[i].msg;
        // Update checklist items
        const clIdx = steps[i].idx;
        if (clIdx !== undefined) {
            // Mark previous as done
            for (let j = 0; j < clIdx; j++) {
                const el = document.getElementById('scl'+j);
                if (el) { el.classList.remove('active'); el.classList.add('done'); const v = el.querySelector('.scl-val'); if(v) v.textContent = 'OK'; }
            }
            const cur = document.getElementById('scl'+clIdx);
            if (cur) { cur.classList.add('active'); const v = cur.querySelector('.scl-val'); if(v) v.textContent = '...'; }
        }
        i++;
        setTimeout(tick, 360);
    };
    tick();
}


/* ── SECURITY BOOTSTRAP ── */
const _CSRF = (() => {
    let t = sessionStorage.getItem('_csrf');
    if (!t) {
        t = Array.from(crypto.getRandomValues(new Uint8Array(16)))
            .map(b => b.toString(16).padStart(2,'0')).join('');
        sessionStorage.setItem('_csrf', t);
    }
    return t;
})();

const _SID = (() => {
    let s = sessionStorage.getItem('_sid');
    if (!s) {
        s = Date.now().toString(36).toUpperCase() +
            Math.random().toString(36).slice(2,8).toUpperCase();
        sessionStorage.setItem('_sid', s);
    }
    return s;
})();

const _RL = (() => {
    const MAX = 120, WIN = 60000;
    let calls = [];
    return {
        allow() {
            const n = Date.now();
            calls = calls.filter(t => n - t < WIN);
            if (calls.length >= MAX) return false;
            calls.push(n);
            return true;
        }
    };
})();

/* ── SANITIZATION ── */
function sanitize(str) {
    if (typeof str !== 'string') return '';
    const d = document.createElement('div');
    d.textContent = str.replace(/[<>"'`]/g,'').slice(0,500);
    return d.innerHTML;
}

function safeURL(url, max=70) {
    if (!window.DOMPurify) return url.slice(0, max);
    const c = DOMPurify.sanitize(String(url).trim(), { ALLOWED_TAGS:[], ALLOWED_ATTR:[] });
    return c.length > max ? c.slice(0,max-1) + '\u2026' : c;
}

function validateInput(v) {
    if (!v || typeof v !== 'string' || v.length > 2000) return false;
    return !/<script|javascript:|data:text|vbscript:|on\w+\s*=/i.test(v);
}

function encryptData(data, key=_CSRF) {
    try { return CryptoJS.AES.encrypt(JSON.stringify(data), key).toString(); }
    catch { return null; }
}

function decryptData(enc, key=_CSRF) {
    try { return JSON.parse(CryptoJS.AES.decrypt(enc, key).toString(CryptoJS.enc.Utf8)); }
    catch { return null; }
}

/* ── GLOBAL STATE ── */
// Phase 3: chart delta tracking
let _lastNormal = 0, _lastAnomaly = 0;

const STATE = {
    logs:[], totalRequests:0, normalRequests:0, anomalyRequests:0,
    isPaused:false, isRecording:false,
    theme: localStorage.getItem('theme') || 'dark',
    userRole: sessionStorage.getItem('userRole') || 'viewer',
    sessionToken: sessionStorage.getItem('authToken') || null,
    charts:{ traffic:null, attack:null },
    auditLog:[], recordedData:[], inactivityTimer:null,
    filterSeverity:'all', filterSearch:'',
    sessionId:_SID, csrfToken:_CSRF, startTime:Date.now()
};

/* ── SESSION ── */
function updateSessionDisplay() {
    document.getElementById('sessionDisplay').textContent =
        STATE.sessionToken ? STATE.sessionToken.slice(0,14)+'\u2026' : STATE.sessionId;
    document.getElementById('sbSession').textContent = STATE.sessionId;
    if (STATE.sessionToken) {
        document.getElementById('st-sess-val').textContent   = STATE.userRole;
        document.getElementById('st-sess-badge').textContent = 'AUTH';
        document.getElementById('st-sess-tile').className    = 'sec-tile ok';
    }
}

function initSessionTimeout() {
    ['mousemove','keydown','click','scroll','touchstart'].forEach(e =>
        document.addEventListener(e, resetInactivity, { passive:true })
    );
    resetInactivity();
}

function resetInactivity() {
    clearTimeout(STATE.inactivityTimer);
    if (!document.getElementById('sessionTimeout')?.checked) return;
    STATE.inactivityTimer = setTimeout(() => {
        showToast('Session expired — inactivity timeout','warning',4000);
        logAudit('session_expired',{ reason:'inactivity' });
        setTimeout(logout, 1500);
    }, 10*60*1000);
}

/* ── AUDIT ── */
function logAudit(action, details={}) {
    STATE.auditLog.push({
        timestamp: new Date().toISOString(),
        action, user: STATE.userRole,
        sessionId: STATE.sessionId, details
    });
    if (STATE.auditLog.length > 300) STATE.auditLog.shift();
}

/* ── CLOCK ── */
function tickClock() {
    const sysTimeEl = document.getElementById('sysTime');
    if (sysTimeEl) {
        sysTimeEl.textContent = new Date().toLocaleTimeString('en-US',{ hour12:false });
    }
}
setInterval(tickClock, 1000);
tickClock();

/* ── TOAST ── */
function showToast(msg, type='info', dur=3500) {
    if (!validateInput(msg)) return;
    const c = document.getElementById('toastContainer');
    const t = document.createElement('div');
    t.className = `toast ${type}`;
    t.setAttribute('role','alert');
    const icons = { success:'\u2713', danger:'\u26A0', warning:'!', info:'i' };

    let safe = msg;
    if (window.DOMPurify) {
        safe = DOMPurify.sanitize(msg, { ALLOWED_TAGS:[], ALLOWED_ATTR:[] });
    }

    t.innerHTML = `<span class="t-ic">${icons[type]||'i'}</span><span>${safe}</span>`;
    c.appendChild(t);
    if (dur > 0) setTimeout(() => {
        t.style.cssText = 'opacity:0;transition:opacity .35s ease';
        setTimeout(() => t.remove(), 350);
    }, dur);
}

/* ── THEME ── */
function applyTheme(th) {
    document.body.className = th === 'light' ? 'light' : '';
    document.documentElement.setAttribute('data-theme', th);
    document.getElementById('themeBtn').classList.toggle('dark', th !== 'light');
}

function toggleTheme() {
    STATE.theme = STATE.theme === 'dark' ? 'light' : 'dark';
    localStorage.setItem('theme', STATE.theme);
    applyTheme(STATE.theme);
    showToast(`${STATE.theme.toUpperCase()} MODE ACTIVATED`,'info',1500);
    logAudit('theme',{ theme:STATE.theme });
}

/* ── MODALS ── */
function openModal(id) {
    const m = document.getElementById(id);
    if (m) { m.classList.add('show'); m.setAttribute('aria-hidden','false'); }
}

function closeModal(id) {
    const m = document.getElementById(id);
    if (m) { m.classList.remove('show'); m.setAttribute('aria-hidden','true'); }
}

/* ── SETTINGS ── */
function saveSettings() {
    const s = {
        autoRefresh:    document.getElementById('autoRefresh').checked,
        soundAlerts:    document.getElementById('soundAlerts').checked,
        emailAlerts:    document.getElementById('emailAlerts').checked,
        dataEncryption: document.getElementById('dataEncryption').checked,
        sessionTimeout: document.getElementById('sessionTimeout').checked
    };
    const enc = encryptData(s);
    if (enc) {
        localStorage.setItem('dashboardSettings', enc);
        showToast('Configuration saved securely','success',2000);
        closeModal('settingsModal');
    } else {
        showToast('Encryption error — settings not saved','danger');
    }
}

function loadSettings() {
    try {
        const enc = localStorage.getItem('dashboardSettings');
        if (!enc) return;
        const s = decryptData(enc);
        if (!s) return;
        ['autoRefresh','soundAlerts','emailAlerts','dataEncryption','sessionTimeout'].forEach(k => {
            const el = document.getElementById(k);
            if (el && s[k] !== undefined) el.checked = s[k];
        });
    } catch {}
}

/* ── CHARTS ── */
function initCharts() {
    const dark = STATE.theme !== 'light';
    const grid = dark ? 'rgba(109,141,255,0.10)' : 'rgba(109,141,255,0.15)';
    const lbl  = dark ? '#5a638c' : '#7a80a0';

    Chart.defaults.color       = lbl;
    Chart.defaults.borderColor = grid;
    Chart.defaults.font.family = "'IBM Plex Mono',monospace";
    Chart.defaults.font.size   = 10;

    STATE.charts.traffic = new Chart(document.getElementById('trafficChart'), {
        type: 'line',
        data: {
            labels: [],
            datasets: [
                {
                    label:'NORMAL', data:[],
                    borderColor:'#38d6c4', backgroundColor:'rgba(56,214,196,.08)',
                    borderWidth:1.6, pointRadius:2.3, tension:.35, fill:true
                },
                {
                    label:'ANOMALY', data:[],
                    borderColor:'#ff4d5f', backgroundColor:'rgba(255,77,95,.08)',
                    borderWidth:1.6, pointRadius:2.3, tension:.35, fill:true
                }
            ]
        },
        options: {
            responsive:true, maintainAspectRatio:true, animation:{ duration:240 },
            plugins: {
                legend:  { position:'top', labels:{ boxWidth:10, padding:14, color:lbl } },
                tooltip: {
                    backgroundColor: dark?'rgba(10,14,24,.96)':'rgba(255,255,255,.97)',
                    borderColor:'rgba(214,179,106,.3)', borderWidth:1,
                    titleColor:'#d6b36a',
                    bodyColor: dark?'#a5afd3':'#3d4070',
                    padding:12, cornerRadius:4
                }
            },
            scales: {
                x:{ grid:{ color:grid }, ticks:{ maxRotation:0 } },
                y:{ grid:{ color:grid }, beginAtZero:true, ticks:{ stepSize:1 } }
            }
        }
    });

    STATE.charts.attack = new Chart(document.getElementById('attackChart'), {
        type: 'doughnut',
        data: {
            labels: ['NORMAL','SQL INJECT','XSS','DIR TRAVERSE','CMD INJECT'],
            datasets: [{
                data: [1,0,0,0,0],
                backgroundColor: [
                    'rgba(56,214,196,.85)','rgba(255,77,95,.85)',
                    'rgba(255,190,85,.85)','rgba(109,141,255,.85)',
                    'rgba(214,179,106,.85)'
                ],
                borderColor: dark ? '#05070d' : '#f2f4fb',
                borderWidth:3, hoverOffset:6
            }]
        },
        options: {
            responsive:true, maintainAspectRatio:true, cutout:'60%',
            plugins: {
                legend: {
                    position:'right',
                    labels:{ boxWidth:10, padding:14, color:lbl, font:{ size:9 } }
                },
                tooltip: {
                    backgroundColor: dark?'rgba(10,14,24,.96)':'rgba(255,255,255,.97)',
                    borderColor:'rgba(214,179,106,.3)', borderWidth:1,
                    titleColor:'#d6b36a',
                    bodyColor: dark?'#a5afd3':'#3d4070',
                    padding:12
                }
            }
        }
    });
}

function updateCharts() {
    if (!STATE.charts.traffic) return;
    const now = new Date().toLocaleTimeString('en-US',{hour12:false});
    const tc  = STATE.charts.traffic;

    if (tc.data.labels.length >= 20) {
        tc.data.labels.shift();
        tc.data.datasets[0].data.shift();
        tc.data.datasets[1].data.shift();
    }
    tc.data.labels.push(now);
    // Phase 3 fix: use delta counts, not rolling slice
    const newNormal  = STATE.normalRequests  - _lastNormal;
    const newAnomaly = STATE.anomalyRequests - _lastAnomaly;
    _lastNormal  = STATE.normalRequests;
    _lastAnomaly = STATE.anomalyRequests;
    tc.data.datasets[0].data.push(newNormal);
    tc.data.datasets[1].data.push(newAnomaly);
    tc.update('none');

    const ac  = STATE.charts.attack;
    const cnt = { normal:0, SQL_INJECTION:0, XSS:0, DIRECTORY_TRAVERSAL:0, COMMAND_INJECTION:0 };
    STATE.logs.forEach(l => {
        if (l.prediction_code===0) cnt.normal++;
        else if (l.attack_type in cnt) cnt[l.attack_type]++;
    });
    ac.data.datasets[0].data = Object.values(cnt);
    ac.update('none');
}

/* ── LOG TABLE ── */
function mClass(m) {
    return ({ GET:'get', POST:'post', PUT:'put', DELETE:'del' })[String(m||'').toUpperCase()] || '';
}

function renderLogs() {
    const tb   = document.getElementById('logTable');
    let   list = [...STATE.logs];

    if (STATE.filterSeverity !== 'all') {
        list = list.filter(l => {
            if (STATE.filterSeverity==='critical') return l.prediction_code===1;
            if (STATE.filterSeverity==='normal')   return l.prediction_code===0;
            if (STATE.filterSeverity==='high')     return l.prediction_code===1 && l.confidence>0.7;
            return true;
        });
    }

    if (STATE.filterSearch) {
        const q = STATE.filterSearch.toLowerCase();
        list = list.filter(l =>
            String(l.url||'').toLowerCase().includes(q)         ||
            String(l.method||'').toLowerCase().includes(q)      ||
            String(l.attack_type||'').toLowerCase().includes(q) ||
            String(l.time||'').toLowerCase().includes(q)        ||
            String(l.model_type||'').toLowerCase().includes(q)  ||
            String(l.confidence||'').toString().includes(q)
        );
    }

    if (!list.length) {
        tb.innerHTML = `<tr><td colspan="5" class="empty-state">
            <div class="empty-lbl">No results matching "${sanitize(STATE.filterSearch||STATE.filterSeverity)}"</div>
        </td></tr>`;
        return;
    }

    tb.innerHTML = list.slice(0,50).map(l => {
        const a = l.prediction_code===1;
        const c = Math.max(0,Math.min(1,l.confidence||0));
        return `<tr>
            <td class="td-time">${sanitize(l.time||'--')}</td>
            <td class="td-method ${mClass(l.method)}">${sanitize(l.method||'--')}</td>
            <td class="td-url">${safeURL(l.url||'--',76)}</td>
            <td>${a
                ? `<span class="badge badge-crit">${sanitize(l.attack_type||'ANOMALY')}</span>`
                : '<span class="badge badge-ok">CLEAN</span>'
            }</td>
            <td class="td-conf">${(c*100).toFixed(0)}</td>
        </tr>`;
    }).join('');
}

/* ── CONNECTION STATUS ── */
function updateConnectionStatus(connected) {
    const dot = document.getElementById('connDot');
    const txt = document.getElementById('connectionStatus');
    const tl  = document.getElementById('threatLabel');
    if (connected) {
        dot.className   = 'sb-dot g';
        txt.textContent = 'CONNECTED LIVE';
        txt.className   = '';
        tl.textContent  = STATE.anomalyRequests > 0 ? 'THREAT ACTIVE' : 'MONITORING';
    } else {
        dot.className   = 'sb-dot r';
        txt.textContent = 'DISCONNECTED';
        txt.className   = 'off';
        tl.textContent  = 'OFFLINE';
    }
}

/* ── UI UPDATER ── */
function playAlert() {
    try { document.getElementById('alertChime').play().catch(()=>{}); } catch {}
}

function updateBars() {
    const tot = STATE.totalRequests;
    if (!tot) return;
    document.getElementById('barTotal').style.width   = Math.min(100,(tot/Math.max(tot,100))*100)+'%';
    document.getElementById('barNormal').style.width  = (STATE.normalRequests/tot*100)+'%';
    document.getElementById('barAnomaly').style.width = (STATE.anomalyRequests/tot*100)+'%';
    document.getElementById('barRate').style.width    = Math.min(100,STATE.anomalyRequests/tot*100)+'%';
}

function updateUI(result) {
    if (!result || STATE.isPaused) return;
    if (typeof result !== 'object' || !('prediction_code' in result)) return;

    const a = result.prediction_code === 1;
    STATE.logs.unshift({
        ...result,
        time:      new Date().toLocaleTimeString('en-US',{hour12:false}),
        timestamp: new Date().toLocaleString('en-US',{hour12:false})
    });
    if (STATE.logs.length > 150) STATE.logs.pop();

    if (a) STATE.anomalyRequests++; else STATE.normalRequests++;
    STATE.totalRequests++;

    const tot  = STATE.totalRequests;
    const rate = tot > 0 ? ((STATE.anomalyRequests/tot)*100).toFixed(1)+'%' : '0%';

    document.getElementById('totalReq').textContent      = tot;
    document.getElementById('normalReq').textContent     = STATE.normalRequests;
    document.getElementById('anomalyReq').textContent    = STATE.anomalyRequests;
    document.getElementById('detectionRate').textContent = rate;
    document.getElementById('sbTotal').textContent       = tot;
    document.getElementById('sbThreats').textContent     = STATE.anomalyRequests;
    document.getElementById('sbRate').textContent        = rate;

    updateBars();
    renderLogs();
    updateCharts();

    if (a && result.attack_type) {
        if (document.getElementById('soundAlerts')?.checked) playAlert();
        const msg = result.threat_probability
            ? `THREAT: ${result.threat_probability}`
            : `THREAT: ${result.attack_type} — ${(result.confidence*100).toFixed(0)}% confidence`;
        showToast(msg, 'danger', 4500);
        document.getElementById('threatLabel').textContent = 'THREAT ACTIVE';
    }
    if (STATE.isRecording) STATE.recordedData.push(result);
}

/* ── API CALLS ── */
async function fetchDetection(method='GET', url='/', content='') {
    if (!_RL.allow()) {
        showToast('Rate limit exceeded — please wait','warning',2000);
        return null;
    }
    try {
        const res = await fetch(`${API_BASE}/api/v1/detect`, {
            method: 'POST',
            headers: {
                'Content-Type':     'application/json',
                'X-CSRF-Token':     STATE.csrfToken,
                'X-Session-ID':     STATE.sessionId,
                'X-Requested-With': 'XMLHttpRequest'
            },
            body: JSON.stringify({ Method:method, URL:url, content:content||'' })
        });
        if (!res.ok) throw new Error('HTTP '+res.status);
        updateConnectionStatus(true);
        return await res.json();
    } catch {
        updateConnectionStatus(false);
        return null;
    }
}

async function fetchStats() {
    try {
        const res = await fetch(`${API_BASE}/api/v1/stats`, {
            headers: {
                'X-CSRF-Token':     STATE.csrfToken,
                'X-Requested-With': 'XMLHttpRequest'
            }
        });
        if (!res.ok) throw new Error('HTTP '+res.status);
        updateConnectionStatus(true);
        return await res.json();
    } catch {
        updateConnectionStatus(false);
        return null;
    }
}

async function fetchHistory(limit=50) {
    try {
        const res = await fetch(`${API_BASE}/api/v1/history?limit=${limit}`, {
            headers: {
                'X-CSRF-Token':     STATE.csrfToken,
                'X-Requested-With': 'XMLHttpRequest'
            }
        });
        if (!res.ok) throw new Error('HTTP '+res.status);
        updateConnectionStatus(true);
        return await res.json();
    } catch {
        updateConnectionStatus(false);
        return null;
    }
}

/* ── ATTACK INFO ── */
const ATTACK_INFO = {
    SQL_INJECTION: {
        label:'SQL INJECTION', risk:'CRITICAL',
        what:'An attack where malicious SQL code is inserted into a query.',
        how:'Attackers inject keywords like OR 1=1 or UNION SELECT into URL parameters.',
        impact:'Full database dump, authentication bypass, data deletion.',
        fix:'Use parameterized queries / prepared statements. Never concatenate user input.',
        patterns:['OR 1=1','UNION SELECT',"' OR '",'-- ','DROP TABLE','INSERT INTO']
    },
    XSS: {
        label:'CROSS-SITE SCRIPTING (XSS)', risk:'CRITICAL',
        what:'Malicious scripts injected into web pages viewed by other users.',
        how:'Attackers embed tags like <script> into URL params or form fields.',
        impact:'Session hijacking, cookie theft, credential harvesting.',
        fix:'Encode all output. Use Content-Security-Policy headers. Sanitize inputs.',
        patterns:['<script>','<iframe>','onerror=','javascript:','alert(','eval(']
    },
    DIRECTORY_TRAVERSAL: {
        label:'DIRECTORY TRAVERSAL', risk:'HIGH',
        what:'An attack that exploits insufficient path validation to access files.',
        how:'Attackers use sequences like ../../ to navigate up the directory tree.',
        impact:'Disclosure of sensitive server files outside the web root.',
        fix:'Validate file paths server-side. Use os.path.realpath() checks.',
        patterns:['../../','%2e%2e','/etc/passwd','../','..\\']
    },
    COMMAND_INJECTION: {
        label:'COMMAND INJECTION', risk:'CRITICAL',
        what:'OS shell commands are injected into application inputs.',
        how:'Attackers append shell metacharacters (;, |, `) to inputs.',
        impact:'Full remote code execution, reverse shells, data exfiltration.',
        fix:'Never pass user input to shell commands. Use language APIs instead.',
        patterns:['; ls','| bash','`cmd`','$(cmd)','&& cat','; rm -rf']
    },
    BEHAVIORAL_ANOMALY: {
        label:'BEHAVIORAL ANOMALY', risk:'MEDIUM',
        what:'The ML model flagged this request as statistically unusual.',
        how:'The Isolation Forest algorithm detected an outlier in request features.',
        impact:'May indicate a novel attack, scanner, or bot activity.',
        fix:'Review request patterns. Check for automated scanning tools.',
        patterns:['unusual url length','high special chars','abnormal method ratio']
    }
};

function getPatternMatch(attackType, url) {
    const info = ATTACK_INFO[attackType];
    if (!info) return url.slice(0,80);
    const decoded = decodeURIComponent(url);
    for (const p of info.patterns) {
        if (decoded.toLowerCase().includes(p.toLowerCase())) return p;
    }
    return decoded.slice(0,60);
}

/* ── SCANNER RESULT RENDERER ── */
function showScanResult(result, url, method) {
    const isAnomaly  = result.prediction_code === 1;
    const conf       = Math.max(0,Math.min(1,result.confidence||0));
    const attackType = result.attack_type || null;  // Phase 2: null-safe (backend now returns null not 'None')

    document.getElementById('scanLoading').style.display = 'none';
    document.getElementById('scanResult').style.display  = 'block';

    const icon = document.getElementById('verdictIcon');
    icon.style.borderColor = isAnomaly ? 'var(--red)' : 'var(--teal)';
    icon.style.background  = isAnomaly ? 'rgba(255,77,95,.12)' : 'rgba(56,214,196,.12)';
    icon.style.color       = isAnomaly ? 'var(--red)' : 'var(--teal)';
    icon.textContent       = isAnomaly ? '!' : '\u2713';

    const statusEl = document.getElementById('verdictStatus');
    statusEl.textContent      = isAnomaly ? 'THREAT DETECTED' : 'REQUEST IS CLEAN';
    statusEl.style.color      = isAnomaly ? 'var(--red)' : 'var(--teal)';
    statusEl.style.textShadow = isAnomaly
        ? '0 0 20px rgba(255,77,95,.4)'
        : '0 0 20px rgba(56,214,196,.4)';

    document.getElementById('verdictDetail').textContent = isAnomaly
        ? (result.threat_probability || `Attack detected — ${result.model_type||'Rule-based'} engine`)
        : 'No attack patterns found — request appears safe';

    const confEl = document.getElementById('verdictConf');
    confEl.textContent      = (conf*100).toFixed(0)+'%';
    confEl.style.color      = isAnomaly ? 'var(--red)' : 'var(--teal)';
    confEl.style.textShadow = isAnomaly
        ? '0 0 20px rgba(255,77,95,.3)'
        : '0 0 20px rgba(56,214,196,.3)';

    const explainer = document.getElementById('attackExplainer');
    if (isAnomaly && attackType && ATTACK_INFO[attackType]) {
        const info = ATTACK_INFO[attackType];
        explainer.style.display = 'block';
        document.getElementById('explainerTitle').textContent = info.label;

        const riskEl = document.getElementById('explainerRisk');
        riskEl.textContent = info.risk;
        if (info.risk === 'HIGH' || info.risk === 'MEDIUM') {
            riskEl.style.borderColor = 'rgba(255,190,85,.4)';
            riskEl.style.color       = 'var(--amber)';
            riskEl.style.background  = 'rgba(255,190,85,.08)';
        } else {
            riskEl.style.borderColor = 'rgba(255,77,95,.4)';
            riskEl.style.color       = 'var(--red)';
            riskEl.style.background  = 'rgba(255,77,95,.08)';
        }

        document.getElementById('explainerWhat').textContent   = info.what;
        document.getElementById('explainerHow').textContent    = info.how;
        document.getElementById('explainerImpact').textContent = info.impact;
        document.getElementById('explainerFix').textContent    = info.fix;
        document.getElementById('pmCode').textContent =
            (result.matched_patterns && result.matched_patterns.length)
                ? result.matched_patterns.join('  ·  ')
                : getPatternMatch(attackType, url);
    } else {
        explainer.style.display = 'none';
    }

    document.getElementById('smUrl').textContent =
        url.length > 70 ? url.slice(0,69)+'\u2026' : url;
    const smMethod = document.getElementById('smMethod');
    smMethod.textContent  = method;
    smMethod.style.color  =
        method==='GET'    ? 'var(--indigo)' :
        method==='DELETE' ? 'var(--red)'    :
        method==='POST'   ? 'var(--amber)'  : 'var(--teal)';
    document.getElementById('smTime').textContent   =
        new Date().toLocaleTimeString('en-US',{hour12:false});
    document.getElementById('smEngine').textContent =
        result.model_type || 'Rule-based';

    updateUI({ ...result, url, method });
}

/* ── RUN SCAN ── */
async function runScan() {
    const urlInput = document.getElementById('scanUrl');
    const url      = urlInput.value.trim();
    const method   = document.getElementById('scanMethod').value;

    if (!url) {
        showToast('Please enter a URL to scan','warning',2500);
        urlInput.focus();
        return;
    }
    if (url.length > 500) {
        showToast('URL too long (max 500 chars)','warning',2500);
        return;
    }

    document.getElementById('scanResult').style.display  = 'none';
    document.getElementById('scanLoading').style.display = 'flex';
    document.getElementById('scanBtn').disabled = true;
    logAudit('manual_scan',{ url:url.slice(0,100), method });

    try {
        const res = await fetch(`${API_BASE}/api/v1/detect`, {
            method: 'POST',
            headers: {
                'Content-Type':     'application/json',
                'X-CSRF-Token':     STATE.csrfToken,
                'X-Session-ID':     STATE.sessionId,
                'X-Requested-With': 'XMLHttpRequest'
            },
            body: JSON.stringify({ Method:method, URL:url, content:'' })
        });
        if (!res.ok) throw new Error('HTTP '+res.status);
        const result = await res.json();
        updateConnectionStatus(true);
        showScanResult(result, url, method);
        if (result.prediction_code === 1) {
            showToast('THREAT: '+(result.attack_type||'ANOMALY')+' detected','danger',5000);
        } else {
            showToast('URL scan complete — no threats found','success',3000);
        }
    } catch {
        document.getElementById('scanLoading').style.display = 'none';
        updateConnectionStatus(false);
        showToast(
            'Scan failed — backend unreachable. Start the Flask server first.',
            'danger', 5000
        );
    } finally {
        document.getElementById('scanBtn').disabled = false;
    }
}

function quickScan(url) {
    document.getElementById('scanUrl').value = decodeURIComponent(url);
    runScan();
    document.querySelector('.scanner-panel')
            .scrollIntoView({ behavior:'smooth', block:'start' });
}

/* ── EXPORT ── */
function exportLogs() {
    if (!STATE.logs.length) { showToast('No logs to export','warning'); return; }
    const hdr  = 'Timestamp,Method,URL,Status,Attack Type,Confidence\n';
    const rows = STATE.logs.map(l =>
        [
            l.timestamp, l.method, l.url,
            l.prediction_code===0 ? 'CLEAN' : 'ANOMALY',
            l.attack_type||'',
            (l.confidence||0).toFixed(4)
        ].map(v => `"${String(v).replace(/"/g,'""')}"`).join(',')
    ).join('\n');
    const blob = new Blob([hdr+rows],{ type:'text/csv;charset=utf-8;' });
    const a    = document.createElement('a');
    a.href     = URL.createObjectURL(blob);
    a.download = `ELWARDANI-logs-${Date.now()}.csv`;
    a.click();
    URL.revokeObjectURL(a.href);
    showToast('Log export complete','success',2000);
    logAudit('export_logs',{ count:STATE.logs.length });
}

function exportAuditLog() {
    if (!STATE.auditLog.length) { showToast('No audit entries','warning'); return; }
    const hdr  = 'Timestamp,Action,User,SessionId,Details\n';
    const rows = STATE.auditLog.map(l =>
        [l.timestamp,l.action,l.user,l.sessionId,JSON.stringify(l.details)]
            .map(v => `"${String(v).replace(/"/g,'""')}"`).join(',')
    ).join('\n');
    const blob = new Blob([hdr+rows],{ type:'text/csv;charset=utf-8;' });
    const a    = document.createElement('a');
    a.href     = URL.createObjectURL(blob);
    a.download = `ELWARDANI-audit-${Date.now()}.csv`;
    a.click();
    URL.revokeObjectURL(a.href);
    showToast('Audit log exported','success',2000);
}

function openAuditModal() {
    const tb = document.getElementById('auditBody');
    if (!STATE.auditLog.length) {
        tb.innerHTML = `<tr><td colspan="3"
            style="color:var(--txt-lo);padding:20px;text-align:center;
                   font-family:var(--ff-mono);font-size:11px;">
            No audit entries yet</td></tr>`;
    } else {
        tb.innerHTML = STATE.auditLog.slice().reverse().map(l =>
            `<tr>
                <td class="td-time">${sanitize(l.timestamp.replace('T',' ').slice(0,19))}</td>
                <td style="font-family:var(--ff-ui);font-size:11px;font-weight:700;
                           color:var(--gold)">${sanitize(l.action)}</td>
                <td style="color:var(--txt-lo);font-family:var(--ff-mono);
                           font-size:10px">${sanitize(l.user)}</td>
            </tr>`
        ).join('');
    }
    openModal('auditModal');
}

/* ── PAUSE / RECORD / LOGOUT ── */
function togglePause() {
    STATE.isPaused = !STATE.isPaused;
    const btn = document.getElementById('pauseBtn');
    if (STATE.isPaused) {
        btn.innerHTML =
            `<svg class="btn-icon" viewBox="0 0 16 16" fill="currentColor">
                <polygon points="3,2 13,8 3,14"/>
             </svg> RESUME`;
        btn.classList.replace('btn-primary','btn-amber');
        showToast('Feed paused','warning',2000);
    } else {
        btn.innerHTML =
            `<svg class="btn-icon" viewBox="0 0 16 16" fill="currentColor">
               <rect x="3" y="2" width="4" height="12" rx="1"/>
               <rect x="9" y="2" width="4" height="12" rx="1"/>
             </svg> PAUSE`;
        btn.classList.replace('btn-amber','btn-primary');
        showToast('Feed resumed','success',2000);
    }
    logAudit('feed_toggle',{ paused:STATE.isPaused });
}

function toggleFullscreen() {
    if (!document.fullscreenElement) {
        document.documentElement.requestFullscreen()
            .catch(err => showToast(`Fullscreen error: ${err.message}`,'danger'));
    } else {
        document.exitFullscreen();
    }
}

function toggleRecord() {
    STATE.isRecording = !STATE.isRecording;
    const btn = document.getElementById('recordBtn');
    if (STATE.isRecording) {
        STATE.recordedData = [];
        btn.classList.add('btn-danger');
        btn.innerHTML =
            `<svg class="btn-icon" viewBox="0 0 16 16" fill="currentColor">
                <rect x="3" y="3" width="10" height="10" rx="1"/>
             </svg> STOP`;
        showToast('Recording session started','danger',2000);
    } else {
        btn.classList.remove('btn-danger');
        btn.innerHTML =
            `<svg class="btn-icon" viewBox="0 0 16 16" fill="currentColor">
               <circle cx="8" cy="8" r="5"/>
             </svg> REC`;
        const cnt = STATE.recordedData.length;
        showToast(`Recording stopped — ${cnt} events captured`,'success',3000);
        if (cnt) {
            const blob = new Blob(
                [JSON.stringify(STATE.recordedData,null,2)],
                { type:'application/json' }
            );
            const a    = document.createElement('a');
            a.href     = URL.createObjectURL(blob);
            a.download = `ELWARDANI-session-${Date.now()}.json`;
            a.click();
            URL.revokeObjectURL(a.href);
        }
    }
    logAudit('record_toggle',{ recording:STATE.isRecording });
}

function logout() {
    logAudit('logout',{ sessionId:STATE.sessionId });
    STATE.sessionToken  = null;
    STATE.logs          = [];
    STATE.auditLog      = [];
    STATE.recordedData  = [];
    try { sessionStorage.clear(); }    catch {}
    try { localStorage.removeItem('dashboardSettings'); } catch {}
    showToast('Session terminated securely','info',2500);
    setTimeout(() => {
        try { window.location.replace('/'); }
        catch { window.location.href = '/'; }
    }, 1500);
}

/* ── AUTO-POLLING SAMPLE URLS ── */
const _MM = ['GET','POST','PUT','DELETE','GET','GET','POST'];
const _MU = [
    '/api/v1/users', '/api/v1/auth/login', '/search?q=report',
    '/api/v1/orders', '/metrics/health',
    '/api/data?id=1 OR 1=1', "/login?user=admin'--",
    '/search?q=1 UNION SELECT username,password FROM users',
    '/page?name=%3Cscript%3Ealert(1)%3C%2Fscript%3E',
    '/download?file=../../etc/passwd',
    '/ping?host=127.0.0.1;ls -la'
];

async function poll() {
    if (STATE.isPaused || !document.getElementById('autoRefresh')?.checked) return;
    const m = _MM[Math.floor(Math.random()*_MM.length)];
    const u = _MU[Math.floor(Math.random()*_MU.length)];
    const r = await fetchDetection(m, u);
    if (r) updateUI(r);
}

/* ── EVENT BINDINGS ── */
document.querySelectorAll('.ct-btn').forEach(btn => {
    btn.addEventListener('click', () => {
        const chart = btn.dataset.chart;
        const type  = btn.dataset.type;
        if (!STATE.charts[chart]) return;
        STATE.charts[chart].config.type = type;
        if (chart==='traffic') {
            STATE.charts[chart].data.datasets.forEach(d => d.fill = type !== 'line');
        }
        STATE.charts[chart].update();
        btn.closest('.chart-toggle').querySelectorAll('.ct-btn')
            .forEach(b => b.classList.remove('active'));
        btn.classList.add('active');
    });
});

document.getElementById('pauseBtn')?.addEventListener('click', togglePause);
document.getElementById('recordBtn')?.addEventListener('click', toggleRecord);
document.getElementById('exportBtn')?.addEventListener('click', exportLogs);
document.getElementById('settingsBtn')?.addEventListener('click', () => openModal('settingsModal'));
document.getElementById('auditBtn')?.addEventListener('click', openAuditModal);
document.getElementById('logoutBtn')?.addEventListener('click', logout);
document.getElementById('themeBtn')?.addEventListener('click', toggleTheme);
document.getElementById('scanBtn')?.addEventListener('click', runScan);
document.getElementById('scanUrl')?.addEventListener('keydown', e => { if (e.key==='Enter') runScan(); });
document.getElementById('exportAuditBtn')?.addEventListener('click', exportAuditLog);

document.getElementById('searchInput')?.addEventListener('input', e => {
    STATE.filterSearch = e.target.value.replace(/[<>"'`]/g,'').slice(0,100);
    renderLogs();
});

document.querySelectorAll('.sev-btn').forEach(btn => {
    btn.addEventListener('click', () => {
        document.querySelectorAll('.sev-btn')
                .forEach(b => b.classList.remove('active'));
        btn.classList.add('active');
        STATE.filterSeverity = btn.dataset.severity;
        renderLogs();
        logAudit('filter',{ severity:STATE.filterSeverity });
    });
});

document.getElementById('refreshBtn')?.addEventListener('click', async () => {
    const data = await fetchHistory(50);
    if (data && data.history) {
        data.history.forEach(h => {
            if (!STATE.logs.find(l => l.timestamp === h.timestamp)) {
                STATE.logs.unshift({
                    ...h,
                    time: new Date(h.timestamp)
                        .toLocaleTimeString('en-US',{hour12:false})
                });
            }
        });
        if (STATE.logs.length > 150) STATE.logs.length = 150;
        renderLogs();
        updateCharts();
    }
    showToast('Feed refreshed from server','info',1200);
});

document.getElementById('clearBtn')?.addEventListener('click', () => {
    if (!confirm('Clear all log data?')) return;
    STATE.logs            = [];
    STATE.totalRequests   = 0;
    STATE.normalRequests  = 0;
    STATE.anomalyRequests = 0;
    ['totalReq','normalReq','anomalyReq'].forEach(id => {
        if(document.getElementById(id)) document.getElementById(id).textContent = '0';
    });
    if(document.getElementById('detectionRate')) document.getElementById('detectionRate').textContent = '0%';
    if(document.getElementById('sbTotal')) document.getElementById('sbTotal').textContent       = '0';
    if(document.getElementById('sbThreats')) document.getElementById('sbThreats').textContent     = '0';
    if(document.getElementById('sbRate')) document.getElementById('sbRate').textContent        = '0%';

    if (STATE.charts.traffic) {
        STATE.charts.traffic.data.labels = [];
        STATE.charts.traffic.data.datasets.forEach(d => d.data = []);
        STATE.charts.traffic.update();
    }
    updateBars();
    renderLogs();
    showToast('Logs cleared','warning',2000);
    logAudit('logs_cleared');
});

document.querySelectorAll('.hint-chip').forEach(chip => {
    chip.addEventListener('click', () => quickScan(chip.dataset.url));
});

document.querySelectorAll('.modal').forEach(m => {
    m.addEventListener('mousedown', e => {
        if (e.target === m) closeModal(m.id);
    });
});

/* ── KEYBOARD SHORTCUTS ── */
if (window.Mousetrap) {
    Mousetrap.bind('ctrl+p', e => { e.preventDefault(); togglePause(); });
    Mousetrap.bind('ctrl+e', e => { e.preventDefault(); exportLogs(); });
    Mousetrap.bind('ctrl+shift+f', e => { e.preventDefault(); toggleFullscreen(); });
    Mousetrap.bind('ctrl+,', e => { e.preventDefault(); openModal('settingsModal'); });
    Mousetrap.bind('escape', () =>
        document.querySelectorAll('.modal.show').forEach(m => closeModal(m.id))
    );
    Mousetrap.bind('/', e => {
        e.preventDefault();
        const input = document.getElementById('searchInput');
        if(input) input.focus();
    });
    Mousetrap.bind('?', () =>
        showToast(
            'Ctrl+P Pause · Ctrl+E Export · Ctrl+, Config · / Search · Esc Close',
            'info', 6000
        )
    );
}

/* ── INIT ── */
async function init() {
    runVideoIntro();         /* ← NEW: cinematic opening */
    applyTheme(STATE.theme);
    loadSettings();
    initCharts();
    initSessionTimeout();
    updateSessionDisplay();
    updateConnectionStatus(false);
    runSplash();
    logAudit('dashboard_init',{ sessionId:STATE.sessionId });

    const stats = await fetchStats();
    if (stats) {
        STATE.totalRequests   = stats.total_requests    || 0;
        STATE.normalRequests  = stats.normal_requests   || 0;
        STATE.anomalyRequests = stats.anomalies_detected || 0;

        document.getElementById('totalReq').textContent   = STATE.totalRequests;
        document.getElementById('normalReq').textContent  = STATE.normalRequests;
        document.getElementById('anomalyReq').textContent = STATE.anomalyRequests;
        document.getElementById('sbTotal').textContent    = STATE.totalRequests;
        document.getElementById('sbThreats').textContent  = STATE.anomalyRequests;

        const rate = STATE.totalRequests > 0
            ? ((STATE.anomalyRequests/STATE.totalRequests)*100).toFixed(1)+'%'
            : '0%';
        document.getElementById('detectionRate').textContent = rate;
        document.getElementById('sbRate').textContent        = rate;
        updateBars();

        if (stats.model_trained !== undefined) {
            document.getElementById('st-model').textContent = stats.model_trained
                ? `Isolation Forest (${(stats.model_accuracy*100).toFixed(1)}%)`
                : 'Not trained';
        }
        updateConnectionStatus(true);
    }

    const hist = await fetchHistory(50);
    if (hist && hist.history && hist.history.length) {
        hist.history.forEach(h => {
            STATE.logs.push({
                ...h,
                time: new Date(h.timestamp)
                    .toLocaleTimeString('en-US',{hour12:false})
            });
        });
        renderLogs();
        updateCharts();
    }

    /* start polling */
    poll();
    setInterval(poll, 3000);

    showToast('ELWARDANI online — threat monitoring active','success',3500);
}

document.addEventListener('DOMContentLoaded', init);
/* ── SPLASH PARTICLE CANVAS ── */
(function initSplashParticles() {
    const canvas = document.getElementById('splashParticles');
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    let W, H, particles = [];
    const GOLD = 'rgba(214,179,106,';
    const BLUE = 'rgba(109,141,255,';

    function resize() {
        W = canvas.width  = window.innerWidth;
        H = canvas.height = window.innerHeight;
    }
    resize();
    window.addEventListener('resize', resize);

    function Particle() {
        this.reset();
    }
    Particle.prototype.reset = function() {
        this.x  = Math.random() * W;
        this.y  = Math.random() * H;
        this.vx = (Math.random() - 0.5) * 0.35;
        this.vy = (Math.random() - 0.5) * 0.35 - 0.15;
        this.size   = Math.random() * 1.8 + 0.4;
        this.alpha  = Math.random() * 0.5 + 0.1;
        this.col    = Math.random() > 0.5 ? GOLD : BLUE;
        this.life   = 1.0;
        this.decay  = Math.random() * 0.003 + 0.001;
    };
    Particle.prototype.update = function() {
        this.x    += this.vx;
        this.y    += this.vy;
        this.life -= this.decay;
        if (this.life <= 0 || this.y < -10) this.reset();
    };
    Particle.prototype.draw = function() {
        ctx.beginPath();
        ctx.arc(this.x, this.y, this.size, 0, Math.PI * 2);
        ctx.fillStyle = this.col + (this.alpha * this.life) + ')';
        ctx.fill();
    };

    for (let i = 0; i < 80; i++) particles.push(new Particle());

    let animId;
    function loop() {
        const splash = document.getElementById('splashScreen');
        if (!splash || splash.classList.contains('hidden')) {
            cancelAnimationFrame(animId);
            return;
        }
        ctx.clearRect(0, 0, W, H);
        particles.forEach(p => { p.update(); p.draw(); });
        animId = requestAnimationFrame(loop);
    }
    loop();
})();