const express = require('express');
const cors = require('cors');
const path = require('path');
const crypto = require('crypto');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;
const ADMIN_USERNAME = 'imudfrsuckit';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'udforeverfn';

// In-memory storage (use Redis or database for production)
const licenses = new Map();
const hwidBindings = new Map();
const accessLogs = [];

// Middleware
app.use(cors());
app.use(express.json());

// Static files with absolute path
const publicPath = path.join(__dirname, 'public');
app.use(express.static(publicPath));
console.log('Serving static files from:', publicPath);

// Helper functions
function generateLicenseKey() {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
    let key = '';
    for (let i = 0; i < 4; i++) {
        for (let j = 0; j < 5; j++) {
            key += chars.charAt(Math.floor(Math.random() * chars.length));
        }
        if (i < 3) key += '-';
    }
    return key;
}

function hashHWID(hwid) {
    return crypto.createHash('sha256').update(hwid).digest('hex');
}

function logAccess(action, key, hwid, success) {
    accessLogs.unshift({
        timestamp: new Date().toISOString(),
        action,
        key: key ? key.substring(0, 8) + '...' : null,
        hwid: hwid ? hwid.substring(0, 16) + '...' : null,
        success
    });
    if (accessLogs.length > 100) accessLogs.pop();
}

// Auth check helper
function checkAuth(req) {
    const auth = req.headers.authorization;
    if (!auth) return false;
    
    const decoded = Buffer.from(auth, 'base64').toString('utf8');
    const [username, password] = decoded.split(':');
    
    return username === ADMIN_USERNAME && password === ADMIN_PASSWORD;
}

// API Routes

// Admin login
app.post('/api/admin/login', (req, res) => {
    const { username, password } = req.body;
    if (username === ADMIN_USERNAME && password === ADMIN_PASSWORD) {
        res.json({ success: true });
    } else {
        res.status(401).json({ success: false, error: 'Invalid credentials' });
    }
});

// Validate license (called from client)
app.post('/api/validate', (req, res) => {
    const { license_key, hwid } = req.body;
    
    if (!license_key || !hwid) {
        return res.json({ success: false, message: 'Missing parameters' });
    }

    const license = licenses.get(license_key);
    
    if (!license) {
        logAccess('validate', license_key, hwid, false);
        return res.json({ success: false, message: 'Invalid license key' });
    }

    if (!license.active) {
        logAccess('validate', license_key, hwid, false);
        return res.json({ success: false, message: 'License key deactivated' });
    }

    if (license.expiresAt && new Date() > new Date(license.expiresAt)) {
        logAccess('validate', license_key, hwid, false);
        return res.json({ success: false, message: 'License key expired' });
    }

    const hwidHash = hashHWID(hwid);
    const boundKey = hwidBindings.get(hwidHash);
    
    if (boundKey && boundKey !== license_key) {
        logAccess('validate', license_key, hwid, false);
        return res.json({ success: false, message: 'HWID already bound to different key' });
    }

    if (!boundKey) {
        hwidBindings.set(hwidHash, license_key);
    }

    license.lastUsed = new Date().toISOString();
    license.useCount = (license.useCount || 0) + 1;
    
    logAccess('validate', license_key, hwid, true);
    res.json({ success: true, message: 'License valid' });
});

// Admin API - Get all licenses
app.get('/api/admin/licenses', (req, res) => {
    if (!checkAuth(req)) {
        return res.status(401).json({ error: 'Unauthorized' });
    }

    const licenseList = Array.from(licenses.entries()).map(([key, data]) => ({
        key: key.substring(0, 8) + '...',
        fullKey: key,
        ...data
    }));

    res.json(licenseList);
});

// Admin API - Create license
app.post('/api/admin/licenses', (req, res) => {
    if (!checkAuth(req)) {
        return res.status(401).json({ error: 'Unauthorized' });
    }
    
    const { durationDays } = req.body;

    const key = generateLicenseKey();
    const expiresAt = durationDays 
        ? new Date(Date.now() + durationDays * 24 * 60 * 60 * 1000).toISOString()
        : null;

    licenses.set(key, {
        createdAt: new Date().toISOString(),
        expiresAt,
        active: true,
        useCount: 0,
        lastUsed: null
    });

    logAccess('create', key, null, true);
    res.json({ success: true, key });
});

// Admin API - Delete license
app.delete('/api/admin/licenses/:key', (req, res) => {
    if (!checkAuth(req)) {
        return res.status(401).json({ error: 'Unauthorized' });
    }
    const { key } = req.params;

    if (licenses.delete(key)) {
        // Remove HWID bindings for this key
        for (const [hwid, boundKey] of hwidBindings.entries()) {
            if (boundKey === key) hwidBindings.delete(hwid);
        }
        logAccess('delete', key, null, true);
        res.json({ success: true });
    } else {
        res.status(404).json({ error: 'License not found' });
    }
});

// Admin API - Toggle license status
app.patch('/api/admin/licenses/:key', (req, res) => {
    if (!checkAuth(req)) {
        return res.status(401).json({ error: 'Unauthorized' });
    }
    const { active } = req.body;
    const { key } = req.params;

    const license = licenses.get(key);
    if (!license) {
        return res.status(404).json({ error: 'License not found' });
    }

    license.active = active;
    logAccess(active ? 'activate' : 'deactivate', key, null, true);
    res.json({ success: true });
});

// Admin API - Get logs
app.get('/api/admin/logs', (req, res) => {
    if (!checkAuth(req)) {
        return res.status(401).json({ error: 'Unauthorized' });
    }

    res.json(accessLogs);
});

// Stats endpoint
app.get('/api/admin/stats', (req, res) => {
    if (!checkAuth(req)) {
        return res.status(401).json({ error: 'Unauthorized' });
    }

    const total = licenses.size;
    const active = Array.from(licenses.values()).filter(l => l.active).length;
    const expired = Array.from(licenses.values()).filter(l => l.expiresAt && new Date() > new Date(l.expiresAt)).length;

    res.json({ total, active, expired });
});

// Health check
app.get('/health', (req, res) => {
    res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// Serve admin panel
const fs = require('fs');

app.get('/', (req, res) => {
    const indexPath = path.join(__dirname, 'public', 'index.html');
    if (fs.existsSync(indexPath)) {
        res.sendFile(indexPath);
    } else {
        // Fallback: serve inline HTML for Render
        res.send(`<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>License Manager</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: -apple-system, BlinkMacSystemFont, sans-serif; background: #0f0f0f; color: #fff; min-height: 100vh; }
        .login-screen { display: flex; align-items: center; justify-content: center; min-height: 100vh; background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%); }
        .login-box { background: rgba(255,255,255,0.05); backdrop-filter: blur(10px); border: 1px solid rgba(255,255,255,0.1); padding: 40px; border-radius: 16px; width: 100%; max-width: 400px; text-align: center; }
        .login-box h1 { font-size: 28px; font-weight: 700; margin-bottom: 8px; background: linear-gradient(90deg, #667eea 0%, #764ba2 100%); -webkit-background-clip: text; -webkit-text-fill-color: transparent; background-clip: text; }
        .login-box p { color: #888; margin-bottom: 24px; }
        .login-box input { width: 100%; padding: 14px 18px; border: 1px solid rgba(255,255,255,0.1); border-radius: 10px; background: rgba(0,0,0,0.3); color: #fff; font-size: 16px; margin-bottom: 12px; }
        .login-box input:focus { outline: none; border-color: #667eea; }
        .login-box button { width: 100%; padding: 14px; border: none; border-radius: 10px; background: linear-gradient(90deg, #667eea 0%, #764ba2 100%); color: #fff; font-size: 16px; font-weight: 600; cursor: pointer; }
        .error { color: #ff4757; font-size: 14px; margin-top: 12px; }
        .dashboard { display: flex; min-height: 100vh; }
        .hidden { display: none !important; }
        .sidebar { width: 260px; background: #141414; border-right: 1px solid #222; display: flex; flex-direction: column; padding: 24px 0; }
        .logo h2 { padding: 0 24px; font-size: 20px; font-weight: 700; background: linear-gradient(90deg, #667eea 0%, #764ba2 100%); -webkit-background-clip: text; -webkit-text-fill-color: transparent; background-clip: text; }
        .nav-links { list-style: none; margin-top: 40px; flex: 1; }
        .nav-links li { padding: 14px 24px; cursor: pointer; color: #888; transition: all 0.2s; border-left: 3px solid transparent; }
        .nav-links li:hover { color: #fff; background: rgba(255,255,255,0.03); }
        .nav-links li.active { color: #667eea; background: rgba(102,126,234,0.1); border-left-color: #667eea; }
        .logout { padding: 0 24px; }
        .logout button { width: 100%; padding: 12px; border: 1px solid #333; border-radius: 8px; background: transparent; color: #888; cursor: pointer; }
        .logout button:hover { border-color: #ff4757; color: #ff4757; }
        .main-content { flex: 1; padding: 32px 40px; overflow-y: auto; }
        .main-content header { margin-bottom: 32px; }
        .main-content h1 { font-size: 28px; font-weight: 600; margin-bottom: 24px; }
        .stats { display: flex; gap: 20px; margin-bottom: 32px; }
        .stat-card { background: #1a1a1a; border: 1px solid #222; border-radius: 12px; padding: 20px 28px; min-width: 140px; }
        .stat-value { display: block; font-size: 32px; font-weight: 700; color: #667eea; }
        .stat-label { color: #666; font-size: 14px; }
        .tab-content { animation: fadeIn 0.3s ease; }
        @keyframes fadeIn { from { opacity: 0; transform: translateY(10px); } to { opacity: 1; transform: translateY(0); } }
        .section-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px; }
        .section-header h2 { font-size: 20px; font-weight: 600; }
        .section-header input { padding: 10px 16px; border: 1px solid #333; border-radius: 8px; background: #1a1a1a; color: #fff; width: 280px; }
        .table-container { background: #1a1a1a; border: 1px solid #222; border-radius: 12px; overflow: hidden; }
        table { width: 100%; border-collapse: collapse; }
        th { text-align: left; padding: 16px; font-weight: 500; color: #888; border-bottom: 1px solid #333; font-size: 13px; text-transform: uppercase; letter-spacing: 0.5px; }
        td { padding: 16px; border-bottom: 1px solid #222; color: #ccc; font-size: 14px; }
        tr:hover td { background: rgba(255,255,255,0.02); }
        .status { display: inline-flex; align-items: center; gap: 6px; padding: 6px 12px; border-radius: 20px; font-size: 12px; font-weight: 500; }
        .status.active { background: rgba(46,213,115,0.15); color: #2ed573; }
        .status.inactive { background: rgba(255,71,87,0.15); color: #ff4757; }
        .status::before { content: ''; width: 6px; height: 6px; border-radius: 50%; background: currentColor; }
        .actions { display: flex; gap: 8px; }
        .actions button { padding: 6px 14px; border: none; border-radius: 6px; font-size: 12px; cursor: pointer; transition: all 0.2s; }
        .actions .toggle { background: #667eea; color: #fff; }
        .actions .delete { background: transparent; border: 1px solid #ff4757; color: #ff4757; }
        .create-form { background: #1a1a1a; border: 1px solid #222; border-radius: 12px; padding: 32px; max-width: 600px; }
        .create-form h2 { margin-bottom: 8px; }
        .create-form .subtitle { color: #888; margin-bottom: 24px; }
        .preset-buttons { display: grid; grid-template-columns: repeat(2, 1fr); gap: 16px; margin-bottom: 32px; }
        .preset-btn { display: flex; flex-direction: column; align-items: center; padding: 20px; background: #141414; border: 1px solid #333; border-radius: 10px; cursor: pointer; transition: all 0.2s; color: #fff; }
        .preset-btn:hover { border-color: #667eea; background: rgba(102,126,234,0.1); transform: translateY(-2px); }
        .preset-btn.lifetime { background: linear-gradient(135deg, rgba(102,126,234,0.2), rgba(118,75,162,0.2)); border-color: #667eea; }
        .preset-title { font-size: 18px; font-weight: 600; margin-bottom: 4px; }
        .preset-desc { font-size: 12px; color: #888; }
        .custom-duration { padding-top: 24px; border-top: 1px solid #333; }
        .custom-duration p { color: #888; margin-bottom: 12px; font-size: 14px; }
        .custom-input-row { display: flex; gap: 12px; }
        .custom-input-row input { flex: 1; padding: 12px 16px; border: 1px solid #333; border-radius: 8px; background: #0f0f0f; color: #fff; font-size: 16px; }
        .custom-input-row button { padding: 12px 24px; border: none; border-radius: 8px; background: #667eea; color: #fff; font-weight: 600; cursor: pointer; }
        .generated-key { margin-top: 24px; padding: 20px; background: #0f0f0f; border-radius: 8px; border: 1px solid #333; }
        .generated-key p { color: #888; margin-bottom: 12px; }
        .generated-key code { display: block; padding: 16px; background: #141414; border-radius: 6px; font-family: monospace; font-size: 18px; color: #2ed573; margin-bottom: 16px; }
        .generated-key button { padding: 10px 20px; border: 1px solid #667eea; border-radius: 6px; background: transparent; color: #667eea; cursor: pointer; }
        .log-success { color: #2ed573; } .log-fail { color: #ff4757; }
    </style>
</head>
<body>
    <div id="login-screen" class="login-screen">
        <div class="login-box">
            <h1>License Manager</h1>
            <p>Enter admin credentials to continue</p>
            <input type="text" id="username-input" placeholder="Username">
            <input type="password" id="password-input" placeholder="Password">
            <button onclick="login()">Login</button>
            <div id="login-error" class="error"></div>
        </div>
    </div>
    <div id="dashboard" class="dashboard hidden">
        <nav class="sidebar">
            <div class="logo"><h2>Auth Panel</h2></div>
            <ul class="nav-links">
                <li class="active" onclick="showTab('licenses')">License Keys</li>
                <li onclick="showTab('create')">Create Key</li>
                <li onclick="showTab('logs')">Access Logs</li>
            </ul>
            <div class="logout"><button onclick="logout()">Logout</button></div>
        </nav>
        <main class="main-content">
            <header>
                <h1>Dashboard</h1>
                <div class="stats">
                    <div class="stat-card"><span class="stat-value" id="stat-total">0</span><span class="stat-label">Total Keys</span></div>
                    <div class="stat-card"><span class="stat-value" id="stat-active">0</span><span class="stat-label">Active</span></div>
                    <div class="stat-card"><span class="stat-value" id="stat-expired">0</span><span class="stat-label">Expired</span></div>
                </div>
            </header>
            <div id="tab-licenses" class="tab-content">
                <div class="section-header"><h2>License Keys</h2><input type="text" id="search-licenses" placeholder="Search keys..." oninput="filterLicenses()"></div>
                <div class="table-container"><table><thead><tr><th>Key</th><th>Created</th><th>Expires</th><th>Uses</th><th>Last Used</th><th>Status</th><th>Actions</th></tr></thead><tbody id="licenses-tbody"></tbody></table></div>
            </div>
            <div id="tab-create" class="tab-content hidden">
                <div class="create-form">
                    <h2>Create New License Key</h2>
                    <p class="subtitle">Select key duration</p>
                    <div class="preset-buttons">
                        <button class="preset-btn" onclick="createLicense(1)"><span class="preset-title">1 Day</span><span class="preset-desc">24 hour access</span></button>
                        <button class="preset-btn" onclick="createLicense(7)"><span class="preset-title">7 Days</span><span class="preset-desc">Week access</span></button>
                        <button class="preset-btn" onclick="createLicense(30)"><span class="preset-title">30 Days</span><span class="preset-desc">Month access</span></button>
                        <button class="preset-btn lifetime" onclick="createLicense(null)"><span class="preset-title">Lifetime</span><span class="preset-desc">Never expires</span></button>
                    </div>
                    <div class="custom-duration"><p>Or enter custom duration:</p><div class="custom-input-row"><input type="number" id="duration-days" placeholder="Days" min="1"><button onclick="createLicenseCustom()">Generate</button></div></div>
                    <div id="generated-key" class="generated-key hidden"><p>Generated Key:</p><code id="key-display"></code><button onclick="copyKey()">Copy</button></div>
                </div>
            </div>
            <div id="tab-logs" class="tab-content hidden">
                <div class="section-header"><h2>Access Logs</h2><button onclick="clearLogs()">Clear Logs</button></div>
                <div class="table-container"><table><thead><tr><th>Time</th><th>Action</th><th>Key</th><th>HWID</th><th>Status</th></tr></thead><tbody id="logs-tbody"></tbody></table></div>
            </div>
        </main>
    </div>
    <script>
let authUsername='',authPassword='',allLicenses=[];
function getAuthHeader(){return'Basic '+btoa(authUsername+':'+authPassword)}
async function api(endpoint,options={}){const url=endpoint.startsWith('http')?endpoint:window.location.origin+endpoint;const res=await fetch(url,{...options,headers:{'Content-Type':'application/json','Authorization':getAuthHeader(),...options.headers}});return res.json()}
async function login(){const username=document.getElementById('username-input').value;const password=document.getElementById('password-input').value;const res=await fetch(window.location.origin+'/api/admin/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username,password})});const data=await res.json();if(data.success){authUsername=username;authPassword=password;document.getElementById('login-screen').classList.add('hidden');document.getElementById('dashboard').classList.remove('hidden');loadStats();loadLicenses()}else{document.getElementById('login-error').textContent='Invalid username or password'}}
function logout(){authUsername='';authPassword='';document.getElementById('dashboard').classList.add('hidden');document.getElementById('login-screen').classList.remove('hidden');document.getElementById('username-input').value='';document.getElementById('password-input').value=''}
function showTab(tab){document.querySelectorAll('.tab-content').forEach(el=>el.classList.add('hidden'));document.getElementById('tab-'+tab).classList.remove('hidden');document.querySelectorAll('.nav-links li').forEach(el=>el.classList.remove('active'));event.target.classList.add('active');if(tab==='logs')loadLogs()}
async function loadStats(){const stats=await api('/api/admin/stats');document.getElementById('stat-total').textContent=stats.total||0;document.getElementById('stat-active').textContent=stats.active||0;document.getElementById('stat-expired').textContent=stats.expired||0}
async function loadLicenses(){const licenses=await api('/api/admin/licenses');allLicenses=licenses;renderLicenses(licenses)}
function renderLicenses(licenses){const tbody=document.getElementById('licenses-tbody');tbody.innerHTML=licenses.map(lic=>\`<tr><td><code>\${lic.key}</code></td><td>\${formatDate(lic.createdAt)}</td><td>\${lic.expiresAt?formatDate(lic.expiresAt):'Never'}</td><td>\${lic.useCount||0}</td><td>\${lic.lastUsed?formatDate(lic.lastUsed):'Never'}</td><td><span class="status \${lic.active?'active':'inactive'}">\${lic.active?'Active':'Inactive'}</span></td><td class="actions"><button class="toggle" onclick="toggleLicense('\${lic.fullKey}',\${!lic.active})">\${lic.active?'Disable':'Enable'}</button><button class="delete" onclick="deleteLicense('\${lic.fullKey}')">Delete</button></td></tr>\`).join('')}
function filterLicenses(){const query=document.getElementById('search-licenses').value.toLowerCase();const filtered=allLicenses.filter(l=>l.key.toLowerCase().includes(query)||l.fullKey.toLowerCase().includes(query));renderLicenses(filtered)}
async function createLicense(days){const result=await api('/api/admin/licenses',{method:'POST',body:JSON.stringify({durationDays:days})});if(result.success){document.getElementById('generated-key').classList.remove('hidden');document.getElementById('key-display').textContent=result.key;loadStats();loadLicenses()}}
async function createLicenseCustom(){const days=document.getElementById('duration-days').value;if(!days||days<1){alert('Please enter a valid number of days');return}const result=await api('/api/admin/licenses',{method:'POST',body:JSON.stringify({durationDays:parseInt(days)})});if(result.success){document.getElementById('generated-key').classList.remove('hidden');document.getElementById('key-display').textContent=result.key;loadStats();loadLicenses()}}
function copyKey(){const key=document.getElementById('key-display').textContent;navigator.clipboard.writeText(key)}
async function toggleLicense(key,active){await api(\`/api/admin/licenses/\${encodeURIComponent(key)}\`,{method:'PATCH',body:JSON.stringify({active})});loadLicenses();loadStats()}
async function deleteLicense(key){if(!confirm('Delete this license key?'))return;await api(\`/api/admin/licenses/\${encodeURIComponent(key)}\`,{method:'DELETE'});loadLicenses();loadStats()}
async function loadLogs(){const logs=await api('/api/admin/logs');const tbody=document.getElementById('logs-tbody');tbody.innerHTML=logs.map(log=>\`<tr><td>\${formatDate(log.timestamp)}</td><td>\${log.action}</td><td>\${log.key||'-'}</td><td>\${log.hwid||'-'}</td><td class="\${log.success?'log-success':'log-fail'}">\${log.success?'Success':'Failed'}</td></tr>\`).join('')}
function clearLogs(){document.getElementById('logs-tbody').innerHTML=''}
function formatDate(dateStr){if(!dateStr)return'-';const d=new Date(dateStr);return d.toLocaleString()}
document.getElementById('password-input')?.addEventListener('keypress',e=>{if(e.key==='Enter')login()});document.getElementById('username-input')?.addEventListener('keypress',e=>{if(e.key==='Enter')login()});
    </script>
</body>
</html>`);
    }
});

app.listen(PORT, () => {
    console.log(`Auth server running on port ${PORT}`);
    console.log(`Admin panel: http://localhost:${PORT}`);
});
