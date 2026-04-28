const express = require('express');
const cors = require('cors');
const path = require('path');
const crypto = require('crypto');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

// Hardcoded credentials - CHANGE THESE
const ADMIN_USERNAME = 'imudfrsuckit';
const ADMIN_PASSWORD = 'udforeverfn';

// In-memory storage
const licenses = new Map();
const hwidBindings = new Map();
const accessLogs = [];

// Middleware
app.use(cors());
app.use(express.json());

// Generate license key
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

// Check Basic Auth
function checkAuth(req) {
    const auth = req.headers.authorization;
    if (!auth) return false;
    
    try {
        const base64 = auth.startsWith('Basic ') ? auth.substring(6) : auth;
        const decoded = Buffer.from(base64, 'base64').toString('utf8');
        const [username, password] = decoded.split(':');
        return username === ADMIN_USERNAME && password === ADMIN_PASSWORD;
    } catch (e) {
        return false;
    }
}

// API Routes

// Client validation
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

// Admin login
app.post('/api/admin/login', (req, res) => {
    const { username, password } = req.body;
    
    console.log('Login attempt:', username, password);
    console.log('Expected:', ADMIN_USERNAME, ADMIN_PASSWORD);
    
    if (username === ADMIN_USERNAME && password === ADMIN_PASSWORD) {
        res.json({ success: true, token: 'basic' });
    } else {
        res.status(401).json({ success: false, error: 'Invalid credentials' });
    }
});

// Get all licenses
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

// Create licenses (single or bulk)
app.post('/api/admin/licenses', (req, res) => {
    if (!checkAuth(req)) {
        return res.status(401).json({ error: 'Unauthorized' });
    }
    
    const { durationDays, count = 1 } = req.body;
    const keys = [];

    for (let i = 0; i < count; i++) {
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
        keys.push(key);
        logAccess('create', key, null, true);
    }

    res.json({ success: true, keys, count: keys.length });
});

// Delete license
app.delete('/api/admin/licenses/:key', (req, res) => {
    if (!checkAuth(req)) {
        return res.status(401).json({ error: 'Unauthorized' });
    }
    const { key } = req.params;

    if (licenses.delete(key)) {
        for (const [hwid, boundKey] of hwidBindings.entries()) {
            if (boundKey === key) hwidBindings.delete(hwid);
        }
        logAccess('delete', key, null, true);
        res.json({ success: true });
    } else {
        res.status(404).json({ error: 'License not found' });
    }
});

// Toggle license status
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

// Get logs
app.get('/api/admin/logs', (req, res) => {
    if (!checkAuth(req)) {
        return res.status(401).json({ error: 'Unauthorized' });
    }
    res.json(accessLogs);
});

// Get stats
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
app.get('/', (req, res) => {
    res.send(`<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>License Manager</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Inter', sans-serif; background: #0a0a0f; color: #fff; min-height: 100vh; }
        
        /* Login */
        .login-screen { display: flex; align-items: center; justify-content: center; min-height: 100vh; background: linear-gradient(135deg, #0f0f1a 0%, #1a1a2e 50%, #16213e 100%); }
        .login-box { background: rgba(20,20,35,0.9); border: 1px solid rgba(102,126,234,0.3); padding: 48px; border-radius: 24px; width: 100%; max-width: 400px; text-align: center; box-shadow: 0 25px 50px rgba(0,0,0,0.5); }
        .login-box h1 { font-size: 32px; font-weight: 700; background: linear-gradient(90deg, #667eea, #764ba2); -webkit-background-clip: text; -webkit-text-fill-color: transparent; margin-bottom: 8px; }
        .login-box .subtitle { color: #667eea; font-size: 14px; text-transform: uppercase; letter-spacing: 2px; margin-bottom: 32px; }
        .login-box p { color: #888; margin-bottom: 24px; }
        .login-box input { width: 100%; padding: 16px 20px; border: 1px solid rgba(255,255,255,0.1); border-radius: 12px; background: rgba(0,0,0,0.3); color: #fff; font-size: 16px; margin-bottom: 12px; }
        .login-box input:focus { outline: none; border-color: #667eea; }
        .login-box button { width: 100%; padding: 16px; border: none; border-radius: 12px; background: linear-gradient(90deg, #667eea, #764ba2); color: #fff; font-size: 16px; font-weight: 600; cursor: pointer; margin-top: 8px; }
        .login-box button:hover { transform: translateY(-2px); box-shadow: 0 10px 30px rgba(102,126,234,0.4); }
        .login-box button:disabled { opacity: 0.6; cursor: not-allowed; }
        .status-msg { margin-top: 16px; padding: 12px; border-radius: 8px; font-size: 14px; min-height: 40px; }
        .status-msg.error { background: rgba(255,71,87,0.1); color: #ff4757; border: 1px solid rgba(255,71,87,0.3); }
        .status-msg.success { background: rgba(46,213,115,0.1); color: #2ed573; border: 1px solid rgba(46,213,115,0.3); }
        .status-msg.info { background: rgba(102,126,234,0.1); color: #667eea; border: 1px solid rgba(102,126,234,0.3); }
        
        /* Dashboard */
        .dashboard { display: flex; min-height: 100vh; }
        .hidden { display: none !important; }
        
        .sidebar { width: 260px; background: #0f0f14; border-right: 1px solid rgba(102,126,234,0.1); padding: 32px 0; }
        .logo { padding: 0 24px; margin-bottom: 40px; }
        .logo h2 { font-size: 24px; font-weight: 700; background: linear-gradient(90deg, #667eea, #764ba2); -webkit-background-clip: text; -webkit-text-fill-color: transparent; }
        .nav { list-style: none; }
        .nav li { padding: 16px 24px; cursor: pointer; color: #888; transition: all 0.3s; margin: 4px 16px; border-radius: 12px; font-weight: 500; }
        .nav li:hover, .nav li.active { color: #fff; background: rgba(102,126,234,0.15); }
        .nav li.active { border-left: 3px solid #667eea; }
        
        .main { flex: 1; padding: 40px; background: linear-gradient(135deg, #0a0a0f, #12121a); }
        .header { margin-bottom: 32px; }
        .header h1 { font-size: 36px; font-weight: 700; margin-bottom: 8px; }
        .header p { color: #667eea; }
        
        .stats { display: grid; grid-template-columns: repeat(3, 1fr); gap: 24px; margin-bottom: 40px; }
        .stat-card { background: rgba(102,126,234,0.1); border: 1px solid rgba(102,126,234,0.2); border-radius: 16px; padding: 24px; }
        .stat-card h3 { font-size: 14px; color: #888; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 12px; }
        .stat-card .num { font-size: 40px; font-weight: 700; color: #fff; }
        
        .tab { display: none; }
        .tab.active { display: block; animation: fadeIn 0.4s; }
        @keyframes fadeIn { from { opacity: 0; transform: translateY(20px); } to { opacity: 1; transform: translateY(0); } }
        
        .section-title { font-size: 24px; font-weight: 600; margin-bottom: 20px; }
        
        .card { background: rgba(20,20,30,0.5); border: 1px solid rgba(102,126,234,0.1); border-radius: 16px; padding: 24px; margin-bottom: 24px; }
        .card h3 { font-size: 18px; margin-bottom: 16px; color: #667eea; }
        
        .preset-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 16px; margin-bottom: 24px; }
        .preset { background: rgba(0,0,0,0.3); border: 1px solid rgba(255,255,255,0.1); border-radius: 12px; padding: 24px; text-align: center; cursor: pointer; transition: all 0.3s; }
        .preset:hover { border-color: #667eea; background: rgba(102,126,234,0.1); transform: translateY(-4px); }
        .preset.lifetime { background: linear-gradient(135deg, rgba(102,126,234,0.2), rgba(118,75,162,0.2)); border-color: #667eea; }
        .preset h4 { font-size: 20px; margin-bottom: 4px; }
        .preset p { color: #888; font-size: 13px; }
        
        .bulk-row { display: flex; gap: 16px; align-items: center; margin-bottom: 16px; }
        .bulk-row label { color: #888; width: 120px; }
        .bulk-row input { width: 100px; padding: 12px; border: 1px solid rgba(255,255,255,0.1); border-radius: 8px; background: rgba(0,0,0,0.3); color: #fff; }
        .btn-group { display: flex; gap: 8px; flex-wrap: wrap; }
        .btn-small { padding: 10px 20px; border: 1px solid rgba(102,126,234,0.3); border-radius: 8px; background: rgba(102,126,234,0.1); color: #667eea; cursor: pointer; font-weight: 500; }
        .btn-small:hover { background: #667eea; color: #fff; }
        .btn-green { background: linear-gradient(90deg, #2ed573, #1eae58); border: none; color: #fff; }
        
        .input-row { display: flex; gap: 12px; }
        .input-row input { flex: 1; padding: 14px; border: 1px solid rgba(255,255,255,0.1); border-radius: 8px; background: rgba(0,0,0,0.3); color: #fff; }
        .input-row button { padding: 14px 28px; border: none; border-radius: 8px; background: linear-gradient(90deg, #667eea, #764ba2); color: #fff; font-weight: 600; cursor: pointer; }
        
        .results { background: rgba(46,213,115,0.1); border: 1px solid rgba(46,213,115,0.3); border-radius: 12px; padding: 20px; margin-top: 24px; }
        .results h4 { color: #2ed573; margin-bottom: 16px; }
        .key-list { max-height: 300px; overflow-y: auto; margin-bottom: 16px; }
        .key-item { display: flex; justify-content: space-between; align-items: center; padding: 12px; background: rgba(0,0,0,0.3); border-radius: 8px; margin-bottom: 8px; font-family: monospace; color: #2ed573; }
        .key-item button { padding: 6px 12px; border: 1px solid #667eea; border-radius: 6px; background: transparent; color: #667eea; cursor: pointer; font-size: 12px; }
        .download-btn { width: 100%; padding: 14px; border: none; border-radius: 8px; background: linear-gradient(90deg, #2ed573, #1eae58); color: #fff; font-weight: 600; cursor: pointer; }
        
        table { width: 100%; border-collapse: collapse; }
        th { text-align: left; padding: 16px; color: #667eea; font-size: 12px; text-transform: uppercase; border-bottom: 1px solid rgba(102,126,234,0.2); }
        td { padding: 16px; border-bottom: 1px solid rgba(255,255,255,0.05); color: #ccc; }
        tr:hover td { background: rgba(102,126,234,0.05); }
        .badge { display: inline-flex; padding: 6px 12px; border-radius: 20px; font-size: 12px; font-weight: 600; }
        .badge.active { background: rgba(46,213,115,0.15); color: #2ed573; }
        .badge.inactive { background: rgba(255,71,87,0.15); color: #ff4757; }
        .actions { display: flex; gap: 8px; }
        .actions button { padding: 8px 16px; border-radius: 6px; font-size: 12px; cursor: pointer; border: none; }
        .toggle-btn { background: #667eea; color: #fff; }
        .delete-btn { background: rgba(255,71,87,0.1); color: #ff4757; border: 1px solid rgba(255,71,87,0.3); }
        
        .search { width: 300px; padding: 12px 16px; border: 1px solid rgba(102,126,234,0.2); border-radius: 8px; background: rgba(0,0,0,0.3); color: #fff; margin-bottom: 16px; }
        .search:focus { outline: none; border-color: #667eea; }
        
        .logout-btn { margin: 0 24px; padding: 12px; border: 1px solid rgba(255,71,87,0.3); border-radius: 8px; background: rgba(255,71,87,0.05); color: #ff4757; cursor: pointer; width: calc(100% - 48px); }
        .logout-btn:hover { background: rgba(255,71,87,0.1); }
    </style>
</head>
<body>
    <div id="login" class="login-screen">
        <div class="login-box">
            <h1>🔐 License Manager</h1>
            <p class="subtitle">Admin Portal</p>
            <p>Enter your credentials to continue</p>
            <input type="text" id="user" placeholder="Username" value="imudfrsuckit">
            <input type="password" id="pass" placeholder="Password" value="udforeverfn">
            <button id="loginBtn" onclick="doLogin()">Sign In</button>
            <div id="status" class="status-msg">Ready to sign in</div>
        </div>
    </div>

    <div id="dash" class="dashboard hidden">
        <div class="sidebar">
            <div class="logo"><h2>🔐 Auth Panel</h2></div>
            <ul class="nav">
                <li class="active" onclick="switchTab('keys')">📋 License Keys</li>
                <li onclick="switchTab('create')">⚡ Create Keys</li>
                <li onclick="switchTab('logs')">📊 Access Logs</li>
            </ul>
            <button class="logout-btn" onclick="doLogout()">🚪 Logout</button>
        </div>
        
        <div class="main">
            <div class="header">
                <h1>Dashboard</h1>
                <p>Welcome back, Administrator</p>
            </div>
            
            <div class="stats">
                <div class="stat-card"><h3>Total Keys</h3><div class="num" id="s-total">0</div></div>
                <div class="stat-card"><h3>Active</h3><div class="num" id="s-active">0</div></div>
                <div class="stat-card"><h3>Expired</h3><div class="num" id="s-expired">0</div></div>
            </div>
            
            <div id="tab-keys" class="tab active">
                <h2 class="section-title">All License Keys</h2>
                <input type="text" class="search" id="search" placeholder="🔍 Search keys..." onkeyup="filterKeys()">
                <div class="card" style="padding:0;overflow:hidden;">
                    <table>
                        <thead><tr><th>Key</th><th>Created</th><th>Expires</th><th>Uses</th><th>Status</th><th>Actions</th></tr></thead>
                        <tbody id="keys-body"></tbody>
                    </table>
                </div>
            </div>
            
            <div id="tab-create" class="tab">
                <h2 class="section-title">Create License Keys</h2>
                
                <div class="card">
                    <h3>⚡ Quick Generate (Single)</h3>
                    <div class="preset-grid">
                        <div class="preset" onclick="genKey(1)"><h4>1 Day</h4><p>24 hours</p></div>
                        <div class="preset" onclick="genKey(7)"><h4>7 Days</h4><p>One week</p></div>
                        <div class="preset" onclick="genKey(30)"><h4>30 Days</h4><p>One month</p></div>
                        <div class="preset lifetime" onclick="genKey(null)"><h4>Lifetime</h4><p>Never expires</p></div>
                    </div>
                </div>
                
                <div class="card">
                    <h3>🔥 Bulk Generation</h3>
                    <div class="bulk-row">
                        <label>Count:</label>
                        <input type="number" id="bulk-num" value="10" min="1" max="100">
                    </div>
                    <div class="bulk-row">
                        <label>Duration:</label>
                        <div class="btn-group">
                            <button class="btn-small" onclick="genBulk(1)">1 Day</button>
                            <button class="btn-small" onclick="genBulk(7)">7 Days</button>
                            <button class="btn-small" onclick="genBulk(30)">30 Days</button>
                            <button class="btn-small" onclick="genBulk(null)">Lifetime</button>
                        </div>
                    </div>
                </div>
                
                <div class="card">
                    <h3>⚙️ Custom</h3>
                    <div class="input-row">
                        <input type="number" id="custom-days" placeholder="Days">
                        <button onclick="genCustom()">Single</button>
                        <button class="btn-green" onclick="genCustomBulk()">Bulk</button>
                    </div>
                    <div id="results" class="results hidden">
                        <h4 id="res-title">Generated Keys</h4>
                        <div class="key-list" id="key-list"></div>
                        <button class="download-btn" onclick="download()">⬇ Download All (.txt)</button>
                    </div>
                </div>
            </div>
            
            <div id="tab-logs" class="tab">
                <h2 class="section-title">Access Logs</h2>
                <div class="card" style="padding:0;overflow:hidden;">
                    <table>
                        <thead><tr><th>Time</th><th>Action</th><th>Key</th><th>HWID</th><th>Status</th></tr></thead>
                        <tbody id="logs-body"></tbody>
                    </table>
                </div>
            </div>
        </div>
    </div>

    <script>
    let u='',p='',keys=[],all=[];
    
    function setStatus(msg,type='info'){
        const s=document.getElementById('status');
        s.textContent=msg;
        s.className='status-msg '+type;
    }
    
    async function doLogin(){
        const user=document.getElementById('user').value;
        const pass=document.getElementById('pass').value;
        const btn=document.getElementById('loginBtn');
        
        if(!user||!pass){setStatus('Please enter username and password','error');return;}
        
        btn.disabled=true;
        setStatus('Signing in...','info');
        
        try{
            const res=await fetch('/api/admin/login',{
                method:'POST',
                headers:{'Content-Type':'application/json'},
                body:JSON.stringify({username:user,password:pass})
            });
            
            const data=await res.json();
            
            if(data.success){
                u=user;p=pass;
                setStatus('Success!','success');
                document.getElementById('login').classList.add('hidden');
                document.getElementById('dash').classList.remove('hidden');
                loadStats();loadKeys();
            }else{
                setStatus(data.error||'Login failed','error');
            }
        }catch(e){
            setStatus('Error: '+e.message,'error');
        }
        
        btn.disabled=false;
    }
    
    function doLogout(){
        u='';p='';
        document.getElementById('dash').classList.add('hidden');
        document.getElementById('login').classList.remove('hidden');
        document.getElementById('results').classList.add('hidden');
        keys=[];
    }
    
    function auth(){
        return 'Basic '+btoa(u+':'+p);
    }
    
    async function api(url,opt={}){
        const res=await fetch(url,{...opt,headers:{'Content-Type':'application/json','Authorization':auth(),...opt.headers}});
        if(res.status===401){doLogout();setStatus('Session expired','error');return null;}
        return res.json();
    }
    
    function switchTab(tab){
        document.querySelectorAll('.tab').forEach(t=>t.classList.remove('active'));
        document.querySelectorAll('.nav li').forEach(n=>n.classList.remove('active'));
        document.getElementById('tab-'+tab).classList.add('active');
        event.target.classList.add('active');
        if(tab==='logs')loadLogs();
        if(tab==='keys')loadKeys();
    }
    
    async function loadStats(){
        const s=await api('/api/admin/stats');
        if(!s)return;
        document.getElementById('s-total').textContent=s.total||0;
        document.getElementById('s-active').textContent=s.active||0;
        document.getElementById('s-expired').textContent=s.expired||0;
    }
    
    async function loadKeys(){
        const k=await api('/api/admin/licenses');
        if(!k)return;
        all=k;renderKeys(k);
    }
    
    function renderKeys(k){
        const b=document.getElementById('keys-body');
        if(k.length===0){b.innerHTML='<tr><td colspan="6" style="text-align:center;color:#666;padding:40px;">No keys yet</td></tr>';return;}
        b.innerHTML=k.map(x=>'<tr><td><code>'+x.key+'</code></td><td>'+fmt(x.createdAt)+'</td><td>'+(x.expiresAt?fmt(x.expiresAt):'Never')+'</td><td>'+(x.useCount||0)+'</td><td><span class="badge '+(x.active?'active':'inactive')+'">'+(x.active?'Active':'Inactive')+'</span></td><td class="actions"><button class="toggle-btn" onclick="toggle(\''+x.fullKey+'\','+!x.active+')">'+(x.active?'Disable':'Enable')+'</button><button class="delete-btn" onclick="del(\''+x.fullKey+'\')">Delete</button></td></tr>').join('');
    }
    
    function filterKeys(){
        const q=document.getElementById('search').value.toLowerCase();
        renderKeys(all.filter(x=>x.key.toLowerCase().includes(q)||x.fullKey.toLowerCase().includes(q)));
    }
    
    async function genKey(days){
        const r=await api('/api/admin/licenses',{method:'POST',body:JSON.stringify({durationDays:days,count:1})});
        if(r&&r.success){keys=r.keys;showResults('1 key generated');loadStats();loadKeys();}
    }
    
    async function genBulk(days){
        const n=parseInt(document.getElementById('bulk-num').value)||10;
        const r=await api('/api/admin/licenses',{method:'POST',body:JSON.stringify({durationDays:days,count:n})});
        if(r&&r.success){keys=r.keys;showResults(n+' keys generated');loadStats();loadKeys();}
    }
    
    async function genCustom(){
        const d=parseInt(document.getElementById('custom-days').value);
        if(!d||d<1){setStatus('Enter valid days','error');return;}
        genKey(d);
    }
    
    async function genCustomBulk(){
        const d=parseInt(document.getElementById('custom-days').value);
        if(!d||d<1){setStatus('Enter valid days','error');return;}
        genBulk(d);
    }
    
    function showResults(title){
        document.getElementById('results').classList.remove('hidden');
        document.getElementById('res-title').textContent='✓ '+title;
        document.getElementById('key-list').innerHTML=keys.map(k=>'<div class="key-item"><span>'+k+'</span><button onclick="copy(\''+k+'\')">Copy</button></div>').join('');
    }
    
    function copy(k){navigator.clipboard.writeText(k);}
    function download(){
        const blob=new Blob([keys.join('\\n')],{type:'text/plain'});
        const url=URL.createObjectURL(blob);
        const a=document.createElement('a');a.href=url;a.download='keys-'+new Date().toISOString().split('T')[0]+'.txt';a.click();URL.revokeObjectURL(url);
    }
    
    async function toggle(k,active){
        await api('/api/admin/licenses/'+encodeURIComponent(k),{method:'PATCH',body:JSON.stringify({active})});
        loadKeys();loadStats();
    }
    
    async function del(k){
        if(!confirm('Delete this key?'))return;
        await api('/api/admin/licenses/'+encodeURIComponent(k),{method:'DELETE'});
        loadKeys();loadStats();
    }
    
    async function loadLogs(){
        const l=await api('/api/admin/logs');
        if(!l)return;
        const b=document.getElementById('logs-body');
        if(l.length===0){b.innerHTML='<tr><td colspan="5" style="text-align:center;color:#666;padding:40px;">No logs yet</td></tr>';return;}
        b.innerHTML=l.map(x=>'<tr><td>'+fmt(x.timestamp)+'</td><td>'+x.action+'</td><td>'+(x.key||'-')+'</td><td>'+(x.hwid||'-')+'</td><td style="color:'+(x.success?'#2ed573':'#ff4757')+'">'+(x.success?'Success':'Failed')+'</td></tr>').join('');
    }
    
    function fmt(d){if(!d)return'-';return new Date(d).toLocaleString();}
    
    document.getElementById('pass').addEventListener('keypress',e=>{if(e.key==='Enter')doLogin();});
    </script>
</body>
</html>`);
});

app.listen(PORT, () => {
    console.log(`Auth server running on port ${PORT}`);
});
