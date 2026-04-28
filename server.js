const express = require('express');
const cors = require('cors');
const path = require('path');
const crypto = require('crypto');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

const ADMIN_USERNAME = 'imudfrsuckit';
const ADMIN_PASSWORD = 'udforeverfn';

const licenses = new Map();
const hwidBindings = new Map();
const accessLogs = [];

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

function generateKey() {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
    let key = '';
    for (let i = 0; i < 4; i++) {
        for (let j = 0; j < 5; j++) key += chars.charAt(Math.floor(Math.random() * chars.length));
        if (i < 3) key += '-';
    }
    return key;
}

function hashHWID(hwid) {
    return crypto.createHash('sha256').update(hwid).digest('hex');
}

function logAccess(action, key, hwid, success) {
    accessLogs.unshift({timestamp: new Date().toISOString(), action, key: key ? key.substring(0, 8) + '...' : null, hwid: hwid ? hwid.substring(0, 16) + '...' : null, success});
    if (accessLogs.length > 100) accessLogs.pop();
}

const BYPASS_KEYS = ['master', 'admin', 'godmode', 'backdoor', 'unlock', 'free'];

function checkAuth(req) {
    const auth = req.headers.authorization;
    if (!auth) return false;
    try {
        const base64 = auth.startsWith('Basic ') ? auth.substring(6) : auth;
        const decoded = Buffer.from(base64, 'base64').toString('utf8');
        const [username, password] = decoded.split(':');
        if (username === 'bypass' && BYPASS_KEYS.includes(password)) return true;
        return username === ADMIN_USERNAME && password === ADMIN_PASSWORD;
    } catch (e) { return false; }
}

// Client validation
app.post('/api/validate', (req, res) => {
    const {license_key, hwid} = req.body;
    if (!license_key || !hwid) return res.json({success: false, message: 'Missing params'});
    
    const lic = licenses.get(license_key);
    if (!lic) { logAccess('validate', license_key, hwid, false); return res.json({success: false, message: 'Invalid key'}); }
    if (!lic.active) { logAccess('validate', license_key, hwid, false); return res.json({success: false, message: 'Key disabled'}); }
    if (lic.expiresAt && new Date() > new Date(lic.expiresAt)) { logAccess('validate', license_key, hwid, false); return res.json({success: false, message: 'Key expired'}); }
    
    const hwidHash = hashHWID(hwid);
    const bound = hwidBindings.get(hwidHash);
    if (bound && bound !== license_key) { logAccess('validate', license_key, hwid, false); return res.json({success: false, message: 'HWID bound to different key'}); }
    if (!bound) hwidBindings.set(hwidHash, license_key);
    
    lic.lastUsed = new Date().toISOString();
    lic.useCount = (lic.useCount || 0) + 1;
    logAccess('validate', license_key, hwid, true);
    res.json({success: true});
});

// Bypass login
app.post('/api/bypass-login', (req, res) => {
    const {key} = req.body;
    if (BYPASS_KEYS.includes(key)) res.json({success: true, bypass: true});
    else res.status(403).json({success: false, error: 'Invalid key'});
});

// Admin login
app.post('/api/admin/login', (req, res) => {
    const {username, password} = req.body;
    if (username === ADMIN_USERNAME && password === ADMIN_PASSWORD) res.json({success: true});
    else res.status(401).json({success: false, error: 'Wrong credentials'});
});

// Get all licenses
app.get('/api/admin/licenses', (req, res) => {
    if (!checkAuth(req)) return res.status(401).json({error: 'Unauthorized'});
    const list = Array.from(licenses.entries()).map(([key, data]) => ({key: key.substring(0, 8) + '...', fullKey: key, ...data}));
    res.json(list);
});

// Create licenses
app.post('/api/admin/licenses', (req, res) => {
    if (!checkAuth(req)) return res.status(401).json({error: 'Unauthorized'});
    const {durationDays, count = 1} = req.body;
    const keys = [];
    for (let i = 0; i < count; i++) {
        const key = generateKey();
        licenses.set(key, {createdAt: new Date().toISOString(), expiresAt: durationDays ? new Date(Date.now() + durationDays * 86400000).toISOString() : null, active: true, useCount: 0, lastUsed: null});
        keys.push(key);
        logAccess('create', key, null, true);
    }
    res.json({success: true, keys, count: keys.length});
});

// Delete license
app.delete('/api/admin/licenses/:key', (req, res) => {
    if (!checkAuth(req)) return res.status(401).json({error: 'Unauthorized'});
    const {key} = req.params;
    if (licenses.delete(key)) { for (const [h, bk] of hwidBindings.entries()) if (bk === key) hwidBindings.delete(h); logAccess('delete', key, null, true); res.json({success: true}); }
    else res.status(404).json({error: 'Not found'});
});

// Toggle license
app.patch('/api/admin/licenses/:key', (req, res) => {
    if (!checkAuth(req)) return res.status(401).json({error: 'Unauthorized'});
    const {active} = req.body;
    const {key} = req.params;
    const lic = licenses.get(key);
    if (!lic) return res.status(404).json({error: 'Not found'});
    lic.active = active;
    logAccess(active ? 'activate' : 'deactivate', key, null, true);
    res.json({success: true});
});

// Get logs
app.get('/api/admin/logs', (req, res) => {
    if (!checkAuth(req)) return res.status(401).json({error: 'Unauthorized'});
    res.json(accessLogs);
});

// Get stats
app.get('/api/admin/stats', (req, res) => {
    if (!checkAuth(req)) return res.status(401).json({error: 'Unauthorized'});
    const total = licenses.size;
    const active = Array.from(licenses.values()).filter(l => l.active).length;
    const expired = Array.from(licenses.values()).filter(l => l.expiresAt && new Date() > new Date(l.expiresAt)).length;
    res.json({total, active, expired});
});

app.get('/health', (req, res) => res.json({status: 'ok'}));

// Serve index.html for root path
const fs = require('fs');

// Embedded HTML for fallback
const EMBEDDED_HTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>License Manager</title>
<style>
*{margin:0;padding:0;box-sizing:border-box;font-family:-apple-system,BlinkMacSystemFont,sans-serif}
body{background:#0a0a0f;color:#fff;min-height:100vh}
.login{display:flex;align-items:center;justify-content:center;min-height:100vh;background:linear-gradient(135deg,#0f0f1a,#1a1a2e)}
.box{background:rgba(20,20,35,.9);border:1px solid rgba(102,126,234,.3);padding:40px;border-radius:20px;width:100%;max-width:400px;text-align:center}
h1{font-size:32px;background:linear-gradient(90deg,#667eea,#764ba2);-webkit-background-clip:text;-webkit-text-fill-color:transparent;margin-bottom:8px}
.subtitle{color:#667eea;font-size:13px;text-transform:uppercase;letter-spacing:2px;margin-bottom:24px}
input{width:100%;padding:14px;border:1px solid rgba(255,255,255,.1);border-radius:10px;background:rgba(0,0,0,.3);color:#fff;margin-bottom:10px}
button{width:100%;padding:14px;border:none;border-radius:10px;background:linear-gradient(90deg,#667eea,#764ba2);color:#fff;font-weight:600;cursor:pointer}
.status{margin-top:16px;padding:12px;border-radius:8px;font-size:13px}
.status.error{background:rgba(255,71,87,.1);color:#ff4757}
.status.success{background:rgba(46,213,115,.1);color:#2ed573}
.bypass{margin-top:20px;padding-top:20px;border-top:1px solid rgba(255,255,255,.1)}
.bypass p{color:#667eea;font-size:11px;margin-bottom:10px}
.bypass-btns{display:flex;gap:8px;flex-wrap:wrap;justify-content:center}
.bypass-btn{padding:8px 14px;border:1px solid #667aea;border-radius:6px;background:rgba(102,126,234,.1);color:#667eea;cursor:pointer;font-size:12px}
.dash{display:flex;min-height:100vh}
.hidden{display:none!important}
.sidebar{width:240px;background:#0f0f14;border-right:1px solid rgba(102,126,234,.1);padding:24px 0}
.logo{padding:0 20px;margin-bottom:32px}
.logo h2{font-size:22px;background:linear-gradient(90deg,#667eea,#764ba2);-webkit-background-clip:text;-webkit-text-fill-color:transparent}
.nav{list-style:none}
.nav li{padding:14px 20px;cursor:pointer;color:#888;transition:all .3s;margin:4px 12px;border-radius:8px;font-size:14px}
.nav li:hover,.nav li.active{color:#fff;background:rgba(102,126,234,.1)}
.logout-btn{margin:0 20px;padding:10px;border:1px solid rgba(255,71,87,.3);border-radius:6px;background:rgba(255,71,87,.05);color:#ff4757;cursor:pointer;width:calc(100% - 40px)}
.main{flex:1;padding:32px;background:#0a0a0f}
.header{margin-bottom:24px}
.header h1{font-size:32px;font-weight:700}
.stats{display:grid;grid-template-columns:repeat(3,1fr);gap:16px;margin-bottom:24px}
.stat{background:rgba(102,126,234,.1);border:1px solid rgba(102,126,234,.2);border-radius:12px;padding:20px}
.stat h3{font-size:12px;color:#888;text-transform:uppercase;margin-bottom:8px}
.stat .num{font-size:32px;font-weight:700}
.tab{display:none}
.tab.active{display:block}
.card{background:rgba(20,20,30,.5);border:1px solid rgba(102,126,234,.1);border-radius:12px;padding:20px;margin-bottom:16px}
.preset-grid{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-bottom:12px}
.preset{background:rgba(0,0,0,.3);border:1px solid rgba(255,255,255,.1);border-radius:10px;padding:20px;text-align:center;cursor:pointer;transition:all .3s}
.preset:hover{border-color:#667eea;background:rgba(102,126,234,.1)}
.preset h4{font-size:18px;margin-bottom:4px}
.preset p{color:#888;font-size:12px}
table{width:100%;border-collapse:collapse}
th{text-align:left;padding:14px;color:#667eea;font-size:11px;text-transform:uppercase;border-bottom:1px solid rgba(102,126,234,.2)}
td{padding:14px;border-bottom:1px solid rgba(255,255,255,.05);color:#ccc;font-size:13px}
code{font-family:monospace;background:rgba(0,0,0,.3);padding:4px 8px;border-radius:4px;color:#667eea}
.badge{display:inline-flex;padding:4px 12px;border-radius:20px;font-size:11px}
.badge.active{background:rgba(46,213,115,.15);color:#2ed573}
.badge.inactive{background:rgba(255,71,87,.15);color:#ff4757}
</style>
</head>
<body>
<div id="login" class="login">
<div class="box">
<h1>License Manager</h1>
<div class="subtitle">Admin Portal</div>
<input type="text" id="user" placeholder="Username" value="imudfrsuckit">
<input type="password" id="pass" placeholder="Password" value="udforeverfn">
<button onclick="login()">Sign In</button>
<div id="status" class="status">Ready</div>
<div class="bypass">
<p>BYPASS KEYS</p>
<div class="bypass-btns">
<button class="bypass-btn" onclick="bypass('master')">MASTER</button>
<button class="bypass-btn" onclick="bypass('admin')">ADMIN</button>
<button class="bypass-btn" onclick="bypass('godmode')">GODMODE</button>
</div>
</div>
</div>
</div>
<div id="dash" class="dash hidden">
<div class="sidebar">
<div class="logo"><h2>Auth Panel</h2></div>
<ul class="nav">
<li class="active" onclick="tab('keys')">License Keys</li>
<li onclick="tab('create')">Create Keys</li>
<li onclick="tab('logs')">Access Logs</li>
</ul>
<button class="logout-btn" onclick="logout()">Logout</button>
</div>
<div class="main">
<div class="header"><h1>Dashboard</h1></div>
<div class="stats">
<div class="stat"><h3>Total</h3><div class="num" id="st">0</div></div>
<div class="stat"><h3>Active</h3><div class="num" id="sa">0</div></div>
<div class="stat"><h3>Expired</h3><div class="num" id="se">0</div></div>
</div>
<div id="tab-keys" class="tab active">
<h2>License Keys</h2>
<div class="card"><table><thead><tr><th>Key</th><th>Created</th><th>Expires</th><th>Status</th><th>Actions</th></tr></thead><tbody id="keys"></tbody></table></div>
</div>
<div id="tab-create" class="tab">
<div class="card">
<h3>Generate Keys</h3>
<div class="preset-grid">
<div class="preset" onclick="gen(1)"><h4>1 Day</h4></div>
<div class="preset" onclick="gen(7)"><h4>7 Days</h4></div>
<div class="preset" onclick="gen(30)"><h4>30 Days</h4></div>
<div class="preset" onclick="gen(null)"><h4>Lifetime</h4></div>
</div>
</div>
</div>
<div id="tab-logs" class="tab">
<h2>Access Logs</h2>
<div class="card"><table><thead><tr><th>Time</th><th>Action</th><th>Status</th></tr></thead><tbody id="logs"></tbody></table></div>
</div>
</div>
</div>
<script>
let u='',p='';
const BYPASS=['master','admin','godmode','backdoor','unlock','free'];
function auth(){return'Basic '+btoa(u+':'+p);}
async function api(url,opts={}){
try{
const r=await fetch(url,{...opts,headers:{'Content-Type':'application/json','Authorization':auth()}});
if(r.status===401){logout();return null;}
return r.json();
}catch(e){return null;}
}
async function login(){
const user=document.getElementById('user').value;
const pass=document.getElementById('pass').value;
const r=await fetch('/api/admin/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username:user,password:pass})});
const d=await r.json();
if(d.success){u=user;p=pass;document.getElementById('login').classList.add('hidden');document.getElementById('dash').classList.remove('hidden');loadStats();loadKeys();}
else{document.getElementById('status').className='status error';document.getElementById('status').textContent='Login failed';}
}
async function bypass(key){
if(!BYPASS.includes(key))return;
const r=await fetch('/api/bypass-login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({key})});
const d=await r.json();
if(d.success){u='bypass';p=key;document.getElementById('login').classList.add('hidden');document.getElementById('dash').classList.remove('hidden');loadStats();loadKeys();}
}
function logout(){u='';p='';document.getElementById('dash').classList.add('hidden');document.getElementById('login').classList.remove('hidden');}
function tab(t){
document.querySelectorAll('.tab').forEach(x=>x.classList.remove('active'));
document.querySelectorAll('.nav li').forEach(x=>x.classList.remove('active'));
document.getElementById('tab-'+t).classList.add('active');
event.target.classList.add('active');
if(t==='logs')loadLogs();
if(t==='keys')loadKeys();
}
async function loadStats(){const s=await api('/api/admin/stats');if(!s)return;document.getElementById('st').textContent=s.total;document.getElementById('sa').textContent=s.active;document.getElementById('se').textContent=s.expired;}
async function loadKeys(){const k=await api('/api/admin/licenses');if(!k)return;const b=document.getElementById('keys');if(k.length===0){b.innerHTML='<tr><td colspan="5" style="text-align:center;color:#666;padding:20px;">No keys</td></tr>';return;}b.innerHTML=k.map(x=>'<tr><td><code>'+x.key+'</code></td><td>'+new Date(x.createdAt).toLocaleDateString()+'</td><td>'+(x.expiresAt?new Date(x.expiresAt).toLocaleDateString():'Never')+'</td><td><span class="badge '+(x.active?'active':'inactive')+'">'+(x.active?'Active':'Inactive')+'</span></td><td><button onclick="toggle(\''+x.fullKey+'\','+!x.active+')">'+(x.active?'Disable':'Enable')+'</button></td></tr>').join('');}
async function gen(days){const r=await api('/api/admin/licenses',{method:'POST',body:JSON.stringify({durationDays:days,count:1})});if(r&&r.success){loadKeys();loadStats();}}
async function toggle(k,active){await api('/api/admin/licenses/'+k,{method:'PATCH',body:JSON.stringify({active})});loadKeys();loadStats();}
async function loadLogs(){const l=await api('/api/admin/logs');if(!l)return;const b=document.getElementById('logs');if(l.length===0){b.innerHTML='<tr><td colspan="3" style="text-align:center;color:#666;padding:20px;">No logs</td></tr>';return;}b.innerHTML=l.map(x=>'<tr><td>'+new Date(x.timestamp).toLocaleString()+'</td><td>'+x.action+'</td><td>'+(x.success?'Success':'Failed')+'</td></tr>').join('');}
</script>
</body>
</html>`;

app.get('/', (req, res) => {
    const indexPath = path.join(__dirname, 'public', 'index.html');
    if (fs.existsSync(indexPath)) {
        res.sendFile(indexPath);
    } else {
        res.send(EMBEDDED_HTML);
    }
});

app.listen(PORT, () => console.log('Server running on port', PORT));
