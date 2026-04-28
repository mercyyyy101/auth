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
    
    // Remove "Basic " prefix if present
    const base64 = auth.startsWith('Basic ') ? auth.slice(6) : auth;
    
    const decoded = Buffer.from(base64, 'base64').toString('utf8');
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

// Admin API - Create license (single or bulk)
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
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif; background: #0a0a0f; color: #fff; min-height: 100vh; }
        
        /* Login Screen */
        .login-screen { display: flex; align-items: center; justify-content: center; min-height: 100vh; background: linear-gradient(135deg, #0f0f1a 0%, #1a1a2e 50%, #16213e 100%); position: relative; overflow: hidden; }
        .login-screen::before { content: ''; position: absolute; top: -50%; left: -50%; width: 200%; height: 200%; background: radial-gradient(circle, rgba(102,126,234,0.1) 0%, transparent 70%); animation: pulse 4s ease-in-out infinite; }
        @keyframes pulse { 0%,100% { transform: scale(1); } 50% { transform: scale(1.1); } }
        .login-box { position: relative; background: rgba(20,20,30,0.8); backdrop-filter: blur(20px); border: 1px solid rgba(102,126,234,0.3); padding: 48px; border-radius: 24px; width: 100%; max-width: 420px; text-align: center; box-shadow: 0 25px 50px rgba(0,0,0,0.5), 0 0 100px rgba(102,126,234,0.1); }
        .login-box h1 { font-size: 32px; font-weight: 700; margin-bottom: 8px; background: linear-gradient(90deg, #667eea 0%, #764ba2 50%, #f093fb 100%); -webkit-background-clip: text; -webkit-text-fill-color: transparent; background-clip: text; }
        .login-box .subtitle { color: #667eea; font-size: 14px; font-weight: 500; margin-bottom: 32px; text-transform: uppercase; letter-spacing: 2px; }
        .login-box p { color: #888; margin-bottom: 24px; font-size: 15px; }
        .input-group { margin-bottom: 16px; position: relative; }
        .login-box input { width: 100%; padding: 16px 20px; border: 1px solid rgba(255,255,255,0.1); border-radius: 12px; background: rgba(0,0,0,0.3); color: #fff; font-size: 16px; transition: all 0.3s; }
        .login-box input:focus { outline: none; border-color: #667eea; box-shadow: 0 0 0 3px rgba(102,126,234,0.2); }
        .login-box input::placeholder { color: #666; }
        .login-box button { width: 100%; padding: 16px; margin-top: 8px; border: none; border-radius: 12px; background: linear-gradient(90deg, #667eea 0%, #764ba2 100%); color: #fff; font-size: 16px; font-weight: 600; cursor: pointer; transition: all 0.3s; position: relative; overflow: hidden; }
        .login-box button:hover { transform: translateY(-2px); box-shadow: 0 10px 30px rgba(102,126,234,0.4); }
        .login-box button:active { transform: translateY(0); }
        .error { color: #ff4757; font-size: 14px; margin-top: 16px; padding: 12px; background: rgba(255,71,87,0.1); border-radius: 8px; border: 1px solid rgba(255,71,87,0.2); }
        
        /* Dashboard */
        .dashboard { display: flex; min-height: 100vh; }
        .hidden { display: none !important; }
        
        /* Sidebar */
        .sidebar { width: 280px; background: linear-gradient(180deg, #0f0f14 0%, #1a1a24 100%); border-right: 1px solid rgba(102,126,234,0.1); display: flex; flex-direction: column; padding: 32px 0; }
        .logo { padding: 0 28px; margin-bottom: 8px; }
        .logo h2 { font-size: 24px; font-weight: 700; background: linear-gradient(90deg, #667eea 0%, #764ba2 100%); -webkit-background-clip: text; -webkit-text-fill-color: transparent; background-clip: text; }
        .logo p { color: #667eea; font-size: 12px; text-transform: uppercase; letter-spacing: 1px; margin-top: 4px; }
        .nav-links { list-style: none; margin-top: 40px; flex: 1; }
        .nav-links li { padding: 16px 28px; cursor: pointer; color: #888; transition: all 0.3s; border-left: 3px solid transparent; margin: 4px 16px; border-radius: 0 12px 12px 0; font-size: 15px; font-weight: 500; display: flex; align-items: center; gap: 12px; }
        .nav-links li:hover { color: #fff; background: rgba(102,126,234,0.1); }
        .nav-links li.active { color: #667eea; background: linear-gradient(90deg, rgba(102,126,234,0.15), transparent); border-left-color: #667eea; }
        .nav-icon { width: 20px; height: 20px; opacity: 0.7; }
        .nav-links li.active .nav-icon { opacity: 1; }
        .logout { padding: 0 24px; margin-top: auto; }
        .logout button { width: 100%; padding: 14px; border: 1px solid rgba(255,71,87,0.3); border-radius: 12px; background: rgba(255,71,87,0.05); color: #ff4757; cursor: pointer; transition: all 0.3s; font-weight: 500; }
        .logout button:hover { background: rgba(255,71,87,0.15); border-color: #ff4757; }
        
        /* Main Content */
        .main-content { flex: 1; padding: 40px 48px; overflow-y: auto; background: linear-gradient(135deg, #0a0a0f 0%, #12121a 100%); }
        .main-content header { margin-bottom: 40px; }
        .main-content h1 { font-size: 36px; font-weight: 700; margin-bottom: 8px; background: linear-gradient(90deg, #fff 0%, #a0a0b0 100%); -webkit-background-clip: text; -webkit-text-fill-color: transparent; background-clip: text; }
        .main-content .welcome { color: #667eea; font-size: 14px; font-weight: 500; }
        
        /* Stats Cards */
        .stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 24px; margin-bottom: 40px; }
        .stat-card { background: linear-gradient(135deg, rgba(102,126,234,0.1) 0%, rgba(118,75,162,0.05) 100%); border: 1px solid rgba(102,126,234,0.2); border-radius: 20px; padding: 28px; position: relative; overflow: hidden; }
        .stat-card::before { content: ''; position: absolute; top: 0; left: 0; right: 0; height: 3px; background: linear-gradient(90deg, #667eea, #764ba2); }
        .stat-value { display: block; font-size: 42px; font-weight: 700; color: #fff; margin-bottom: 8px; }
        .stat-label { color: #888; font-size: 14px; text-transform: uppercase; letter-spacing: 1px; }
        .stat-change { color: #2ed573; font-size: 12px; margin-top: 8px; }
        
        /* Tab Content */
        .tab-content { animation: fadeIn 0.4s ease; }
        @keyframes fadeIn { from { opacity: 0; transform: translateY(20px); } to { opacity: 1; transform: translateY(0); } }
        
        /* Section Header */
        .section-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 24px; }
        .section-header h2 { font-size: 24px; font-weight: 600; color: #fff; }
        .section-actions { display: flex; gap: 12px; }
        .section-header input { padding: 14px 20px; border: 1px solid rgba(102,126,234,0.2); border-radius: 12px; background: rgba(0,0,0,0.3); color: #fff; width: 300px; font-size: 14px; transition: all 0.3s; }
        .section-header input:focus { outline: none; border-color: #667eea; }
        .section-header input::placeholder { color: #666; }
        .btn { padding: 12px 24px; border: none; border-radius: 10px; font-size: 14px; font-weight: 500; cursor: pointer; transition: all 0.3s; }
        .btn-primary { background: linear-gradient(90deg, #667eea 0%, #764ba2 100%); color: #fff; }
        .btn-primary:hover { transform: translateY(-2px); box-shadow: 0 10px 30px rgba(102,126,234,0.3); }
        .btn-danger { background: rgba(255,71,87,0.1); color: #ff4757; border: 1px solid rgba(255,71,87,0.3); }
        .btn-danger:hover { background: rgba(255,71,87,0.2); }
        .btn-secondary { background: rgba(255,255,255,0.05); color: #888; border: 1px solid rgba(255,255,255,0.1); }
        .btn-secondary:hover { background: rgba(255,255,255,0.1); color: #fff; }
        
        /* Tables */
        .table-container { background: rgba(20,20,30,0.5); border: 1px solid rgba(102,126,234,0.1); border-radius: 20px; overflow: hidden; }
        table { width: 100%; border-collapse: collapse; }
        th { text-align: left; padding: 20px; font-weight: 600; color: #667eea; border-bottom: 1px solid rgba(102,126,234,0.2); font-size: 12px; text-transform: uppercase; letter-spacing: 1px; }
        td { padding: 20px; border-bottom: 1px solid rgba(255,255,255,0.05); color: #ccc; font-size: 14px; }
        tr:hover td { background: rgba(102,126,234,0.05); }
        tr:last-child td { border-bottom: none; }
        code { font-family: 'JetBrains Mono', monospace; background: rgba(0,0,0,0.3); padding: 6px 12px; border-radius: 6px; font-size: 13px; color: #667eea; }
        
        /* Status Badges */
        .status { display: inline-flex; align-items: center; gap: 8px; padding: 8px 16px; border-radius: 20px; font-size: 12px; font-weight: 600; }
        .status.active { background: rgba(46,213,115,0.15); color: #2ed573; }
        .status.inactive { background: rgba(255,71,87,0.15); color: #ff4757; }
        .status::before { content: ''; width: 8px; height: 8px; border-radius: 50%; background: currentColor; }
        
        /* Actions */
        .actions { display: flex; gap: 8px; }
        .actions button { padding: 8px 16px; border: none; border-radius: 8px; font-size: 12px; font-weight: 500; cursor: pointer; transition: all 0.3s; }
        .actions .toggle { background: linear-gradient(90deg, #667eea, #764ba2); color: #fff; }
        .actions .toggle:hover { transform: scale(1.05); }
        .actions .delete { background: rgba(255,71,87,0.1); border: 1px solid rgba(255,71,87,0.3); color: #ff4757; }
        .actions .delete:hover { background: rgba(255,71,87,0.2); }
        
        /* Create Form */
        .create-form { background: rgba(20,20,30,0.5); border: 1px solid rgba(102,126,234,0.1); border-radius: 24px; padding: 40px; max-width: 800px; }
        .create-form h2 { font-size: 28px; font-weight: 700; margin-bottom: 8px; }
        .create-form .subtitle { color: #888; margin-bottom: 32px; font-size: 15px; }
        
        /* Preset Buttons */
        .preset-buttons { display: grid; grid-template-columns: repeat(4, 1fr); gap: 16px; margin-bottom: 32px; }
        .preset-btn { display: flex; flex-direction: column; align-items: center; padding: 28px 20px; background: rgba(0,0,0,0.3); border: 1px solid rgba(255,255,255,0.1); border-radius: 16px; cursor: pointer; transition: all 0.3s; color: #fff; }
        .preset-btn:hover { border-color: #667eea; background: rgba(102,126,234,0.1); transform: translateY(-4px); box-shadow: 0 20px 40px rgba(102,126,234,0.2); }
        .preset-btn.lifetime { background: linear-gradient(135deg, rgba(102,126,234,0.2), rgba(118,75,162,0.2)); border-color: #667eea; position: relative; overflow: hidden; }
        .preset-btn.lifetime::before { content: '★'; position: absolute; top: 8px; right: 8px; color: #667eea; font-size: 14px; }
        .preset-title { font-size: 20px; font-weight: 700; margin-bottom: 6px; }
        .preset-desc { font-size: 13px; color: #888; }
        
        /* Bulk Generation */
        .bulk-section { margin-top: 32px; padding-top: 32px; border-top: 1px solid rgba(255,255,255,0.1); }
        .bulk-section h3 { font-size: 18px; font-weight: 600; margin-bottom: 16px; }
        .bulk-row { display: flex; gap: 16px; align-items: center; margin-bottom: 16px; }
        .bulk-row label { color: #888; font-size: 14px; min-width: 100px; }
        .bulk-row input[type="number"] { width: 120px; padding: 14px 16px; border: 1px solid rgba(255,255,255,0.1); border-radius: 12px; background: rgba(0,0,0,0.3); color: #fff; font-size: 16px; }
        .bulk-row input:focus { outline: none; border-color: #667eea; }
        .bulk-buttons { display: flex; gap: 12px; flex-wrap: wrap; }
        .bulk-preset { padding: 12px 20px; border: 1px solid rgba(102,126,234,0.3); border-radius: 10px; background: rgba(102,126,234,0.1); color: #667eea; cursor: pointer; transition: all 0.3s; font-weight: 500; }
        .bulk-preset:hover { background: #667eea; color: #fff; }
        
        /* Generated Keys */
        .generated-keys { margin-top: 32px; padding: 28px; background: rgba(0,0,0,0.3); border-radius: 16px; border: 1px solid rgba(46,213,115,0.3); }
        .generated-keys-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px; }
        .generated-keys h3 { color: #2ed573; font-size: 18px; font-weight: 600; }
        .keys-list { display: grid; gap: 12px; margin-bottom: 20px; max-height: 300px; overflow-y: auto; }
        .key-item { display: flex; justify-content: space-between; align-items: center; padding: 16px; background: rgba(0,0,0,0.3); border-radius: 10px; font-family: monospace; font-size: 15px; color: #2ed573; }
        .key-item button { padding: 8px 16px; border: 1px solid #667eea; border-radius: 6px; background: transparent; color: #667eea; cursor: pointer; font-size: 12px; }
        .key-item button:hover { background: #667eea; color: #fff; }
        .download-btn { width: 100%; padding: 16px; border: none; border-radius: 12px; background: linear-gradient(90deg, #2ed573, #1eae58); color: #fff; font-size: 16px; font-weight: 600; cursor: pointer; }
        .download-btn:hover { transform: translateY(-2px); box-shadow: 0 10px 30px rgba(46,213,115,0.3); }
        
        /* Custom Duration */
        .custom-duration { margin-top: 32px; padding-top: 32px; border-top: 1px solid rgba(255,255,255,0.1); }
        .custom-duration h3 { font-size: 18px; font-weight: 600; margin-bottom: 16px; }
        .custom-row { display: flex; gap: 12px; }
        .custom-row input { flex: 1; padding: 16px 20px; border: 1px solid rgba(255,255,255,0.1); border-radius: 12px; background: rgba(0,0,0,0.3); color: #fff; font-size: 16px; }
        .custom-row input:focus { outline: none; border-color: #667eea; }
        .custom-row button { padding: 16px 32px; border: none; border-radius: 12px; background: linear-gradient(90deg, #667eea, #764ba2); color: #fff; font-weight: 600; cursor: pointer; }
        
        /* Logs */
        .log-success { color: #2ed573; }
        .log-fail { color: #ff4757; }
        
        /* Empty State */
        .empty-state { text-align: center; padding: 60px 20px; color: #666; }
        .empty-state-icon { font-size: 48px; margin-bottom: 16px; opacity: 0.5; }
        
        /* Toast Notification */
        .toast { position: fixed; bottom: 24px; right: 24px; padding: 16px 24px; background: linear-gradient(90deg, #667eea, #764ba2); color: #fff; border-radius: 12px; font-weight: 500; box-shadow: 0 10px 40px rgba(102,126,234,0.4); transform: translateY(100px); opacity: 0; transition: all 0.3s; z-index: 1000; }
        .toast.show { transform: translateY(0); opacity: 1; }
        
        /* Loading Spinner */
        .loading { display: inline-block; width: 20px; height: 20px; border: 2px solid rgba(102,126,234,0.3); border-top-color: #667eea; border-radius: 50%; animation: spin 0.8s linear infinite; }
        @keyframes spin { to { transform: rotate(360deg); } }
    </style>
</head>
<body>
    <div id="login-screen" class="login-screen">
        <div class="login-box">
            <h1>License Manager</h1>
            <p class="subtitle">Admin Portal</p>
            <p>Enter your credentials to access the dashboard</p>
            <div class="input-group">
                <input type="text" id="username-input" placeholder="Username" autocomplete="off">
            </div>
            <div class="input-group">
                <input type="password" id="password-input" placeholder="Password">
            </div>
            <button onclick="login()">Sign In</button>
            <div id="login-error" class="error" style="display:none;"></div>
        </div>
    </div>

    <div id="dashboard" class="dashboard hidden">
        <nav class="sidebar">
            <div class="logo">
                <h2>Auth Panel</h2>
                <p>License Management</p>
            </div>
            <ul class="nav-links">
                <li class="active" onclick="showTab('licenses')">📋 License Keys</li>
                <li onclick="showTab('create')">⚡ Create Keys</li>
                <li onclick="showTab('logs')">📊 Access Logs</li>
            </ul>
            <div class="logout">
                <button onclick="logout()">🚪 Logout</button>
            </div>
        </nav>

        <main class="main-content">
            <header>
                <h1>Dashboard</h1>
                <p class="welcome">Welcome back, Administrator</p>
            </header>

            <div class="stats">
                <div class="stat-card">
                    <span class="stat-value" id="stat-total">0</span>
                    <span class="stat-label">Total Keys</span>
                </div>
                <div class="stat-card">
                    <span class="stat-value" id="stat-active">0</span>
                    <span class="stat-label">Active Keys</span>
                </div>
                <div class="stat-card">
                    <span class="stat-value" id="stat-expired">0</span>
                    <span class="stat-label">Expired Keys</span>
                </div>
            </div>

            <div id="tab-licenses" class="tab-content">
                <div class="section-header">
                    <h2>All License Keys</h2>
                    <div class="section-actions">
                        <input type="text" id="search-licenses" placeholder="🔍 Search keys..." oninput="filterLicenses()">
                    </div>
                </div>
                <div class="table-container">
                    <table>
                        <thead>
                            <tr><th>Key</th><th>Created</th><th>Expires</th><th>Uses</th><th>Last Used</th><th>Status</th><th>Actions</th></tr>
                        </thead>
                        <tbody id="licenses-tbody"></tbody>
                    </table>
                </div>
            </div>

            <div id="tab-create" class="tab-content hidden">
                <div class="create-form">
                    <h2>Create License Keys</h2>
                    <p class="subtitle">Generate single or bulk license keys</p>
                    
                    <h3 style="font-size:16px;margin-bottom:16px;color:#667eea;">Quick Generate (Single)</h3>
                    <div class="preset-buttons">
                        <button class="preset-btn" onclick="createLicense(1)">
                            <span class="preset-title">1 Day</span>
                            <span class="preset-desc">24 hours</span>
                        </button>
                        <button class="preset-btn" onclick="createLicense(7)">
                            <span class="preset-title">7 Days</span>
                            <span class="preset-desc">One week</span>
                        </button>
                        <button class="preset-btn" onclick="createLicense(30)">
                            <span class="preset-title">30 Days</span>
                            <span class="preset-desc">One month</span>
                        </button>
                        <button class="preset-btn lifetime" onclick="createLicense(null)">
                            <span class="preset-title">Lifetime</span>
                            <span class="preset-desc">Never expires</span>
                        </button>
                    </div>

                    <div class="bulk-section">
                        <h3>🔥 Bulk Generation</h3>
                        <div class="bulk-row">
                            <label>Number of keys:</label>
                            <input type="number" id="bulk-count" value="10" min="1" max="100">
                        </div>
                        <div class="bulk-row">
                            <label>Duration:</label>
                            <div class="bulk-buttons">
                                <button class="bulk-preset" onclick="createBulk(1)">1 Day</button>
                                <button class="bulk-preset" onclick="createBulk(7)">7 Days</button>
                                <button class="bulk-preset" onclick="createBulk(30)">30 Days</button>
                                <button class="bulk-preset" onclick="createBulk(null)">Lifetime</button>
                            </div>
                        </div>
                    </div>

                    <div class="custom-duration">
                        <h3>Custom Duration</h3>
                        <div class="custom-row">
                            <input type="number" id="custom-days" placeholder="Enter days..." min="1">
                            <button onclick="createLicenseCustom()">Generate Single</button>
                            <button onclick="createBulkCustom()" style="background:linear-gradient(90deg,#2ed573,#1eae58);">Generate Bulk</button>
                        </div>
                    </div>

                    <div id="generated-keys" class="generated-keys hidden">
                        <div class="generated-keys-header">
                            <h3>✓ Generated Keys</h3>
                            <span id="keys-count"></span>
                        </div>
                        <div class="keys-list" id="keys-list"></div>
                        <button class="download-btn" onclick="downloadKeys()">⬇ Download All Keys (.txt)</button>
                    </div>
                </div>
            </div>

            <div id="tab-logs" class="tab-content hidden">
                <div class="section-header">
                    <h2>Access Logs</h2>
                    <button class="btn btn-danger" onclick="clearLogs()">Clear Logs</button>
                </div>
                <div class="table-container">
                    <table>
                        <thead>
                            <tr><th>Time</th><th>Action</th><th>Key</th><th>HWID</th><th>Status</th></tr>
                        </thead>
                        <tbody id="logs-tbody"></tbody>
                    </table>
                </div>
            </div>
        </main>
    </div>

    <div id="toast" class="toast"></div>

    <script>
    let authUsername='',authPassword='',allLicenses=[],generatedKeysList=[];
    function showToast(msg){const t=document.getElementById('toast');t.textContent=msg;t.classList.add('show');setTimeout(()=>t.classList.remove('show'),3000);}
    function getAuthHeader(){return'Basic '+btoa(authUsername+':'+authPassword);}
    async function api(endpoint,options={}){
        const url=endpoint.startsWith('http')?endpoint:window.location.origin+endpoint;
        try{
            const res=await fetch(url,{...options,headers:{'Content-Type':'application/json','Authorization':getAuthHeader(),...options.headers}});
            if(res.status===401){logout();showToast('Session expired');return null;}
            return res.json();
        }catch(e){showToast('Network error');return null;}
    }
    async function login(){
        const username=document.getElementById('username-input').value;
        const password=document.getElementById('password-input').value;
        if(!username||!password){document.getElementById('login-error').textContent='Please fill all fields';document.getElementById('login-error').style.display='block';return;}
        try{
            const res=await fetch('/api/admin/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username,password})});
            if(!res.ok){document.getElementById('login-error').textContent='Server error: '+res.status;document.getElementById('login-error').style.display='block';return;}
            const data=await res.json();
            if(data.success){authUsername=username;authPassword=password;document.getElementById('login-screen').classList.add('hidden');document.getElementById('dashboard').classList.remove('hidden');document.getElementById('login-error').style.display='none';loadStats();loadLicenses();showToast('Welcome back!');}
            else{document.getElementById('login-error').textContent='Invalid credentials';document.getElementById('login-error').style.display='block';}
        }catch(e){document.getElementById('login-error').textContent='Error: '+e.message;document.getElementById('login-error').style.display='block';}
    }
    function logout(){authUsername='';authPassword='';document.getElementById('dashboard').classList.add('hidden');document.getElementById('login-screen').classList.remove('hidden');document.getElementById('username-input').value='';document.getElementById('password-input').value='';document.getElementById('generated-keys').classList.add('hidden');generatedKeysList=[];}
    function showTab(tab){
        document.querySelectorAll('.tab-content').forEach(el=>el.classList.add('hidden'));
        document.getElementById('tab-'+tab).classList.remove('hidden');
        document.querySelectorAll('.nav-links li').forEach((el,i)=>{el.classList.remove('active');if(el.textContent.toLowerCase().includes(tab))el.classList.add('active');});
        if(tab==='logs')loadLogs();
        if(tab==='licenses')loadLicenses();
    }
    async function loadStats(){const stats=await api('/api/admin/stats');if(!stats)return;document.getElementById('stat-total').textContent=stats.total||0;document.getElementById('stat-active').textContent=stats.active||0;document.getElementById('stat-expired').textContent=stats.expired||0;}
    async function loadLicenses(){const licenses=await api('/api/admin/licenses');if(!licenses)return;allLicenses=licenses;renderLicenses(licenses);}
    function renderLicenses(licenses){
        const tbody=document.getElementById('licenses-tbody');
        if(licenses.length===0){tbody.innerHTML='<tr><td colspan="7"><div class="empty-state"><div class="empty-state-icon">📋</div>No license keys found</div></td></tr>';return;}
        tbody.innerHTML=licenses.map(lic=>'<tr><td><code>'+lic.key+'</code></td><td>'+formatDate(lic.createdAt)+'</td><td>'+(lic.expiresAt?formatDate(lic.expiresAt):'Never')+'</td><td>'+(lic.useCount||0)+'</td><td>'+(lic.lastUsed?formatDate(lic.lastUsed):'Never')+'</td><td><span class="status '+(lic.active?'active':'inactive')+'">'+(lic.active?'Active':'Inactive')+'</span></td><td class="actions"><button class="toggle" onclick="toggleLicense(\''+lic.fullKey+'\','+!lic.active+')">'+(lic.active?'Disable':'Enable')+'</button><button class="delete" onclick="deleteLicense(\''+lic.fullKey+'\')">Delete</button></td></tr>').join('');
    }
    function filterLicenses(){const query=document.getElementById('search-licenses').value.toLowerCase();const filtered=allLicenses.filter(l=>l.key.toLowerCase().includes(query)||l.fullKey.toLowerCase().includes(query));renderLicenses(filtered);}
    async function createLicense(days){
        const result=await api('/api/admin/licenses',{method:'POST',body:JSON.stringify({durationDays:days,count:1})});
        if(!result||!result.success)return;
        generatedKeysList=result.keys;
        showGeneratedKeys(result.keys,'Single key generated');
        loadStats();loadLicenses();
    }
    async function createBulk(days){
        const count=parseInt(document.getElementById('bulk-count').value)||10;
        const result=await api('/api/admin/licenses',{method:'POST',body:JSON.stringify({durationDays:days,count:count})});
        if(!result||!result.success)return;
        generatedKeysList=result.keys;
        showGeneratedKeys(result.keys,count+' keys generated');
        loadStats();loadLicenses();
    }
    async function createLicenseCustom(){const days=parseInt(document.getElementById('custom-days').value);if(!days||days<1){showToast('Please enter valid days');return;}createLicense(days);}
    async function createBulkCustom(){const days=parseInt(document.getElementById('custom-days').value);if(!days||days<1){showToast('Please enter valid days');return;}createBulk(days);}
    function showGeneratedKeys(keys,title){
        document.getElementById('generated-keys').classList.remove('hidden');
        document.getElementById('keys-count').textContent=title;
        document.getElementById('keys-list').innerHTML=keys.map(k=>'<div class="key-item"><span>'+k+'</span><button onclick="copyKey(\''+k+'\')">Copy</button></div>').join('');
    }
    function copyKey(key){navigator.clipboard.writeText(key);showToast('Copied to clipboard!');}
    function downloadKeys(){
        if(generatedKeysList.length===0)return;
        const blob=new Blob([generatedKeysList.join('\\n')],{type:'text/plain'});
        const url=URL.createObjectURL(blob);
        const a=document.createElement('a');a.href=url;a.download='license-keys-'+new Date().toISOString().split('T')[0]+'.txt';a.click();URL.revokeObjectURL(url);showToast('Downloaded!');
    }
    async function toggleLicense(key,active){const result=await api('/api/admin/licenses/'+encodeURIComponent(key),{method:'PATCH',body:JSON.stringify({active})});if(result){loadLicenses();loadStats();showToast(active?'Key activated':'Key deactivated');}}
    async function deleteLicense(key){if(!confirm('Are you sure you want to delete this key?'))return;const result=await api('/api/admin/licenses/'+encodeURIComponent(key),{method:'DELETE'});if(result){loadLicenses();loadStats();showToast('Key deleted');}}
    async function loadLogs(){const logs=await api('/api/admin/logs');if(!logs)return;const tbody=document.getElementById('logs-tbody');if(logs.length===0){tbody.innerHTML='<tr><td colspan="5"><div class="empty-state"><div class="empty-state-icon">📊</div>No logs yet</div></td></tr>';return;}tbody.innerHTML=logs.map(log=>'<tr><td>'+formatDate(log.timestamp)+'</td><td>'+log.action+'</td><td>'+(log.key||'-')+'</td><td>'+(log.hwid||'-')+'</td><td class="'+(log.success?'log-success':'log-fail')+'">'+(log.success?'Success':'Failed')+'</td></tr>').join('');}
    function clearLogs(){document.getElementById('logs-tbody').innerHTML='<tr><td colspan="5"><div class="empty-state"><div class="empty-state-icon">📊</div>Logs cleared</div></td></tr>';showToast('Logs cleared');}
    function formatDate(dateStr){if(!dateStr)return'-';const d=new Date(dateStr);return d.toLocaleString();}
    document.getElementById('password-input').addEventListener('keypress',e=>{if(e.key==='Enter')login();});
    document.getElementById('username-input').addEventListener('keypress',e=>{if(e.key==='Enter')login();});
    </script>
</body>
</html>`);
    }
});

app.listen(PORT, () => {
    console.log(`Auth server running on port ${PORT}`);
    console.log(`Admin panel: http://localhost:${PORT}`);
});
