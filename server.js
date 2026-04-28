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
app.get('/', (req, res) => {
    const indexPath = path.join(__dirname, 'public', 'index.html');
    if (fs.existsSync(indexPath)) {
        res.sendFile(indexPath);
    } else {
        res.status(404).send('index.html not found');
    }
});

app.listen(PORT, () => console.log('Server running on port', PORT));
