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
app.use(express.static(path.join(__dirname, 'public')));

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
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => {
    console.log(`Auth server running on port ${PORT}`);
    console.log(`Admin panel: http://localhost:${PORT}`);
});
