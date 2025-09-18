// server.js
const express = require('express');
const helmet = require('helmet');
const cookieParser = require('cookie-parser');
const fs = require('fs');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { LowSync, JSONFileSync } = require('lowdb');
const { nanoid } = require('nanoid');
require('dotenv').config();

const app = express();
app.use(helmet());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

// LowDB setup
const dbFile = './db.json';
if (!fs.existsSync(dbFile)) fs.writeFileSync(dbFile, JSON.stringify({ users: [], settings: { godModeEnabled: false }, audit: [] }, null, 2));
const adapter = new JSONFileSync(dbFile);
const db = new LowSync(adapter);
db.read();

// JWT secret
const JWT_SECRET = process.env.JWT_SECRET || 'dev_jwt_secret';

// Helpers
function signToken(payload, expiresIn = '1h') {
    return jwt.sign(payload, JWT_SECRET, { expiresIn });
}
function auditLog(adminId, action, meta = {}) {
    db.read();
    db.data.audit.push({ id: nanoid(), adminId, action, meta, timestamp: new Date().toISOString() });
    db.write();
}

// Auth middleware
function requireAuth(req, res, next) {
    try {
        const token = req.cookies['prevail_token'];
        if (!token) return res.status(401).json({ error: 'Unauthorized' });
        const payload = jwt.verify(token, JWT_SECRET);
        db.read();
        const user = db.data.users.find(u => u.id === payload.id);
        if (!user) return res.status(401).json({ error: 'Unauthorized' });
        req.user = user;
        next();
    } catch (e) {
        return res.status(401).json({ error: 'Unauthorized' });
    }
}
function requireAdmin(req, res, next) {
    if (!req.user || !req.user.roles.includes('admin')) return res.status(403).json({ error: 'Forbidden - admin only' });
    next();
}

// Routes
app.post('/auth/register', async (req, res) => {
    const { email, password, displayName } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'email and password required' });
    db.read();
    if (db.data.users.find(u => u.email === email)) return res.status(400).json({ error: 'already registered' });
    const hash = await bcrypt.hash(password, 12);
    const newUser = { id: nanoid(), email, passwordHash: hash, displayName: displayName || email, roles: ['admin'], createdAt: new Date().toISOString() };
    db.data.users.push(newUser);
    db.write();
    auditLog(newUser.id, 'register', { email });
    res.json({ ok: true });
});

app.post('/auth/login', async (req, res) => {
    const { email, password } = req.body;
    db.read();
    const user = db.data.users.find(u => u.email === email);
    if (!user) return res.status(400).json({ error: 'invalid credentials' });
    const match = await bcrypt.compare(password, user.passwordHash);
    if (!match) return res.status(400).json({ error: 'invalid credentials' });
    const token = signToken({ id: user.id, roles: user.roles });
    res.cookie('prevail_token', token, { httpOnly: true });
    auditLog(user.id, 'login', { email });
    res.json({ ok: true });
});

// Logout
app.post('/auth/logout', (req, res) => {
    res.clearCookie('prevail_token');
    res.json({ ok: true });
});

// Admin routes
app.get('/admin/settings', requireAuth, requireAdmin, (req, res) => {
    db.read();
    res.json({ settings: db.data.settings });
});

app.post('/admin/godmode/toggle', requireAuth, requireAdmin, (req, res) => {
    const { action, masterKey } = req.body;
    if (!masterKey || masterKey !== process.env.GOD_MODE_KEY) return res.status(403).json({ error: 'invalid_master_key' });
    db.read();
    const enable = action === 'enable';
    db.data.settings.godModeEnabled = enable;
    db.write();
    auditLog(req.user.id, enable ? 'godmode_enabled' : 'godmode_disabled');
    res.json({ ok: true, godModeEnabled: enable });
});

// Serve admin panel
app.use('/admin', express.static('public/admin'));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`BuildMyWeb admin running on port ${PORT}`));
