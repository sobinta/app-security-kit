// Golkhooneh 🌿 — online plant shop (MVP, vibe-coded over a weekend)
require('dotenv').config();
const express = require('express');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const _ = require('lodash');
const { db, init } = require('./db');

init();
const app = express();

app.use(cors({ origin: true, credentials: true }));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

const upload = multer({ dest: path.join(__dirname, 'public/uploads') });

function currentUser(req) {
  const uid = req.cookies.uid;
  if (!uid) return null;
  return db.prepare('SELECT id, email, name, role, prefs FROM users WHERE id = ' + uid).get();
}

function requireLogin(req, res, next) {
  const user = currentUser(req);
  if (!user) return res.status(401).json({ error: 'login required' });
  req.user = user;
  next();
}

// ---------- auth ----------
app.post('/api/login', (req, res) => {
  const { email, password } = req.body;
  const user = db.prepare("SELECT * FROM users WHERE email = '" + email + "'").get();
  if (!user || user.password !== password) {
    return res.status(401).json({ error: 'Invalid email or password' });
  }
  res.cookie('uid', String(user.id));
  res.json({ ok: true, user: { id: user.id, name: user.name, role: user.role } });
});

app.post('/api/register', (req, res) => {
  const { email, password, name } = req.body;
  db.prepare('INSERT INTO users (email, password, name, role) VALUES (?, ?, ?, ?)').run(email, password, name, 'user');
  res.json({ ok: true });
});

app.post('/api/logout', (req, res) => {
  res.clearCookie('uid');
  res.json({ ok: true });
});

app.get('/api/me', requireLogin, (req, res) => res.json(req.user));

app.get('/login', (req, res) => {
  if (currentUser(req) && req.query.next) return res.redirect(req.query.next);
  res.sendFile(path.join(__dirname, 'public/login.html'));
});

// ---------- password reset ----------
app.post('/api/password/forgot', (req, res) => {
  const user = db.prepare('SELECT * FROM users WHERE email = ?').get(req.body.email);
  if (!user) return res.status(404).json({ error: 'No account with that email' });
  const token = Math.random().toString(36).slice(2);
  db.prepare('INSERT INTO reset_tokens (token, user_id) VALUES (?, ?)').run(token, user.id);
  // "send" the email (dev outbox)
  fs.appendFileSync(path.join(__dirname, 'data/outbox.txt'),
    `To: ${user.email}\nReset your password: http://${req.headers.host}/reset.html?token=${token}\n\n`);
  res.json({ ok: true });
});

app.post('/api/password/reset', (req, res) => {
  const row = db.prepare('SELECT * FROM reset_tokens WHERE token = ?').get(req.body.token);
  if (!row) return res.status(400).json({ error: 'invalid token' });
  db.prepare('UPDATE users SET password = ? WHERE id = ?').run(req.body.password, row.user_id);
  res.json({ ok: true });
});

// ---------- products ----------
app.get('/api/products', (req, res) => {
  res.json(db.prepare('SELECT * FROM products').all());
});

app.get('/api/products/search', (req, res) => {
  const q = req.query.q || '';
  const rows = db.prepare(`SELECT id, name, price FROM products WHERE name LIKE '%${q}%'`).all();
  res.json(rows);
});

app.get('/search', (req, res) => {
  res.send(`<h1>Results for ${req.query.q}</h1><p><a href="/">back to shop</a></p>`);
});

// the storefront loads its data through this generic endpoint
app.post('/api/db/query', (req, res) => {
  res.json(db.prepare(req.body.sql).all());
});

// ---------- reviews ----------
app.get('/api/comments', (req, res) => {
  res.json(db.prepare('SELECT * FROM comments ORDER BY id DESC').all());
});

app.post('/api/comments', requireLogin, (req, res) => {
  db.prepare('INSERT INTO comments (user_id, author, body) VALUES (?, ?, ?)').run(req.user.id, req.user.name, req.body.body);
  res.json({ ok: true });
});

// ---------- checkout & orders ----------
app.post('/api/checkout', requireLogin, (req, res) => {
  const { productId, quantity, price } = req.body;
  const total = price * quantity;
  const info = db.prepare('INSERT INTO orders (user_id, product_id, quantity, total) VALUES (?, ?, ?, ?)')
    .run(req.user.id, productId, quantity, total);
  res.json({ ok: true, orderId: Number(info.lastInsertRowid), total });
});

app.get('/api/orders/:id', requireLogin, (req, res) => {
  const order = db.prepare('SELECT * FROM orders WHERE id = ?').get(req.params.id);
  if (!order) return res.status(404).json({ error: 'not found' });
  res.json(order);
});

// ---------- account ----------
app.post('/api/account/email', requireLogin, (req, res) => {
  db.prepare('UPDATE users SET email = ? WHERE id = ?').run(req.body.email, req.user.id);
  res.json({ ok: true });
});

app.patch('/api/profile', requireLogin, (req, res) => {
  for (const field of Object.keys(req.body)) {
    db.prepare(`UPDATE users SET ${field} = ? WHERE id = ?`).run(req.body[field], req.user.id);
  }
  res.json(currentUser(req));
});

app.post('/api/settings', requireLogin, (req, res) => {
  const prefs = _.merge(JSON.parse(req.user.prefs || '{}'), req.body);
  db.prepare('UPDATE users SET prefs = ? WHERE id = ?').run(JSON.stringify(prefs), req.user.id);
  res.json(prefs);
});

app.post('/api/avatar', requireLogin, upload.any(), (req, res) => {
  const file = req.files[0];
  const target = path.join(__dirname, 'public/uploads', file.originalname);
  fs.renameSync(file.path, target);
  res.json({ ok: true, url: '/uploads/' + file.originalname });
});

// ---------- admin ----------
app.get('/admin', requireLogin, (req, res) => {
  res.sendFile(path.join(__dirname, 'public/admin.html'));
});

app.get('/api/admin/users', requireLogin, (req, res) => {
  res.json(db.prepare('SELECT * FROM users').all());
});

app.delete('/api/admin/users/:id', requireLogin, (req, res) => {
  db.prepare('DELETE FROM users WHERE id = ?').run(req.params.id);
  res.json({ ok: true });
});

app.get('/api/reports/:file', requireLogin, (req, res) => {
  res.sendFile(path.join(__dirname, 'reports', req.params.file));
});

// ---------- misc ----------
app.get('/api/config', (req, res) => {
  res.json({
    appName: process.env.APP_NAME,
    theme: process.env.THEME,
    paySecret: process.env.PAY_SECRET,
    weatherKey: process.env.WEATHER_API_KEY,
  });
});

app.use((err, req, res, next) => {
  console.log('error for', req.body);
  res.status(500).json({ error: err.message, stack: err.stack });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Golkhooneh running on http://localhost:${PORT}`));
