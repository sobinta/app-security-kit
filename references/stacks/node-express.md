# Node.js · Express (also Fastify/Koa/Hono/Nest notes) · Socket.IO

## Hardened Express baseline
```js
require('dotenv').config();
const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const session = require('express-session');
const { rateLimit } = require('express-rate-limit');

const app = express();
app.disable('x-powered-by');
app.set('trust proxy', 1);                       // behind Nginx/Cloudflare: correct req.ip & req.secure
app.use(helmet());                               // CSP, HSTS, XFO, nosniff, Referrer-Policy …
app.use(cors({ origin: process.env.CORS_ORIGINS?.split(',') ?? false, credentials: true }));
app.use(express.json({ limit: '100kb' }));
app.use(express.urlencoded({ extended: false, limit: '100kb' }));
app.use(express.static('public', { dotfiles: 'deny', index: 'index.html' }));

app.use(session({
  name: '__Host-sid',                            // requires secure + path=/ + no domain (use 'sid' on plain-http localhost)
  secret: process.env.SESSION_SECRET,            // fail fast at boot if missing/short
  resave: false, saveUninitialized: false,
  store: /* connect-redis / connect-pg-simple / better-sqlite3-session-store — never MemoryStore in production */ undefined,
  cookie: { httpOnly: true, secure: process.env.NODE_ENV === 'production', sameSite: 'lax', maxAge: 1000 * 60 * 60 * 8 },
}));
```
Fail fast on config: `if (!process.env.SESSION_SECRET || process.env.SESSION_SECRET.length < 32) throw new Error('SESSION_SECRET missing/weak');`

## Auth helpers
```js
function requireLogin(req, res, next) {
  if (!req.session.userId) return res.status(401).json({ error: 'login required' });
  next();
}
const requireRole = (role) => (req, res, next) => {
  const user = db.prepare('SELECT id, role FROM users WHERE id = ?').get(req.session.userId);
  if (!user || user.role !== role) return res.status(403).json({ error: 'forbidden' });
  req.user = user; next();
};
app.use('/api/admin', requireLogin, requireRole('admin'));   // whole router, deny by default

// login: rotate the session id (fixation), generic error, hash compare
app.post('/api/login', loginLimiter, async (req, res, next) => {
  const { email, password } = LoginSchema.parse(req.body);
  const user = db.prepare('SELECT id, password_hash FROM users WHERE email = ?').get(email.toLowerCase());
  const ok = user && await argon2.verify(user.password_hash, password);
  if (!ok) { log.warn({ event: 'login_failed', email, ip: req.ip }); return res.status(401).json({ error: 'Invalid email or password' }); }
  req.session.regenerate((err) => { if (err) return next(err); req.session.userId = user.id; res.json({ ok: true }); });
});
// logout: destroy server-side
app.post('/api/logout', (req, res) => req.session.destroy(() => res.clearCookie('__Host-sid').json({ ok: true })));
```
Password hashing: `argon2` (`await argon2.hash(pw)` → argon2id by default; `argon2.verify(hash, pw)`) or `bcrypt`/`bcryptjs` (`hash(pw, 12)`, `compare`).

## Rate limiting
```js
const loginLimiter = rateLimit({ windowMs: 60_000, limit: 5, standardHeaders: 'draft-7', legacyHeaders: false,
  keyGenerator: (req) => `${req.ip}:${String(req.body?.email || '').toLowerCase()}`,
  handler: (req, res) => { log.warn({ event: 'rate_limited', ip: req.ip, path: req.path }); res.status(429).json({ error: 'Too many attempts, try again later' }); } });
```
Use a shared store (`rate-limit-redis`) with PM2 cluster / multiple instances. Also limit forgot/reset, signup, OTP, contact, search and AI endpoints. (express-rate-limit v7+: `limit`; older versions: `max`.)

## Validation (zod middleware)
```js
const { z } = require('zod');
const validate = (schema, where = 'body') => (req, res, next) => {
  const r = schema.safeParse(req[where]);
  if (!r.success) return res.status(400).json({ error: 'invalid input' });
  req[where] = r.data; next();
};
const Checkout = z.object({ productId: z.coerce.number().int().positive(), quantity: z.coerce.number().int().min(1).max(10) }).strict();
app.post('/api/checkout', requireLogin, validate(Checkout), (req, res) => {
  const product = db.prepare('SELECT id, price, stock FROM products WHERE id = ?').get(req.body.productId);
  if (!product) return res.status(404).json({ error: 'not found' });
  const total = product.price * req.body.quantity;           // price from the DB, never from the client
  /* create order + payment with `total` … */
});
```

## SQL — parameterized everywhere
`pg`: `pool.query('SELECT * FROM orders WHERE id = $1 AND user_id = $2', [id, userId])` · `mysql2`: `conn.execute('… WHERE id = ?', [id])` · `better-sqlite3` / `node:sqlite`: `db.prepare('… WHERE id = ?').get(id)` · Prisma: `prisma.$queryRaw\`SELECT … WHERE id = ${id}\`` (tagged = safe; `$queryRawUnsafe` = unsafe) · Knex: `knex.raw('… where id = ?', [id])` · Sequelize: `sequelize.query('… :id', { replacements: { id } })`. Dynamic column/sort names → allow-list map.

## CSRF for cookie sessions
Simplest robust option for JSON APIs (no extra package):
```js
const allowed = new Set((process.env.CORS_ORIGINS || '').split(','));   // e.g. https://shop.example
app.use((req, res, next) => {
  if (['GET', 'HEAD', 'OPTIONS'].includes(req.method)) return next();
  const origin = req.get('origin') || (req.get('referer') ? new URL(req.get('referer')).origin : null);
  const self = `${req.protocol}://${req.get('host')}`;
  if (origin !== self && !allowed.has(origin)) return res.status(403).json({ error: 'cross-site request blocked' });
  if (!req.is('application/json') && !req.is('multipart/form-data')) return res.status(415).json({ error: 'JSON only' });
  next();
});
```
For classic HTML form posts use a token library (`csrf-sync` synchronizer token, or `csrf-csrf` signed double-submit — check the installed major's README: option names changed between versions). `csurf` is deprecated.

## Uploads (multer)
```js
const multer = require('multer');
const crypto = require('crypto');
const upload = multer({
  storage: multer.diskStorage({
    destination: path.join(__dirname, 'storage/uploads'),             // NOT under public/
    filename: (req, file, cb) => cb(null, crypto.randomUUID()),        // never file.originalname
  }),
  limits: { fileSize: 2 * 1024 * 1024, files: 1 },
  fileFilter: (req, file, cb) => cb(null, ['image/png', 'image/jpeg', 'image/webp'].includes(file.mimetype)),
});
app.post('/api/avatar', requireLogin, upload.single('avatar'), async (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'png/jpeg/webp up to 2MB' });
  const { fileTypeFromFile } = await import('file-type');               // magic bytes, ESM-only
  const t = await fileTypeFromFile(req.file.path);
  if (!t || !['png', 'jpg', 'webp'].includes(t.ext)) { fs.unlinkSync(req.file.path); return res.status(400).json({ error: 'type' }); }
  /* optional: sharp(req.file.path).rotate().resize(512).toFile(...) to re-encode */
});
// error handler maps MulterError LIMIT_FILE_SIZE → 413
```
Serve uploads through a route with `res.sendFile(name, { root: UPLOAD_DIR, headers: { 'Content-Disposition': 'attachment', 'X-Content-Type-Options': 'nosniff' } })` after checking ownership.

## Safe file serving (path traversal)
`res.sendFile(req.params.file, { root: REPORTS_DIR, dotfiles: 'deny' })` — the `root` option rejects `..`. Or map ids → filenames.

## Error handling (no leaks)
```js
app.use((err, req, res, next) => {
  const id = crypto.randomUUID();
  log.error({ id, err, path: req.path });                  // full details only in logs
  if (err.type === 'entity.parse.failed') return res.status(400).json({ error: 'invalid JSON', id });
  if (err.code === 'LIMIT_FILE_SIZE') return res.status(413).json({ error: 'file too large', id });
  res.status(err.status && err.status < 500 ? err.status : 500).json({ error: 'Something went wrong', id });
});
```
Run with `NODE_ENV=production`.

## Socket.IO
```js
const io = new Server(httpServer, { cors: { origin: allowedOrigins, credentials: true }, maxHttpBufferSize: 1e6 });
io.use(async (socket, next) => {                          // authenticate the handshake
  const user = await verifySessionOrToken(socket.handshake.auth?.token || socket.request.headers.cookie);
  if (!user) return next(new Error('unauthorized'));
  socket.data.user = user; next();
});
io.on('connection', (socket) => {
  socket.on('join', (roomId) => { if (!canAccessRoom(socket.data.user, roomId)) return; socket.join(roomId); });
  socket.on('message', (msg) => { const m = MessageSchema.safeParse(msg); if (!m.success) return; /* rate-limit per socket */ });
});
```
Uploads over sockets: size + type checks like HTTP. Admin namespaces: role check in `io.of('/admin').use(...)`.

## Server timeouts (slowloris / load)
`server.headersTimeout = 20_000; server.requestTimeout = 30_000; server.keepAliveTimeout = 65_000;` (keep `keepAliveTimeout` above the proxy's upstream keepalive). Heavy CPU work (PDF, image, crypto) → worker threads or a queue, never on the request path.

## Fastify / Koa / Hono / Nest
Fastify: `@fastify/helmet`, `@fastify/cors`, `@fastify/rate-limit`, `@fastify/csrf-protection`, JSON-schema validation built in. Koa: `koa-helmet`, `@koa/cors`, `koa-ratelimit`. Hono: `hono/secure-headers`, `hono/cors`, `hono/csrf`. Nest: `helmet`, `@nestjs/throttler`, `ValidationPipe({ whitelist: true, forbidNonWhitelisted: true })`, Guards for roles.
