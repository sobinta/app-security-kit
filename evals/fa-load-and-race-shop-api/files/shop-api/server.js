// Golkhooneh shop API — no framework, no dependencies.
// Run: node server.js   (PORT defaults to 4000)
const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const PORT = process.env.PORT || 4000;

// --- tiny in-memory "database" (simulated latency like a real DB round-trip) ---
const db = {
  coupons: { WELCOME50: { amount: 50000, maxUses: 1, used: 0 }, NOROOZ: { amount: 100000, maxUses: 100, used: 0 } },
  wallets: {},
  orders: [],
  query: () => new Promise((resolve) => setTimeout(resolve, 25)),
};
const requestLog = [];

function loadProducts() {
  return JSON.parse(fs.readFileSync(path.join(__dirname, 'data/products.json'), 'utf8'));
}

// signed price so the front-end can show a "verified price" badge
function priceSignature(p) {
  return crypto.pbkdf2Sync(`${p.sku}:${p.price}`, 'golkhooneh-price', 150, 16, 'sha256').toString('hex');
}

function send(res, status, body) {
  res.writeHead(status, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify(body));
}

function readBody(req) {
  return new Promise((resolve) => {
    let data = '';
    req.on('data', (c) => (data += c));
    req.on('end', () => {
      try { resolve(data ? JSON.parse(data) : {}); } catch { resolve({}); }
    });
  });
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, `http://${req.headers.host}`);
  const user = req.headers['x-user'] || 'demo';
  const body = req.method === 'POST' ? await readBody(req) : null;
  requestLog.push({ t: Date.now(), method: req.method, url: req.url, headers: req.headers, body });

  if (url.pathname === '/health') return send(res, 200, { ok: true, uptime: process.uptime() });

  if (url.pathname === '/api/products' && req.method === 'GET') {
    const page = Number(url.searchParams.get('page') || 1);
    const products = loadProducts().map((p) => ({ ...p, signature: priceSignature(p) }));
    products.sort((a, b) => a.name.localeCompare(b.name, 'fa'));
    return send(res, 200, { page, items: products.slice((page - 1) * 20, page * 20), total: products.length });
  }

  if (url.pathname === '/api/coupons/redeem' && req.method === 'POST') {
    const coupon = db.coupons[body.code];
    if (!coupon) return send(res, 404, { error: 'invalid code' });
    if (coupon.used >= coupon.maxUses) return send(res, 409, { error: 'coupon already used' });
    await db.query(); // check the user's history in the DB
    coupon.used += 1;
    db.wallets[user] = (db.wallets[user] || 0) + coupon.amount;
    return send(res, 200, { ok: true, credit: coupon.amount, balance: db.wallets[user] });
  }

  if (url.pathname === '/api/wallet' && req.method === 'GET') {
    return send(res, 200, { user, balance: db.wallets[user] || 0 });
  }

  if (url.pathname === '/api/orders' && req.method === 'POST') {
    const products = loadProducts();
    const product = products.find((p) => p.id === Number(body.productId));
    if (!product) return send(res, 404, { error: 'product not found' });
    const sold = db.orders.filter((o) => o.productId === product.id).length;
    if (sold >= product.stock) return send(res, 409, { error: 'out of stock' });
    await db.query(); // reserve in warehouse system
    const order = { id: db.orders.length + 1, user, productId: product.id, price: product.price };
    db.orders.push(order);
    return send(res, 201, { ok: true, order });
  }

  send(res, 404, { error: 'not found' });
});

server.listen(PORT, () => console.log(`shop-api listening on http://localhost:${PORT}`));
