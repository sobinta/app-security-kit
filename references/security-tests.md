# Security regression tests (S27)

Write tests in the project's own framework so they run in CI forever. One test per fixed finding is the minimum; the authorization matrix (anon / user / other user / admin per route) is the most valuable suite. Use the project's test DB/seed — never production.

## Node / Express (Vitest or Jest + supertest)
```js
// tests/security.test.js
import request from 'supertest';
import { app } from '../app.js';            // export the app without listen() so tests can import it

const agentFor = async (email, password) => {
  const agent = request.agent(app);
  const r = await agent.post('/api/login').send({ email, password });
  expect(r.status).toBe(200);
  return agent;
};

describe('S01/S09 authorization', () => {
  it('anonymous cannot read admin data', async () => {
    expect((await request(app).get('/api/admin/users')).status).toBe(401);
  });
  it('normal user gets 403 on admin routes', async () => {
    const ali = await agentFor('ali@example.com', 'correct horse battery');
    expect((await ali.get('/api/admin/users')).status).toBe(403);
  });
  it('forged identity cookie is ignored', async () => {
    const r = await request(app).get('/api/me').set('Cookie', 'uid=1');
    expect(r.status).toBe(401);
  });
  it('X01: user cannot read another user\'s order (IDOR)', async () => {
    const ali = await agentFor('ali@example.com', 'correct horse battery');
    expect([403, 404]).toContain((await ali.get('/api/orders/1')).status);   // order 1 belongs to sara
  });
});

describe('S10 SQL injection', () => {
  it('search treats input as data', async () => {
    const r = await request(app).get('/api/products/search').query({ q: "' UNION SELECT email, password, 1 FROM users --" });
    expect(r.status).toBe(200);
    expect(JSON.stringify(r.body)).not.toMatch(/@|password/i);
  });
  it('login bypass payload fails', async () => {
    const r = await request(app).post('/api/login').send({ email: "' OR '1'='1' --", password: 'x' });
    expect(r.status).toBe(401);
  });
});

describe('S07 XSS', () => {
  it('reflected input is escaped', async () => {
    const r = await request(app).get('/search').query({ q: '<script>alert(1)</script>' });
    expect(r.text).not.toContain('<script>alert(1)</script>');
  });
});

describe('S12 rate limiting', () => {
  it('blocks brute force', async () => {
    let last;
    for (let i = 0; i < 12; i++) last = await request(app).post('/api/login').send({ email: 'sara@example.com', password: 'wrong' + i });
    expect(last.status).toBe(429);
  });
});

describe('S13/S14/S15 headers, CORS, cookies', () => {
  it('sets security headers and hides x-powered-by', async () => {
    const r = await request(app).get('/');
    expect(r.headers['content-security-policy']).toBeDefined();
    expect(r.headers['x-content-type-options']).toBe('nosniff');
    expect(r.headers['x-powered-by']).toBeUndefined();
  });
  it('does not reflect foreign origins', async () => {
    const r = await request(app).get('/api/products').set('Origin', 'https://evil.example');
    expect(r.headers['access-control-allow-origin']).not.toBe('https://evil.example');
  });
  it('session cookie is HttpOnly + SameSite', async () => {
    const r = await request(app).post('/api/login').send({ email: 'sara@example.com', password: 'correct horse battery' });
    const c = r.headers['set-cookie'].join(';');
    expect(c).toMatch(/HttpOnly/i); expect(c).toMatch(/SameSite=(Lax|Strict)/i);
  });
});

describe('S16 CSRF', () => {
  it('rejects cross-site state change', async () => {
    const sara = await agentFor('sara@example.com', 'correct horse battery');
    const r = await sara.post('/api/account/email').set('Origin', 'https://evil.example').type('form').send({ email: 'x@evil.example' });
    expect([403, 415]).toContain(r.status);
  });
});

describe('S06/S19 validation & prices', () => {
  it('rejects negative quantity', async () => {
    const ali = await agentFor('ali@example.com', 'correct horse battery');
    expect((await ali.post('/api/checkout').send({ productId: 1, quantity: -3 })).status).toBe(400);
  });
  it('ignores client price', async () => {
    const ali = await agentFor('ali@example.com', 'correct horse battery');
    const r = await ali.post('/api/checkout').send({ productId: 1, quantity: 1, price: 1 });
    expect(r.body.total).toBe(1200000);          // DB price
  });
});

describe('S17 password reset', () => {
  it('token is single-use', async () => { /* request token via test mailer/outbox, use twice → 2nd = 400 */ });
  it('expired token fails', async () => { /* insert token with expires_at in the past → 400 */ });
});

describe('S18 uploads', () => {
  it('rejects php and oversized files', async () => {
    const ali = await agentFor('ali@example.com', 'correct horse battery');
    expect((await ali.post('/api/avatar').attach('avatar', Buffer.from('<?php system($_GET[0]);'), 'shell.php')).status).toBe(400);
    expect([400, 413]).toContain((await ali.post('/api/avatar').attach('avatar', Buffer.alloc(6 * 1024 * 1024), 'big.png')).status);
  });
});

describe('S20 debug', () => {
  it('errors do not leak stack traces', async () => {
    const r = await request(app).post('/api/login').set('Content-Type', 'application/json').send('{"broken":');
    expect(JSON.stringify(r.body)).not.toMatch(/at \w+ \(|node_modules|\.js:\d+/);
  });
});
```
Playwright for DOM XSS (stored payload rendered via the real front-end):
```js
test('stored XSS payload renders as text', async ({ page }) => {
  await createCommentViaApi('<img src=x onerror="window.__xss=1">');
  await page.goto('/');
  await page.waitForLoadState('networkidle');
  expect(await page.evaluate(() => window.__xss)).toBeUndefined();
});
```

## Python (pytest)
```python
def test_admin_forbidden_for_user(client, user_token):
    r = client.get("/api/admin/users", headers={"Authorization": f"Bearer {user_token}"})
    assert r.status_code == 403

def test_idor(client, alice, bob_order_id):
    assert client.get(f"/api/orders/{bob_order_id}", headers=alice).status_code in (403, 404)

def test_sqli(client):
    r = client.get("/api/products/search", params={"q": "' OR 1=1 --"})
    assert r.status_code == 200 and len(r.json()) == 0

def test_rate_limit(client):
    codes = [client.post("/login", json={"email": "a@b.c", "password": f"x{i}"}).status_code for i in range(12)]
    assert 429 in codes
```
Django: `self.client.force_login(user)`; `django.test.override_settings(DEBUG=False)` for error-page tests.

## PHP (Pest / PHPUnit, Laravel)
```php
it('forbids admin for normal users', function () {
    $user = User::factory()->create(['role' => 'user']);
    $this->actingAs($user)->get('/admin/users')->assertForbidden();
});
it('throttles login', function () {
    foreach (range(1, 10) as $i) { $r = $this->post('/login', ['email' => 'a@b.c', 'password' => "x$i"]); }
    $r->assertStatus(429);
});
```

## Black-box checks (no test framework needed)
```bash
B=http://localhost:3000
curl -s -o /dev/null -w '%{http_code}\n' $B/api/admin/users                       # 401
curl -s -o /dev/null -w '%{http_code}\n' -b 'uid=1' $B/api/admin/users            # 401/403 (forged cookie)
curl -s "$B/search?q=%3Cscript%3Ealert(1)%3C/script%3E" | grep -c '<script>alert' # 0
curl -sI -H 'Origin: https://evil.example' $B/api/products | grep -i access-control-allow-origin   # nothing / not evil
curl -s -o /dev/null -w '%{http_code}\n' $B/.env $B/backup.zip                    # 404 404
python3 <skill>/scripts/check_live.py $B --api /api/products --admin-path /admin --login-path /api/login
python3 <skill>/scripts/race_test.py $B/api/coupons/redeem -X POST --json '{"code":"WELCOME50"}' -H 'Cookie: …' -n 20 --max-success 1
```

## Reporting test results
In the report, list each test with ✅/❌ and the command to re-run the suite (`npm test -- security`, `pytest -k security`). A fix without a passing test is reported as ⚠️ partial.
