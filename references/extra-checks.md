# Extra checks beyond the 27 steps (X01–X15)

The video's 27 steps cover the classics. These are the issues that most often survive them in real vibe-coded apps. Run them in S26 (full review), prioritising what the stack actually uses (`detect_stack.py` → `features`).

## Contents
X01 Access control (IDOR, mass assignment, multi-tenant) · X02 SSRF · X03 Open redirect · X04 Path traversal / command / code injection · X05 Auth extras (JWT, sessions, enumeration, OAuth, Telegram) · X06 Business logic & race conditions · X07 Webhooks · X08 AI / LLM features · X09 Privacy & sensitive data (GDPR) · X10 Server / VPS / Docker · X11 Client bundle & source maps · X12 Malware / backdoors (hacked sites) · X13 Monitoring, backups, incident readiness · X14 Supply chain & CI · X15 Load, stress & concurrency

---

## X01 — Access control (the #1 real-world bug)
- **IDOR / BOLA:** `GET /api/orders/123` returns *anyone's* order. Every query by id must be scoped to the caller: `WHERE id = $1 AND user_id = $2` (or tenant/org id). Return 404 (not 403) for other people's objects to avoid enumeration. Prefer UUIDs over sequential ids (defence in depth, not a fix).
- **Mass assignment:** `update(req.body)` lets users set `role`, `isAdmin`, `balance`, `ownerId`, `price`, `emailVerified`. Pick allowed fields explicitly (zod `.pick()`/`.strict()`, Laravel `$fillable`, DRF serializer fields).
- **Multi-tenant SaaS:** every table that holds customer data has a tenant/org column and every query filters by the tenant from the session — never from the request body. In Supabase, RLS policies check membership (`exists (select 1 from members where org_id = … and user_id = auth.uid())`).
- **Function-level:** every server action / route handler re-checks permissions (UI hiding is not access control).
- **Files:** downloads/signed URLs scoped to the owner; signed URLs short-lived (≤ 5–15 min).
- **Verify:** with two normal users A and B: B requests every A-owned resource id (GET/PUT/DELETE) → 404/403. Automate from `list_routes.py`.

## X02 — SSRF
Server fetches a user-supplied URL (link preview, image import, webhook tester, PDF from URL) → attacker reaches `http://169.254.169.254/` (cloud metadata), `localhost:6379`, internal admin panels. **Fix:** allow-list hosts/schemes; resolve DNS and reject private/loopback/link-local ranges (re-check after redirects, or disable redirects); timeouts + size limits; run fetchers without access to internal networks. **Verify:** request `http://127.0.0.1:22`, `http://169.254.169.254/latest/meta-data/` → rejected.

## X03 — Open redirect
`/login?next=https://evil.example` → phishing that starts on your domain; also OAuth token leakage. **Fix:** accept only relative paths that start with `/` and not `//` or `/\`; or an allow-list of hosts. **Verify:** `next=https://evil.example`, `next=//evil.example`, `next=/\evil.example` → stay on site.

## X04 — Path traversal, command & code injection, deserialization
- `sendFile(path.join(dir, req.params.file))` with `..%2F.env` → reads any file. Resolve and check `resolved.startsWith(baseDir + path.sep)`, or map ids → filenames.
- `exec(\`convert ${name}\`)` → shell injection. Use `execFile`/`spawn` with argument arrays + allow-lists; Python `subprocess.run([...], shell=False)`.
- `eval`, `new Function`, `vm` with user data, Python `pickle.loads`, `yaml.load` (unsafe loader), PHP `unserialize` on input, template engines rendering user-provided templates (SSTI) → remote code execution.
- Prototype pollution (JS): deep merges of request bodies (`_.merge(obj, req.body)`) → validate first; block `__proto__`/`constructor`/`prototype` keys.

## X05 — Auth extras
- **JWT:** `jwt.verify` with pinned `algorithms`, short expiry (≤15 min access tokens), rotate refresh tokens and detect reuse, never `jwt.decode` for auth, strong secret (≥256-bit) or asymmetric keys; avoid storing JWTs in localStorage.
- **Sessions:** regenerate on login (fixation), invalidate on logout/password change, list & revoke active sessions for users.
- **Enumeration:** login/register/forgot return the same message and similar timing for existing and non-existing accounts.
- **OAuth/OIDC:** validate `state` (and PKCE), exact redirect-URI allow-list, verify `email_verified` before linking accounts by email.
- **Email verification** before granting access to sensitive features; **2FA** (TOTP/passkeys) for admins and staff.
- **Password policy (NIST 800-63B):** min 8 (better 12+), allow long passphrases, check against breached-password lists (HIBP k-anonymity API), no forced periodic rotation.
- **Telegram Mini Apps / bots:** validate `initData` server-side with HMAC-SHA256 (key = HMAC("WebAppData", bot_token)) and check `auth_date` freshness; never trust `initDataUnsafe`. Bot webhooks: set `secret_token` and compare the `X-Telegram-Bot-Api-Secret-Token` header.
- **Socket.IO / WebSockets:** authenticate the handshake (`io.use`), authorize every room join and event, validate payloads, limit message size/rate; set CORS origins.
- **postMessage:** check `event.origin` against an allow-list.

## X06 — Business logic & race conditions
- Anything that must happen **at most once** (coupon, gift card, referral bonus, wallet spend, withdrawal, stock decrement, vote, invite, reset token) is a race-condition target: check-then-act across an `await` lets 20 parallel requests all pass the check.
- **Fix:** single atomic statement (`UPDATE coupons SET used = used + 1 WHERE code = $1 AND used < max_uses RETURNING *`), unique constraints (`UNIQUE(user_id, coupon_id)`), `SELECT … FOR UPDATE` inside a transaction, Redis `SET NX`/Lua, idempotency keys for payments/orders. In single-process Node, doing the check and the write before any `await` closes the window, but breaks again with PM2 cluster/multiple instances — prefer DB-level atomicity.
- **Verify:** `race_test.py <url> -n 20 --max-success 1` (and repeat 3–5×; races are probabilistic).
- Other logic flaws: negative/zero/huge quantities, currency mix-ups, applying a coupon after payment, skipping steps in multi-step flows (go straight to `/checkout/confirm`), refund > paid, changing email to an existing one, invitation acceptance by the wrong user.

## X07 — Webhooks
Verify the signature **on the raw body** before parsing (Stripe `constructEvent`, GitHub `X-Hub-Signature-256`, Svix/Resend, PayPal verify API, Telegram secret token), use constant-time compare, reject old timestamps (replay), make handlers idempotent (store processed event ids), and re-fetch critical state from the provider API instead of trusting the payload blindly.

## X08 — AI / LLM features
- Keys server-side only (S02); never `dangerouslyAllowBrowser`.
- **Cost abuse:** auth + per-user rate limits + monthly quotas + `max_tokens` caps + provider budget alerts; cache where possible.
- **Prompt injection:** treat model output as untrusted input — don't let it call tools/DB/email with more privilege than the current user; confirm destructive actions with the user; keep secrets and other users' data out of the context; separate system instructions from retrieved content.
- **Output handling:** render as text or sanitized markdown (XSS via model output is real); validate structured output (JSON schema) before use.
- **Data:** don't send PII/health/legal documents to providers without a legal basis and a DPA; log prompts carefully (they contain user data).

## X09 — Privacy & sensitive data (EU/GDPR-relevant)
Collect the minimum; encrypt sensitive documents at rest (passports, visas, medical, financial uploads) and serve them only via short-lived signed URLs to their owner/staff; data retention + deletion (account delete, export on request); cookie consent for non-essential cookies/analytics; DPA with processors (hosting, email, AI, analytics); breach plan (GDPR: notify the supervisory authority within 72 h when required); no PII in logs, URLs or analytics events; backups encrypted.

## X10 — Server / VPS / Docker hardening (see `stacks/vps-docker-nginx.md`)
SSH keys only, no root login, non-default user with sudo; firewall (`ufw default deny incoming; allow 22/80/443`); **Docker-published ports bypass ufw** → bind DBs to `127.0.0.1`; fail2ban; unattended security upgrades; DB/Redis not public, Redis with password; PM2 runs as a non-root user with `NODE_ENV=production`; containers as non-root, no secrets in images; TLS auto-renew; server-level backups + off-site copies.

## X11 — Client bundle & source maps
Grep the production bundle for secrets and internal URLs; disable public source maps (or upload privately to Sentry); remove `console.log` of sensitive data; don't ship admin-only code paths with hard-coded secrets in the client; feature flags evaluated server-side.

## X12 — Malware / backdoors (hacked PHP/CMS sites)
If a site was ever compromised (or runs old WordPress/Joomla): scan for web shells and injected code — `scan_code_patterns.py` flags `eval(base64_decode(`, `assert($_POST`, `preg_replace(/e)`, `$_POST['x'](...)`, known shell names (FilesMan, b374k, WSO, c99). Also check: files modified recently (`find . -name "*.php" -mtime -30`), PHP files inside `uploads/`/`images/`, unknown admin users, `.htaccess` redirects, cron jobs, database-injected scripts (`<script` in posts/options), SEO spam pages. **Response:** take a full copy for forensics, restore from a known-good backup or clean core + reinstalled extensions, rotate **all** credentials (hosting, FTP/SFTP, DB, admin users, API keys, salts), patch the entry point, then monitor. See `stacks/php-cms.md`.

## X13 — Monitoring, backups, incident readiness
Uptime monitor + TLS-expiry alerts; error tracking (Sentry) with PII scrubbing; security alerts (S08); automated off-site backups with a **tested restore** (write down RPO/RTO); an incident runbook (who to call, how to rotate keys, how to put the site in maintenance mode); `/.well-known/security.txt` with a contact; status page for bigger products.

## X14 — Supply chain & CI
Lockfiles committed; `npm ci`; review new dependencies (typosquats, abandoned packages, install scripts); Dependabot/Renovate; CI security job (`assets/ci/security.yml`: gitleaks + audit + dependency review); GitHub push protection & secret scanning on; no secrets in CI logs; pin third-party GitHub Actions to SHAs for sensitive repos; avoid `pull_request_target` with checkout of PR code; protect the main branch; 2FA on GitHub/npm/hosting/registrar/DNS accounts.

## X15 — Load, stress & concurrency (see `references/load-testing.md`)
Will it survive launch day / an Instagram live / a viral post? Smoke → load → spike → (stress, soak) with `load_test.py` or k6; rate limits must hold under load; races tested with `race_test.py`; graceful degradation (429/503 instead of crashes); body size limits and timeouts so slow clients can't exhaust the server.
