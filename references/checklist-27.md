# The 27-step pre-launch checklist

Each step: **Attack** (why it matters) · **Find** (where to look) · **Fix** (what good looks like) · **Verify** (proof) · **Done when**.
Stack-specific code lives in `references/stacks/*.md`; test templates in `references/security-tests.md`.

Record every step in the report as: ✅ fixed · ✅ already OK · ⚠️ partial · ❌ open · ➖ N/A (+ one-line reason). "No scanner hits" is never enough for ✅ — a ✅ needs evidence (code read, request/response, or test).

## Contents
1. [S01 Authentication](#s01) · 2. [S02 API keys](#s02) · 3. [S03 Database](#s03) · 4. [S04 HTTPS](#s04) · 5. [S05 Password hashing](#s05) · 6. [S06 Server validation](#s06) · 7. [S07 XSS](#s07) · 8. [S08 Logging](#s08) · 9. [S09 Admin routes](#s09) · 10. [S10 SQL injection](#s10) · 11. [S11 Env vars](#s11) · 12. [S12 Rate limiting](#s12) · 13. [S13 CORS](#s13) · 14. [S14 Headers](#s14) · 15. [S15 Cookies](#s15) · 16. [S16 CSRF](#s16) · 17. [S17 Password reset](#s17) · 18. [S18 Uploads](#s18) · 19. [S19 Prices & payments](#s19) · 20. [S20 Debug](#s20) · 21. [S21 Vulnerable packages](#s21) · 22. [S22 Unused packages](#s22) · 23. [S23 Exposed files](#s23) · 24. [S24 Git history](#s24) · 25. [S25 Rotate keys](#s25) · 26. [S26 Full review](#s26) · 27. [S27 Test & report](#s27)

---

<a id="s01"></a>
## S01 — Authentication done right · احراز هویت درست
**Attack:** forged identity (`uid=1` cookie, `x-user-id` header, `?userId=` param), guessable/never-expiring sessions, session fixation, login bypass via SQLi, sessions that survive logout or password change.
**Find:** how each request learns *who* the user is. Anything the client can edit (plain cookie value, header, query, localStorage flag, `initDataUnsafe`) is not identity. Check: library vs home-made auth, session lifetime, logout, re-auth for email/password change, 2FA for admins, OAuth `state`/redirect URI, email verification.
**Fix:**
- Prefer a maintained auth layer (Auth.js/next-auth, Supabase Auth, Clerk, better-auth/Lucia, Passport+express-session, Django auth, Laravel Breeze/Fortify/Sanctum). Don't invent crypto.
- Server-side session id (≥128-bit random) or a signed+encrypted cookie (iron-session) or short-lived JWT (≤15 min) + rotating refresh token.
- Regenerate the session id on login; idle timeout (e.g. 30 min–24 h) + absolute timeout; destroy server session on logout; invalidate all sessions after password change/reset.
- Same error for unknown email and wrong password; 2FA (TOTP) at least for admin accounts.
**Verify:** edit/forge the cookie → 401; replay a cookie after logout → 401; `' OR '1'='1` as email → 401; session id changes after login.
**Done when:** identity always comes from a server-verified session/token, and tests cover forged + logged-out sessions.

<a id="s02"></a>
## S02 — Hide API keys · کلیدهای API رو مخفی کن
**Attack:** everything shipped to a browser or mobile app is public. Bots scrape JS bundles and GitHub for `sk_live_`, `sk-proj-`, `AKIA`… within minutes → bills, data theft, spam from your account.
**Find:** `scan_secrets.py` (client files, `public/`, built bundles in `.next/static`, `dist/`, `build/`), browser network tab (requests going straight from the browser to third-party APIs with a key), `NEXT_PUBLIC_*`/`VITE_*`/`REACT_APP_*`/`EXPO_PUBLIC_*` names, mobile bundles.
**Fix:** move the third-party call to the server (API route / server action / edge function) that reads the key from env; the client calls *your* endpoint (authenticated + rate-limited). Keys that are public by design (Stripe publishable, Supabase anon/publishable, Firebase web config, Maps browser key) must be **restricted** (HTTP-referrer/app restrictions, RLS, quotas). Every key that was ever exposed gets rotated (S25).
**Verify:** rebuild, then `grep -rEn "sk_live|sk-proj|sk-ant|AKIA|service_role|whsec_" .next/static dist build out 2>/dev/null || echo clean`; re-run `scan_secrets.py`.
**Done when:** no secret in source, bundle, repo or mobile app; exposed keys rotated.

<a id="s03"></a>
## S03 — Secure the database · دیتابیس رو امن کن
**Attack:** the browser talks to the DB directly (Supabase/Firebase without RLS/rules = public database; "run this SQL" endpoints), DB port open to the internet, app connects as superuser, no backups.
**Find:** Supabase tables without RLS, `using (true)` policies, `service_role` outside server code (`stacks/supabase-firebase.md`); Firebase rules; endpoints that execute client SQL or accept arbitrary filters; DB user privileges; `docker-compose` publishing 5432/3306/27017/6379; DB firewall; backup job.
**Fix:**
- Browser → **your server** → DB (or BaaS with RLS on *every* table in exposed schemas + policies using `auth.uid()`).
- Least-privilege DB role for the app (no superuser/DDL); separate migration role.
- DB bound to localhost/private network; TLS for remote connections; strong unique password.
- Automated, encrypted, off-server backups + a restore you have actually tested.
**Verify:** with only the anon key: `curl "$SUPABASE_URL/rest/v1/<table>?select=*" -H "apikey: $ANON" -H "Authorization: Bearer $ANON"` → `[]`/401 for private tables; from outside: `nc -zv <server-ip> 5432` → refused; Postgres: `select relname, relrowsecurity from pg_class where relnamespace='public'::regnamespace and relkind='r';`.
**Done when:** no table is readable/writable beyond its policy; DB unreachable from the internet; restore tested.

<a id="s04"></a>
## S04 — Enforce HTTPS · HTTPS رو اجباری کن
**Attack:** passwords/cookies sniffed on public Wi-Fi, SSL-stripping, mixed content.
**Find:** proxy/CDN/hosting config, `http://` URLs in code, cookies without `Secure`, missing HSTS, cert renewal.
**Fix:** valid TLS (Let's Encrypt/certbot or host-managed, auto-renew) · 301 HTTP→HTTPS at proxy/CDN · `Strict-Transport-Security: max-age=31536000; includeSubDomains` (preload only when every subdomain is HTTPS) · `Secure` cookies · CSP `upgrade-insecure-requests` · behind Nginx/Cloudflare set `app.set('trust proxy', 1)` (Express) so `req.secure`/IPs are right · all outbound calls over https.
**Verify:** `check_live.py https://domain` (redirect, HSTS, cert days left); `curl -sI http://domain | head -3` → 301 to https.
**Done when:** no page/API reachable over plain HTTP; HSTS present; renewal automated.

<a id="s05"></a>
## S05 — Hash passwords · پسوردها رو هش کن
**Attack:** one DB leak exposes every password (reused on email/banking). MD5/SHA-x are cracked at billions of guesses per second.
**Find:** look at a stored value: plaintext? 32 hex chars (MD5)? `$2b$`/`$2y$` (bcrypt) or `$argon2id$`? Check register, login compare, reset, change-password, admin seeding, imports.
**Fix:** argon2id (OWASP baseline: m=19 MiB, t=2, p=1) or bcrypt cost ≥ 12; compare only with the library (`argon2.verify`, `bcrypt.compare`, `password_verify`, Django `check_password`). Migrate existing users: plaintext → hash now; legacy MD5 → wrap (`argon2(md5)`) and re-hash on next login. Cap input length (bcrypt uses 72 bytes). Never log passwords.
**Verify:** new user row starts with `$argon2id$`/`$2b$12$`; `SELECT count(*) FROM users WHERE password NOT LIKE '$argon2%' AND password NOT LIKE '$2%'` → 0; old accounts can still log in.
**Done when:** no plaintext/fast-hash password remains anywhere (incl. backups, seeds, logs).

<a id="s06"></a>
## S06 — Server-side validation · فرم‌ها رو سمت سرور چک کن
**Attack:** HTML `min/max/required` and JS checks are skipped with curl/devtools → `quantity: -3`, 10 MB strings, wrong types, extra fields (`role: "admin"`).
**Find:** every handler/action: is the body/query/params parsed with a schema? ranges, lengths, enums, array sizes, unknown fields stripped?
**Fix:** schema at every entry point (zod/valibot, joi, pydantic, Laravel FormRequest, Django forms/serializers): types, required, min/max (quantity 1..10), max lengths, enum allow-lists, `.strict()`/strip unknown keys; body size limit (`express.json({ limit: '100kb' })`); normalise (trim, lowercase email); return 400 with a generic message.
**Verify:** quantity `-3`, `0`, `1e9`, `"abc"`, missing fields, 1 MB string → 400, nothing written.
**Done when:** no handler trusts the client's shape or values.

<a id="s07"></a>
## S07 — Prevent XSS · جلوی XSS رو بگیر
**Attack:** a review like `<img src=x onerror=…>` runs in every visitor's browser → session theft, actions as the victim, defacement.
**Find:** `innerHTML`, `dangerouslySetInnerHTML`, `v-html`, `{@html}`, `|safe`, `{!! !!}`, `<%- %>`, server-built HTML strings (`res.send(\`<h1>${q}\`)`), markdown renderers, user links (`javascript:`), SVG/HTML uploads served inline, JSON embedded in `<script>`.
**Fix:** framework auto-escaping; `textContent`/DOM APIs instead of HTML strings; DOMPurify (allow-list) for required rich text; only `http(s)` URLs for user links; uploads served as attachments (S18); CSP with nonces as defence-in-depth (S14); HttpOnly session cookies (S15).
**Verify:** store `<img src=x onerror="document.title='XSS'">` → shows as text; reflected `?q=<script>alert(1)</script>` → `&lt;script&gt;` in HTML; Playwright test asserts no dialog fired.
**Done when:** no sink receives unsanitized user data; payload tests pass.

<a id="s08"></a>
## S08 — Log & monitor suspicious activity · فعالیت مشکوک رو لاگ کن و زیر نظر بگیر
**Attack:** brute force, credential stuffing, admin abuse and data scraping go unnoticed; after an incident there is nothing to investigate.
**Find:** what gets logged for login fail/success, 401/403, 429, password reset, admin actions, payment events, 5xx; where logs go; retention; alerts; are secrets/PII in logs?
**Fix:** structured logs (pino/winston, Python logging, Monolog) with event, user id, IP, user-agent, request id; **never** passwords, tokens, full card numbers; alerts on bursts (e.g. ≥5 failed logins/min/account or ≥20/min/IP, 5xx spikes, new admin created); error monitoring (Sentry) with PII scrubbing; 30–90 days retention, access-restricted; on a VPS feed nginx/app logs to fail2ban.
**Verify:** 5 failed logins → log lines with IP/user + alert (or documented threshold); `grep -ri password logs/` → nothing sensitive.
**Done when:** you would notice an attack today, not next month.

<a id="s09"></a>
## S09 — Lock admin routes · مسیر ادمین رو قفل کن
**Attack:** a normal user (or anonymous) opens `/admin` or calls `/api/admin/*` directly; hiding the button protects nothing.
**Find:** `list_routes.py` → every admin page, API, server action, socket event; check a **server-side role check** on each (not only UI or Next.js middleware). Default/seeded admin passwords, admin tools left in prod (phpMyAdmin, Adminer, Supabase Studio, Swagger with auth off).
**Fix:** one `requireRole('admin')` guard on the admin router + inside each server action/route handler; deny by default; 2FA for admins; audit-log admin actions; remove dev/admin tools from production or IP-allow-list them.
**Verify:** as a normal user → 403 on every admin endpoint; anonymous → 401/redirect; forged role cookie → 403. Automate it from the route list.
**Done when:** the authorization matrix (anon / user / other user / admin) is filled and tested.

<a id="s10"></a>
## S10 — Parameterized queries · کوئری‌های پارامتردار
**Attack:** `' OR 1=1 --` → login bypass; `' UNION SELECT email,password FROM users --` → data dump; stacked queries → data loss.
**Find:** SQL built with `+`, template strings, f-strings, `.format`, PHP interpolation; `ORDER BY`/column names from input; ORM raw APIs (`$queryRawUnsafe`, `knex.raw`, `sequelize.query`, `whereRaw`); Mongo operator injection (`{"$ne": null}`); identifiers from cookies/headers too.
**Fix:** placeholders (`$1`, `?`, `:name`) or the ORM; allow-list maps for identifiers (`{price: 'price', name: 'name'}[sort]`); ORM raw only with bindings (Prisma tagged `$queryRaw\`…${v}\``); Mongo: validate types (string not object), `express-mongo-sanitize`.
**Verify:** payloads above + `1; DROP TABLE x` → no extra rows, no 500, no SQL error text.
**Done when:** zero string-built queries with untrusted data remain.

<a id="s11"></a>
## S11 — Check environment variables · متغیرهای محیطی رو چک کن
**Attack:** secrets in code, `.env` committed or served, secrets bundled through public prefixes, endpoints that echo env (`/api/config`), weak defaults (`SESSION_SECRET=secret`) → forged sessions; same secrets in dev and prod.
**Find:** `scan_secrets.py`, `.gitignore`, `.env.example` holding real values, `process.env.X || 'fallback'`, config endpoints, CI logs printing env, Docker `ENV` lines.
**Fix:** secrets only in env/secret manager; `.env*` ignored (`!.env.example` with placeholders); validate env at boot and **fail fast** (zod/envalid/pydantic-settings); strong random values (`openssl rand -base64 48`); separate dev/staging/prod values; least-privilege keys (Stripe restricted keys); Next.js `import 'server-only'` in modules that read secrets; never return secrets from APIs; production env set in the host (Vercel, PM2 `env_production`, Docker `env_file`), not baked into images.
**Verify:** `scan_secrets.py` clean; app refuses to start without required vars; bundle grep clean (S02).
**Done when:** each secret lives in exactly one protected place per environment.

<a id="s12"></a>
## S12 — Rate-limit login · ریت‌لیمیت برای لاگین
**Attack:** password guessing, credential stuffing, OTP brute force (6 digits = 10⁶), SMS/email bombing, scraping, expensive endpoints (AI, PDF, search) → bills or downtime.
**Find:** login, register, forgot/reset, OTP verify, contact forms, search, AI endpoints, uploads; how client IP is derived behind a proxy; multi-instance (PM2 cluster) needs a shared store.
**Fix:** per-IP **and** per-account limits (login: ~5/min/account + ~20/min/IP, then backoff/temporary lock + email notice); 429 with `Retry-After`; Redis/Upstash store when >1 instance; edge limits too (Nginx `limit_req`, Cloudflare); CAPTCHA (Turnstile) after N failures; OTP: max attempts per code then invalidate; per-user quotas on AI endpoints.
**Verify:** `check_live.py --login-path /api/login` → 429 within ~10 tries; `race_test.py` with 30 parallel wrong logins → limiter still counts them (atomic increments).
**Done when:** brute force is slowed to useless for every credential-checking endpoint.

<a id="s13"></a>
## S13 — Restrict CORS · CORS رو محدود کن
**Attack:** `origin: true` / reflected origin + `credentials: true` → any website can read your API responses as the logged-in visitor.
**Find:** `cors()` config, manual `Access-Control-Allow-Origin`, Socket.IO `cors`, FastAPI/Django CORS settings, `null` origin allowed.
**Fix:** exact allow-list from env (`https://app.example.com`), credentials only with exact origins, never `null`; same-origin frontends need no CORS at all; `Vary: Origin`.
**Verify:** `check_live.py` (evil Origin must not be echoed); `curl -sI -H "Origin: https://evil.example" https://api/x | grep -i access-control`.
**Done when:** only your own origins get CORS headers.

<a id="s14"></a>
## S14 — Add security headers · هدرهای امنیتی اضافه کن
**Set:** `Content-Security-Policy` (nonce/hash based; `object-src 'none'; base-uri 'self'; frame-ancestors 'none'`), `Strict-Transport-Security`, `X-Frame-Options: DENY` (or frame-ancestors), `X-Content-Type-Options: nosniff`, `Referrer-Policy: strict-origin-when-cross-origin`, `Permissions-Policy: camera=(), microphone=(), geolocation=()`; remove `X-Powered-By` and versioned `Server`.
**Where:** helmet (Express), `next.config.js headers()` + middleware nonce (Next.js), Nginx `add_header … always` (`assets/nginx/security-headers.conf`), Django `SecurityMiddleware` + django-csp, Laravel middleware, Flask-Talisman. Roll out CSP as `Report-Only` first if the app loads many third-party scripts.
**Verify:** `check_live.py`; securityheaders.com / Mozilla Observatory for the public domain.
**Done when:** all headers present on HTML and API responses, CSP without `unsafe-inline` scripts (or a documented plan).

<a id="s15"></a>
## S15 — Secure session cookies · کوکی‌های سشن رو امن کن
**Fix:** `HttpOnly; Secure; SameSite=Lax` (Strict for admin-only apps), `Path=/`, sensible `Max-Age`, `__Host-` prefix for the session cookie when possible; signed/encrypted if it carries data; tokens **not** in localStorage (web) — use HttpOnly cookies; mobile → Keychain/Keystore (expo-secure-store).
**Verify:** `check_live.py` / devtools Application tab; a test asserting the `Set-Cookie` flags on login.
**Done when:** JavaScript cannot read the session and it never travels over HTTP.

<a id="s16"></a>
## S16 — CSRF protection · محافظت CSRF
**Attack:** evil.site silently submits a form to `/api/account/email` using the victim's cookies → account takeover.
**Applies when:** auth is cookie-based (sessions, next-auth, Supabase SSR cookies, PHP sessions). Pure `Authorization: Bearer` APIs are not CSRF-able (XSS matters more there).
**Fix:** SameSite=Lax/Strict cookies **plus** one of: CSRF token (synchronizer or signed double-submit: `csrf-csrf`, `csrf-sync`, framework middleware) · strict `Origin`/`Referer` check against an allow-list on every state-changing request · JSON-only APIs (reject `application/x-www-form-urlencoded`/`multipart` cross-site). Never change state on GET. Built-ins: Django `CsrfViewMiddleware`, Laravel `VerifyCsrfToken` (keep `$except` empty), Next.js Server Actions (Origin/Host check), WordPress nonces.
**Verify:** logged-in cookie + `Origin: https://evil.example` + no token → 403; form-encoded cross-site POST → rejected.
**Done when:** no state change is possible from another origin.

<a id="s17"></a>
## S17 — Time-limited password reset links · لینک ریست پسورد زمان‌دار
**Attack:** guessable tokens (`Math.random`), tokens valid forever or reusable, host-header injection in the emailed link, user enumeration, old sessions surviving the reset.
**Fix:** 32-byte CSPRNG token (`crypto.randomBytes(32).toString('base64url')`); store only `sha256(token)`; `expires_at` 15–60 min; single use (delete on use) and invalidate older tokens; invalidate all sessions + notify by email after reset; identical response whether the account exists or not; build the link from configured `APP_URL`, never from the `Host` header; rate-limit `forgot`; `Referrer-Policy: no-referrer` on the reset page. Managed auth (Supabase/Clerk/Firebase): set OTP/link expiry in its settings and verify redirect URLs allow-list.
**Verify:** use a token twice → second fails; expired token (set `expires_at` in the past in a test) → fails; token length ≥ 43 chars; response for unknown email = known email.
**Done when:** a reset link is unguessable, short-lived and one-shot.

<a id="s18"></a>
## S18 — Restrict uploads (type & size) · آپلود: نوع و حجم محدود
**Attack:** `shell.php`/`.html`/`.svg` upload → remote code execution or stored XSS; 900 MB file → disk/RAM exhaustion; `../../` in filenames; zip bombs; image-parser exploits.
**Fix:** size limits at proxy (`client_max_body_size`) **and** app (`multer({ limits: { fileSize: 5*1024*1024, files: 1 } })`); allow-list extensions **and** verify magic bytes (`file-type`); re-encode images (sharp) to strip payloads/metadata; random server-side names (UUID), never the original name in paths; store outside the web root or in a private bucket; serve through a controller/signed URL with `Content-Disposition: attachment`, correct `Content-Type`, `nosniff`; no script execution in upload dirs; per-user quotas; auth required; AV scan (ClamAV) for shared documents.
**Verify:** upload `shell.php` → 400; 20 MB → 413; PNG-named HTML → rejected; `../../x.png` → stored under a UUID.
**Done when:** only expected files of bounded size are stored, and none can execute or render as HTML from your origin.

<a id="s19"></a>
## S19 — Verify prices & payments · قیمت و پرداخت رو چک کن
**Attack:** client sends `price: 1`; negative quantity; stacking coupons; replaying the "payment success" redirect; fake webhooks; parallel requests double-spending a coupon/credit/stock.
**Fix:** the client sends only ids + quantities; the server loads prices from the DB, validates quantity ranges, applies coupons, computes totals and creates the payment (intent/session) with that amount; fulfil **only** after server-side verification with the provider (signed webhook — Stripe `constructEvent`; or the gateway's verify API with amount check, e.g. Zarinpal/IDPay verify); idempotency keys; order state machine (pending → paid → fulfilled, no double fulfilment); atomic stock/coupon updates (`UPDATE … WHERE used < max_uses` / transaction + row lock); currency fixed server-side.
**Verify:** tampered price → server total unchanged; quantity −3 → 400; unsigned webhook → 400; `race_test.py` on coupon/checkout → at most the allowed successes.
**Done when:** money and stock depend only on server-side truth.

<a id="s20"></a>
## S20 — Turn off debug · دیباگ رو خاموش کن
**Attack:** stack traces leak paths, versions, SQL and even secrets (`DB_PASS=… at db.js:42`); Werkzeug/Django debug pages; Laravel Ignition; public source maps; `phpinfo.php`.
**Fix:** `NODE_ENV=production`, `DEBUG=False`, `APP_DEBUG=false`, `display_errors=Off`, `WP_DEBUG_DISPLAY=false`; global error handler → `500 · Something went wrong` + request id, details only in server logs; remove debug/test routes and files; no public source maps; strip `X-Powered-By`.
**Verify:** `check_live.py` debug probes (404 page, malformed JSON, `'"<x>` in params) show no stack/paths.
**Done when:** errors are boring for visitors and detailed only in your logs.

<a id="s21"></a>
## S21 — Update vulnerable packages · پکیج‌های آسیب‌پذیر رو آپدیت کن
**Fix:** `audit_deps.py` (npm/pnpm/yarn audit, pip-audit, composer audit); upgrade direct deps; `overrides`/`resolutions` for transitive ones; avoid blind `npm audit fix --force` — do semver-major bumps one at a time with tests; commit the lockfile and deploy with `npm ci`; watch framework/CMS advisories (Next.js, Laravel, WordPress/Joomla core **and** extensions); enable Dependabot/Renovate (`assets/ci/`).
**Verify:** re-run the audit → 0 critical/high in production deps, or each exception documented with its mitigation.
**Done when:** nothing known-exploitable ships.

<a id="s22"></a>
## S22 — Remove unused packages · پکیج‌های بی‌استفاده رو پاک کن
**Fix:** confirm with `audit_deps.py` / `npx knip` / `npx depcheck`, then uninstall; move build-only tools to devDependencies; delete unused CMS plugins/themes, sample pages, test endpoints, old API versions.
**Verify:** build + tests pass; fewer packages in the audit; smaller bundle.
**Done when:** every dependency and route has a reason to exist.

<a id="s23"></a>
## S23 — Find exposed files · دنبال فایل‌های لورفته بگرد
**Attack:** `/.env`, `/backup.zip`, `/db.sql`, `/.git/config` downloadable → full compromise.
**Fix:** delete backups/dumps/env files from served folders (keep backups off the web root, encrypted, off-server); deploy build output only; `.dockerignore`; never deploy `.git` (or block it); Nginx deny for dotfiles and backup extensions (`assets/nginx/security-headers.conf`); no directory listing; remove `phpinfo.php`/test scripts; private object-storage buckets.
**Verify:** `scan_exposed_files.py <dir>` and `--url https://domain` (soft-404 aware); `curl -sI https://domain/.env` → 403/404.
**Done when:** nothing but intended assets is reachable.

<a id="s24"></a>
## S24 — Scan git history · تاریخچه‌ی گیت رو اسکن کن
**Why:** deleting a file in a new commit does not remove it from history, clones, forks or caches.
**Do:** `scan_git_history.py <dir>` (all branches; also lists sensitive files ever committed) — optionally confirm with `gitleaks detect` or `trufflehog git file://.`; shallow clones need `git fetch --unshallow` first. Build the list of secrets to rotate (S25). History rewriting (`git filter-repo`) is optional, comes **after** rotation, needs the owner's explicit OK, and requires force-push + collaborators re-cloning — see `references/leaked-secrets.md`.
**Done when:** every secret ever committed is identified and handed to S25.

<a id="s25"></a>
## S25 — Revoke & rotate leaked keys · کلیدهای لورفته رو باطل و عوض کن
**Do (per secret):** create the new key → put it in the server env (host dashboard / VPS `.env` / CI secrets) → redeploy and verify → revoke the old key → prove the old key fails (`curl` with it → 401) → review provider logs/billing for abuse during the exposure window. Claude prepares the exact checklist; **the owner performs dashboard actions** — never report a key as rotated unless the user confirms it. Rotating session/JWT secrets logs everyone out; DB password rotation needs `ALTER USER` + env update + restart. Details per provider: `references/leaked-secrets.md`.
**Done when:** every leaked credential is dead and replaced.

<a id="s26"></a>
## S26 — Full security review · بررسی امنیتی کامل
After the fixes, do a second, slower pass: threat-model the critical flows (signup/login/reset, payments, uploads, admin, multi-tenant data, AI features, webhooks, integrations); go through `references/extra-checks.md` (IDOR, mass assignment, SSRF, open redirect, races, webhooks, AI, privacy, infra); fill the authorization matrix from `list_routes.py`; re-run `run_all.py` and compare with the first run; optionally run an OWASP ZAP baseline scan against **staging** (`docker run -t ghcr.io/zaproxy/zaproxy:stable zap-baseline.py -t https://staging.example.com`).
**Done when:** a fresh pass finds nothing new at critical/high.

<a id="s27"></a>
## S27 — Test everything & report · همه رو تست کن، گزارش بده
Write regression tests for each fix (`references/security-tests.md`), run the project's own tests and build, run `check_live.py` against a local/staging instance, run load/race tests when traffic or money is involved (`references/load-testing.md`), then write the short report (`assets/report-template.md`): what was fixed (with proof), what is still risky (and why), what the owner must do (rotate keys, enable 2FA, DNS/email records…), and how to re-run the checks.
**Done when:** every ✅ in the report has a test, a request/response, or a re-scan behind it.
