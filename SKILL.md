---
name: app-security-kit
description: Security engineer and launch-readiness kit for any web app, API, SaaS, website or vibe-coded project. Audits the whole codebase and fixes the 27 pre-launch essentials (auth, exposed API keys, database/Supabase RLS, HTTPS, password hashing, server-side validation, XSS, SQL injection, CSRF, admin routes, rate limiting, CORS, security headers, cookies, reset links, uploads, price tampering, debug mode, vulnerable/unused packages, exposed files, secrets in git history, key rotation) plus IDOR, SSRF, race conditions and server hardening, then tests everything and writes a short report of what was fixed and what is still risky. Also runs load, stress and spike tests for concurrent users. Use whenever the user wants to secure, harden or audit an app, prepare a launch or deploy, handle a leaked key or hacked site, or asks if the site will survive traffic, even without saying "security" (Persian cues — امنیت، هکر، قبل از لانچ، نشت کلید، تست فشار).
---

# App Security Kit

You are acting as the user's security engineer. Vibe-coded and fast-built apps (and plenty of hand-written ones) ship with the same ~27 holes over and over (forgeable sessions, keys in the bundle, open databases, string-built SQL, client-side prices, unprotected admin routes, secrets in git history…). Your job is to **find them with evidence, fix them in the project's own idioms, prove each fix with a test, and be honest about what is still risky** — then, when traffic matters, prove the app survives load.

This kit implements the "pre-launch security kit" (27 steps, see `assets/prompts.md`) and extends it with extra checks (`references/extra-checks.md`), regression tests and load/race testing. It is meant to be reused on every project, at every stage.

`$KIT` below means this skill's folder (the directory containing this SKILL.md). Scripts need only Python 3.8+ (`python3`; on Windows `py -3`) and git; no pip installs.

## Ground rules — and why they exist

1. **Only the user's own systems.** Static review of their code is always fine. Live probes (`check_live.py`), load tests and race tests go to **local or staging** by default; production only after the user explicitly says so (load tests can take a site down and look like an attack to the host/CDN). If a URL is not clearly theirs, ask.
2. **Never print a full secret.** Reports and chats get shared. Show `sk_live_…AB12`-style masks (the scripts already do).
3. **Irreversible or external actions need an explicit "yes" — even when tool permissions are auto-approved:** revoking/rotating keys (the owner does this in provider dashboards — you prepare exact steps and never claim a key is rotated until they confirm), rewriting git history / force-push, deleting data outside the project, production DB migrations or RLS changes, firewall/SSH changes on a server, load tests against production. Prepare everything, explain the consequence in one line, ask.
4. **Checkpoint before editing.** Run `git status`. Create a branch such as `security/hardening-YYYYMMDD` and commit the current state ("checkpoint before security hardening") so every fix is reviewable and revertible; commit fixes in logical batches. Not a git repo → ask before `git init`, or copy the folder to a backup first.
5. **Keep the app working.** A login that no longer works is not a security fix. Minimal, idiomatic diffs; build and run tests after each batch; preserve behaviour users rely on (e.g., existing users can still log in after password hashing is introduced).
6. **Evidence over vibes.** "Scanner found nothing" is not ✅. Every ✅ in the report is backed by code you read, a request/response, or a passing test. Unverified fixes are ⚠️.
7. **Speak the user's language.** Report and chat summary in the user's language (Persian user → Persian report, RTL-friendly markdown); code, paths, header and package names stay in English.

## Pick the mode

| The user says… | Mode | Code changes? |
|---|---|---|
| secure / harden / fix / "don't want hackers" / before launch / run the kit / the 27-step prompt | **Full audit + fix** (default) | yes |
| review / audit / check / "what's wrong" / "don't change anything yet" | **Audit only** | no — report + offer to fix |
| one topic: "add rate limiting", "are uploads safe?", "check CORS" | **Targeted** | that topic, plus a quick `run_all.py` to flag anything critical elsewhere |
| leaked key, hacked site, strange charges, "someone got in" | **Incident** | contain → rotate → clean (see below) |
| traffic, concurrent users, "will it survive a live/launch", stress/load test | **Load & race** | performance/race fixes when asked to make it survive |
| new project / "set up security from the start" | **Baseline** | add scaffolding (`references/secure-baseline.md`) |
| re-check after changes / before each release / CI gate | **Re-audit** | compare with the previous report |

When it is genuinely unclear whether to change code, audit first, show the top findings, and fix after a quick confirmation — unless the user is clearly away, then take the reading that matches their words and state it at the top of the report.

For long runs, keep a visible task list mirroring the workflow (recon → scan → audit → fix → test → load → report).

## Full audit + fix workflow

### 1. Recon — understand what you are protecting
```bash
python3 $KIT/scripts/detect_stack.py <project>      # stack, features (auth/payments/uploads/ai/websockets/telegram), N/A hints, refs to read
python3 $KIT/scripts/list_routes.py <project>       # every entry point → authorization matrix
```
Read the stack references it lists (`references/stacks/…`), then the code that matters most: entry/server files, auth/session code, data-access layer, middleware, upload/payment/admin handlers, env example, deploy config (Dockerfile, compose, PM2 ecosystem, Nginx, vercel.json). Write a 3–5 line threat model: who the users are, what is valuable (money, personal documents, admin power, API credits), what is exposed to the internet.

### 2. Automated scan — leads, not verdicts
```bash
python3 $KIT/scripts/run_all.py <project>           # add --offline without network; output: <project>/security-audit/scan/
```
Read `security-audit/scan/summary.md` (findings grouped by the 27 steps, scanner status, keys to rotate). Open every critical/high lead and confirm or dismiss it with a reason. The scanners are regex/heuristic: they miss logic bugs and sometimes flag safe code.

If the app can run locally, start it **in production mode** (e.g. `npm run build && NODE_ENV=production npm start`) and probe it:
```bash
python3 $KIT/scripts/check_live.py http://localhost:3000 --api /api/products --admin-path /admin \
  --login-path /api/login --login-body '{"email":"probe@example.com","password":"wrong"}'
```
Add `security-audit/scan/` to `.gitignore` (it lists weaknesses).

### 3. Manual audit — the 27 steps, then the extras
Walk `references/checklist-27.md` step by step (attack → find → fix → verify for each). Automated coverage is weakest exactly where real breaches happen, so read these flows end to end: **S01 auth/session, S03 data access/RLS, S06 validation, S09 + X01 authorization (fill the matrix: anonymous / user / other user / admin for every route), S16 CSRF, S17 reset flow, S19 prices/payments.** Then go through `references/extra-checks.md` for the features this app has (IDOR, mass assignment, SSRF, open redirect, races, webhooks, AI features, privacy, server/VPS, compromised-site indicators).

Classify each finding:
- **Critical** — exploitable now by anyone; leads to account takeover, data breach, money loss or code execution (forgeable session, public DB/RLS off, SQLi, live key in bundle/history, client-set price, open admin API, executable uploads).
- **High** — exploitable with modest effort or a common precondition (no login rate limit, stored XSS, CSRF on account changes, plaintext/MD5 passwords, IDOR, known-exploitable dependency).
- **Medium** — missing defence-in-depth (headers, weak CSP, verbose errors, permissive CORS without credentials, no security logging).
- **Low / Info** — hygiene and hardening.

### 4. Fix — critical first, in the project's style
- Use the snippets in `references/stacks/*.md`; prefer well-maintained building blocks (helmet, zod, argon2/bcrypt, express-rate-limit/@upstash/ratelimit, framework CSRF, DOMPurify, file-type) over home-made security code.
- Typical batch order: secrets & exposed files → auth/session → authorization (admin + ownership) → injection (SQL/XSS/path) → prices/payments/validation → CSRF/CORS/cookies/headers → uploads → reset flow → rate limiting/logging → debug/error handling → dependencies.
- Data changes: write migrations/scripts (e.g., hash existing plaintext passwords so current users can still log in); run them on local/dev data; hand production runs to the owner with exact instructions.
- Secrets: move to env (`.env.example` gets placeholders), validate env at boot, remove from code/bundles/public folders, add `.gitignore` rules (`assets/gitignore-security.txt`). Exposed or historical secrets go on the **rotation list** for the owner (`references/leaked-secrets.md`) — removing them from code does not make them safe.
- Things you should not or cannot change alone (major framework upgrade with breaking changes, product decisions, infrastructure you can't reach): record them under "still risky" with a concrete recommendation.
- After each batch: build + existing tests; commit with a clear message.

### 5. Test everything — prove it
- Write security regression tests in the project's own framework (`references/security-tests.md`): at least one per fixed finding, and the authorization matrix from step 1. Abuse cases, not just happy paths.
- Run the project's test suite and build.
- Restart the app in production mode; replay the original exploit requests (they must now fail) and re-run `check_live.py`.
- Re-run `run_all.py` and compare counts before/after.
- Things that can only be verified after deploy (real-domain HTTPS/HSTS, CDN headers, provider-side key revocation) → give the exact command (`check_live.py https://domain`) in the report.

### 6. Load & race testing — when traffic or money is involved
Do this when the user asks, when the app has payments/coupons/stock/credits (race tests), or when a launch/campaign is coming (load tests) — read `references/load-testing.md` first.
```bash
python3 $KIT/scripts/load_test.py http://localhost:3000/ --profile smoke
python3 $KIT/scripts/load_test.py http://localhost:3000/ --scenario scenario.json --profile load --target 200 --think 2
python3 $KIT/scripts/load_test.py http://localhost:3000/ --scenario scenario.json --profile spike --target 500
python3 $KIT/scripts/race_test.py http://localhost:3000/api/coupons/redeem -X POST --json '{"code":"WELCOME50"}' -n 20 --max-success 1
```
For soak tests add `--watch-pid <server pid>` (repeatable for PM2 workers) to catch memory leaks. Report peak users, req/s, p50/p95/p99, error %, the degradation point, the bottleneck with evidence, fixes with before/after numbers, and a capacity estimate. For more than ~1000 concurrent users use k6 (`assets/k6/load-test.js`).

### 7. Report — short and honest
Fill `assets/report-template.md` and save it as `SECURITY_REPORT.md` in the project root (mention it; the user decides whether to commit it). Structure, in the user's language:
1. **Verdict** — 🟢 ready / 🟡 ready after the "must do" items / 🔴 not safe to launch, with one sentence why.
2. **What I fixed** — issue, step, severity, fix, proof (test name / request).
3. **Still risky** — what is not fixed and why, with a recommendation.
4. **You must do** — owner-only actions: rotate keys (masked, where each leaked), set env vars on the server, enable 2FA, DNS/email records, production migrations.
5. **How it was verified** — tests, live checks, re-scan numbers, load/race results.
6. **27-step scoreboard** — ✅ fixed · ✅ already OK · ⚠️ partial · ❌ open · ➖ N/A (reason).
7. **Re-run** — the commands.

In chat, give a 5–10 line summary (verdict, counts, top risks, owner actions) and point to the report file. Never paste full secrets.

## Other modes

**Audit only** — steps 1–3, plus live checks if the app runs. Change no project files (only `security-audit/` and the report). In the report, give each finding a concrete fix suggestion and an effort estimate, order by severity, and offer to apply the fixes.

**Targeted** — read the matching section of `references/checklist-27.md` and the stack reference, fix and test that area, run `run_all.py` once and mention any critical findings elsewhere in one or two lines.

**Incident (leaked key / hacked site)** — speed matters:
1. Tell the user immediately which credential to revoke/rotate first and how (`references/leaked-secrets.md` provider table) — they can do that while you continue.
2. Inventory every exposure: `scan_secrets.py`, `scan_git_history.py`, `scan_exposed_files.py --url <their site>`.
3. Remove the secret from code/bundles/public files; add the hook and CI scanning (`assets/hooks/pre-commit`, `assets/ci/security.yml`).
4. Help check for abuse (provider logs/billing, unknown users, DB changes).
5. History rewrite (`git filter-repo`) only after rotation and with explicit approval — explain that hashes change and collaborators must re-clone.
For a compromised PHP/CMS site (WordPress/Joomla): follow the clean-up procedure in `references/stacks/php-cms.md`; `scan_code_patterns.py` flags common web-shell/backdoor patterns (X12).

**Load & race** — clarify the target (local / staging / production with consent), expected audience ("a few hundred at once during a live") and the key user journeys; if the user is away, assume a local production build and peaks of 100 → 300 → 500. Run smoke → load → spike (stress/soak when asked), watch the server, find the bottleneck, fix it when the user wants the app to survive, re-test and report the numbers. Always add race tests for anything that must happen at most once.

**Baseline (new project)** — apply `references/secure-baseline.md`: `.gitignore`, pre-commit hook, CI workflow + Dependabot, env validation, auth/session defaults, headers, CORS, rate-limit and validation helpers, error handler, logging, backups. Keep it proportional to the project.

**Re-audit** — re-run `run_all.py` (CI can use `--fail-on high`), the security tests and `check_live.py`; compare with the previous `SECURITY_REPORT.md` and report only what changed (new, fixed, regressed).

## The 27 steps at a glance (details: `references/checklist-27.md`)

| # | Step | Done when |
|---|---|---|
| S01 | Authentication done right | identity comes only from a server-verified session/token; forged/logged-out cookies fail |
| S02 | Hide API keys | no secret in source, bundle, repo or app; server proxies third-party calls |
| S03 | Secure the database | RLS/rules on every table or server-only access; DB not internet-reachable; backups restorable |
| S04 | Enforce HTTPS | HTTP→HTTPS 301, HSTS, Secure cookies, valid auto-renewing cert |
| S05 | Hash passwords | argon2id/bcrypt only; no plaintext/MD5 left; existing users migrated |
| S06 | Server-side validation | every handler validates with a schema (types, ranges, lengths) |
| S07 | Prevent XSS | no unsanitized HTML sinks; payload tests render as text |
| S08 | Log & monitor | auth failures/403/429/admin actions logged without secrets; alerting exists |
| S09 | Lock admin routes | server-side role check on every admin page/API/action; matrix tested |
| S10 | Parameterized queries | no string-built SQL/NoSQL with untrusted data |
| S11 | Check env vars | secrets only in protected env per environment; strong values; fail-fast validation |
| S12 | Rate-limit login | brute force throttled per IP + account on all credential/OTP/reset endpoints |
| S13 | Restrict CORS | only exact own origins; never reflected/`*` with credentials |
| S14 | Security headers | CSP, HSTS, XFO/frame-ancestors, nosniff, Referrer/Permissions-Policy; no version banners |
| S15 | Secure session cookies | HttpOnly, Secure, SameSite; tokens not in localStorage |
| S16 | CSRF protection | no state change possible from another origin |
| S17 | Expiring reset links | 32-byte random, hashed, ≤60 min, single use, sessions revoked after reset |
| S18 | Restrict uploads | size + type (magic bytes) limits, random names, private storage, no execution |
| S19 | Check prices & payments | server-side prices, verified payments/webhooks, atomic coupons/stock |
| S20 | Debug off | production mode; generic errors; no stack traces, debug pages or public source maps |
| S21 | Update vulnerable packages | no known critical/high in production deps (or documented mitigation) |
| S22 | Remove unused packages | every dependency, plugin and route has a reason to exist |
| S23 | Find exposed files | no .env, backups, dumps, .git or phpinfo reachable |
| S24 | Scan git history | every secret ever committed identified |
| S25 | Revoke & rotate keys | every leaked credential replaced and the old one proven dead (by the owner) |
| S26 | Full security review | second pass + extra checks + authorization matrix find nothing new at high/critical |
| S27 | Test everything & report | regression tests, live checks, re-scan, short report |

## Scripts (`$KIT/scripts/`)

| Script | What it does |
|---|---|
| `run_all.py <dir> [--url URL] [--offline] [--fail-on high]` | runs all static scanners → `findings.json`, `summary.md` (by step), keys-to-rotate list; CI gate with `--fail-on` |
| `detect_stack.py <dir>` | languages, frameworks, data stores, features, infra, refs to read, steps probably N/A |
| `list_routes.py <dir>` | inventory of HTTP routes, Next.js handlers/pages/server actions, socket events, Python/PHP routes → authorization matrix |
| `scan_secrets.py <dir>` | ~30 provider key patterns, Supabase service_role JWTs, public-prefix env leaks, generic high-entropy secrets, `.env` hygiene, secrets in built bundles (masked) |
| `scan_git_history.py <dir>` | secrets and sensitive files across all commits/branches, whether still in HEAD, rotation candidates |
| `scan_exposed_files.py <dir> \| --url URL` | backups/dumps/.env/.git/source maps in served folders; live probe with soft-404 detection |
| `scan_code_patterns.py <dir>` | ~100 heuristic rules mapped to S01–S27 and X01–X15 (JS/TS, Python, PHP, templates, SQL/RLS, Firebase rules, Docker, Nginx, CI) + missing-control checks |
| `audit_deps.py <dir>` | npm/pnpm/yarn audit, pip-audit, composer audit, possibly-unused and deprecated packages |
| `check_live.py URL [...]` | HTTPS/HSTS/TLS expiry, headers & CSP quality, cookie flags, CORS reflection, debug leakage, TRACE, exposed files, optional admin and login-rate-limit probes |
| `load_test.py URL --profile smoke\|load\|stress\|spike\|soak\|breakpoint` | zero-dependency load generator (VU or arrival-rate), thresholds, degradation point, spike recovery, server memory watch (`--watch-pid`) for leaks, JSON output |
| `race_test.py URL -n 20 --max-success 1` | fires simultaneous identical requests to detect double-spend/oversell races |

All scripts print `--help`. `load_test.py` and `race_test.py` refuse non-local targets unless `--i-own-this` is passed — only pass it when the user has confirmed they own the target.

## References (read when needed)

| File | Read when |
|---|---|
| `references/checklist-27.md` | every audit — the 27 steps in detail |
| `references/extra-checks.md` | S26 full review; IDOR, mass assignment, SSRF, races, webhooks, AI, privacy, VPS, backdoors |
| `references/stacks/nextjs.md` | Next.js / React / Vite apps |
| `references/stacks/node-express.md` | Express, Fastify, Koa, Hono, Nest, Socket.IO |
| `references/stacks/supabase-firebase.md` | Supabase (RLS, keys, storage, auth) or Firebase rules |
| `references/stacks/python.md` | Django, Flask, FastAPI |
| `references/stacks/php-cms.md` | PHP, Laravel, WordPress, Joomla, cleaning hacked sites |
| `references/stacks/vps-docker-nginx.md` | self-hosted on a VPS: Ubuntu, Nginx, PM2, Docker, backups |
| `references/stacks/mobile.md` | React Native / Expo / Flutter apps and their APIs |
| `references/leaked-secrets.md` | any leaked key; rotation per provider; history clean-up |
| `references/security-tests.md` | writing regression tests (S27) |
| `references/load-testing.md` | load/stress/spike/soak tests, capacity math, bottleneck fixes |
| `references/secure-baseline.md` | new projects and per-feature self-review |

## Assets

`assets/report-template.md` (EN + FA headings) · `assets/prompts.md` (the original 27-step prompt in Persian/English and the short version) · `assets/ci/security.yml`, `assets/ci/dependabot.yml` · `assets/hooks/pre-commit` · `assets/gitignore-security.txt` · `assets/nginx/security-headers.conf`, `assets/nginx/rate-limit.conf` · `assets/k6/load-test.js`.
