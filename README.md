# 🛡️ App Security Kit

**A Claude skill that acts as your security engineer before launch.** It audits a whole project, fixes the 27 classic pre-launch security holes (plus the ones that usually slip through), proves every fix with tests, load-tests the app for real traffic, and hands you a short report: *what was fixed + what is still risky*. Built for vibe-coded apps, equally useful for hand-written ones.

[فارسی ↓](#فارسی) · [Install](#install) · [Use](#use) · [The 27 steps](#the-27-steps) · [Scripts](#scripts-work-without-claude-too) · [Load testing](#load--stress-testing) · [CI](#use-it-in-ci) · [Safety](#safety--scope)

[![self-test](https://github.com/sobinta/app-security-kit/actions/workflows/selftest.yml/badge.svg)](https://github.com/sobinta/app-security-kit/actions/workflows/selftest.yml)
[![release](https://img.shields.io/github/v/release/sobinta/app-security-kit)](https://github.com/sobinta/app-security-kit/releases)
[![license: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

---

## What it does
- **Audit + fix** the 27 pre-launch essentials: auth, exposed API keys, database access (incl. Supabase RLS), HTTPS, password hashing, server-side validation, XSS, SQL injection, CSRF, admin routes, rate limiting, CORS, security headers, cookies, password-reset links, uploads, price/payment tampering, debug mode, vulnerable & unused packages, exposed files, secrets in git history, key rotation, full review, tests & report.
- **Extra checks** that real breaches come from: IDOR / mass assignment / multi-tenant leaks, SSRF, open redirects, path traversal & command injection, JWT/session flaws, race conditions (double-spent coupons, oversold stock), webhooks, AI/LLM endpoints (cost abuse, prompt injection), privacy/GDPR, VPS/Docker/Nginx hardening, source maps, web-shells in hacked PHP/CMS sites, backups & monitoring, CI/supply chain.
- **Tests, not promises:** writes security regression tests in your project's framework, replays the original exploits against the fixed app, re-scans and compares.
- **Load & stress testing:** smoke / load / stress / spike / soak / breakpoint profiles, race-condition tests, server memory watch — answers "will it survive the launch / the Instagram live?" with numbers.
- **Honest report** in your language (Persian or English): verdict, fixed, still risky, what *you* must do (e.g. rotate keys — Claude never pretends it did), how it was verified, 27-step scoreboard.

Stacks covered with dedicated guides: **Next.js/React, Node/Express/Socket.IO, Supabase/Firebase, Django/Flask/FastAPI, PHP/Laravel/WordPress/Joomla, VPS (Ubuntu/Nginx/PM2/Docker), mobile (React Native/Expo/Flutter)** — and the checklist itself is stack-agnostic.

## Install
**Claude Code** (personal, available in every project):
```bash
git clone https://github.com/sobinta/app-security-kit ~/.claude/skills/app-security-kit
# update later: git -C ~/.claude/skills/app-security-kit pull
```
**Per project** (shared with your team through the repo): clone/copy it to `.claude/skills/app-security-kit/` inside the project.

**Claude app (claude.ai / desktop):** download `app-security-kit.skill` from the [latest release](https://github.com/sobinta/app-security-kit/releases/latest) and add it as a custom skill in the app's skills settings.

Requirements for the bundled scripts: Python 3.8+ and git (no pip installs). Node is only needed for your own JS projects.

## Use
Just talk to Claude — the skill triggers on security, launch, leak and load-test requests, in English or Persian:

| You say | What happens |
|---|---|
| "Run the security kit on ./my-app — fix what you safely can, test it, short report." | Full audit + fix (default) |
| «کیت امنیتی رو روی این پروژه اجرا کن، همه رو درست کن، تست کن و گزارش کوتاه بده.» | Full audit + fix, report in Persian |
| "Audit only, don't change code — prioritized report for my developer." | Audit only |
| "Are my file uploads safe?" / "Add rate limiting to login." | Targeted |
| "I pushed my Stripe key to GitHub last month." / «سایتم هک شده» | Incident: rotate → inventory → clean → prevent |
| "Will it survive 500 users during the launch?" / «تست فشار بگیر» | Load, spike & race tests with numbers |
| "Set up security for this new project." | Secure-by-default baseline (hooks, CI, headers…) |
| "Re-check before release." | Re-audit vs the previous report |

Before changing code the skill creates a checkpoint branch, keeps the app working (build + tests after each batch) and asks before anything irreversible (key revocation, history rewrite, production changes, load tests on production).

## The 27 steps
| # | Step | ≈ OWASP Top 10 (2021) |
|---|---|---|
| S01 | Authentication done right | A07 |
| S02 | Hide API keys | A07 / A05 |
| S03 | Secure the database (RLS / server-only) | A01 / A05 |
| S04 | Enforce HTTPS | A02 |
| S05 | Hash passwords (argon2id / bcrypt) | A02 |
| S06 | Server-side validation | A04 / A03 |
| S07 | Prevent XSS | A03 |
| S08 | Log & monitor suspicious activity | A09 |
| S09 | Lock admin routes | A01 |
| S10 | Parameterized queries | A03 |
| S11 | Check environment variables | A05 |
| S12 | Rate-limit login | A07 |
| S13 | Restrict CORS | A05 / A01 |
| S14 | Security headers | A05 |
| S15 | Secure session cookies | A05 / A07 |
| S16 | CSRF protection | A01 |
| S17 | Time-limited, single-use reset links | A07 |
| S18 | Restrict upload type & size | A04 |
| S19 | Verify prices & payments server-side | A04 |
| S20 | Debug off in production | A05 |
| S21 | Update vulnerable packages | A06 |
| S22 | Remove unused packages | A06 |
| S23 | Find exposed files | A05 / A01 |
| S24 | Scan git history for secrets | A05 / A07 |
| S25 | Revoke & rotate leaked keys | A07 |
| S26 | Full security review | all |
| S27 | Test everything & report | — |

Plus X01–X15 extra checks (`references/extra-checks.md`); SSRF = A10, supply chain & webhooks = A08.

## Scripts (work without Claude too)
All in `scripts/`, standard-library Python, every one has `--help`:
```bash
python3 scripts/run_all.py ./my-app                    # all static scanners → my-app/security-audit/scan/summary.md
python3 scripts/run_all.py ./my-app --fail-on high     # exit 1 on high/critical → CI / pre-deploy gate
python3 scripts/list_routes.py ./my-app                # every entry point → authorization matrix
python3 scripts/check_live.py http://localhost:3000 --api /api/products --admin-path /admin --login-path /api/login
python3 scripts/load_test.py http://localhost:3000/ --profile spike --target 300
python3 scripts/race_test.py http://localhost:3000/api/coupons/redeem -X POST --json '{"code":"WELCOME50"}' -n 20 --max-success 1
```
| Script | Purpose |
|---|---|
| `run_all.py` | runs everything below (static) → `findings.json` + `summary.md` grouped by the 27 steps + keys-to-rotate list |
| `detect_stack.py` | frameworks, data stores, features, infra, which guides to read, steps that are N/A |
| `list_routes.py` | routes, Next.js handlers/pages/server actions, socket events, Python/PHP routes |
| `scan_secrets.py` | ~30 provider key formats, Supabase service_role JWTs, `NEXT_PUBLIC_`/`VITE_` leaks, high-entropy secrets, `.env` hygiene, built bundles — always masked |
| `scan_git_history.py` | secrets & sensitive files across all commits/branches, still-in-HEAD check, rotation list |
| `scan_exposed_files.py` | `.env`, backups, dumps, `.git`, source maps in served folders; live probe with soft-404 detection |
| `scan_code_patterns.py` | ~100 heuristic rules mapped to the steps (JS/TS, Python, PHP, templates, SQL/RLS, Firebase rules, Docker, Nginx, GitHub Actions) + missing-control checks |
| `audit_deps.py` | npm/pnpm/yarn audit, pip-audit, composer audit, unused & deprecated packages |
| `check_live.py` | HTTPS/HSTS/TLS expiry, headers & CSP quality, cookie flags, CORS reflection, debug leaks, exposed files, admin & login-rate-limit probes |
| `load_test.py` | load generator: VU or arrival-rate, 6 profiles, thresholds, degradation point, spike recovery, `--watch-pid` memory leak watch |
| `race_test.py` | simultaneous identical requests → detects double-spend / oversell |

Scanners are lead generators: they find a lot fast, but logic bugs (authorization, business rules) need the manual review the skill performs.

## Load & stress testing
`load_test.py` profiles: **smoke** (sanity) · **load** (expected busy hour) · **stress** (1×→2×→3× peak) · **spike** (viral post / live stream, checks recovery) · **soak** (memory leaks, pool exhaustion — use `--watch-pid`) · **breakpoint** (max capacity). For thousands of concurrent users use the k6 script in `assets/k6/`. Methodology, capacity math, what to watch on the server and a symptom→fix table: `references/load-testing.md`.

## Use it in CI
- `assets/ci/security.yml` → `.github/workflows/` (gitleaks over full history, npm/pip/composer audit, dependency review on PRs).
- `assets/ci/dependabot.yml` → `.github/dependabot.yml`.
- `assets/hooks/pre-commit` → `.git/hooks/pre-commit` (blocks secrets and `.env`/keys/dumps before they reach history).
- Optional gate: copy `scripts/` to `tools/security/` and run `python3 tools/security/run_all.py . --offline --fail-on high`.

## Safety & scope
- Use it on **your own** projects and systems (or with written permission). Live probes and load tests default to local/staging; production only when you explicitly say so.
- Secrets are always masked in output. Key revocation, history rewrites, server firewall changes and production migrations are prepared for you but never done without your explicit OK.
- This is a strong pre-launch baseline, **not** a replacement for a professional penetration test on high-risk systems (payments at scale, health/legal data).

## Repository layout
```
SKILL.md                 the skill (workflow, modes, rules)
references/              checklist-27, extra-checks, stacks/*, leaked-secrets, security-tests, load-testing, secure-baseline
scripts/                 zero-dependency scanners and testers
assets/                  report template (EN/FA), original prompts, CI, hooks, nginx, k6, .gitignore block
evals/                   3 deliberately vulnerable sample apps + eval cases (never deploy them)
tests/run_tests.py       self-tests for the scripts (python3 tests/run_tests.py -v)
```

## Contributing
[Issues](https://github.com/sobinta/app-security-kit/issues) and PRs welcome: new scanner rules (with a sample that triggers them), stack guides, false-positive fixes. Run `python3 tests/run_tests.py -v` before a PR; CI runs it on Linux and macOS. Report security problems in this repo privately via GitHub's "Report a vulnerability" (Security tab).

## Author
**Sobhan Nouri** — [Sobinta](https://github.com/sobinta) · 🌐 [sobhannouri.com](https://sobhannouri.com) · Instagram [@sobhannouri.ai](https://instagram.com/sobhannouri.ai) · Telegram [@sobi82](https://t.me/sobi82)

## Credits & license
Inspired by the Persian "pre-launch security kit" reel — 27 steps in one prompt (`assets/prompts.md`) — and extended with extra checks, tests and load testing. [MIT](LICENSE) © 2026 [sobinta](https://github.com/sobinta).

---

<a id="فارسی"></a>
<div dir="rtl">

## 🇮🇷 فارسی

**App Security Kit یک اسکیل Claude است که قبل از انتشار عمومی، نقش مهندس امنیت پروژه‌ات را بازی می‌کند.** کل پروژه را بررسی می‌کند، ۲۷ حفره‌ی امنیتی رایج قبل از لانچ (به‌علاوه‌ی مواردی که معمولاً از چشم می‌افتند) را درست می‌کند، برای هر اصلاح تست می‌نویسد و اجرا می‌کند، پروژه را زیر بار کاربران همزمان تست می‌کند و در آخر یک گزارش کوتاه می‌دهد: **چه چیزهایی درست شد + چه چیزهایی هنوز ریسک دارد**. مخصوص پروژه‌های وایب‌کد ساخته شده، ولی برای کدنویسی معمولی هم به همان اندازه کاربرد دارد.

### چه کارهایی می‌کند
- **بررسی و اصلاح ۲۷ مرحله:** احراز هویت، مخفی کردن کلیدهای API، امنیت دیتابیس (از جمله RLS در Supabase)، اجباری کردن HTTPS، هش پسوردها، اعتبارسنجی سمت سرور، XSS، SQL Injection، CSRF، قفل مسیرهای ادمین، ریت‌لیمیت لاگین، CORS، هدرهای امنیتی، کوکی‌های سشن، لینک ریست پسورد زمان‌دار، محدودیت آپلود، بررسی قیمت و پرداخت سمت سرور، خاموش کردن دیباگ، پکیج‌های آسیب‌پذیر و بی‌استفاده، فایل‌های لورفته، اسکن تاریخچه‌ی گیت، باطل و عوض کردن کلیدها، بررسی کامل، تست و گزارش.
- **بررسی‌های اضافه:** IDOR و دسترسی به داده‌ی کاربران دیگر، mass assignment، SSRF، ریدایرکت باز، race condition (استفاده‌ی چندباره از کد تخفیف یا فروش بیشتر از موجودی)، وب‌هوک‌ها، امنیت قابلیت‌های هوش مصنوعی (هزینه و prompt injection)، حریم خصوصی/GDPR، امن‌سازی سرور VPS و Docker و Nginx، و پیدا کردن بک‌دور در سایت‌های هک‌شده‌ی وردپرس/جوملا.
- **تست، نه ادعا:** تست‌های امنیتی در فریمورک خود پروژه نوشته و اجرا می‌شوند و همان حمله‌های اولیه دوباره روی نسخه‌ی اصلاح‌شده امتحان می‌شوند.
- **تست بار و تست فشار:** پروفایل‌های smoke / load / stress / spike / soak / breakpoint، تست race و پایش حافظه‌ی سرور؛ با عدد و رقم جواب می‌دهد که «سایت توی لانچ یا لایو اینستاگرام دووم میاره یا نه».
- **گزارش صادقانه به فارسی یا انگلیسی:** وضعیت کلی، موارد درست‌شده، موارد پرریسک باقی‌مانده، کارهایی که خودت باید انجام بدهی (مثل عوض کردن کلیدها؛ Claude هیچ‌وقت ادعا نمی‌کند این کار را انجام داده) و جدول ۲۷ مرحله.

### نصب
برای **Claude Code** (در همه‌ی پروژه‌ها در دسترس):

</div>

```bash
git clone https://github.com/sobinta/app-security-kit ~/.claude/skills/app-security-kit
```

<div dir="rtl">

برای یک پروژه‌ی خاص: داخل پوشه‌ی `.claude/skills/app-security-kit/` همان پروژه قرارش بده. برای **اپ Claude**: فایل `app-security-kit.skill` را از [آخرین نسخه (Releases)](https://github.com/sobinta/app-security-kit/releases/latest) دانلود کن و به‌عنوان اسکیل سفارشی در تنظیمات اسکیل‌های اپ اضافه کن. اسکریپت‌ها فقط به Python 3.8 به بالا و git نیاز دارند.

### نمونه‌ی استفاده
- «کیت امنیتی رو روی این پروژه اجرا کن، همه رو درست کن، تست کن و گزارش کوتاه بده.»
- «فقط بررسی کن و گزارش اولویت‌بندی‌شده بده، هنوز به کد دست نزن.»
- «کلید Stripe توی گیت‌هاب لو رفته، چی‌کار کنم؟» یا «سایتم هک شده.»
- «تست فشار بگیر ببین با ۵۰۰ کاربر همزمان دووم میاره یا نه.»
- «برای این پروژه‌ی جدید از اول تنظیمات امنیتی رو بچین.»

### نکته‌های ایمنی
- فقط روی پروژه‌ها و سرورهای **خودت** (یا با مجوز کتبی) استفاده کن. تست‌های زنده و تست بار به‌طور پیش‌فرض روی محیط لوکال یا staging اجرا می‌شوند و روی سرور اصلی فقط با تأیید صریح خودت.
- کلیدها همیشه ماسک‌شده نمایش داده می‌شوند. کارهای برگشت‌ناپذیر (باطل کردن کلید، بازنویسی تاریخچه‌ی گیت، تغییرات سرور و دیتابیس اصلی) فقط آماده می‌شوند و بدون تأیید تو انجام نمی‌شوند.
- این کیت یک خط پایه‌ی قوی قبل از لانچ است، **جایگزین تست نفوذ حرفه‌ای** برای سیستم‌های حساس نیست.

### تست خودِ کیت
`python3 tests/run_tests.py -v` سه اپ نمونه‌ی عمداً آسیب‌پذیر را می‌سازد و بررسی می‌کند که اسکنرها همه‌ی مشکلات کاشته‌شده را پیدا کنند و هیچ کلیدی را کامل چاپ نکنند. همین تست‌ها در GitHub Actions روی لینوکس و مک اجرا می‌شوند.

### سازنده
**سبحان نوری** — [Sobinta](https://github.com/sobinta) · [sobhannouri.com](https://sobhannouri.com) · اینستاگرام [@sobhannouri.ai](https://instagram.com/sobhannouri.ai) · تلگرام [@sobi82](https://t.me/sobi82)

</div>
