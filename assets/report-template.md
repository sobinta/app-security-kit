<!--
Report template. Write it in the user's language (Persian → Persian headings below; code, paths and header names stay in English).
Keep it SHORT: the user asked "what you fixed + what's still risky". Details go in the appendix tables, not in prose.
Never include full secrets — masked only (sk_live_…AB12).
Save as SECURITY_REPORT.md in the project root (or security-audit/REPORT.md) and summarise it in chat.
-->

# Security report — {project} · {date}

**Verdict:** {🟢 ready to launch | 🟡 launch after the "must do" items | 🔴 not safe to launch} — {one sentence why}
**Scope:** {repo/path, commit, stack} · **Mode:** {audit+fix | audit only | targeted | incident | load test}
**Score:** {N}/27 steps ✅ · {critical} critical / {high} high still open

## ✅ What I fixed
| # | Issue (step) | Severity | Fix | Proof |
|---|---|---|---|---|
| 1 | {e.g. Forgeable `uid` cookie → anyone could become admin (S01)} | critical | {express-session with random id, HttpOnly/Secure/SameSite} | {test `forged cookie → 401` ✅} |

## ⚠️ Still risky (not fixed, and why)
| # | Risk (step) | Severity | Why not fixed | Recommendation |
|---|---|---|---|---|
| 1 | {e.g. multer 1.x → 2.x is a major upgrade (S21)} | medium | {needs manual QA of uploads} | {upgrade in a separate PR} |

## 🔑 You must do (Claude can't)
- [ ] {Rotate the Stripe live key `sk_live_…O6pA` (leaked in git history, commit ba1dd1e, 2026-08-09): Dashboard → Developers → API keys → Roll; then confirm the old key returns 401.}
- [ ] {Set the new env vars on the server: SESSION_SECRET, …}
- [ ] {Enable 2FA for admin accounts / GitHub / hosting}

## 🧪 How it was verified
- Tests: `{npm test -- security}` → {N passed}
- Live checks: `check_live.py {url}` → {summary}
- Re-scan: `run_all.py` → {before: X critical/Y high → after: …}
- Load/race (if run): {peak users, p95, error %, race result}

## 27-step scoreboard
| Step | Status | Note |
|---|---|---|
| S01 Authentication | ✅ fixed | … |
| … | … | … |
| S27 Test & report | ✅ | this report |
<!-- statuses: ✅ fixed · ✅ already OK · ⚠️ partial · ❌ open · ➖ N/A (reason) -->

## Re-run later
`python3 <skill>/scripts/run_all.py . && python3 <skill>/scripts/check_live.py https://staging…` · tests: `{command}`

---

## نسخه‌ی فارسی سرفصل‌ها (برای گزارش فارسی)
- **وضعیت کلی:** 🟢 آماده‌ی لانچ / 🟡 بعد از کارهای ضروری / 🔴 فعلاً امن نیست
- **✅ چه چیزهایی درست شد** (مشکل · شدت · راه‌حل · مدرک/تست)
- **⚠️ چه چیزهایی هنوز ریسک دارد** (و چرا درست نشد)
- **🔑 کارهایی که خودت باید انجام بدی** (مثلاً عوض کردن کلیدها در داشبورد سرویس‌دهنده)
- **🧪 چطور تست شد**
- **جدول ۲۷ مرحله**
- **اجرای دوباره**
