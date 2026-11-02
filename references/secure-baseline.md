# Secure-by-default baseline for NEW projects

Use this when starting a project (or adding a big feature) so the pre-launch audit finds little. Each item maps to a kit step.

## Day 0 setup
- [ ] `.gitignore` from `assets/gitignore-security.txt` **before the first commit** (S11, S24).
- [ ] Pre-commit secret hook: `cp <skill>/assets/hooks/pre-commit .git/hooks/pre-commit && chmod +x .git/hooks/pre-commit` (S24). Teams: wire it through husky/lefthook/pre-commit so everyone gets it.
- [ ] CI: `assets/ci/security.yml` (gitleaks + dependency audit + dependency review) and `assets/ci/dependabot.yml` → `.github/` (S21, X14).
- [ ] Env validation module that fails fast at boot (zod/envalid/pydantic-settings); `.env.example` with placeholders only (S11).
- [ ] Auth from a maintained library/provider; sessions in HttpOnly/Secure/SameSite cookies (S01, S15).
- [ ] One data-access layer with ownership checks (`where: { id, userId }`) and role guards; RLS on day one for Supabase (S03, S09, X01).
- [ ] Schema validation helper used by every handler/action (S06).
- [ ] Security headers (helmet / next.config headers / Nginx snippet) and strict CORS from the first deploy (S13, S14).
- [ ] Rate limiter utility applied to auth, OTP, reset, contact, AI endpoints (S12).
- [ ] Central error handler with generic messages; `NODE_ENV=production` in deploy config (S20).
- [ ] Structured logger + Sentry with PII scrubbing; log auth failures (S08).
- [ ] Upload helper with size/type/magic-byte checks and private storage (S18).
- [ ] Payments: server-side pricing + signed webhooks + idempotency from the start (S19, X07).
- [ ] 2FA on GitHub, hosting, registrar/DNS, email, payment and cloud accounts (X14).
- [ ] Backups + restore test scheduled; uptime/TLS monitoring (X13).
- [ ] `/.well-known/security.txt` (`Contact: mailto:security@example.com`, `Expires: <date>`), and a privacy policy if you collect personal data (X09).

## Every feature PR (quick self-review)
1. Who can call this? (anon/user/other user/admin) — enforced on the server?
2. What input does it accept? — validated with a schema, sizes bounded?
3. Does it touch money, stock, credits or one-time things? — atomic + server-priced + race-tested?
4. Does it render user content? — escaped/sanitized?
5. Does it call out to a URL, file path or shell with user input? — allow-listed?
6. Does it need a new secret? — env only, server only, documented in `.env.example`?
7. Does it add a dependency? — maintained, needed, audited?
8. Is there a test for the abuse case, not only the happy path?

## Before every release
`python3 <skill>/scripts/run_all.py . --fail-on high` (exit code 1 blocks the deploy in CI), `npm audit --omit=dev --audit-level=high`, then `check_live.py` against staging.
