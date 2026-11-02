# Leaked secret playbook (S23–S25)

**Rule zero: once a secret has been in a public place (git history, a bundle, a public file, a screenshot, a chat), it is compromised. Deleting it does not un-leak it — rotating it does.** Bots scan new GitHub pushes and JS bundles within minutes.

## 1. Inventory (Claude does this)
- `scan_secrets.py <dir>` — working tree + built bundles + public folders.
- `scan_git_history.py <dir>` — all branches, all commits, plus sensitive files ever committed (`.env`, keys, dumps, backups). Shallow clone? `git fetch --unshallow` first.
- `scan_exposed_files.py --url https://site` — was it downloadable from the live site?
- Also think about: CI logs, Docker images (`docker history --no-trunc`), error trackers, mobile builds, shared screenshots, `.env` sent to freelancers, backups in public buckets.
- Output: a table — secret (masked) · provider · where found · first exposure date · public? · rotation status.

## 2. Rotate (the owner does this — Claude prepares the exact steps)
Order per secret: **create new → deploy new → verify app → revoke old → prove old is dead → check for abuse.**

| Secret | Where to rotate (dashboard wording changes; look for "API keys"/"Credentials") | Gotchas |
|---|---|---|
| Stripe secret/restricted key | Dashboard → Developers → API keys → Roll key | Rolling can keep the old key alive for a grace period — set it to expire now if leaked. Check Events/Logs for unknown API calls. Webhook secret (`whsec_`) is rotated per endpoint. |
| OpenAI / Anthropic / other LLM keys | Platform/Console → API keys → revoke + create | Check usage/billing for spikes; set spend limits and per-project keys. |
| AWS access key | IAM → user → Security credentials → create new, deactivate, then delete old | Review CloudTrail for the key id; prefer roles/SSO over long-lived keys. |
| Google Cloud / Firebase service account | IAM → Service accounts → Keys → delete key, create new | Web API keys: add restrictions (referrer/app + API list). |
| Supabase service_role / JWT secret | Project Settings → API keys / JWT keys (new key system allows rotating secret keys individually) | Legacy JWT-secret rotation invalidates anon + service keys and all sessions — redeploy every client. |
| GitHub / GitLab / npm tokens | Settings → Developer settings / Access tokens → revoke | Check audit log; prefer fine-grained, expiring tokens. |
| Telegram bot token | @BotFather → `/revoke` | Re-set the webhook with a new `secret_token`. |
| SMTP / Resend / SendGrid / Mailgun | Provider dashboard → API keys / SMTP credentials | Check sending logs for spam sent from your account. |
| Payment gateways (Zarinpal, IDPay, PayPal…) | Merchant panel → regenerate merchant key/credentials | Verify recent transactions & payout settings weren't changed. |
| Database password | `ALTER USER app WITH PASSWORD '…';` / hosting panel | Update env everywhere (app, workers, cron, backups) then restart; if the DB was internet-reachable, check for unknown users/tables. |
| `SESSION_SECRET`, `NEXTAUTH_SECRET`/`AUTH_SECRET`, `APP_KEY`, JWT secret | Generate new (`openssl rand -base64 48`), deploy | Logs everyone out (and Laravel `APP_KEY` change breaks encrypted data — re-encrypt or keep old key as previous key). |
| SSH keys / server passwords | Remove from `authorized_keys`, create new keypair | Check `last`, `/var/log/auth.log`, unknown cron jobs/users. |
| CMS salts (WordPress/Joomla `$secret`) | Regenerate | Forces re-login. |

Prove the old key is dead, e.g. Stripe: `curl -s https://api.stripe.com/v1/balance -u "<old_key>:" | head -c 200` → `401`/"Invalid API Key". Only report a key as rotated after the owner confirms it (or the proof request fails with 401).

## 3. Look for abuse
Provider usage/billing graphs and logs for the exposure window; unknown resources (cloud instances, Stripe payouts/products, email sends); DB access logs; new admin users. Personal data possibly accessed → GDPR breach assessment (72-hour notification rule where it applies).

## 4. Clean up (optional, only with explicit approval)
After rotation, history can be purged so the dead secret stops triggering scanners and the data (e.g. dumps with personal data) is removed:
```bash
# work on a fresh mirror clone; coordinate with every collaborator first
git clone --mirror git@github.com:owner/repo.git && cd repo.git
pip install git-filter-repo
git filter-repo --invert-paths --path config/keys.js --path public/backup.zip     # drop files
# or replace strings everywhere: echo 'sk_live_xxx==>REMOVED' > replace.txt && git filter-repo --replace-text replace.txt
git push --force --mirror
```
Consequences to explain before doing it: all commit hashes change, open PRs break, everyone must re-clone, forks and GitHub's cached views/PR refs may still hold the data (GitHub support can purge sensitive data on request). This is irreversible on the remote — never run it without the owner's explicit "yes".

## 5. Prevent recurrence
`.gitignore` (`assets/gitignore-security.txt`), pre-commit hook (`assets/hooks/pre-commit`), CI secret scanning (`assets/ci/security.yml`), GitHub secret scanning + push protection, env validation at boot, `server-only` imports, least-privilege & expiring keys, spend limits/alerts on paid APIs.
