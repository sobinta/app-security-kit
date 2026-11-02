# Changelog

Repository: https://github.com/sobinta/app-security-kit

## 1.0.0 — 2026-11-02
First public release.
- Skill workflow with 7 modes: full audit + fix, audit only, targeted, incident (leaked key / hacked site), load & race, new-project baseline, re-audit.
- The 27 pre-launch steps (attack → find → fix → verify → done-when) plus 15 extra checks (IDOR, mass assignment, SSRF, open redirect, injection, JWT/session, races, webhooks, AI/LLM, privacy, VPS/Docker, source maps, backdoors, monitoring/backups, supply chain, load).
- Stack references: Next.js/React, Node/Express/Socket.IO, Supabase/Firebase, Django/Flask/FastAPI, PHP/Laravel/WordPress/Joomla (incl. hacked-site clean-up), VPS/Nginx/PM2/Docker, mobile.
- Zero-dependency scripts: run_all, detect_stack, list_routes, scan_secrets, scan_git_history, scan_exposed_files, scan_code_patterns (~100 rules), audit_deps, check_live, load_test (smoke/load/stress/spike/soak/breakpoint, memory watch), race_test.
- Assets: report template (EN/FA), original prompts, CI workflow, Dependabot config, pre-commit secret hook, .gitignore block, Nginx security/rate-limit snippets, k6 script.
- Three deliberately vulnerable sample apps + eval cases, and a self-test suite with CI.
