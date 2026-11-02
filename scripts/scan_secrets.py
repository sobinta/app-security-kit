#!/usr/bin/env python3
"""Find hardcoded secrets in a project's working tree and built client bundles.

Covers steps S02 (hide API keys), S11 (environment variables), S23 (exposed
files) and feeds S25 (rotate leaked keys). Secrets are always masked in output.

Usage:
  python3 scan_secrets.py <project_dir> [--json out.json] [--no-build]
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import List, Optional

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _common import (BUILD_DIRS, CODE_EXTS_JS, CODE_EXTS_PHP, CODE_EXTS_PY, finding, git_ignored,  # noqa: E402
                     git_tracked_files, is_git_repo, iter_files, line_of, load_package_json, looks_placeholder,
                     mask, mask_in_line, print_table, read_text, rel, shannon_entropy, sort_findings, write_json)

# (rule id, title, regex with named group "s" for the secret, severity)
PROVIDER_RULES = [
    ("aws-access-key-id", "AWS access key ID", r"\b(?P<s>(?:AKIA|ASIA)[0-9A-Z]{16})\b", "critical"),
    ("aws-secret-access-key", "AWS secret access key",
     r"(?i)aws[_\-\s.]{0,20}(?:secret|private)[_\-\s.]{0,20}(?:access[_\-\s.]{0,5})?key[\"']?\s*[:=]\s*[\"']?(?P<s>[0-9a-zA-Z/+]{40})\b",
     "critical"),
    ("stripe-live-secret", "Stripe LIVE secret/restricted key", r"\b(?P<s>(?:sk|rk)_live_[0-9a-zA-Z]{16,})\b", "critical"),
    ("stripe-test-secret", "Stripe test secret key", r"\b(?P<s>(?:sk|rk)_test_[0-9a-zA-Z]{16,})\b", "medium"),
    ("stripe-webhook-secret", "Stripe webhook signing secret", r"\b(?P<s>whsec_[0-9a-zA-Z]{20,})\b", "high"),
    ("openai-api-key", "OpenAI API key",
     r"\b(?P<s>sk-(?:proj|svcacct|admin)-[A-Za-z0-9_\-]{20,}|sk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20})", "critical"),
    ("anthropic-api-key", "Anthropic API key", r"\b(?P<s>sk-ant-(?:api|admin)\d{2}-[A-Za-z0-9_\-]{20,})", "critical"),
    ("generic-sk-key", "API secret key (sk-… format: OpenAI-compatible/DeepSeek/etc.)",
     r"(?<![A-Za-z0-9_\-])(?P<s>sk-[A-Za-z0-9]{32,})\b", "high"),
    ("github-token", "GitHub token",
     r"\b(?P<s>(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{22,})\b", "critical"),
    ("gitlab-token", "GitLab token", r"\b(?P<s>glpat-[A-Za-z0-9_\-]{20,})\b", "critical"),
    ("slack-token", "Slack token", r"\b(?P<s>xox[abposr]-[A-Za-z0-9\-]{10,})\b", "high"),
    ("slack-webhook", "Slack incoming webhook URL",
     r"(?P<s>https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+)", "high"),
    ("discord-webhook", "Discord webhook URL",
     r"(?P<s>https://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/\d+/[\w\-]+)", "medium"),
    ("google-api-key", "Google API key (if Firebase web key: public by design but MUST be restricted)",
     r"\b(?P<s>AIza[0-9A-Za-z_\-]{35})\b", "medium"),
    ("google-oauth-client-secret", "Google OAuth client secret", r"\b(?P<s>GOCSPX-[A-Za-z0-9_\-]{28})\b", "high"),
    ("gcp-service-account", "Google service-account private key (JSON)",
     r"\"private_key\"\s*:\s*\"(?P<s>-{5}BEGIN PRIVATE KEY-{5}[^\"]{20,})", "critical"),
    ("private-key-block", "Private key block",
     r"(?P<s>-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----)", "critical"),
    ("sendgrid-api-key", "SendGrid API key", r"\b(?P<s>SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43})\b", "high"),
    ("resend-api-key", "Resend API key", r"\b(?P<s>re_[A-Za-z0-9]{6,}_[A-Za-z0-9]{20,})\b", "high"),
    ("mailgun-api-key", "Mailgun API key", r"\b(?P<s>key-[0-9a-zA-Z]{32})\b", "medium"),
    ("twilio-api-key", "Twilio API key SID", r"\b(?P<s>SK[0-9a-fA-F]{32})\b", "medium"),
    ("telegram-bot-token", "Telegram bot token", r"\b(?P<s>\d{8,10}:AA[0-9A-Za-z_\-]{33})\b", "high"),
    ("npm-token", "npm access token", r"\b(?P<s>npm_[A-Za-z0-9]{36})\b", "high"),
    ("pypi-token", "PyPI upload token", r"\b(?P<s>pypi-AgEIcHlwaS5vcmc[A-Za-z0-9_\-]{50,})", "high"),
    ("huggingface-token", "Hugging Face token", r"\b(?P<s>hf_[A-Za-z0-9]{34,})\b", "high"),
    ("shopify-token", "Shopify access token", r"\b(?P<s>shp(?:at|ca|pa|ss)_[a-fA-F0-9]{32})\b", "high"),
    ("supabase-secret-key", "Supabase secret key (bypasses RLS)", r"\b(?P<s>sb_secret_[A-Za-z0-9_\-]{20,})", "critical"),
    ("db-url-with-password", "Database/cache connection string with password",
     r"(?P<s>\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|rediss|amqps?)://[^:\s/'\"@]+:[^@\s'\"]{3,}@[^\s'\"<>]+)",
     "critical"),
    ("url-basic-auth", "Credentials embedded in URL",
     r"(?P<s>https?://[A-Za-z0-9._%\-]{1,64}:[^@\s'\"/]{6,}@[A-Za-z0-9.\-]+)", "high"),
]
PROVIDER_RULES = [(rid, title, re.compile(rx), sev) for rid, title, rx, sev in PROVIDER_RULES]

JWT_RE = re.compile(r"\b(?P<s>eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,})")

GENERIC_RE = re.compile(
    r"(?i)(?P<name>[A-Za-z0-9_.\-]{0,40}(?:secret|passw(?:or)?d|pwd|api[_\-]?key|apikey|access[_\-]?key|"
    r"private[_\-]?key|auth[_\-]?token|access[_\-]?token|client[_\-]?secret|signing[_\-]?key|encryption[_\-]?key)"
    r"[A-Za-z0-9_.\-]{0,40})[\"']?\s*(?:=|:|=>|:=)\s*[\"'`](?P<s>[^\"'`\s]{8,200})[\"'`]")

DOTENV_LINE_RE = re.compile(r"^\s*(?:export\s+)?(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?P<val>.*?)\s*$")
PUBLIC_ENV_RE = re.compile(r"\b(?P<prefix>NEXT_PUBLIC_|VITE_|REACT_APP_|EXPO_PUBLIC_|NUXT_PUBLIC_|GATSBY_|VUE_APP_)"
                           r"(?P<name>[A-Z0-9_]{2,})")
PUBLIC_ENV_SENSITIVE = re.compile(r"SECRET|SERVICE_?ROLE|PRIVATE|PASSWORD|PASSWD|DB_|DATABASE|ADMIN|WEBHOOK|"
                                  r"(?:^|_)SK(?:_|$)|ACCESS_KEY|AUTH_TOKEN|CLIENT_SECRET|JWT|SIGNING|ENCRYPTION")
PUBLIC_ENV_OK = re.compile(r"PUBLISHABLE|ANON|SITE_KEY|PUBLIC_KEY|MEASUREMENT|_URL$|_HOST$|_DOMAIN$|_ID$")

CONFIG_EXTS = {".json", ".yml", ".yaml", ".toml", ".ini", ".cfg", ".conf", ".properties", ".xml", ".env",
               ".rb", ".go", ".java", ".kt", ".cs", ".swift", ".dart", ".rs", ".sh", ".bash", ".zsh", ".ps1", ".tf"}
GENERIC_EXTS = CODE_EXTS_JS | CODE_EXTS_PY | CODE_EXTS_PHP | CONFIG_EXTS
EXAMPLE_ENV = re.compile(r"\.env\.(example|sample|template|dist|defaults|schema)$|\.env\.[a-z]+\.example$", re.I)
WEAK_SIGNING_KEYS = re.compile(r"(?i)(JWT|SESSION|NEXTAUTH|AUTH|APP|SECRET_KEY|COOKIE|ENCRYPTION|SIGNING)[A-Z_]*")


def fingerprint(secret: str) -> str:
    return hashlib.sha256(secret.encode("utf-8", "replace")).hexdigest()[:12]


def decode_jwt_payload(token: str) -> Optional[dict]:
    try:
        part = token.split(".")[1]
        part += "=" * (-len(part) % 4)
        return json.loads(base64.urlsafe_b64decode(part.encode()).decode("utf-8", "replace"))
    except Exception:  # noqa: BLE001 - any decode problem just means "not a JWT we understand"
        return None


def client_side_reason(root: Path, path: Path, text: str, spa: bool) -> Optional[str]:
    r = rel(root, path)
    parts = r.split("/")
    for b in BUILD_DIRS:
        if r.startswith(b.rstrip("/") + "/"):
            return f"inside built client output ({b}/) that is shipped to browsers"
    if parts and parts[0] in {"public", "static", "www", "htdocs", "wwwroot", "html", "web"}:
        return f"in {parts[0]}/ which is served directly to browsers"
    head = text[:300]
    if "'use client'" in head or '"use client"' in head:
        return "in a 'use client' component (bundled for the browser)"
    if path.suffix in {".vue", ".svelte"} and "server" not in r.lower():
        return "in a front-end component"
    if spa and parts and parts[0] == "src" and "server" not in r.lower() and "api" not in parts[:2]:
        return "in the front-end source of a client-side app (Vite/CRA bundle)"
    return None


def scan(root: Path, include_build: bool = True) -> dict:
    root = root.resolve()
    findings: List[dict] = []
    pkg = load_package_json(root)
    deps = {**(pkg.get("dependencies") or {}), **(pkg.get("devDependencies") or {})}
    spa = ("vite" in deps or "react-scripts" in deps) and "next" not in deps
    git = is_git_repo(root)
    tracked = git_tracked_files(root) if git else set()
    seen_public_env = set()

    files = list(iter_files(root))
    if include_build:
        for b in BUILD_DIRS:
            bd = root / b
            if bd.is_dir():
                files.extend(iter_files(bd, skip_dirs={"node_modules", ".git", "cache"}, max_bytes=8_000_000))

    for path in files:
        r = rel(root, path)
        text = read_text(path)
        if not text:
            continue
        in_build = any(r.startswith(b.rstrip("/") + "/") for b in BUILD_DIRS)
        client = client_side_reason(root, path, text, spa)
        is_env = path.name == ".env" or path.name.startswith(".env.") or path.suffix == ".env"
        is_example_env = bool(EXAMPLE_ENV.search(path.name))
        # A secret inside an untracked, git-ignored, non-public .env file is in the RIGHT place:
        # only the dotenv hygiene checks below apply to it.
        private_env = is_env and not is_example_env and not client and (
            not git or (r not in tracked and git_ignored(root, r) is not False))
        claimed = set()  # character spans already reported for this file

        def add(rule, title, sev, start, secret, step="S02", fix="", conf="high", extra_title=""):
            ln = line_of(text, start)
            line = text.splitlines()[ln - 1] if text else ""
            s, e = start, start + len(secret)
            for cs, ce in claimed:
                if s < ce and cs < e:
                    return
            claimed.add((s, e))
            ttl = title + extra_title
            if client and sev in {"high", "medium"} and rule not in {"google-api-key"}:
                sev = "critical"
            if client:
                ttl += f" — exposed to the browser ({client})"
            findings.append(finding(
                rule, step, sev, ttl, r, ln, mask_in_line(line, secret), fix or
                "Move the value to a server-side environment variable, call the provider from the server only, "
                "and ROTATE the key (anything that was in code/git/bundles must be treated as leaked).",
                confidence=conf, source="scan_secrets", fingerprint=fingerprint(secret),
                client_exposed=bool(client), tracked_in_git=(r in tracked) if git else None))

        # 1) provider-specific patterns (all text files)
        for rid, title, rx, sev in ([] if private_env else PROVIDER_RULES):
            for m in rx.finditer(text):
                secret = m.group("s")
                if rid in {"db-url-with-password", "url-basic-auth"}:
                    pw = re.search(r"://[^:/@\s]+:([^@\s]+)@", secret)
                    host = re.search(r"@([^:/\s?]+)", secret)
                    if pw and (looks_placeholder(pw.group(1)) or pw.group(1).startswith("$")):
                        continue
                    if host and host.group(1) in {"localhost", "127.0.0.1", "db", "postgres", "mysql", "redis",
                                                  "mongo", "host"} and not client:
                        sev_eff = "low"
                    else:
                        sev_eff = sev
                    add(rid, title, sev_eff, m.start("s"), secret, step="S11" if not client else "S02",
                        conf="medium" if sev_eff == "low" else "high")
                    continue
                if rid == "stripe-test-secret" and is_example_env:
                    continue
                if looks_placeholder(secret.split("_")[-1] if "_" in secret else secret):
                    continue
                add(rid, title, sev, m.start("s"), secret,
                    conf="medium" if rid in {"google-api-key", "twilio-api-key", "mailgun-api-key"} else "high")

        # 2) JWTs: decode to spot Supabase service_role keys (bypass RLS)
        for m in ([] if private_env else JWT_RE.finditer(text)):
            payload = decode_jwt_payload(m.group("s")) or {}
            role = payload.get("role")
            if role == "anon":
                continue  # public by design; only safe if RLS is enabled (checked elsewhere)
            if role == "service_role":
                add("supabase-service-role-jwt", "Supabase service_role key (bypasses Row Level Security)", "critical",
                    m.start("s"), m.group("s"), step="S03",
                    fix="Never ship the service_role key to a browser or commit it. Use it only in server code via an "
                        "env var, rotate it in Supabase (Settings → API / JWT keys), and rely on RLS + the anon key in clients.")
            elif payload:
                add("hardcoded-jwt", "Hardcoded JWT token", "medium", m.start("s"), m.group("s"), conf="medium")

        # 3) public-prefixed env vars that look like server secrets (bundled into JS)
        for m in PUBLIC_ENV_RE.finditer(text):
            full = m.group(0)
            name = m.group("name")
            if full in seen_public_env:
                continue
            if PUBLIC_ENV_SENSITIVE.search(name) and not PUBLIC_ENV_OK.search(name):
                seen_public_env.add(full)
                ln = line_of(text, m.start())
                line = text.splitlines()[ln - 1]
                # mask any value on the line (dotenv style)
                dm = DOTENV_LINE_RE.match(line)
                ev = mask_in_line(line, dm.group("val").strip("'\"")) if dm and dm.group("val") else line.strip()[:180]
                findings.append(finding(
                    "public-env-secret", "S11", "critical" if re.search(r"SERVICE_?ROLE|SECRET|PRIVATE|PASSWORD|DB_|DATABASE", name) else "high",
                    f"Server secret exposed through public env prefix {m.group('prefix')} ({full})", r, ln, ev,
                    f"Variables prefixed {m.group('prefix')} are inlined into the browser bundle. Rename to a non-public "
                    "name, read it only in server code, and rotate the value if it was ever deployed.",
                    confidence="high", source="scan_secrets"))

        # 4) generic secret assignments (code/config only, entropy-filtered)
        if not in_build and not private_env and (path.suffix.lower() in GENERIC_EXTS or is_env):
            for m in GENERIC_RE.finditer(text):
                secret = m.group("s")
                name = m.group("name")
                if looks_placeholder(secret) or secret.startswith(("/", "./", "http", "$", "{", "%", "#", "process.", "env.")):
                    continue
                ent = shannon_entropy(secret)
                if ent < 3.0 and len(secret) < 16:
                    continue
                if re.search(r"(?i)(label|placeholder|field|input|hint|message|error|text|title|name|type|regex|pattern)$", name):
                    continue
                add("hardcoded-secret", f"Hardcoded secret in '{name}'", "high" if ent >= 3.5 else "medium",
                    m.start("s"), secret, conf="medium" if ent >= 3.5 else "low")

        # 5) dotenv files: committed / not ignored / exposed / weak values / debug in prod
        if is_env:
            if r in tracked and not is_example_env:
                findings.append(finding("env-file-committed", "S11", "critical",
                                        f"Environment file {r} is committed to git", r, 1, "",
                                        "git rm --cached the file, add it to .gitignore, and ROTATE every secret it "
                                        "contains (they are in git history — see S24/S25).", "high", "scan_secrets"))
            elif git and not is_example_env and git_ignored(root, r) is False:
                findings.append(finding("env-file-not-ignored", "S11", "high",
                                        f"Environment file {r} is not covered by .gitignore", r, 1, "",
                                        "Add `.env*` (and `!.env.example`) to .gitignore before the next commit.",
                                        "high", "scan_secrets"))
            for i, line in enumerate(text.splitlines(), 1):
                dm = DOTENV_LINE_RE.match(line)
                if not dm or line.lstrip().startswith("#"):
                    continue
                name, val = dm.group("name"), dm.group("val").strip().strip("'\"")
                if is_example_env:
                    continue
                if re.search(r"(?i)(SECRET|_KEY)$", name) and WEAK_SIGNING_KEYS.match(name) and val and \
                        not val.startswith("$") and (looks_placeholder(val) or len(val) < 32):
                    findings.append(finding("weak-signing-secret", "S11", "high",
                                            f"Weak/placeholder signing secret {name} (len {len(val)})", r, i,
                                            f"{name}={mask(val)}",
                                            "Generate a random value: `openssl rand -base64 48` (or "
                                            "`python3 -c 'import secrets;print(secrets.token_urlsafe(48))'`). "
                                            "Rotating it logs users out — plan for it.", "medium", "scan_secrets"))
                if re.search(r"prod", path.name, re.I) and (
                        (name in {"DEBUG", "APP_DEBUG", "FLASK_DEBUG", "WP_DEBUG"} and val.lower() in {"1", "true", "yes", "on"})
                        or (name == "NODE_ENV" and val.lower() != "production")):
                    findings.append(finding("debug-in-prod-env", "S20", "high", f"{name}={val} in {path.name}", r, i,
                                            line.strip()[:120], "Production must run with debug off / NODE_ENV=production.",
                                            "high", "scan_secrets"))

        # 6) special credential files
        lname = path.name.lower()
        if r.endswith(".vscode/sftp.json") and re.search(r"\"password\"\s*:\s*\"[^\"]+\"", text):
            findings.append(finding("sftp-password", "S11", "critical", "FTP/SFTP password stored in .vscode/sftp.json",
                                    r, 1, "", "Use SSH keys, move the file out of the repo and change that password.",
                                    "high", "scan_secrets"))
        if lname in {".npmrc", ".yarnrc", ".yarnrc.yml"} and re.search(r"(_authToken|npmAuthToken)\s*[=:]\s*[^$\s{]", text):
            findings.append(finding("npmrc-token", "S11", "high", f"Registry auth token in {r}", r, 1, "",
                                    "Use ${NPM_TOKEN} interpolation and rotate the token.", "high", "scan_secrets"))
        if lname in {"wp-config.php", "configuration.php", "settings.php", "local.xml", "parameters.yml"} and r in tracked:
            findings.append(finding("cms-config-committed", "S11", "high",
                                    f"CMS config with DB credentials/secret committed: {r}", r, 1, "",
                                    "Keep credentials out of git (env vars or untracked config) and rotate the DB password "
                                    "and secret salts.", "medium", "scan_secrets"))

    # .gitignore coverage for env files
    gi = root / ".gitignore"
    if git and (not gi.exists() or not re.search(r"(?m)^\s*\.env", read_text(gi))):
        findings.append(finding("gitignore-missing-env", "S11", "medium", ".gitignore does not ignore .env files",
                                ".gitignore", 0, "", "Add:\n.env\n.env.*\n!.env.example", "high", "scan_secrets"))

    findings = sort_findings(findings)
    return {"scanner": "scan_secrets", "root": str(root), "findings": findings,
            "meta": {"files_scanned": len(files), "git": git}}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("project")
    ap.add_argument("--json", help="write findings JSON here")
    ap.add_argument("--no-build", action="store_true", help="skip built bundles (dist/, .next/static, ...)")
    a = ap.parse_args(argv)
    res = scan(Path(a.project), include_build=not a.no_build)
    print(f"scan_secrets: {len(res['findings'])} finding(s) in {res['meta']['files_scanned']} files")
    print_table(res["findings"])
    if a.json:
        write_json(Path(a.json), res)
    return 0


if __name__ == "__main__":
    sys.exit(main())
