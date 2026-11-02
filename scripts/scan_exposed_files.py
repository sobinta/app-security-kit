#!/usr/bin/env python3
"""Find files that are (or would be) publicly downloadable: .env, backups, dumps,
.git, source maps, phpinfo, logs ... (step S23).

Local mode looks inside web-served folders of the project. Live mode (--url)
probes a running site and uses soft-404 detection so SPAs that answer 200 for
every path don't produce false alarms. Only probe sites you own.

Usage:
  python3 scan_exposed_files.py <project_dir> [--json out.json]
  python3 scan_exposed_files.py --url https://staging.example.com [--json out.json] [--insecure]
"""
from __future__ import annotations

import argparse
import hashlib
import os
import re
import ssl
import sys
import urllib.error
import urllib.request
import uuid
from pathlib import Path
from typing import List, Optional, Tuple
from urllib.parse import urljoin

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _common import finding, git_tracked_files, is_git_repo, print_table, rel, sort_findings, write_json  # noqa: E402

PUBLIC_DIR_NAMES = ["public", "static", "www", "wwwroot", "htdocs", "public_html", "html", "web", "dist", "build", "out",
                    ".output/public", "public/uploads", "uploads", "media"]

LOCAL_RULES: List[Tuple[re.Pattern, str, str]] = [
    (re.compile(r"(^|/)\.env(\.[\w.\-]+)?$", re.I), "critical", "environment file with secrets"),
    (re.compile(r"(^|/)\.git(/|$)"), "critical", "git repository metadata (whole source + history downloadable)"),
    (re.compile(r"(^|/)(\.svn|\.hg)(/|$)"), "critical", "VCS metadata"),
    (re.compile(r"\.(pem|key|p12|pfx|ppk|keystore|jks)$|(^|/)id_(rsa|ed25519|ecdsa)", re.I), "critical", "private key"),
    (re.compile(r"\.(sql|dump|sqlite3?|db|mdb)(\.gz|\.zip)?$", re.I), "critical", "database file/dump"),
    (re.compile(r"\.(zip|tar|tgz|tar\.gz|rar|7z|bak|backup|old|orig|save|swp|swo)$|~$", re.I), "high", "backup/archive/editor copy"),
    (re.compile(r"(^|/)(\.htpasswd|\.npmrc|\.pypirc|\.netrc|sftp\.json|docker-compose[\w.\-]*\.ya?ml|\.DS_Store)$", re.I),
     "high", "config/credential file"),
    (re.compile(r"(^|/)(phpinfo|info|test|adminer[\w.\-]*|phpmyadmin)\.php$", re.I), "high", "diagnostic/admin script"),
    (re.compile(r"\.(log)$", re.I), "medium", "log file (may contain tokens/PII)"),
    (re.compile(r"\.(csv|xlsx?|json)$", re.I), "low", "data export? verify it contains no personal data"),
    (re.compile(r"\.map$", re.I), "medium", "source map (exposes original source code)"),
]

# path, expected-content signature (regex on first bytes), severity, label
LIVE_PROBES: List[Tuple[str, Optional[str], str, str]] = [
    ("/.env", r"(?m)^[A-Z][A-Z0-9_]+=", "critical", ".env file"),
    ("/.env.local", r"(?m)^[A-Z][A-Z0-9_]+=", "critical", ".env.local"),
    ("/.env.production", r"(?m)^[A-Z][A-Z0-9_]+=", "critical", ".env.production"),
    ("/.env.development", r"(?m)^[A-Z][A-Z0-9_]+=", "critical", ".env.development"),
    ("/.env.backup", r"(?m)^[A-Z][A-Z0-9_]+=", "critical", ".env.backup"),
    ("/.env.bak", r"(?m)^[A-Z][A-Z0-9_]+=", "critical", ".env.bak"),
    ("/.env.old", r"(?m)^[A-Z][A-Z0-9_]+=", "critical", ".env.old"),
    ("/api/.env", r"(?m)^[A-Z][A-Z0-9_]+=", "critical", "api/.env"),
    ("/.git/config", r"\[core\]", "critical", ".git/config"),
    ("/.git/HEAD", r"^ref: refs/", "critical", ".git/HEAD"),
    ("/.svn/entries", r"^\d+|<\?xml", "critical", ".svn"),
    ("/.hg/hgrc", r"\[paths\]", "high", ".hg"),
    ("/backup.zip", "^PK", "critical", "backup.zip"),
    ("/backup.tar.gz", "^\x1f\x8b", "critical", "backup.tar.gz"),
    ("/site.zip", "^PK", "critical", "site.zip"),
    ("/www.zip", "^PK", "critical", "www.zip"),
    ("/public_html.zip", "^PK", "critical", "public_html.zip"),
    ("/backup.sql", r"(?i)(CREATE TABLE|INSERT INTO|-- MySQL dump|PostgreSQL database dump)", "critical", "backup.sql"),
    ("/db.sql", r"(?i)(CREATE TABLE|INSERT INTO)", "critical", "db.sql"),
    ("/dump.sql", r"(?i)(CREATE TABLE|INSERT INTO)", "critical", "dump.sql"),
    ("/database.sql", r"(?i)(CREATE TABLE|INSERT INTO)", "critical", "database.sql"),
    ("/data.sql", r"(?i)(CREATE TABLE|INSERT INTO)", "critical", "data.sql"),
    ("/database.sqlite", "^SQLite format 3", "critical", "database.sqlite"),
    ("/wp-config.php.bak", r"DB_PASSWORD", "critical", "wp-config.php.bak"),
    ("/wp-config.php~", r"DB_PASSWORD", "critical", "wp-config.php~"),
    ("/wp-config.php.save", r"DB_PASSWORD", "critical", "wp-config.php.save"),
    ("/configuration.php.bak", r"\$password|\$secret", "critical", "Joomla configuration.php.bak"),
    ("/configuration.php~", r"\$password|\$secret", "critical", "Joomla configuration.php~"),
    ("/config.php.bak", r"(?i)password", "critical", "config.php.bak"),
    ("/.htpasswd", r"^[^:\s]+:\$?", "high", ".htpasswd"),
    ("/.npmrc", r"_authToken|registry", "high", ".npmrc"),
    ("/.DS_Store", "Bud1", "medium", ".DS_Store (lists file names)"),
    ("/.vscode/sftp.json", r"\"host\"", "critical", ".vscode/sftp.json"),
    ("/docker-compose.yml", r"(?m)^services:|^version:", "high", "docker-compose.yml"),
    ("/phpinfo.php", r"phpinfo\(\)|PHP Version", "high", "phpinfo.php"),
    ("/info.php", r"phpinfo\(\)|PHP Version", "high", "info.php"),
    ("/server-status", r"Apache Server Status", "medium", "Apache server-status"),
    ("/adminer.php", r"(?i)adminer", "high", "Adminer DB console"),
    ("/storage/logs/laravel.log", r"(?i)\[\d{4}-\d\d-\d\d|stack trace", "high", "Laravel log"),
    ("/debug.log", r"(?i)(error|warning|exception)", "medium", "debug.log"),
    ("/wp-content/debug.log", r"(?i)PHP (Warning|Notice|Fatal)", "high", "WordPress debug.log"),
    ("/error.log", r"(?i)(error|exception)", "medium", "error.log"),
    ("/npm-debug.log", r"(?i)npm", "low", "npm-debug.log"),
    ("/.aws/credentials", r"aws_access_key_id", "critical", ".aws/credentials"),
    ("/id_rsa", r"PRIVATE KEY", "critical", "id_rsa"),
    ("/.ssh/id_rsa", r"PRIVATE KEY", "critical", ".ssh/id_rsa"),
    ("/composer.json", r"\"require\"", "low", "composer.json (stack disclosure)"),
    ("/package.json", r"\"dependencies\"", "low", "package.json (stack disclosure)"),
    ("/uploads/", r"(?i)<title>Index of", "medium", "directory listing on /uploads/"),
    ("/backup/", r"(?i)<title>Index of", "high", "directory listing on /backup/"),
]


def scan_local(root: Path) -> dict:
    root = root.resolve()
    findings: List[dict] = []
    served_dirs = []
    for name in PUBLIC_DIR_NAMES:
        d = root / name
        if d.is_dir():
            served_dirs.append(d)
    # PHP / CMS apps: the project root itself is often the web root
    php_root = (root / "index.php").exists() and not (root / "public" / "index.php").exists()
    if php_root:
        served_dirs.append(root)
    tracked = git_tracked_files(root) if is_git_repo(root) else set()
    seen = set()
    for base in served_dirs:
        for dirpath, dirnames, filenames in os.walk(base):
            rel_dir = rel(root, Path(dirpath))
            if "node_modules" in dirnames:
                dirnames.remove("node_modules")
            if base == root:  # whole project is web root: don't descend into vendor deps
                dirnames[:] = [d for d in dirnames if d not in {"vendor", "node_modules"}]
            entries = [(n, True) for n in dirnames] + [(n, False) for n in filenames]
            for name, is_dir in entries:
                rp = (rel_dir + "/" + name).lstrip("./") if rel_dir != "." else name
                if rp in seen:
                    continue
                for rx, sev, label in LOCAL_RULES:
                    if rx.search(rp + ("/" if is_dir else "")):
                        if label.startswith("source map") and not any(x in rp for x in ("static", "dist", "build", "out", "assets", "_next")):
                            continue
                        if label.startswith("data export") and rp.endswith(("manifest.json", "site.webmanifest", "package.json")):
                            continue
                        seen.add(rp)
                        web = "the project root is the web root (PHP)" if base == root else f"{rel(root, base)}/ is web-served"
                        findings.append(finding(
                            "exposed-file-local", "S23", sev, f"{label}: {rp} ({web})", rp, 0, "",
                            "Delete it from the served folder (keep backups outside the web root/off-server), and block "
                            "dotfiles/backups at the web server (see assets/nginx/security-headers.conf). If it ever "
                            "went live, rotate whatever secrets it held.", "high", "scan_exposed_files",
                            tracked_in_git=rp in tracked))
                        break
    # Laravel/Symfony/Joomla-specific: .env next to index.php in the web root
    if php_root and (root / ".env").exists():
        findings.append(finding("env-in-web-root", "S23", "critical",
                                ".env sits in the web root of a PHP app — likely downloadable at /.env",
                                ".env", 0, "", "Move the web root to public/ (Laravel) or block dotfiles in the server config.",
                                "medium", "scan_exposed_files"))
    return {"scanner": "scan_exposed_files", "mode": "local", "root": str(root),
            "findings": sort_findings(findings), "meta": {"served_dirs": [rel(root, d) or "." for d in served_dirs]}}


def _fetch(url: str, ctx: Optional[ssl.SSLContext], timeout: float = 8.0, max_bytes: int = 65536):
    req = urllib.request.Request(url, headers={"User-Agent": "app-security-kit/1.0 (owner-authorized scan)"})
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:  # noqa: S310 - owner-authorized
            body = resp.read(max_bytes)
            return resp.status, body, dict(resp.headers), resp.geturl()
    except urllib.error.HTTPError as e:
        try:
            body = e.read(max_bytes)
        except Exception:  # noqa: BLE001
            body = b""
        return e.code, body, dict(e.headers or {}), url
    except Exception as e:  # noqa: BLE001
        return None, str(e).encode(), {}, url


def scan_live(base_url: str, insecure: bool = False) -> dict:
    ctx = ssl._create_unverified_context() if insecure else None  # noqa: S323 - opt-in for self-signed staging
    base = base_url.rstrip("/") + "/"
    findings: List[dict] = []
    # soft-404 baselines: random file at root, random dotfile, random php
    baselines = []
    for probe in (f"/{uuid.uuid4().hex}.txt", f"/.{uuid.uuid4().hex[:8]}", f"/{uuid.uuid4().hex[:8]}.zip"):
        st, body, _, _ = _fetch(urljoin(base, probe.lstrip("/")), ctx)
        baselines.append((st, hashlib.sha1(body).hexdigest(), len(body)))
    checked = 0
    errors = 0
    for path, sig, sev, label in LIVE_PROBES:
        url = urljoin(base, path.lstrip("/"))
        st, body, headers, final = _fetch(url, ctx)
        checked += 1
        if st is None:
            errors += 1
            continue
        if st != 200:
            continue
        h = hashlib.sha1(body).hexdigest()
        if any(h == bh or (bst == 200 and abs(len(body) - bl) < 64 and b"<html" in body[:400].lower()) for bst, bh, bl in baselines):
            continue  # soft 404 (SPA fallback)
        text = body.decode("latin-1")
        if sig and not re.search(sig, text):
            continue
        findings.append(finding("exposed-file-live", "S23", sev, f"Publicly downloadable: {path} ({label})", url, 0,
                                f"HTTP 200, {len(body)} bytes, content matches expected signature",
                                "Remove the file from the server and deny it in the web server config; rotate any "
                                "secrets it contained (assume they were downloaded).", "high", "scan_exposed_files"))
    return {"scanner": "scan_exposed_files", "mode": "live", "url": base_url, "findings": sort_findings(findings),
            "meta": {"probes": checked, "network_errors": errors,
                     "soft404_baseline_status": [b[0] for b in baselines]}}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("project", nargs="?")
    ap.add_argument("--url", help="probe a running site you own")
    ap.add_argument("--insecure", action="store_true", help="accept self-signed TLS (staging)")
    ap.add_argument("--json")
    a = ap.parse_args(argv)
    if not a.project and not a.url:
        ap.error("give a project dir and/or --url")
    results = []
    if a.project:
        results.append(scan_local(Path(a.project)))
    if a.url:
        results.append(scan_live(a.url, a.insecure))
    for res in results:
        print(f"scan_exposed_files ({res['mode']}): {len(res['findings'])} finding(s)")
        print_table(res["findings"])
    if a.json:
        write_json(Path(a.json), results[0] if len(results) == 1 else {"results": results})
    return 0


if __name__ == "__main__":
    sys.exit(main())
