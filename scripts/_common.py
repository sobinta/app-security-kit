"""Shared helpers for the app-security-kit scanners.

Standard library only (Python 3.8+), so the scripts run on any dev machine, CI
runner or VPS without installing anything.
"""
from __future__ import annotations

import json
import math
import os
import re
import subprocess
from collections import Counter
from pathlib import Path
from typing import Dict, Iterable, Iterator, List, Optional

# ---------------------------------------------------------------------------
# The 27 pre-launch steps (from the "pre-launch security kit") + extra checks.
# Scanners tag every finding with one of these ids so the report can show a
# 27/27 scoreboard.
# ---------------------------------------------------------------------------
STEPS: Dict[str, Dict[str, str]] = {
    "S01": {"en": "Authentication done right", "fa": "احراز هویت درست"},
    "S02": {"en": "Hide API keys (server-side only)", "fa": "مخفی کردن کلیدهای API"},
    "S03": {"en": "Secure database access (RLS / server-only)", "fa": "امن کردن دیتابیس"},
    "S04": {"en": "Enforce HTTPS", "fa": "اجباری کردن HTTPS"},
    "S05": {"en": "Hash passwords (argon2id/bcrypt)", "fa": "هش کردن پسوردها"},
    "S06": {"en": "Server-side validation", "fa": "اعتبارسنجی سمت سرور"},
    "S07": {"en": "Prevent XSS", "fa": "جلوگیری از XSS"},
    "S08": {"en": "Log & monitor suspicious activity", "fa": "لاگ و پایش فعالیت مشکوک"},
    "S09": {"en": "Lock admin routes (authorization)", "fa": "قفل کردن مسیر ادمین"},
    "S10": {"en": "Parameterized queries (no SQL injection)", "fa": "کوئری‌های پارامتردار"},
    "S11": {"en": "Check environment variables", "fa": "بررسی متغیرهای محیطی"},
    "S12": {"en": "Rate-limit login & sensitive endpoints", "fa": "ریت‌لیمیت لاگین"},
    "S13": {"en": "Restrict CORS", "fa": "محدود کردن CORS"},
    "S14": {"en": "Security headers", "fa": "هدرهای امنیتی"},
    "S15": {"en": "Secure session cookies", "fa": "امن کردن کوکی‌های سشن"},
    "S16": {"en": "CSRF protection", "fa": "محافظت CSRF"},
    "S17": {"en": "Time-limited, single-use password reset", "fa": "لینک ریست پسورد زمان‌دار"},
    "S18": {"en": "Restrict upload type & size", "fa": "محدودیت نوع و حجم آپلود"},
    "S19": {"en": "Verify prices & payments server-side", "fa": "بررسی قیمت و پرداخت سمت سرور"},
    "S20": {"en": "Debug off in production", "fa": "خاموش کردن دیباگ"},
    "S21": {"en": "Update vulnerable packages", "fa": "آپدیت پکیج‌های آسیب‌پذیر"},
    "S22": {"en": "Remove unused packages", "fa": "حذف پکیج‌های بی‌استفاده"},
    "S23": {"en": "Find exposed/leaked files", "fa": "پیدا کردن فایل‌های لورفته"},
    "S24": {"en": "Scan git history for secrets", "fa": "اسکن تاریخچه گیت"},
    "S25": {"en": "Revoke & rotate leaked keys", "fa": "باطل و عوض کردن کلیدهای لورفته"},
    "S26": {"en": "Full security review", "fa": "بررسی امنیتی کامل"},
    "S27": {"en": "Test everything & report", "fa": "تست همه‌چیز و گزارش"},
    # Extra checks beyond the video (see references/extra-checks.md)
    "X01": {"en": "Access control: IDOR / mass assignment / tenant isolation", "fa": "کنترل دسترسی (IDOR)"},
    "X02": {"en": "SSRF", "fa": "SSRF"},
    "X03": {"en": "Open redirect", "fa": "ریدایرکت باز"},
    "X04": {"en": "Path traversal / command & code injection", "fa": "پیمایش مسیر و تزریق دستور"},
    "X05": {"en": "Auth extras: JWT, sessions, enumeration", "fa": "جزئیات احراز هویت"},
    "X06": {"en": "Business logic & race conditions", "fa": "منطق کسب‌وکار و رقابت"},
    "X07": {"en": "Webhook signature verification", "fa": "تأیید امضای وب‌هوک"},
    "X08": {"en": "AI / LLM features", "fa": "امنیت قابلیت‌های هوش مصنوعی"},
    "X09": {"en": "Privacy & sensitive data", "fa": "حریم خصوصی و داده حساس"},
    "X10": {"en": "Server / VPS / Docker hardening", "fa": "امن‌سازی سرور"},
    "X11": {"en": "Client bundle & source maps", "fa": "باندل کلاینت و سورس‌مپ"},
    "X12": {"en": "Malware / backdoor indicators", "fa": "نشانه‌های بدافزار و بک‌دور"},
    "X13": {"en": "Monitoring, backups & incident readiness", "fa": "مانیتورینگ و بکاپ"},
    "X14": {"en": "Supply chain & CI", "fa": "زنجیره تأمین و CI"},
    "X15": {"en": "Load, stress & concurrency", "fa": "تست بار و فشار"},
}

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

# Directories that never contain first-party source worth scanning.
SKIP_DIRS = {
    ".git", "node_modules", ".next", ".nuxt", ".svelte-kit", ".output", "dist", "build", "out",
    "coverage", ".turbo", ".vercel", ".netlify", ".cache", ".parcel-cache", "vendor", "__pycache__",
    ".venv", "venv", ".tox", ".mypy_cache", ".pytest_cache", "bower_components", "jspm_packages",
    ".gradle", "Pods", "DerivedData", ".expo", ".dart_tool", "security-audit", ".terraform",
    "site-packages", ".pnpm-store", ".yarn", "target", ".angular", ".docusaurus",
}
# Built client output: skipped for code review, but scanned for leaked secrets
# because this is literally what ships to the browser.
BUILD_DIRS = ["dist", "build", "out", ".next/static", ".output/public", "public/build", ".svelte-kit/output/client"]

BINARY_EXTS = {
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".avif", ".ico", ".bmp", ".tiff", ".psd", ".svgz",
    ".pdf", ".zip", ".gz", ".tgz", ".bz2", ".xz", ".7z", ".rar", ".tar", ".jar", ".war", ".apk", ".ipa",
    ".woff", ".woff2", ".ttf", ".otf", ".eot", ".mp3", ".mp4", ".mov", ".avi", ".webm", ".wav", ".ogg",
    ".flac", ".m4a", ".exe", ".dll", ".so", ".dylib", ".bin", ".class", ".pyc", ".pyo", ".o", ".a",
    ".wasm", ".node", ".sqlite", ".sqlite3", ".db", ".mdb", ".parquet", ".pkl", ".npy", ".onnx",
    ".pt", ".h5", ".heic", ".docx", ".xlsx", ".pptx", ".odt", ".key", ".keystore", ".jks", ".p12", ".pfx",
}
LOCK_FILES = {
    "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "composer.lock", "Pipfile.lock", "poetry.lock",
    "Cargo.lock", "go.sum", "Gemfile.lock", "bun.lockb", "pubspec.lock", "packages.lock.json", "uv.lock",
}

CODE_EXTS_JS = {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".vue", ".svelte", ".astro"}
CODE_EXTS_PY = {".py"}
CODE_EXTS_PHP = {".php", ".phtml", ".inc"}
TEMPLATE_EXTS = {".html", ".htm", ".jinja", ".jinja2", ".j2", ".twig", ".ejs", ".hbs", ".handlebars", ".njk", ".erb", ".liquid"}


# ---------------------------------------------------------------------------
# File walking
# ---------------------------------------------------------------------------
def is_probably_binary(path: Path) -> bool:
    if path.suffix.lower() in BINARY_EXTS:
        return True
    try:
        with open(path, "rb") as fh:
            chunk = fh.read(8192)
        return b"\x00" in chunk
    except OSError:
        return True


def iter_files(root: Path, skip_dirs: Optional[set] = None, max_bytes: int = 1_500_000,
               include_hidden: bool = True) -> Iterator[Path]:
    """Yield text files under root, skipping dependency/build folders."""
    skip = SKIP_DIRS if skip_dirs is None else skip_dirs
    root = root.resolve()
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in skip and not (not include_hidden and d.startswith("."))]
        for name in filenames:
            p = Path(dirpath) / name
            if name in LOCK_FILES:
                continue
            try:
                if p.is_symlink() or p.stat().st_size > max_bytes:
                    continue
            except OSError:
                continue
            if is_probably_binary(p):
                continue
            yield p


def read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def rel(root: Path, path: Path) -> str:
    try:
        return str(path.resolve().relative_to(root.resolve())).replace(os.sep, "/")
    except ValueError:
        return str(path)


def line_of(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def line_text(text: str, lineno: int) -> str:
    lines = text.splitlines()
    if 1 <= lineno <= len(lines):
        return lines[lineno - 1]
    return ""


# ---------------------------------------------------------------------------
# Secrets: masking, entropy, placeholder detection
# ---------------------------------------------------------------------------
def mask(secret: str) -> str:
    """Never print a full secret: keep a recognisable prefix and the last chars."""
    s = secret.strip()
    n = len(s)
    if n == 0:
        return ""
    if n < 10:
        return s[0] + "*" * (n - 1)
    if n < 20:
        return f"{s[:3]}…{s[-2:]}"
    return f"{s[:8]}…{s[-4:]} (len {n})"


def mask_in_line(line: str, secret: str, width: int = 180) -> str:
    out = line.replace(secret, mask(secret)) if secret else line
    out = out.strip()
    return out if len(out) <= width else out[: width - 1] + "…"


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in counts.values())


PLACEHOLDER_RE = re.compile(
    r"(?i)^(?:x{3,}.*|\*+|\.+|-+|_+|0+|1234\w*|pass(word)?\d*|passw0rd|secret\d*|changeme|change[-_]?me.*|"
    r"your[-_ ].*|my[-_].*|example.*|sample.*|test(ing)?[-_]?\w*|dummy.*|placeholder.*|todo.*|fixme.*|"
    r"replace.*|insert.*|enter.*|<[^>]*>|\$\{.*\}|\{\{.*\}\}|%\(.*\)s|%s|process\.env.*|import\.meta\.env.*|"
    r"os\.environ.*|os\.getenv.*|getenv.*|env\(.*\)|config\(.*\)|null|none|nil|undefined|true|false|string|"
    r"redacted.*|abc\w*|foo\w*|bar\w*|qwerty\w*|admin\d*|root|postgres|mysql|localhost|\w*_here|"
    r"sk_(live|test)_x+|xxxx.*|dev|development|local|default|wrong[-_\w]*|invalid[-_\w]*|fake[-_\w]*)$"
)


def looks_placeholder(value: str) -> bool:
    v = value.strip().strip("'\"`")
    if not v or len(v) < 6:
        return True
    if PLACEHOLDER_RE.match(v):
        return True
    if re.fullmatch(r"(.)\1{5,}", v):  # aaaaaa
        return True
    return False


# ---------------------------------------------------------------------------
# Findings
# ---------------------------------------------------------------------------
def finding(rule: str, step: str, severity: str, title: str, file: str = "", line: int = 0,
            evidence: str = "", fix: str = "", confidence: str = "medium", source: str = "",
            **extra) -> dict:
    f = {
        "rule": rule,
        "step": step,
        "step_title": STEPS.get(step, {}).get("en", step),
        "severity": severity,
        "confidence": confidence,
        "title": title,
        "file": file,
        "line": line,
        "evidence": evidence,
        "fix": fix,
        "source": source,
    }
    f.update(extra)
    return f


def sort_findings(findings: List[dict]) -> List[dict]:
    return sorted(findings, key=lambda f: (SEVERITY_ORDER.get(f.get("severity", "info"), 9),
                                           f.get("step", ""), f.get("file", ""), f.get("line", 0)))


def dedupe(findings: Iterable[dict]) -> List[dict]:
    seen = set()
    out = []
    for f in findings:
        key = (f.get("rule"), f.get("file"), f.get("line"), f.get("evidence"))
        if key in seen:
            continue
        seen.add(key)
        out.append(f)
    return out


def write_json(path: Path, data) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")


def print_table(findings: List[dict], limit: int = 200) -> None:
    if not findings:
        print("  (no findings)")
        return
    for f in sort_findings(findings)[:limit]:
        loc = f"{f['file']}:{f['line']}" if f.get("file") else "-"
        print(f"  [{f['severity'].upper():8}] {f['step']} {f['title']}  ->  {loc}")
        if f.get("evidence"):
            print(f"             {f['evidence'][:160]}")
    if len(findings) > limit:
        print(f"  ... {len(findings) - limit} more (see JSON output)")


def run(cmd: List[str], cwd: Optional[Path] = None, timeout: int = 300) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, cwd=str(cwd) if cwd else None, capture_output=True, text=True,
                          timeout=timeout, errors="replace")


def is_git_repo(root: Path) -> bool:
    try:
        r = run(["git", "-C", str(root), "rev-parse", "--is-inside-work-tree"], timeout=20)
        return r.returncode == 0 and r.stdout.strip() == "true"
    except (OSError, subprocess.SubprocessError):
        return False


def git_tracked_files(root: Path) -> set:
    try:
        r = run(["git", "-C", str(root), "ls-files", "-z"], timeout=60)
        if r.returncode == 0:
            return {p for p in r.stdout.split("\0") if p}
    except (OSError, subprocess.SubprocessError):
        pass
    return set()


def git_ignored(root: Path, relpath: str) -> Optional[bool]:
    try:
        r = run(["git", "-C", str(root), "check-ignore", "-q", relpath], timeout=20)
        if r.returncode == 0:
            return True
        if r.returncode == 1:
            return False
    except (OSError, subprocess.SubprocessError):
        pass
    return None


def load_package_json(root: Path) -> dict:
    p = root / "package.json"
    if not p.exists():
        return {}
    try:
        return json.loads(read_text(p))
    except json.JSONDecodeError:
        return {}


def all_js_deps(pkg: dict) -> Dict[str, str]:
    deps: Dict[str, str] = {}
    for key in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
        deps.update(pkg.get(key) or {})
    return deps


def is_local_host(host: str) -> bool:
    host = (host or "").lower().strip("[]")
    if host in {"localhost", "127.0.0.1", "0.0.0.0", "::1", "host.docker.internal"}:
        return True
    if host.endswith(".local") or host.endswith(".localhost") or host.endswith(".test"):
        return True
    if re.match(r"^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|127\.)", host):
        return True
    return False
