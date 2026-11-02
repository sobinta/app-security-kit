#!/usr/bin/env python3
"""Dependency audit: known-vulnerable packages (S21) and unused packages (S22).

Runs the ecosystem's own auditor when available (npm/pnpm/yarn audit,
pip-audit, composer audit) and adds an offline "possibly unused dependency"
check for JavaScript projects. Network failures are reported, not hidden.

Usage:
  python3 audit_deps.py <project_dir> [--json out.json] [--offline]
"""
from __future__ import annotations

import argparse
import json
import re
import shutil
import sys
from pathlib import Path
from typing import Dict, List

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _common import SKIP_DIRS, finding, iter_files, print_table, read_text, rel, run, sort_findings, write_json  # noqa: E402

SEV_MAP = {"critical": "critical", "high": "high", "moderate": "medium", "medium": "medium", "low": "low", "info": "info"}
# Packages that are used implicitly (CLIs, framework peers, config-only plugins)
IMPLICIT = re.compile(r"^(next|react|react-dom|typescript|tslib|@types/.*|eslint.*|@eslint/.*|prettier.*|tailwindcss|"
                      r"@tailwindcss/.*|postcss.*|autoprefixer|sass|less|sharp|@next/.*|eslint-config-.*|"
                      r"nodemon|ts-node|tsx|concurrently|cross-env|husky|lint-staged|pm2|dotenv|dotenv-cli|vite|"
                      r"@vitejs/.*|vitest|jest|@jest/.*|ts-jest|babel-.*|@babel/.*|webpack.*|rollup.*|esbuild|turbo|"
                      r"prisma|drizzle-kit|supabase|wrangler|vercel|netlify-cli|@playwright/test|playwright|cypress|"
                      r"@testing-library/.*|nuxt|@nuxt/.*|svelte|@sveltejs/.*|astro|@astrojs/.*|expo|expo-.*|react-native|"
                      r"@react-native/.*|pg-native|bufferutil|utf-8-validate|encoding|@biomejs/biome|knip|depcheck|"
                      r"node-gyp|patch-package|rimraf|npm-run-all2?|serve|http-server|nodemon|@commitlint/.*)$")
DEPRECATED = {
    "csurf": "archived/deprecated CSRF middleware — use csrf-csrf or csrf-sync",
    "request": "deprecated HTTP client — use fetch/undici/axios",
    "node-uuid": "deprecated — use crypto.randomUUID()",
    "bcrypt-nodejs": "unmaintained — use bcrypt or argon2",
    "node-serialize": "known RCE via unserialize — remove",
    "jwt-simple": "minimal JWT lib without alg pinning — prefer jose/jsonwebtoken@9",
    "crypto-js": "unmaintained since 2023; use Web Crypto / node:crypto",
    "express-fileupload": "frequent prototype-pollution issues — prefer multer with limits",
    "md5": "MD5 is not for passwords",
    "sha1": "SHA-1 is not for passwords",
}


def _js_projects(root: Path) -> List[Path]:
    out = []
    for pj in [root / "package.json"] + sorted(root.glob("*/package.json")) + sorted(root.glob("*/*/package.json")):
        if pj.exists() and not any(part in SKIP_DIRS for part in pj.relative_to(root).parts[:-1]):
            out.append(pj.parent)
    return list(dict.fromkeys(out))


def _npm_audit(proj: Path, root: Path, offline: bool) -> (List[dict], dict):
    findings, meta = [], {"project": rel(root, proj) or "."}
    lock = next((proj / f for f in ("package-lock.json", "npm-shrinkwrap.json", "pnpm-lock.yaml", "yarn.lock")
                 if (proj / f).exists()), None)
    if lock is None:
        findings.append(finding("no-lockfile", "S21", "medium", f"No lockfile in {meta['project']} (installs are not reproducible)",
                                f"{meta['project']}/package.json", 0, "", "Commit package-lock.json (or pnpm-lock/yarn.lock) and "
                                "install with `npm ci` in CI/production.", "high", "audit_deps"))
        meta["audit"] = "skipped: no lockfile (npm audit needs one; run `npm i --package-lock-only` first)"
        return findings, meta
    if offline:
        meta["audit"] = "skipped (--offline)"
        return findings, meta
    if lock.name == "pnpm-lock.yaml" and shutil.which("pnpm"):
        cmd = ["pnpm", "audit", "--json"]
    elif lock.name == "yarn.lock" and shutil.which("yarn"):
        cmd = ["yarn", "audit", "--json"]
    elif shutil.which("npm") and lock.name in {"package-lock.json", "npm-shrinkwrap.json"}:
        cmd = ["npm", "audit", "--json"]
    else:
        meta["audit"] = f"skipped: tool for {lock.name} not installed"
        return findings, meta
    try:
        r = run(cmd, cwd=proj, timeout=240)
    except Exception as e:  # noqa: BLE001
        meta["audit"] = f"failed: {e}"
        return findings, meta
    out = r.stdout.strip()
    try:
        data = json.loads(out) if cmd[0] != "yarn" else None
    except json.JSONDecodeError:
        data = None
    if data is None and cmd[0] == "yarn":
        advisories = {}
        for line in out.splitlines():
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            if obj.get("type") == "auditAdvisory":
                adv = obj["data"]["advisory"]
                advisories[adv["module_name"]] = adv
        for name, adv in advisories.items():
            sev = SEV_MAP.get(adv.get("severity", "low"), "low")
            findings.append(finding("vulnerable-dependency", "S21", sev, f"{name}: {adv.get('title', 'advisory')}",
                                    f"{meta['project']}/package.json", 0, f"vulnerable {adv.get('vulnerable_versions')} → "
                                    f"patched {adv.get('patched_versions')}", "Upgrade (yarn up / yarn upgrade) and re-test.",
                                    "high", "audit_deps", package=name))
        meta["audit"] = "yarn audit"
        return findings, meta
    if not data:
        err = (r.stderr or out)[:300]
        meta["audit"] = f"failed (network/registry?): {err}"
        return findings, meta
    if "error" in data and "vulnerabilities" not in data:
        meta["audit"] = f"failed: {json.dumps(data['error'])[:300]}"
        return findings, meta
    vulns = data.get("vulnerabilities") or {}
    if not vulns and "advisories" in data:  # npm v6 / pnpm format
        for adv in data["advisories"].values():
            sev = SEV_MAP.get(adv.get("severity", "low"), "low")
            findings.append(finding("vulnerable-dependency", "S21", sev, f"{adv.get('module_name')}: {adv.get('title')}",
                                    f"{meta['project']}/package.json", 0,
                                    f"vulnerable {adv.get('vulnerable_versions')} → patched {adv.get('patched_versions')}",
                                    "Upgrade the package (or its parent) and re-run tests.", "high", "audit_deps",
                                    package=adv.get("module_name")))
    for name, v in vulns.items():
        sev = SEV_MAP.get(v.get("severity", "low"), "low")
        titles = [x.get("title") for x in v.get("via", []) if isinstance(x, dict) and x.get("title")]
        via_pk = [x for x in v.get("via", []) if isinstance(x, str)]
        fix = v.get("fixAvailable")
        if isinstance(fix, dict):
            fix_txt = f"fix: {fix.get('name')}@{fix.get('version')}" + (" (SEMVER-MAJOR — test carefully)" if fix.get("isSemVerMajor") else "")
        elif fix:
            fix_txt = "fix available via `npm audit fix`"
        else:
            fix_txt = "no fix available yet — consider replacing the package or mitigating"
        direct = v.get("isDirect", False)
        findings.append(finding("vulnerable-dependency", "S21", sev,
                                f"{name} ({'direct' if direct else 'transitive via ' + ', '.join(via_pk[:3])}): "
                                f"{'; '.join(titles[:2]) or 'see advisory'}",
                                f"{meta['project']}/package.json", 0, f"range {v.get('range')}; {fix_txt}",
                                "Upgrade, run the test suite, and re-run the audit. Prefer `npm audit fix` without --force; "
                                "handle semver-major bumps one by one.", "high", "audit_deps", package=name, direct=direct))
    meta["audit"] = " ".join(cmd)
    meta["counts"] = (data.get("metadata") or {}).get("vulnerabilities")
    return findings, meta


def _unused_js(proj: Path, root: Path) -> List[dict]:
    pkg_path = proj / "package.json"
    try:
        pkg = json.loads(read_text(pkg_path))
    except json.JSONDecodeError:
        return []
    deps: Dict[str, str] = dict(pkg.get("dependencies") or {})
    if not deps:
        return []
    scripts = json.dumps(pkg.get("scripts") or {})
    corpus_parts = []
    for p in iter_files(proj, max_bytes=800_000):
        if p.name == "package.json" and p.parent == proj:
            continue
        if p.suffix.lower() in {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".vue", ".svelte", ".astro", ".json",
                                ".css", ".scss", ".html", ".md", ".mdx", ".yml", ".yaml"} or p.name.startswith((".babelrc", ".eslintrc")):
            corpus_parts.append(read_text(p))
    corpus = "\n".join(corpus_parts)
    out = []
    for name in sorted(deps):
        if IMPLICIT.match(name):
            continue
        esc = re.escape(name)
        pat = rf"""(?:from\s+|require\(\s*|import\(\s*|import\s+)['"]{esc}(?:/[^'"]*)?['"]|['"]{esc}(?:/[^'"]*)?['"]"""
        if re.search(pat, corpus) or re.search(rf"(?<![\w@/-]){esc}(?![\w-])", scripts):
            continue
        if name.startswith("@types/"):
            continue
        out.append(finding("possibly-unused-dependency", "S22", "low", f"Possibly unused dependency: {name}",
                           f"{rel(root, proj) or '.'}/package.json", 0, f'"{name}": "{deps[name]}"',
                           "Confirm it isn't loaded dynamically/by config, then `npm uninstall` it (less code = less attack "
                           "surface and smaller bundles).", "medium", "audit_deps", package=name))
    for name in deps:
        if name in DEPRECATED:
            out.append(finding("risky-dependency", "S21", "medium", f"{name}: {DEPRECATED[name]}",
                               f"{rel(root, proj) or '.'}/package.json", 0, f'"{name}": "{deps[name]}"',
                               "Replace with the suggested alternative.", "high", "audit_deps", package=name))
    for name, ver in deps.items():
        if ver.strip() in {"*", "latest", ""} or ver.startswith(("git+", "github:", "http:", "https:")):
            out.append(finding("unpinned-dependency", "S21", "low", f"{name} uses an unpinned/remote version spec ({ver})",
                               f"{rel(root, proj) or '.'}/package.json", 0, f'"{name}": "{ver}"',
                               "Pin to a semver range and rely on the lockfile.", "high", "audit_deps", package=name))
    return out


def _python(root: Path, offline: bool) -> (List[dict], dict):
    reqs = [p for p in (root / "requirements.txt", root / "requirements-prod.txt", root / "pyproject.toml") if p.exists()]
    if not reqs:
        return [], {}
    meta = {"python": "found " + ", ".join(rel(root, p) for p in reqs)}
    if offline:
        meta["python_audit"] = "skipped (--offline)"
        return [], meta
    if not shutil.which("pip-audit"):
        meta["python_audit"] = "pip-audit not installed (pip install pip-audit) — run it manually"
        return [], meta
    findings = []
    target = ["-r", str(reqs[0])] if reqs[0].name.startswith("requirements") else [str(root)]
    r = run(["pip-audit", "--format", "json", "--progress-spinner", "off"] + target, cwd=root, timeout=300)
    try:
        data = json.loads(r.stdout)
    except json.JSONDecodeError:
        meta["python_audit"] = f"failed: {(r.stderr or r.stdout)[:300]}"
        return [], meta
    deps = data.get("dependencies", data) if isinstance(data, dict) else data
    for d in deps or []:
        for v in d.get("vulns", []):
            findings.append(finding("vulnerable-dependency", "S21", "high", f"{d.get('name')} {d.get('version')}: {v.get('id')}",
                                    rel(root, reqs[0]), 0, f"fix versions: {', '.join(v.get('fix_versions') or []) or 'none'}",
                                    "Upgrade and re-test.", "high", "audit_deps", package=d.get("name")))
    meta["python_audit"] = "pip-audit"
    return findings, meta


def _composer(root: Path, offline: bool) -> (List[dict], dict):
    if not (root / "composer.lock").exists():
        return [], ({"composer": "composer.json without composer.lock"} if (root / "composer.json").exists() else {})
    if offline or not shutil.which("composer"):
        return [], {"composer_audit": "skipped (offline or composer not installed)"}
    r = run(["composer", "audit", "--format=json", "--no-interaction"], cwd=root, timeout=300)
    try:
        data = json.loads(r.stdout)
    except json.JSONDecodeError:
        return [], {"composer_audit": f"failed: {(r.stderr or r.stdout)[:300]}"}
    findings = []
    for pkg, advs in (data.get("advisories") or {}).items():
        for adv in (advs.values() if isinstance(advs, dict) else advs):
            findings.append(finding("vulnerable-dependency", "S21", "high", f"{pkg}: {adv.get('title')}", "composer.lock", 0,
                                    f"affected {adv.get('affectedVersions')}", "composer update the package and re-test.",
                                    "high", "audit_deps", package=pkg))
    return findings, {"composer_audit": "composer audit"}


def scan(root: Path, offline: bool = False) -> dict:
    root = root.resolve()
    findings: List[dict] = []
    meta: Dict[str, object] = {"js_projects": []}
    for proj in _js_projects(root):
        f, m = _npm_audit(proj, root, offline)
        findings += f
        findings += _unused_js(proj, root)
        meta["js_projects"].append(m)  # type: ignore[union-attr]
    f, m = _python(root, offline)
    findings += f
    meta.update(m)
    f, m = _composer(root, offline)
    findings += f
    meta.update(m)
    return {"scanner": "audit_deps", "root": str(root), "findings": sort_findings(findings), "meta": meta}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("project")
    ap.add_argument("--json")
    ap.add_argument("--offline", action="store_true", help="skip registry-backed audits")
    a = ap.parse_args(argv)
    res = scan(Path(a.project), a.offline)
    print(f"audit_deps: {len(res['findings'])} finding(s)")
    for m in res["meta"].get("js_projects", []):
        print(f"  npm project {m.get('project')}: {m.get('audit')} {m.get('counts') or ''}")
    for k in ("python_audit", "composer_audit"):
        if k in res["meta"]:
            print(f"  {k}: {res['meta'][k]}")
    print_table(res["findings"])
    if a.json:
        write_json(Path(a.json), res)
    return 0


if __name__ == "__main__":
    sys.exit(main())
