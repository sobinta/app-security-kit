#!/usr/bin/env python3
"""Scan the whole git history (all branches) for secrets and sensitive files.

Step S24 of the kit. A secret that was committed and later deleted is still in
history (and in every clone/fork), so it must be rotated (S25) even if the
current code is clean. Output is masked.

Usage:
  python3 scan_git_history.py <project_dir> [--json out.json] [--max-commits 5000]
"""
from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path
from typing import Dict, List

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _common import finding, git_tracked_files, is_git_repo, looks_placeholder, mask_in_line, print_table, run, \
    shannon_entropy, sort_findings, write_json  # noqa: E402
from scan_secrets import GENERIC_EXTS, GENERIC_RE, JWT_RE, PROVIDER_RULES, decode_jwt_payload, fingerprint  # noqa: E402

SENSITIVE_FILE_RULES = [
    (re.compile(r"(^|/)\.env(\.(?!example$|sample$|template$|dist$|defaults$)[\w.\-]+)?$", re.I), "critical", "environment file"),
    (re.compile(r"(^|/)(id_rsa|id_dsa|id_ecdsa|id_ed25519)(\.\w+)?$|\.(pem|p12|pfx|keystore|jks|ppk|kdbx|ovpn)$", re.I),
     "critical", "private key / credential store"),
    (re.compile(r"(credentials|service[-_]?account|firebase-adminsdk|client_secret)[^/]*\.json$", re.I), "critical",
     "cloud credentials JSON"),
    (re.compile(r"\.tfstate(\.backup)?$|\.tfvars$", re.I), "critical", "Terraform state/vars (contains secrets)"),
    (re.compile(r"(^|/)(\.htpasswd|\.npmrc|\.pypirc|\.netrc|sftp\.json|\.git-credentials)$", re.I), "high",
     "credential config"),
    (re.compile(r"\.(sql|dump|sqlite3?|db)(\.gz|\.zip)?$", re.I), "high", "database dump (may hold PII / password hashes)"),
    (re.compile(r"(^|/)(backup|bak|dump|db|site|www|public_html)[^/]*\.(zip|tar|tar\.gz|tgz|rar|7z)$|\.(bak|backup|old|orig)$", re.I),
     "high", "backup archive / backup copy"),
    (re.compile(r"(^|/)(wp-config\.php|configuration\.php|settings\.php|local\.xml)$", re.I), "high",
     "CMS config with DB credentials"),
]
EXCLUDES = [":(exclude)*package-lock.json", ":(exclude)*yarn.lock", ":(exclude)*pnpm-lock.yaml",
            ":(exclude)*composer.lock", ":(exclude)*.min.js", ":(exclude)*.map", ":(exclude)*poetry.lock",
            ":(exclude)*Pipfile.lock", ":(exclude)*go.sum", ":(exclude)*.svg"]


MIGRATION_PATH = re.compile(r"(^|/)(migrations?|supabase|prisma|db/migrate|database/(migrations|schema)|schema|sql/schema)/"
                            r"|(^|/)(schema|structure)\.sql$", re.I)


def _lines(proc: subprocess.Popen):
    try:
        for raw in proc.stdout:  # type: ignore[union-attr]
            yield raw
    finally:
        proc.stdout.close()  # type: ignore[union-attr]
        proc.wait()


def _classify_file(path: str):
    if MIGRATION_PATH.search(path) and re.search(r"\.sql$", path, re.I):
        return None  # schema/migration files are expected in repos
    for rx, sev, label in SENSITIVE_FILE_RULES:
        if rx.search(path):
            return sev, label
    return None


def scan(root: Path, max_commits: int = 5000) -> dict:
    root = root.resolve()
    if not is_git_repo(root):
        return {"scanner": "scan_git_history", "root": str(root), "findings": [],
                "meta": {"skipped": "not a git repository"}}
    meta: Dict[str, object] = {}
    sh = run(["git", "-C", str(root), "rev-parse", "--is-shallow-repository"], timeout=20)
    meta["shallow"] = sh.stdout.strip() == "true"
    cnt = run(["git", "-C", str(root), "rev-list", "--all", "--count"], timeout=60)
    meta["commits_total"] = int(cnt.stdout.strip() or 0) if cnt.returncode == 0 else None

    secrets: Dict[str, dict] = {}
    cmd = ["git", "-C", str(root), "log", "--all", f"--max-count={max_commits}", "-p", "--no-color", "--no-ext-diff",
           "--unified=0", "--date=short", "--pretty=format:@@@COMMIT %H %ad%n@@@SUBJ %s", "--", "."] + EXCLUDES
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, errors="replace")
    commit, date, subject, cur_file = "", "", "", ""
    commits_seen = 0
    assert proc.stdout is not None
    for raw in _lines(proc):
        line = raw.rstrip("\n")
        if line.startswith("@@@COMMIT "):
            parts = line.split(" ")
            commit, date = parts[1], parts[2] if len(parts) > 2 else ""
            commits_seen += 1
            continue
        if line.startswith("@@@SUBJ "):
            subject = line[8:]
            continue
        if line.startswith("diff --git "):
            m = re.match(r"diff --git a/(.*) b/(.*)", line)
            cur_file = m.group(2) if m else ""
            continue
        if not line.startswith("+") or line.startswith("+++") or len(line) > 5000:
            continue
        content = line[1:]
        hits = []
        for rid, title, rx, sev in PROVIDER_RULES:
            for m in rx.finditer(content):
                s = m.group("s")
                if rid in {"db-url-with-password", "url-basic-auth"}:
                    pw = re.search(r"://[^:/@\s]+:([^@\s]+)@", s)
                    if pw and (looks_placeholder(pw.group(1)) or pw.group(1).startswith("$")):
                        continue
                hits.append((rid, title, sev, s))
        for m in JWT_RE.finditer(content):
            payload = decode_jwt_payload(m.group("s")) or {}
            if payload.get("role") == "service_role":
                hits.append(("supabase-service-role-jwt", "Supabase service_role key", "critical", m.group("s")))
        ext = "." + cur_file.rsplit(".", 1)[-1].lower() if "." in cur_file else ""
        if ext in GENERIC_EXTS or "/.env" in "/" + cur_file:
            for m in GENERIC_RE.finditer(content):
                s = m.group("s")
                if looks_placeholder(s) or s.startswith(("/", "./", "http", "$", "{", "%", "process.")):
                    continue
                if shannon_entropy(s) >= 3.5 and len(s) >= 12:
                    hits.append(("hardcoded-secret", f"Secret in '{m.group('name')}'", "high", s))
        for rid, title, sev, s in hits:
            fp = fingerprint(s)
            entry = secrets.get(fp)
            info = {"commit": commit[:10], "date": date, "file": cur_file, "subject": subject[:80]}
            if entry is None:
                secrets[fp] = {"rule": rid, "title": title, "severity": sev, "secret": s,
                               "evidence": mask_in_line(content, s), "newest": info, "oldest": info,
                               "files": {cur_file}}
            else:
                entry["oldest"] = info  # git log goes newest -> oldest
                entry["evidence"] = mask_in_line(content, s)
                entry["files"].add(cur_file)
    meta["commits_scanned"] = commits_seen

    findings: List[dict] = []
    rotation: List[dict] = []
    for fp, e in list(secrets.items())[:300]:
        g = run(["git", "-C", str(root), "grep", "-l", "-a", "-F", "-e", e["secret"], "HEAD", "--", "."], timeout=60)
        head_files = sorted({ln.split(":", 1)[1] if ":" in ln else ln for ln in g.stdout.splitlines() if ln.strip()})
        in_head = bool(head_files)
        where = e["oldest"]
        title = (f"{e['title']} in git history (added {where['date']} in {where['commit']} "
                 f"'{where['subject']}', file {where['file']})" +
                 (f"; STILL in HEAD ({', '.join(head_files[:3])})" if in_head else "; deleted later but still in history"))
        findings.append(finding("history-" + e["rule"], "S24", e["severity"], title, where["file"], 0, e["evidence"],
                                "Treat as leaked: revoke/rotate it at the provider NOW (S25), update the new value in the "
                                "server env, redeploy, then optionally purge history (git filter-repo) — rotation first, "
                                "purging alone does not help because clones/forks/caches keep it.",
                                "high", "scan_git_history", fingerprint=fp, still_in_head=in_head,
                                files=sorted(e["files"]), first_commit=where["commit"], last_commit=e["newest"]["commit"]))
        rotation.append({"provider_rule": e["rule"], "masked": e["evidence"], "fingerprint": fp,
                         "first_seen": where, "still_in_head": in_head})

    # Sensitive files ever added to history
    tracked = git_tracked_files(root)
    ns = run(["git", "-C", str(root), "log", "--all", f"--max-count={max_commits}", "--diff-filter=AD", "--name-status",
              "--date=short", "--pretty=format:@@@COMMIT %H %ad"], timeout=300)
    added: Dict[str, dict] = {}
    deleted: Dict[str, dict] = {}
    commit, date = "", ""
    for line in ns.stdout.splitlines():
        if line.startswith("@@@COMMIT "):
            parts = line.split(" ")
            commit, date = parts[1][:10], parts[2] if len(parts) > 2 else ""
            continue
        m = re.match(r"^([AD])\t(.+)$", line)
        if not m:
            continue
        status, path = m.group(1), m.group(2)
        if not _classify_file(path):
            continue
        if status == "A":
            added[path] = {"commit": commit, "date": date}  # ends with the oldest add
        else:
            deleted.setdefault(path, {"commit": commit, "date": date})
    for path, a in added.items():
        sev, label = _classify_file(path)  # type: ignore[misc]
        still = path in tracked
        state = "still tracked in HEAD" if still else (
            f"deleted in {deleted[path]['commit']} ({deleted[path]['date']}) but recoverable from history"
            if path in deleted else "not in HEAD (other branch?)")
        findings.append(finding("history-sensitive-file", "S24", sev,
                                f"Sensitive file ever committed: {path} ({label}); added {a['date']} in {a['commit']}; {state}",
                                path, 0, "", "Rotate any credentials it contained; if it held user data, assess "
                                "breach-notification duties; purge from history with git filter-repo after rotation.",
                                "high", "scan_git_history", still_in_head=still))

    meta["unique_secrets"] = len(secrets)
    meta["rotation_candidates"] = rotation
    return {"scanner": "scan_git_history", "root": str(root), "findings": sort_findings(findings), "meta": meta}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("project")
    ap.add_argument("--json")
    ap.add_argument("--max-commits", type=int, default=5000)
    a = ap.parse_args(argv)
    res = scan(Path(a.project), a.max_commits)
    m = res["meta"]
    if m.get("skipped"):
        print(f"scan_git_history: skipped ({m['skipped']})")
    else:
        print(f"scan_git_history: {len(res['findings'])} finding(s); scanned {m.get('commits_scanned')} of "
              f"{m.get('commits_total')} commits" + (" — SHALLOW clone: older history not available" if m.get("shallow") else ""))
    print_table(res["findings"])
    if a.json:
        write_json(Path(a.json), res)
    return 0


if __name__ == "__main__":
    sys.exit(main())
