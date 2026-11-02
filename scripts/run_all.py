#!/usr/bin/env python3
"""Run every static scanner of the kit in one go and write a step-by-step summary.

  detect_stack → scan_secrets → scan_git_history → scan_exposed_files → scan_code_patterns → audit_deps
  (+ check_live when --url is given)

Outputs (default <project>/security-audit/scan/):
  findings.json  all findings with ids (SEC-001 ...), masked secrets
  summary.md     findings grouped by the 27 steps + extra checks, scanner status, keys to rotate
  stack.json     detected stack / features / references to read / steps that are probably N/A

Usage:
  python3 run_all.py <project_dir> [--out DIR] [--url http://localhost:3000] [--offline] [--insecure]
"""
from __future__ import annotations

import argparse
import datetime as dt
import sys
import time
import traceback
from pathlib import Path
from typing import Dict, List

sys.path.insert(0, str(Path(__file__).resolve().parent))
import audit_deps  # noqa: E402
import detect_stack  # noqa: E402
import scan_code_patterns  # noqa: E402
import scan_exposed_files  # noqa: E402
import scan_git_history  # noqa: E402
import scan_secrets  # noqa: E402
from _common import SEVERITY_ORDER, STEPS, dedupe, sort_findings, write_json  # noqa: E402

MANUAL_STEPS = {
    "S01": "verify login/session logic, logout, session expiry, 2FA for admins",
    "S03": "verify every table/collection is protected (RLS/rules) and DB only reachable from the server",
    "S06": "check every handler validates input on the server (types, ranges, lengths)",
    "S08": "confirm failed logins / 403s / rate-limit hits are logged and alerting exists",
    "S09": "log in as a normal user and try every admin URL & API",
    "S16": "try a cross-site form POST against state-changing endpoints",
    "S17": "request a reset link: expires ≤ 15-60 min, single use, invalidated after password change",
    "S19": "tamper price/quantity/coupon in the request; verify server recomputes & verifies payment",
    "S25": "rotate every key found in code/history/bundles at the provider and confirm the old one fails",
    "S26": "manual review pass over the riskiest flows (auth, payments, uploads, admin, multi-tenant data)",
    "S27": "write/run security regression tests + live checks, then write the report",
}


def run_scanner(name, fn, log):
    t0 = time.time()
    try:
        res = fn()
        log.append(f"- {name}: ok ({len(res.get('findings', []))} findings, {time.time() - t0:.1f}s)")
        return res
    except Exception as e:  # noqa: BLE001 - one failing scanner must not kill the run
        log.append(f"- {name}: FAILED — {type(e).__name__}: {e}")
        traceback.print_exc()
        return {"scanner": name, "findings": [], "meta": {"error": str(e)}}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("project")
    ap.add_argument("--out")
    ap.add_argument("--url", help="also run live checks against a running instance you own")
    ap.add_argument("--api", help="API path for live CORS/debug checks")
    ap.add_argument("--offline", action="store_true", help="skip registry-backed dependency audits")
    ap.add_argument("--insecure", action="store_true")
    ap.add_argument("--max-commits", type=int, default=5000)
    ap.add_argument("--fail-on", choices=["critical", "high", "medium"],
                    help="exit 1 if any high-confidence finding at/above this severity (CI / pre-deploy gate)")
    a = ap.parse_args(argv)

    root = Path(a.project).resolve()
    if not root.is_dir():
        print(f"not a directory: {root}")
        return 2
    out = Path(a.out).resolve() if a.out else root / "security-audit" / "scan"
    out.mkdir(parents=True, exist_ok=True)
    log: List[str] = []
    stack = run_scanner("detect_stack", lambda: {"findings": [], **detect_stack.detect(root)}, log)
    results = [
        run_scanner("scan_secrets", lambda: scan_secrets.scan(root), log),
        run_scanner("scan_git_history", lambda: scan_git_history.scan(root, a.max_commits), log),
        run_scanner("scan_exposed_files", lambda: scan_exposed_files.scan_local(root), log),
        run_scanner("scan_code_patterns", lambda: scan_code_patterns.scan(root), log),
        run_scanner("audit_deps", lambda: audit_deps.scan(root, a.offline), log),
    ]
    if a.url:
        import check_live  # noqa: E402
        results.append(run_scanner("check_live", lambda: check_live.check(a.url, a.api, None, None, None, False, 12,
                                                                          a.insecure), log))
    findings = sort_findings(dedupe(f for r in results for f in r.get("findings", [])))
    for i, f in enumerate(findings, 1):
        f["id"] = f"SEC-{i:03d}"
    by_step: Dict[str, List[dict]] = {}
    for f in findings:
        by_step.setdefault(f["step"], []).append(f)
    counts = {s: sum(1 for f in findings if f["severity"] == s) for s in SEVERITY_ORDER}

    write_json(out / "findings.json", {"generated": dt.datetime.now().isoformat(timespec="seconds"), "root": str(root),
                                       "counts": counts, "findings": findings,
                                       "scanner_meta": {r.get("scanner", "?"): r.get("meta") for r in results}})
    write_json(out / "stack.json", stack)

    na = stack.get("probably_not_applicable", {}) if isinstance(stack, dict) else {}
    L = [f"# Automated scan summary — {root.name}", "",
         f"_Generated {dt.datetime.now():%Y-%m-%d %H:%M}. Leads, not verdicts: confirm each one in the code, discard false "
         "positives with a note, and do the manual checks listed for steps without automated coverage._", "",
         "**Counts:** " + " · ".join(f"{k}: {v}" for k, v in counts.items()), "",
         "**Stack:** " + ", ".join(stack.get("frameworks", []) + stack.get("data_stores", [])) if isinstance(stack, dict) else "",
         "**Features:** " + ", ".join(stack.get("features", [])) if isinstance(stack, dict) else "",
         "**Read:** " + ", ".join(stack.get("references_to_read", [])) if isinstance(stack, dict) else "", "",
         "## Scanners", *log, ""]
    for r in results:
        m = r.get("meta") or {}
        if r.get("scanner") == "audit_deps":
            for p in m.get("js_projects", []):
                L.append(f"- npm audit [{p.get('project')}]: {p.get('audit')} {p.get('counts') or ''}")
            for k in ("python_audit", "composer_audit"):
                if k in m:
                    L.append(f"- {k}: {m[k]}")
        if r.get("scanner") == "scan_git_history" and m.get("shallow"):
            L.append("- WARNING: shallow clone — fetch full history (`git fetch --unshallow`) and re-run S24")
    L += ["", "## By step (27-step kit)", ""]
    for sid in [s for s in STEPS if s.startswith("S")] + [s for s in STEPS if s.startswith("X")]:
        items = by_step.get(sid, [])
        head = f"### {sid} — {STEPS[sid]['en']} / {STEPS[sid]['fa']}"
        if not items:
            if sid.startswith("X"):
                continue
            note = na.get(sid)
            L += [head, "- No automated leads." + (f" Probably N/A: {note}." if note else "") +
                  (f" Manual check: {MANUAL_STEPS[sid]}." if sid in MANUAL_STEPS else ""), ""]
            continue
        L.append(head)
        for f in items[:12]:
            loc = f"`{f['file']}:{f['line']}`" if f.get("file") and f.get("line") else (f"`{f['file']}`" if f.get("file") else "project-wide")
            L.append(f"- **{f['id']}** [{f['severity']}/{f['confidence']}] {f['title']} — {loc}")
            if f.get("evidence"):
                L.append(f"  - evidence: `{f['evidence'][:150].replace('`', "'")}`")
        if len(items) > 12:
            L.append(f"- … {len(items) - 12} more in findings.json")
        if sid in MANUAL_STEPS:
            L.append(f"- Manual check: {MANUAL_STEPS[sid]}")
        L.append("")
    rot = []
    for r in results:
        if r.get("scanner") == "scan_git_history":
            rot = (r.get("meta") or {}).get("rotation_candidates", [])
    live_keys = [f for f in findings if f["source"] == "scan_secrets" and f["severity"] in ("critical", "high")
                 and f["rule"] not in {"env-file-not-ignored", "gitignore-missing-env", "weak-signing-secret", "debug-in-prod-env"}]
    if rot or live_keys:
        L += ["## Keys to rotate (S25) — Claude cannot do this; the owner must, at each provider", ""]
        for f in live_keys:
            L.append(f"- [ ] {f['title']} — `{f['file']}:{f['line']}` — `{f['evidence'][:100]}`")
        for c in rot:
            fs = c.get("first_seen", {})
            L.append(f"- [ ] {c.get('provider_rule')} from git history (first {fs.get('date')} {fs.get('commit')} "
                     f"{fs.get('file')}) — `{c.get('masked', '')[:100]}`" + (" — still in HEAD" if c.get("still_in_head") else ""))
        L.append("")
    (out / "summary.md").write_text("\n".join(L), encoding="utf-8")
    print("\n".join(log))
    print(f"\n{len(findings)} findings → {out / 'findings.json'}\nsummary → {out / 'summary.md'}")
    print("counts: " + ", ".join(f"{k}={v}" for k, v in counts.items()))
    print("Tip: keep security-audit/scan/ out of git (it lists weaknesses); commit only the final report if you want.")
    if a.fail_on:
        limit = SEVERITY_ORDER[a.fail_on]
        blocking = [f for f in findings if SEVERITY_ORDER.get(f["severity"], 9) <= limit and f.get("confidence") != "low"
                    and not f.get("missing_control")]
        if blocking:
            print(f"FAIL: {len(blocking)} finding(s) at or above '{a.fail_on}' (first: {blocking[0]['id']} {blocking[0]['title']})")
            return 1
        print(f"PASS: nothing at or above '{a.fail_on}'")
    return 0


if __name__ == "__main__":
    sys.exit(main())
