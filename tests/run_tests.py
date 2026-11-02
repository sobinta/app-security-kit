#!/usr/bin/env python3
"""Self-tests for app-security-kit.

Scaffolds the deliberately vulnerable sample apps from evals/ into temp folders
and checks that the scanners find what was planted, stay quiet where they
should, never print full secrets, and that the live/load/race tools behave.

Run from the repo root:   python3 tests/run_tests.py  [-v]
Needs: python3 (3.8+), git, bash. Node.js (18+) is optional — without it the
live/load/race tests are skipped. No network access is needed.
"""
from __future__ import annotations

import io
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import unittest
import urllib.request
from contextlib import redirect_stdout
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
EVALS = ROOT / "evals"
sys.path.insert(0, str(SCRIPTS))

import audit_deps  # noqa: E402
import check_live  # noqa: E402
import detect_stack  # noqa: E402
import list_routes  # noqa: E402
import load_test  # noqa: E402
import race_test  # noqa: E402
import run_all  # noqa: E402
import scan_code_patterns  # noqa: E402
import scan_exposed_files  # noqa: E402
import scan_git_history  # noqa: E402
import scan_secrets  # noqa: E402

NODE = shutil.which("node")
SECRET_RX = re.compile(r"(?:sk|rk)_(?:live|test)_[0-9A-Za-z]{16,}|sk-proj-[A-Za-z0-9_\-]{20,}|"
                       r"eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}")


def scaffold(case: str) -> Path:
    tmp = Path(tempfile.mkdtemp(prefix="ask-selftest-"))
    subprocess.run(["bash", str(EVALS / case / "place-files.sh")], cwd=tmp, check=True, capture_output=True)
    return tmp


def rules(result: dict) -> set:
    return {f["rule"] for f in result["findings"]}


def quiet(fn, *args, **kwargs):
    buf = io.StringIO()
    with redirect_stdout(buf):
        rv = fn(*args, **kwargs)
    return rv, buf.getvalue()


def free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


class GolkhoonehStatic(unittest.TestCase):
    """Express + SQLite shop with all 27 problems planted (see evals/fa-full-audit-golkhooneh)."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = scaffold("fa-full-audit-golkhooneh")
        cls.app = cls.tmp / "golkhooneh"
        env = (cls.app / ".env").read_text()
        cls.real_secrets = SECRET_RX.findall(env) + SECRET_RX.findall((cls.app / "public/app.js").read_text())
        cls.secrets = scan_secrets.scan(cls.app)
        cls.history = scan_git_history.scan(cls.app)
        cls.code = scan_code_patterns.scan(cls.app)
        cls.exposed = scan_exposed_files.scan_local(cls.app)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def test_client_key_is_critical(self):
        hits = [f for f in self.secrets["findings"] if f["file"] == "public/app.js"]
        self.assertTrue(hits, "API key in public/app.js not found")
        self.assertEqual(hits[0]["severity"], "critical")
        self.assertTrue(hits[0]["client_exposed"])

    def test_private_env_not_reported_as_leak(self):
        leaks = [f for f in self.secrets["findings"] if f["file"] == ".env" and f["rule"] in {"stripe-live-secret", "openai-api-key"}]
        self.assertEqual(leaks, [], "a git-ignored, non-public .env is the right place for secrets")
        self.assertIn("weak-signing-secret", rules(self.secrets))

    def test_git_history(self):
        r = rules(self.history)
        self.assertIn("history-stripe-live-secret", r)
        self.assertIn("history-sensitive-file", r)
        stripe = [f for f in self.history["findings"] if f["rule"] == "history-stripe-live-secret"][0]
        self.assertIn("add payment keys", stripe["title"])
        self.assertGreaterEqual(len(self.history["meta"]["rotation_candidates"]), 2)

    def test_code_patterns_cover_the_27_steps(self):
        expected = {
            "unsigned-identity-cookie", "client-sql-executed", "client-sends-sql", "js-sql-concatenation",
            "js-sql-template-interpolation", "reflected-xss-template", "js-innerhtml-assign", "admin-route-no-role",
            "cors-wildcard", "cookie-flags", "weak-random-token", "reset-token-no-expiry", "price-destructured-from-body",
            "client-sends-price", "upload-no-limits", "upload-original-name", "stack-trace-in-response",
            "secret-env-in-response", "idor-by-id", "js-open-redirect", "js-path-traversal", "plaintext-password-compare",
            "no-rate-limiting", "no-security-headers", "no-csrf-protection", "no-password-hashing", "user-enumeration",
            "request-body-logged", "http-url-in-code", "js-prototype-pollution",
        }
        missing = expected - rules(self.code)
        self.assertFalse(missing, f"rules not triggered: {sorted(missing)}")
        steps = {f["step"] for f in self.code["findings"]}
        for s in ("S01", "S03", "S05", "S07", "S09", "S10", "S12", "S13", "S14", "S15", "S16", "S17", "S18", "S19", "S20"):
            self.assertIn(s, steps)

    def test_exposed_backup(self):
        self.assertTrue(any(f["file"] == "public/backup.zip" for f in self.exposed["findings"]))

    def test_unused_and_vulnerable_deps_offline(self):
        r = audit_deps.scan(self.app, offline=True)
        unused = {f["package"] for f in r["findings"] if f["rule"] == "possibly-unused-dependency"}
        self.assertTrue({"left-pad", "moment", "jsonwebtoken"} <= unused, unused)
        self.assertNotIn("express", unused)

    def test_routes_inventory(self):
        routes = list_routes.scan(self.app)
        paths = {r["path"] for r in routes}
        self.assertIn("/api/admin/users", paths)
        self.assertGreaterEqual(len(routes), 20)

    def test_stack_detection(self):
        st = detect_stack.detect(self.app)
        self.assertIn("express", st["frameworks"])
        self.assertIn("references/stacks/node-express.md", st["references_to_read"])

    def test_no_full_secret_in_any_output(self):
        blob = json.dumps([self.secrets, self.history, self.code, self.exposed])
        for s in self.real_secrets:
            self.assertNotIn(s, blob, "a full secret leaked into scanner output")

    def test_run_all_writes_summary_and_gates(self):
        out = self.tmp / "scan"
        rc, _ = quiet(run_all.main, [str(self.app), "--out", str(out), "--offline", "--fail-on", "critical"])
        self.assertEqual(rc, 1, "--fail-on critical must fail on this app")
        summary = (out / "summary.md").read_text(encoding="utf-8")
        self.assertIn("S27", summary)
        self.assertIn("Keys to rotate", summary)
        for s in self.real_secrets:
            self.assertNotIn(s, summary)
            self.assertNotIn(s, (out / "findings.json").read_text(encoding="utf-8"))


class VisaPortalStatic(unittest.TestCase):
    """Next.js 14 + Supabase portal (see evals/nextjs-supabase-audit-only)."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = scaffold("nextjs-supabase-audit-only")
        cls.app = cls.tmp / "visa-portal"
        cls.real_secrets = SECRET_RX.findall((cls.app / ".env.local").read_text())
        cls.secrets = scan_secrets.scan(cls.app)
        cls.history = scan_git_history.scan(cls.app)
        cls.code = scan_code_patterns.scan(cls.app)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def test_service_role_and_env(self):
        r = rules(self.secrets)
        self.assertTrue({"supabase-service-role-jwt", "public-env-secret", "env-file-committed"} <= r, r)
        anon = [f for f in self.secrets["findings"] if "anon" in f.get("evidence", "").lower() and f["rule"] == "hardcoded-jwt"]
        self.assertEqual(anon, [], "the anon key is public by design and must not be reported as a leak")

    def test_supabase_and_nextjs_rules(self):
        expected = {
            "admin-client-in-client-component", "supabase-table-without-rls", "public-storage-bucket", "view-bypasses-rls",
            "sql-policy-using-true", "webhook-unverified", "ai-endpoint-unprotected", "nextjs-middleware-bypass",
            "server-action-no-auth", "form-object-from-entries", "supabase-idor-eq-param", "js-dangerously-set-inner-html",
            "source-maps-in-prod", "long-signed-url", "price-from-client", "route-handler-no-auth", "middleware-only-auth",
            "error-details-in-response",
        }
        missing = expected - rules(self.code)
        self.assertFalse(missing, f"rules not triggered: {sorted(missing)}")
        no_rls = {f["title"] for f in self.code["findings"] if f["rule"] == "supabase-table-without-rls"}
        self.assertEqual(len(no_rls), 3, no_rls)

    def test_migrations_are_not_sensitive_files(self):
        self.assertFalse([f for f in self.history["findings"] if f["file"].endswith(".sql")])

    def test_no_full_secret_in_any_output(self):
        blob = json.dumps([self.secrets, self.history, self.code])
        for s in self.real_secrets:
            self.assertNotIn(s, blob)


@unittest.skipUnless(NODE, "node not installed")
class ShopApiLive(unittest.TestCase):
    """Dependency-free Node API with a CPU bottleneck, a coupon race and a memory leak."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = scaffold("fa-load-and-race-shop-api")
        cls.port = free_port()
        cls.base = f"http://127.0.0.1:{cls.port}"
        cls.proc = subprocess.Popen([NODE, "server.js"], cwd=cls.tmp / "shop-api", env={**os.environ, "PORT": str(cls.port)},
                                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        for _ in range(50):
            try:
                urllib.request.urlopen(cls.base + "/health", timeout=1)
                break
            except Exception:  # noqa: BLE001
                time.sleep(0.1)

    @classmethod
    def tearDownClass(cls):
        cls.proc.terminate()
        cls.proc.wait(timeout=5)
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def test_race_detected(self):
        rc, out = quiet(race_test.main, [self.base + "/api/coupons/redeem", "-X", "POST", "--json", '{"code":"WELCOME50"}',
                                         "-H", "x-user: selftest", "-n", "15", "--max-success", "1"])
        self.assertEqual(rc, 1, out)
        self.assertIn("RACE CONDITION", out)

    def test_load_test_runs_and_reports(self):
        out_json = self.tmp / "load.json"
        rc, out = quiet(load_test.main, [self.base + "/health", "--stages", "1s:10,3s:10", "--think", "0", "--quiet",
                                         "--watch-pid", str(self.proc.pid), "--json-out", str(out_json)])
        self.assertIn(rc, (0, 1))
        data = json.loads(out_json.read_text())
        self.assertGreater(data["requests"], 50)
        self.assertEqual(data["error_rate_pct"], 0.0)
        self.assertIsNotNone(data["server_memory"])

    def test_check_live_finds_missing_headers(self):
        res = check_live.check(self.base + "/", "/api/products", None, None, None, False, 5, False)
        r = rules(res)
        self.assertIn("missing-csp", r)
        self.assertIn("clickjacking", r)

    def test_refuses_foreign_targets(self):
        rc, out = quiet(load_test.main, ["https://example.com/", "--profile", "smoke"])
        self.assertEqual(rc, 2)
        rc, out = quiet(race_test.main, ["https://example.com/x", "-n", "2"])
        self.assertEqual(rc, 2)


class Cli(unittest.TestCase):
    def test_every_script_has_help(self):
        for p in sorted(SCRIPTS.glob("*.py")):
            if p.name.startswith("_"):
                continue
            r = subprocess.run([sys.executable, str(p), "--help"], capture_output=True, text=True, timeout=60)
            self.assertEqual(r.returncode, 0, f"{p.name} --help failed: {r.stderr[:300]}")

    def test_skill_frontmatter(self):
        text = (ROOT / "SKILL.md").read_text(encoding="utf-8")
        m = re.match(r"---\nname: ([a-z0-9-]+)\ndescription: (.+?)\n---\n", text, re.S)
        self.assertIsNotNone(m, "SKILL.md frontmatter malformed")
        self.assertEqual(m.group(1), "app-security-kit")
        self.assertLessEqual(len(m.group(2)), 1024)
        self.assertLess(text.count("\n"), 500, "keep SKILL.md under 500 lines")

    def test_referenced_files_exist(self):
        text = (ROOT / "SKILL.md").read_text(encoding="utf-8")
        for ref in set(re.findall(r"`((?:references|assets|scripts)/[\w./-]+\.(?:md|py|yml|conf|js|txt))`", text)):
            self.assertTrue((ROOT / ref).exists(), f"SKILL.md references missing file {ref}")


if __name__ == "__main__":
    unittest.main(verbosity=2 if "-v" in sys.argv else 1, argv=[sys.argv[0]])
