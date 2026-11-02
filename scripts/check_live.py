#!/usr/bin/env python3
"""Black-box checks against a RUNNING app you own (local, staging, or — with the
owner's explicit OK — production). Verifies the fixes from the outside:

  S04 HTTP→HTTPS redirect, HSTS, TLS certificate expiry
  S14 security headers (CSP quality, XFO/frame-ancestors, nosniff, Referrer/Permissions-Policy)
  S15 Set-Cookie flags (HttpOnly / Secure / SameSite)
  S13 CORS: does an evil origin get reflected / allowed with credentials?
  S20 debug leakage: stack traces on 404 / malformed JSON; X-Powered-By/Server versions; TRACE
  S23 exposed files (/.env, /.git/config, /backup.zip ...) with soft-404 detection
  S09 optional: anonymous request to an admin path must be refused
  S12 optional: repeated bad logins must hit a rate limit (429/lock)

Usage:
  python3 check_live.py https://staging.example.com [--api /api/health] [--admin-path /admin]
         [--login-path /api/login --login-body '{"email":"probe@example.com","password":"wrong"}' --attempts 12]
         [--insecure] [--json out.json]
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import re
import socket
import ssl
import sys
import time
import urllib.error
import urllib.request
import uuid
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from urllib.parse import urljoin, urlparse

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _common import finding, is_local_host, print_table, sort_findings, write_json  # noqa: E402
from scan_exposed_files import scan_live as exposed_scan_live  # noqa: E402

UA = "app-security-kit/1.0 (owner-authorized check)"
LEAK_MARKERS = [
    r"Traceback \(most recent call last\)", r"\bat (?:Object\.<anonymous>|Module\._compile|async Promise\.all)",
    r"node_modules[\\/]", r"/home/\w+/", r"/var/www/", r"C:\\\\Users\\\\", r"SQLSTATE\[", r"Whoops!",
    r"Werkzeug Debugger", r"DisallowedHost", r"Django Version:", r"Exception in thread", r"PG::\w+Error",
    r"ER_PARSE_ERROR|ER_BAD_FIELD_ERROR", r"Fatal error: ", r"<b>Warning</b>:", r"Notice: Undefined", r"MongoServerError",
    r"ReferenceError:|TypeError: Cannot read", r"SyntaxError: Unexpected token", r"Stack trace:", r"\.php on line \d+",
    r"DB_PASS|DATABASE_URL=|APP_KEY=",
]
SESSION_COOKIE = re.compile(r"sess|sid|token|auth|jwt|connect\.sid|laravel_session|PHPSESSID|next-auth|__Secure|__Host|remember",
                            re.I)


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D401
        return None


def request(url: str, method: str = "GET", headers: Optional[Dict[str, str]] = None, body: Optional[bytes] = None,
            insecure: bool = False, follow: bool = True, timeout: float = 10.0, max_bytes: int = 200_000):
    h = {"User-Agent": UA}
    h.update(headers or {})
    req = urllib.request.Request(url, data=body, headers=h, method=method)
    ctx = ssl._create_unverified_context() if insecure else None  # noqa: S323 - explicit opt-in
    handlers = [urllib.request.HTTPSHandler(context=ctx)] if ctx else []
    if not follow:
        handlers.append(NoRedirect())
    opener = urllib.request.build_opener(*handlers)
    try:
        with opener.open(req, timeout=timeout) as r:  # noqa: S310
            return r.status, r.headers, r.read(max_bytes), r.geturl()
    except urllib.error.HTTPError as e:
        try:
            b = e.read(max_bytes)
        except Exception:  # noqa: BLE001
            b = b""
        return e.code, e.headers, b, url
    except Exception as e:  # noqa: BLE001
        return None, None, str(e).encode(), url


def header_all(headers, name: str) -> List[str]:
    if headers is None:
        return []
    try:
        return headers.get_all(name) or []
    except AttributeError:
        v = headers.get(name)
        return [v] if v else []


def check(base: str, api: Optional[str], admin_path: Optional[str], login_path: Optional[str], login_body: Optional[str],
          login_form: bool, attempts: int, insecure: bool) -> dict:
    F: List[dict] = []
    info: Dict[str, object] = {}
    u = urlparse(base)
    host = u.hostname or ""
    local = is_local_host(host)

    def add(rule, step, sev, title, evidence="", fix="", conf="high"):
        F.append(finding(rule, step, sev, title, base, 0, evidence, fix, conf, "check_live"))

    st, hd, body, final = request(base, insecure=insecure)
    if st is None:
        return {"scanner": "check_live", "url": base, "findings": [], "meta": {"error": body.decode(errors="replace")[:300]}}
    info["status"] = st
    info["final_url"] = final

    # ---- S04 HTTPS ----
    if u.scheme == "https":
        http_url = base.replace("https://", "http://", 1)
        st2, hd2, _, _ = request(http_url, follow=False, insecure=insecure, timeout=6)
        loc = (hd2.get("Location") if hd2 else "") or ""
        if st2 is None:
            info["http_port"] = "closed/unreachable (fine if only 443 is open)"
        elif not (300 <= st2 < 400 and loc.startswith("https://")):
            add("no-https-redirect", "S04", "high", f"http:// does not redirect to https:// (status {st2})",
                f"GET {http_url} → {st2} Location={loc or '-'}", "Redirect all HTTP to HTTPS with 301 at the proxy/CDN.")
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((host, u.port or 443), timeout=8) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ss:
                    cert = ss.getpeercert()
                    info["tls_version"] = ss.version()
                    exp = dt.datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
                    days = (exp - dt.datetime.utcnow()).days
                    info["cert_days_left"] = days
                    if days < 14:
                        add("tls-cert-expiring", "S04", "high" if days < 7 else "medium",
                            f"TLS certificate expires in {days} days", cert["notAfter"],
                            "Fix auto-renewal (certbot renew --dry-run / hosting panel).")
                    if ss.version() in {"TLSv1", "TLSv1.1"}:
                        add("tls-old-version", "S04", "medium", f"Negotiated {ss.version()}", "", "Allow TLS 1.2+ only.")
        except ssl.SSLCertVerificationError as e:
            add("tls-invalid-cert", "S04", "high", "TLS certificate is not valid", str(e)[:160], "Install a valid certificate.")
        except Exception as e:  # noqa: BLE001
            info["tls_check"] = f"skipped: {e}"
    elif not local:
        add("site-on-http", "S04", "critical", "Site is served over plain HTTP", base, "Serve only over HTTPS with HSTS.")
    else:
        info["https_note"] = "local http URL — verify HTTPS/HSTS on the deployed domain"

    # ---- S14 headers ----
    def h(name):
        return (hd.get(name) if hd else None) or ""
    csp = h("Content-Security-Policy")
    if not csp:
        if h("Content-Security-Policy-Report-Only"):
            add("csp-report-only", "S14", "low", "CSP only in Report-Only mode", "", "Enforce it once reports are clean.")
        else:
            add("missing-csp", "S14", "medium", "Missing Content-Security-Policy",
                fix="Start with: default-src 'self'; script-src 'self' 'nonce-…'; object-src 'none'; base-uri 'self'; "
                    "frame-ancestors 'none'; form-action 'self'; upgrade-insecure-requests")
    else:
        weak = []
        sm = re.search(r"script-src([^;]*)", csp) or re.search(r"default-src([^;]*)", csp)
        if sm and "'unsafe-inline'" in sm.group(1) and "nonce-" not in sm.group(1) and "strict-dynamic" not in sm.group(1):
            weak.append("script-src allows 'unsafe-inline'")
        if sm and "'unsafe-eval'" in sm.group(1):
            weak.append("'unsafe-eval'")
        if sm and re.search(r"(^|\s)(\*|https:|http:)(\s|$)", sm.group(1)):
            weak.append("wildcard script source")
        if "object-src" not in csp and "default-src 'none'" not in csp:
            weak.append("no object-src")
        if weak:
            add("weak-csp", "S14", "low", "Content-Security-Policy is weak: " + ", ".join(weak), csp[:180],
                "Use nonces/hashes instead of 'unsafe-inline'; set object-src 'none'.")
    hsts = h("Strict-Transport-Security")
    if u.scheme == "https":
        if not hsts:
            add("missing-hsts", "S14", "medium", "Missing Strict-Transport-Security", "",
                "Strict-Transport-Security: max-age=31536000; includeSubDomains (add preload only when sure)")
        else:
            mm = re.search(r"max-age=(\d+)", hsts)
            if mm and int(mm.group(1)) < 15552000:
                add("short-hsts", "S14", "low", f"HSTS max-age is short ({mm.group(1)}s)", hsts, "Use ≥ 1 year.")
    if not h("X-Frame-Options") and "frame-ancestors" not in csp:
        add("clickjacking", "S14", "medium", "No X-Frame-Options / CSP frame-ancestors (clickjacking)", "",
            "X-Frame-Options: DENY (or CSP frame-ancestors 'none')")
    if h("X-Content-Type-Options").lower() != "nosniff":
        add("missing-nosniff", "S14", "low", "Missing X-Content-Type-Options: nosniff", "", "Add it.")
    if not h("Referrer-Policy"):
        add("missing-referrer-policy", "S14", "low", "Missing Referrer-Policy", "", "strict-origin-when-cross-origin")
    if not h("Permissions-Policy"):
        add("missing-permissions-policy", "S14", "info", "Missing Permissions-Policy", "",
            "e.g. camera=(), microphone=(), geolocation=()")
    for name in ("X-Powered-By", "Server", "X-AspNet-Version", "X-Generator"):
        v = h(name)
        if v and (name != "Server" or re.search(r"\d", v)):
            add("version-disclosure", "S20", "low", f"{name} header discloses technology/version: {v}", "",
                "Remove it (app.disable('x-powered-by'), server_tokens off, expose_php Off).")

    # ---- S15 cookies ----
    for c in header_all(hd, "Set-Cookie"):
        name = c.split("=", 1)[0].strip()
        low = c.lower()
        missing = [f for f in ("httponly", "secure", "samesite") if f not in low]
        if u.scheme != "https" and "secure" in missing:
            missing.remove("secure")
        if missing and SESSION_COOKIE.search(name):
            add("cookie-flags-live", "S15", "medium" if "httponly" in missing else "low",
                f"Cookie '{name}' missing {', '.join(missing)}", c[:160],
                "Set HttpOnly; Secure; SameSite=Lax (or Strict) on session/auth cookies.")
        if "samesite=none" in low and "secure" not in low:
            add("cookie-samesite-none", "S15", "medium", f"Cookie '{name}' SameSite=None without Secure", c[:160], "Add Secure.")

    # ---- S13 CORS ----
    target = urljoin(base, api) if api else base
    evil = "https://evil-" + uuid.uuid4().hex[:6] + ".example"
    st3, hd3, _, _ = request(target, headers={"Origin": evil}, insecure=insecure)
    acao = (hd3.get("Access-Control-Allow-Origin") if hd3 else "") or ""
    acac = ((hd3.get("Access-Control-Allow-Credentials") if hd3 else "") or "").lower() == "true"
    if acao == evil:
        add("cors-reflects-origin", "S13", "high" if acac else "medium",
            f"CORS reflects arbitrary Origin{' WITH credentials' if acac else ''} on {target}",
            f"Origin: {evil} → Access-Control-Allow-Origin: {acao}", "Allow-list exact origins.")
    elif acao == "*" and acac:
        add("cors-wildcard-credentials", "S13", "high", "CORS * with credentials", "", "Allow-list exact origins.")
    elif acao == "*":
        add("cors-wildcard", "S13", "low", f"CORS Access-Control-Allow-Origin: * on {target}", "",
            "Fine only for truly public, non-authenticated resources.", conf="medium")
    st4, hd4, _, _ = request(target, method="OPTIONS", insecure=insecure,
                             headers={"Origin": evil, "Access-Control-Request-Method": "POST",
                                      "Access-Control-Request-Headers": "content-type,authorization"})
    acao4 = (hd4.get("Access-Control-Allow-Origin") if hd4 else "") or ""
    if acao4 == evil and acao != evil:
        add("cors-preflight-reflects", "S13", "medium", "CORS preflight allows arbitrary origin", f"OPTIONS → {acao4}",
            "Allow-list exact origins.")

    # ---- S20 debug leakage ----
    probes: List[Tuple[str, str, Optional[bytes], Dict[str, str]]] = [
        ("GET", urljoin(base, f"/{uuid.uuid4().hex}/does-not-exist"), None, {}),
        ("GET", urljoin(base, "/%"), None, {}),
    ]
    if api:
        probes.append(("POST", urljoin(base, api), b'{"broken": ', {"Content-Type": "application/json"}))
        probes.append(("GET", urljoin(base, api) + ("&" if "?" in api else "?") + "id='\"<x>", None, {}))
    for method, url, data, hdrs in probes:
        s5, _, b5, _ = request(url, method=method, body=data, headers=hdrs, insecure=insecure)
        text = (b5 or b"").decode("utf-8", "replace")
        for mk in LEAK_MARKERS:
            mm = re.search(mk, text)
            if mm:
                add("debug-leak-live", "S20", "high", f"Error details leaked on {method} {url} (status {s5})",
                    text[max(0, mm.start() - 40): mm.end() + 60].replace("\n", " ")[:180],
                    "Turn debug off in production; return generic errors; log details server-side.")
                break
    s6, _, _, _ = request(base, method="TRACE", insecure=insecure)
    if s6 == 200:
        add("trace-enabled", "S20", "low", "HTTP TRACE method enabled", "", "Disable TRACE at the web server.")

    # ---- S09 admin probe ----
    if admin_path:
        s7, h7, b7, f7 = request(urljoin(base, admin_path), follow=False, insecure=insecure)
        loc = (h7.get("Location") if h7 else "") or ""
        if s7 == 200:
            add("admin-open-anonymous", "S09", "critical", f"{admin_path} returns 200 to an anonymous visitor",
                f"{len(b7 or b'')} bytes", "Require an authenticated admin session on the server for every admin route.",
                conf="medium")
        info["admin_probe"] = f"{s7} {loc}"

    # ---- S12 login rate limit ----
    if login_path:
        url = urljoin(base, login_path)
        payload = (login_body or '{"email":"rate-limit-probe@example.com","password":"wrong-password"}')
        if login_form:
            hdrs = {"Content-Type": "application/x-www-form-urlencoded"}
        else:
            hdrs = {"Content-Type": "application/json"}
        statuses = []
        blocked_at = None
        for i in range(1, attempts + 1):
            s8, h8, _, _ = request(url, method="POST", body=payload.encode(), headers=hdrs, insecure=insecure, follow=False)
            statuses.append(s8)
            if s8 in (429, 423) or (s8 == 403 and i > 3):
                blocked_at = i
                break
            time.sleep(0.15)
        info["login_probe_statuses"] = statuses
        if blocked_at is None:
            add("login-not-rate-limited", "S12", "high", f"{attempts} failed logins in a row were not throttled",
                f"statuses: {statuses}", "Limit by IP and by account (e.g. 5/min then backoff), return 429 with Retry-After.")
        else:
            info["login_rate_limited_after"] = blocked_at

    # ---- S23 exposed files ----
    ex = exposed_scan_live(base, insecure)
    F.extend(ex["findings"])
    info["exposed_probe"] = ex["meta"]
    return {"scanner": "check_live", "url": base, "findings": sort_findings(F), "meta": info}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("url")
    ap.add_argument("--api", help="an API path to test CORS/debug on, e.g. /api/products")
    ap.add_argument("--admin-path")
    ap.add_argument("--login-path")
    ap.add_argument("--login-body")
    ap.add_argument("--login-form", action="store_true", help="send login body as form-urlencoded")
    ap.add_argument("--attempts", type=int, default=12)
    ap.add_argument("--insecure", action="store_true")
    ap.add_argument("--json")
    a = ap.parse_args(argv)
    res = check(a.url, a.api, a.admin_path, a.login_path, a.login_body, a.login_form, max(3, min(a.attempts, 50)), a.insecure)
    if res["meta"].get("error"):
        print(f"check_live: could not reach {a.url}: {res['meta']['error']}")
        return 2
    print(f"check_live {a.url}: {len(res['findings'])} finding(s)")
    print_table(res["findings"])
    print("meta:", json.dumps(res["meta"], ensure_ascii=False)[:800])
    if a.json:
        write_json(Path(a.json), res)
    return 0


if __name__ == "__main__":
    sys.exit(main())
