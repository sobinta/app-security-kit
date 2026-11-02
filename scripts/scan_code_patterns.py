#!/usr/bin/env python3
"""Heuristic static scan for risky code patterns, mapped to the 27 pre-launch
steps (S01-S27) and the extra checks (X01-X15).

It is a lead generator, not a verdict: every hit must be confirmed by reading
the code (false positives happen; absence of hits is not proof of safety).
Covers JS/TS (Node, Express, Next.js, React, Vue, Svelte, Socket.IO), Python
(Django, Flask, FastAPI), PHP (Laravel, WordPress, Joomla, plain PHP),
templates, SQL migrations (Supabase RLS), Firebase rules, Docker, Nginx and CI.

Usage:
  python3 scan_code_patterns.py <project_dir> [--json out.json] [--include-tests]
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Callable, Dict, List, Optional

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _common import (CODE_EXTS_JS, CODE_EXTS_PHP, CODE_EXTS_PY, TEMPLATE_EXTS, finding, iter_files, line_of,  # noqa: E402
                     line_text, load_package_json, mask, print_table, read_text, rel, sort_findings, write_json)

JS, PY, PHP, TPL = CODE_EXTS_JS, CODE_EXTS_PY, CODE_EXTS_PHP, TEMPLATE_EXTS
SQL = {".sql"}
DOWN = {"critical": "high", "high": "medium", "medium": "low", "low": "info", "info": "info"}
TEST_PATH = re.compile(r"(^|/)(tests?|__tests__|spec|specs|e2e|cypress|playwright|fixtures?|mocks?|__mocks__|stories)(/|$)|"
                       r"\.(test|spec|stories|e2e)\.[a-z]+$", re.I)
I, S, M = re.I, re.S, re.M


class Rule:
    def __init__(self, id, step, sev, title, rx, fix, exts=None, names=None, path_rx=None, flags=0,
                 near_unless=None, file_unless=None, near_require=None, file_require=None, window=250,
                 unless_action="suppress", conf="medium", mask_literals=False, max_per_file=5,
                 post: Optional[Callable] = None, once=False):
        self.id, self.step, self.sev, self.title, self.fix = id, step, sev, title, fix
        self.rx = re.compile(rx, flags)
        self.exts = exts
        self.names = re.compile(names, re.I) if names else None
        self.path_rx = re.compile(path_rx, re.I) if path_rx else None
        self.near_unless = re.compile(near_unless, re.I) if near_unless else None
        self.file_unless = re.compile(file_unless, re.I | re.M) if file_unless else None
        self.near_require = re.compile(near_require, re.I) if near_require else None
        self.file_require = re.compile(file_require, re.I | re.M) if file_require else None
        self.window, self.unless_action, self.conf = window, unless_action, conf
        self.mask_literals, self.max_per_file, self.post, self.once = mask_literals, max_per_file, post, once

    def applies(self, relpath: str, name: str, ext: str) -> bool:
        if self.names and not self.names.search(name):
            return False
        if self.path_rx and not self.path_rx.search(relpath):
            return False
        if self.exts is not None and ext not in self.exts and not self.names:
            return False
        return True


def _cookie_post(m, text):
    call = m.group(0)
    if re.search(r"(?i)\bhttpOnly\s*:\s*false", call):
        return "high", "Cookie explicitly set with httpOnly: false"
    if not re.search(r"(?i)httpOnly", call):
        name = re.search(r"\(\s*['\"`]([^'\"`]+)", call)
        nm = name.group(1) if name else "cookie"
        before = text[max(0, m.start() - 700): m.start()]
        if re.search(r"(?i)sess|sid|token|auth|jwt|login|user|uid|account|remember", nm) or \
                re.search(r"(?i)login|signin|sign_in|authenticate|password", before):
            return "medium", f"Session/auth cookie '{nm}' set without httpOnly/secure/sameSite flags"
        return None
    if not re.search(r"(?i)secure", call):
        return "low", "Cookie set without `secure` flag"
    return None


def _cors_post(m, text):
    win = text[max(0, m.start() - 300): m.end() + 300]
    if re.search(r"credentials\s*:\s*true|allow_credentials\s*=\s*True|Allow-Credentials['\"]?\s*[,:]\s*['\"]?true", win, I):
        return "high", "CORS allows any origin together with credentials (any site can make authenticated requests)"
    return None


R: List[Rule] = [
    # ---------------- S07 XSS ----------------
    Rule("js-dangerously-set-inner-html", "S07", "medium", "dangerouslySetInnerHTML with dynamic content",
         r"dangerouslySetInnerHTML\s*=\s*\{\{?\s*__html\s*:\s*(?![\"'`])", "Render as text, or sanitize with DOMPurify "
         "(isomorphic-dompurify on the server) using a strict allow-list.", exts=JS,
         near_unless=r"DOMPurify|sanitize|xss\(|purify|marked\.parse\([^)]*sanitize", unless_action="downgrade"),
    Rule("js-innerhtml-assign", "S07", "medium", "innerHTML/outerHTML assigned dynamic content",
         r"\.(?:innerHTML|outerHTML)\s*\+?=(?!=)(?!\s*([\"'`])\s*\1)", "Use textContent / createElement, or sanitize "
         "with DOMPurify.", exts=JS | TPL, near_unless=r"DOMPurify|sanitize|escapeHtml|escape\(", unless_action="downgrade"),
    Rule("js-insert-adjacent-html", "S07", "medium", "insertAdjacentHTML/document.write with dynamic content",
         r"insertAdjacentHTML\s*\(|document\.write(?:ln)?\s*\(", "Build DOM nodes or sanitize input first.", exts=JS | TPL),
    Rule("vue-v-html", "S07", "medium", "v-html renders raw HTML", r"\bv-html\s*=", "Prefer {{ }} interpolation; "
         "sanitize with DOMPurify if HTML is required.", exts=JS | TPL),
    Rule("svelte-html", "S07", "medium", "{@html} renders raw HTML", r"\{@html\s", "Sanitize before rendering.", exts=JS),
    Rule("ejs-unescaped", "S07", "medium", "Unescaped template output (<%- / {{{ / |raw / |safe)",
         r"<%-\s*(?!include\b)|\{\{\{\s*[\w.]|\|\s*raw\b|\|\s*safe\b|\{%\s*autoescape\s+(?:false|off)", "Use escaped "
         "output ({{ }}, <%= %>) unless the value is trusted & sanitized.", exts=TPL | JS | PY),
    Rule("blade-unescaped", "S07", "medium", "Blade raw output {!! !!}", r"\{!!\s*(?!csrf_field|method_field)[^!]{1,120}!!\}",
         "Use {{ }} (escaped) or purify the HTML.", exts=PHP, names=r"\.blade\.php$"),
    Rule("reflected-xss-template", "S07", "high", "Request data reflected into HTML without escaping",
         r"(?:res|response|reply)\.(?:send|write|end)\(\s*`[^`]{0,400}<[a-z][^`]{0,400}\$\{\s*req\.(?:query|body|params)",
         "Escape output (template engine auto-escaping, or a tiny escapeHtml helper) and send JSON for APIs.",
         exts=JS, flags=I | S),
    Rule("php-echo-input", "S07", "high", "User input echoed without escaping",
         r"(?:\becho|\bprint|<\?=)\s*\(?\s*\$_(?:GET|POST|REQUEST|COOKIE|SERVER)\s*\[", "Wrap output in "
         "htmlspecialchars($v, ENT_QUOTES, 'UTF-8').", exts=PHP),
    Rule("py-mark-safe", "S07", "medium", "Auto-escaping bypassed (mark_safe/Markup/|safe)",
         r"\bmark_safe\s*\(|\bMarkup\s*\(|\|\s*safe\b", "Only mark trusted, sanitized HTML as safe (bleach/nh3).", exts=PY | TPL),
    Rule("py-render-template-string", "X04", "high", "render_template_string (template injection risk)",
         r"render_template_string\s*\(", "Use render_template with a file; never build templates from user input.", exts=PY),
    Rule("js-postmessage-no-origin", "X05", "medium", "postMessage listener without origin check",
         r"addEventListener\(\s*['\"]message['\"]", "Check event.origin against an allow-list before using event.data.",
         exts=JS | TPL, near_unless=r"\.origin\b", window=500),

    # ---------------- code execution / injection ----------------
    Rule("js-eval", "X04", "high", "eval / new Function / string timers (code injection)",
         r"(?<![\w.$])eval\s*\(|new\s+Function\s*\(|set(?:Timeout|Interval)\s*\(\s*[\"'`]", "Remove eval; parse data "
         "with JSON.parse and use real functions.", exts=JS),
    Rule("js-command-injection", "X04", "high", "Shell command built from variables",
         r"\b(?:exec|execSync)\s*\(\s*(?:`[^`]*\$\{|[^)\n]{0,80}(?:req\.|\+\s*[A-Za-z_$]))",
         "Use execFile/spawn with an argument array and a strict allow-list; never pass user input to a shell.", exts=JS),
    Rule("js-path-traversal", "X04", "high", "File system access with request-controlled path",
         r"\b(?:readFile|readFileSync|createReadStream|sendFile|download|unlink|unlinkSync|rmSync|writeFile|writeFileSync)"
         r"\s*\(\s*[^)\n]{0,120}(?:req\.(?:query|params|body)|params\.|searchParams\.get\()",
         "Resolve the path, then verify it stays inside an allowed base dir (path.resolve + startsWith), or map ids to files.",
         exts=JS, near_unless=r"startsWith\(|basename\(|normalize\(", unless_action="downgrade"),
    Rule("js-prototype-pollution", "X04", "medium", "Deep merge of request body (prototype pollution)",
         r"(?:_\.merge|\bmerge|deepMerge|defaultsDeep|\$\.extend)\s*\(\s*[^,\n]{0,40},\s*req\.body", "Validate with a "
         "schema first; block __proto__/constructor keys.", exts=JS),
    Rule("js-ssrf", "X02", "medium", "Server-side request to a user-controlled URL (SSRF)",
         r"\b(?:fetch|axios(?:\.(?:get|post|request))?|got|needle|superagent\.get|https?\.get)\s*\(\s*"
         r"(?:req\.(?:body|query|params)|body\.|query\.|searchParams\.get\(|(?:url|targetUrl|imageUrl|webhookUrl|callbackUrl|link)\b)",
         "Allow-list hosts/schemes, resolve DNS and block private/metadata IPs (169.254.169.254, 10/8, 127/8 ...), set timeouts.",
         exts=JS, conf="low"),
    Rule("js-open-redirect", "X03", "medium", "Redirect target taken from the request (open redirect)",
         r"(?:res\.redirect|NextResponse\.redirect|Response\.redirect|\bredirect)\s*\(\s*(?:new URL\(\s*)?"
         r"(?:req\.(?:query|body|params)|searchParams\.get\(|query\.|params\.)",
         "Only allow relative paths (starts with '/' but not '//') or an allow-list of hosts.", exts=JS),
    Rule("js-location-from-query", "X03", "medium", "window.location set from URL parameters",
         r"window\.location(?:\.href)?\s*=\s*(?:params|query|searchParams|new URLSearchParams|decodeURIComponent)",
         "Validate the destination against an allow-list.", exts=JS | TPL),

    # ---------------- S10 SQL / NoSQL injection ----------------
    Rule("js-sql-template-interpolation", "S10", "high", "SQL built with template-string interpolation",
         r"(?:\b|\.)(?:query|execute|exec|raw|all|get|run|prepare|unsafe|\$queryRawUnsafe|\$executeRawUnsafe)\s*\(\s*`"
         r"[^`]{0,800}?\b(?:SELECT|INSERT|UPDATE|DELETE|WHERE|VALUES)\b[^`]{0,800}?\$\{", "Use placeholders "
         "($1 / ? / :name) and pass values separately; for Prisma use the tagged $queryRaw`...${v}` form.", exts=JS, flags=I | S),
    Rule("js-sql-concatenation", "S10", "high", "SQL built by string concatenation",
         r"([\"'`])\s*(?:SELECT\b|INSERT\s+INTO|UPDATE\s+\w+\s+SET|DELETE\s+FROM)(?:(?!\1).){0,300}\1\s*\+\s*[\w$(]",
         "Use parameterized queries / the ORM query builder.", exts=JS, flags=I),
    Rule("client-sql-executed", "S03", "critical", "Server executes SQL sent by the client (browser talks to the DB)",
         r"\.(?:prepare|query|exec|execute|raw|all|run|unsafe)\(\s*(?:req\.body|req\.query|body|params|request\.json\(\))\s*\.\s*"
         r"(?:sql|query|q|statement|stmt)\b", "Delete the generic endpoint; expose specific, authorized API routes that run "
         "fixed, parameterized queries.", exts=JS | PY | PHP),
    Rule("client-sends-sql", "S03", "critical", "Front-end sends raw SQL to the server",
         r"JSON\.stringify\(\s*\{\s*(?:sql|query|statement)\s*:\s*[\"'`]\s*(?:SELECT|INSERT|UPDATE|DELETE)", "Replace with "
         "purpose-built endpoints (GET /api/products) — the client must never choose the query.", exts=JS | TPL, flags=I),
    Rule("idor-by-id", "X01", "medium", "Record loaded by id from the URL without an ownership check (IDOR)",
         r"(?:SELECT|UPDATE|DELETE)\b[^;'\"`]{0,120}\bWHERE\s+(?:\w+\.)?id\s*=\s*(?:\?|\$1|:id)[^;]{0,200}?req\.params\.id"
         r"|findById\(\s*req\.params\.id\s*\)|findUnique\(\s*\{\s*where\s*:\s*\{\s*id\s*:\s*(?:params|req\.params)\.id\s*\}\s*\}\s*\)",
         "Scope every query to the caller: WHERE id = ? AND user_id = ? (or check order.user_id === req.user.id → 404).",
         exts=JS, flags=I | S, near_unless=r"user_?id|owner|req\.user\.id|userId|session\.user|auth\.uid|tenant", window=60),
    Rule("js-prisma-unsafe", "S10", "medium", "Prisma $queryRawUnsafe/$executeRawUnsafe", r"\$(?:queryRawUnsafe|executeRawUnsafe)\s*\(",
         "Use the tagged-template $queryRaw`…${value}` which parameterizes automatically.", exts=JS),
    Rule("js-nosql-injection", "S10", "high", "Request object passed straight into a MongoDB query (operator injection)",
         r"\.(?:find|findOne|findOneAndUpdate|updateOne|deleteOne|deleteMany|countDocuments)\(\s*req\.(?:body|query)\s*[,)]|\$where\s*:",
         "Pick and type-check fields (zod), or use mongo-sanitize / express-mongo-sanitize.", exts=JS),
    Rule("py-sql-format", "S10", "high", "SQL built with f-string/format/% /concatenation",
         r"\.(?:execute|executemany|raw|extra|executescript)\s*\(\s*(?:f[\"']|[\"'][^\"']*[\"']\s*(?:%|\+)|[^)\n]{0,200}\.format\()"
         r"|\btext\s*\(\s*f[\"']", "Use parameters: cursor.execute('... WHERE id = %s', [id]) / ORM filters / text(':id').",
         exts=PY),
    Rule("php-sql-superglobal", "S10", "critical", "Request data used directly in an SQL call",
         r"(?:mysqli_query|mysql_query|->query|->exec|pg_query|sqlsrv_query)\s*\([^;]{0,300}\$_(?:GET|POST|REQUEST|COOKIE|SERVER)",
         "Use PDO/mysqli prepared statements with bound parameters.", exts=PHP),
    Rule("php-sql-interpolation", "S10", "high", "Variables interpolated into SQL string",
         r"(?:mysqli_query|->query|->exec|pg_query)\s*\(\s*(?:\$\w+\s*,\s*)?\"[^\";]{0,300}\$\w+|"
         r"(?:DB::raw|whereRaw|selectRaw|orderByRaw|havingRaw|DB::select|DB::statement)\s*\(\s*[\"'][^\"']*\$\w+|"
         r"[\"']\s*(?:SELECT|INSERT|UPDATE|DELETE)\b[^\"']{0,200}[\"']\s*\.\s*\$\w+",
         "Use prepared statements / query-builder bindings (`whereRaw('id = ?', [$id])`).", exts=PHP, flags=I),

    # ---------------- S06 validation / X01 mass assignment ----------------
    Rule("js-mass-assignment", "X01", "medium", "Request body passed whole into a DB write (mass assignment)",
         r"\.(?:create|update|updateOne|updateMany|insert|insertOne|findOneAndUpdate|findByIdAndUpdate|upsert)\s*\(\s*"
         r"(?:\{\s*)?(?:data\s*:\s*)?(?:\.\.\.)?\s*(?:req\.body|await\s+req\.json\(\)|body)\s*\}?\s*[,)]"
         r"|\bdata\s*:\s*(?:\.\.\.)?\s*(?:req\.body|await\s+req\.json\(\)|Object\.fromEntries\(\s*formData)",
         "Validate with a schema (zod) and copy only allowed fields; never let clients set role/ownerId/price/isAdmin.",
         exts=JS, file_unless=r"\bz\.object|\bJoi\.|\byup\.|valibot|class-validator|express-validator|\.safeParse\(|\.parse\(",
         unless_action="downgrade"),
    Rule("php-guarded-empty", "X01", "medium", "Eloquent model with $guarded = [] (mass assignment)",
         r"protected\s+\$guarded\s*=\s*\[\s*\]", "Use $fillable with an explicit list.", exts=PHP),

    # ---------------- S19 prices & payments ----------------
    Rule("price-from-client", "S19", "high", "Price/amount taken from the client request",
         r"\b(?:price|amount|total|unit_amount|unitAmount|cost|subtotal|discount|fee)\s*[:=]\s*"
         r"(?:Number\(|parseFloat\(|parseInt\(|\+)?\s*(?:req\.body|req\.query|request\.body|ctx\.request\.body|body|"
         r"formData\.get\(|searchParams\.get\(|request\.(?:json|form|POST|data))\b",
         "Look up prices on the server from your DB/catalog by product id; recompute totals; verify the paid amount from "
         "the payment provider (webhook/verify API) before fulfilling.", exts=JS | PY | PHP),
    Rule("price-field-from-body", "S19", "high", "Client-sent price field used",
         r"(?:req\.body|body|input|\$_POST|\$request->input\()\s*(?:\.|\[\s*['\"])\s*(?:price|amount|total|unit_amount|discount)\b",
         "Never trust client prices — recalculate on the server.", exts=JS | PY | PHP),
    Rule("price-destructured-from-body", "S19", "high", "Price/amount destructured from the request body",
         r"(?:const|let|var)\s*\{[^}]{0,200}\b(?:price|amount|total|unit_amount|unitAmount|discount)\b[^}]{0,200}\}\s*=\s*"
         r"(?:req\.body|await\s+req\.json\(\)|body|request\.body|ctx\.request\.body)", "Accept only productId/quantity; read "
         "the price from the database and compute the total on the server.", exts=JS, flags=S),
    Rule("client-sends-price", "S19", "medium", "Front-end sends a price/total to the server",
         r"JSON\.stringify\(\s*\{[^}]{0,200}\b(?:price|amount|total)\b[^}]{0,200}\}\s*\)", "The server must ignore any "
         "client price and recalculate it.", exts=JS | TPL, path_rx=r"(^|/)(public|static|src|app|components|pages|client)/",
         flags=S, conf="low"),

    # ---------------- S13 CORS ----------------
    Rule("cors-default-open", "S13", "medium", "cors() with no options (allows every origin)", r"\bcors\(\s*\)",
         "Pass an explicit allow-list: cors({ origin: ['https://app.example.com'], credentials: true }).", exts=JS),
    Rule("cors-wildcard", "S13", "medium", "CORS allows any origin",
         r"\borigin\s*:\s*(?:[\"']\*[\"']|true)\b|Access-Control-Allow-Origin[\"']?\s*[,:]\s*(?:[\"']\*[\"']|req\.headers\.origin|origin\b)"
         r"|CORS_(?:ALLOW_ALL_ORIGINS|ORIGIN_ALLOW_ALL)\s*=\s*True|allow_origins\s*=\s*\[\s*[\"']\*[\"']|\bCORS\(\s*app\s*\)",
         "Allow-list exact origins; never combine * / reflected origins with credentials.", exts=JS | PY | PHP, post=_cors_post),

    # ---------------- S15 cookies & token storage ----------------
    Rule("cookie-flags", "S15", "medium", "Cookie without HttpOnly/Secure/SameSite",
         r"(?:res|response|reply|ctx)\.(?:cookie|setCookie|cookies\.set)\s*\(\s*[^)]{0,400}\)|\bcookies\(\)\.set\s*\([^)]{0,400}\)",
         "Set { httpOnly: true, secure: true, sameSite: 'lax', path: '/', maxAge } for session cookies.", exts=JS,
         post=_cookie_post),
    Rule("cookie-flag-disabled", "S15", "medium", "Cookie security flag explicitly disabled",
         r"\b(?:httpOnly|HttpOnly)\s*:\s*false|\bsecure\s*:\s*false|SESSION_COOKIE_(?:SECURE|HTTPONLY)\s*=\s*False|"
         r"CSRF_COOKIE_SECURE\s*=\s*False|session\.cookie_(?:secure|httponly)\s*=\s*(?:0|Off)", "Enable secure/httpOnly "
         "in production (secure: process.env.NODE_ENV === 'production').", exts=JS | PY | PHP),
    Rule("token-in-localstorage", "S15", "medium", "Auth token stored in localStorage/AsyncStorage (readable by XSS)",
         r"(?:localStorage|sessionStorage|AsyncStorage)\.setItem\(\s*[\"'`][^\"'`]*(?:token|jwt|auth|session|access|refresh)",
         "Prefer HttpOnly cookies (web) or SecureStore/Keychain (mobile).", exts=JS, flags=I),

    # ---------------- S05 password hashing ----------------
    Rule("weak-password-hash", "S05", "high", "Fast/unsalted hash used for passwords",
         r"createHash\(\s*[\"'](?:md5|sha1|sha256|sha512)[\"']\s*\)|\b(?:MD5|SHA1|SHA256|md5|sha1)\s*\(\s*\$?(?:password|pass\b|pwd)"
         r"|hashlib\.(?:md5|sha1|sha256|sha512)\(|\b(?:md5|sha1)\s*\(\s*\$_POST",
         "Use argon2id (preferred) or bcrypt (cost ≥ 12) — e.g. `argon2.hash(pw)`, `password_hash($pw, PASSWORD_ARGON2ID)`.",
         exts=JS | PY | PHP, near_require=r"pass(?:word)?|pwd", window=200),
    Rule("plaintext-password-compare", "S05", "critical", "Password compared in plain text (passwords stored unhashed)",
         r"\.password\s*(?:===?|!==?)\s*(?:req\.body\.password|body\.password|password\b|input\.password|credentials\.password)"
         r"|(?:req\.body\.password|body\.password)\s*(?:===?|!==?)\s*\w+\.password|\[\s*['\"]password['\"]\s*\]\s*==\s*\$_POST"
         r"|WHERE[^\n]{0,80}password\s*=\s*(?:\?|\$\d|:\w+|['\"]\s*\+)", "Store argon2id/bcrypt hashes and verify with "
         "argon2.verify / bcrypt.compare / password_verify (constant-time).", exts=JS | PY | PHP, flags=I),

    # ---------------- S17 reset tokens / randomness ----------------
    Rule("weak-random-token", "S17", "high", "Predictable randomness used for a token/code",
         r"Math\.random\(\)|\brandom\.(?:random|randint|choice|choices|randrange|getrandbits)\(|\b(?:rand|mt_rand|uniqid)\s*\(",
         "Use crypto.randomBytes(32)/crypto.randomUUID(), Python `secrets.token_urlsafe(32)`, PHP random_bytes().",
         exts=JS | PY | PHP, near_require=r"token|reset|otp|code|secret|nonce|salt|invite|verif|session|password|key\b", window=120),

    # ---------------- S01 / X05 auth & JWT ----------------
    Rule("jwt-decode-not-verify", "X05", "high", "jwt.decode() used — it does NOT verify the signature",
         r"\bjwt\.decode\s*\(", "Use jwt.verify(token, secret, { algorithms: ['HS256'] }) (or jose.jwtVerify).", exts=JS,
         near_unless=r"jwt\.verify|jwtVerify", window=400),
    Rule("jwt-alg-none-or-noexp", "X05", "critical", "JWT verification weakened (alg none / ignoreExpiration / verify=False)",
         r"algorithms\s*:\s*\[[^\]]*[\"']none[\"']|ignoreExpiration\s*:\s*true|verify_signature[\"']\s*:\s*False|verify\s*=\s*False",
         "Pin algorithms, keep expiry checks, never disable signature verification.", exts=JS | PY),
    Rule("jwt-hardcoded-secret", "S11", "high", "JWT signed with a hardcoded secret",
         r"\bjwt\.sign\s*\([^)\n]{0,200}?,\s*[\"'`][^\"'`]{1,80}[\"'`]", "Load a 256-bit+ secret from env and rotate it.",
         exts=JS, mask_literals=True),
    Rule("env-fallback-secret", "S11", "high", "Hardcoded fallback for a secret env var",
         r"process\.env\.[A-Z0-9_]*(?:SECRET|KEY|TOKEN|PASSWORD|PASS)[A-Z0-9_]*\s*(?:\|\||\?\?)\s*[\"'`][^\"'`]{4,}[\"'`]"
         r"|os\.(?:environ\.get|getenv)\(\s*[\"'][A-Z0-9_]*(?:SECRET|KEY|TOKEN|PASSWORD)[A-Z0-9_]*[\"']\s*,\s*[\"'][^\"']{4,}[\"']",
         "Fail fast when the variable is missing instead of falling back to a known value.", exts=JS | PY, mask_literals=True),
    Rule("secret-env-in-response", "S11", "critical", "Secret environment variable returned in an HTTP response",
         r"(?:res|response|reply)\.(?:json|send)\(\s*\{[^;]{0,600}?process\.env\.[A-Z0-9_]*(?:SECRET|KEY|TOKEN|PASSWORD|PASS|PRIVATE)",
         "Return only public config (app name, theme, publishable keys). Rotate any secret that was served.", exts=JS, flags=S),
    Rule("unsigned-identity-cookie", "S01", "critical", "User identity/role read from an unsigned cookie (forgeable)",
         r"req\.cookies\.(?:uid|user_?id|userId|user|role|isAdmin|is_admin|admin|email)\b|\$_COOKIE\[\s*[\"'](?:uid|user_?id|role|admin)[\"']",
         "Use a real session: random session id (express-session / iron-session / framework auth) or a signed, verified token; "
         "never trust a plain cookie value as identity.", exts=JS | PHP),
    Rule("reset-token-no-expiry", "S17", "medium", "Password-reset tokens without visible expiry / single-use logic",
         r"reset[_-]?tokens?|resetToken|password_resets|passwordReset", "Store a hash of a 32-byte random token with "
         "expires_at (15–60 min), delete/mark it used after one use, and invalidate other sessions on reset.",
         exts=JS | PY | PHP, flags=I, file_unless=r"expires?_?at|expir|ttl|valid_?until|\bexp\b|maxAge", once=True),
    Rule("user-enumeration", "X05", "low", "Response reveals whether an account exists (user enumeration)",
         r"[\"'`](?:No account|User not found|Email not found|No user|Unknown email|This email is not registered)",
         "Return the same message for existing and non-existing accounts (\"If the email exists, a link was sent\").",
         exts=JS | PY | PHP, flags=I),
    Rule("request-body-logged", "S08", "low", "Whole request body written to logs (passwords/tokens end up in logs)",
         r"console\.(?:log|error|info)\([^)\n]{0,120}\breq\.body\b", "Log ids and event names, not raw bodies.", exts=JS),
    Rule("py-hardcoded-secret-key", "S11", "high", "Hardcoded Django/Flask SECRET_KEY",
         r"^\s*(?:SECRET_KEY|app\.secret_key|app\.config\[[\"']SECRET_KEY[\"']\])\s*=\s*[\"'][^\"']{8,}[\"']",
         "Load from env (os.environ['SECRET_KEY']) and rotate.", exts=PY, flags=M, mask_literals=True),
    Rule("py-allowed-hosts-any", "S11", "medium", "ALLOWED_HOSTS = ['*']", r"ALLOWED_HOSTS\s*=\s*\[[^\]]*[\"']\*[\"']",
         "List real hostnames (prevents host-header attacks on reset links).", exts=PY),
    Rule("telegram-initdata-unsafe", "X05", "high", "Telegram Mini App initDataUnsafe trusted for identity",
         r"initDataUnsafe", "Send raw initData to the server and validate its HMAC with the bot token before trusting user.id.",
         exts=JS, file_unless=r"createHmac|validate\(|isValid|init-data-node|checkSignature", unless_action="downgrade"),
    Rule("socketio-no-auth", "S01", "medium", "Socket.IO connection handler without auth middleware",
         r"\bio\.on\(\s*[\"']connection[\"']", "Authenticate in io.use((socket, next) => …) (verify session/JWT) and "
         "authorize every event/room join.", exts=JS, file_unless=r"io\.use\(|handshake\.auth|verifyToken|jwt\.verify|getSession",
         once=True),
    Rule("server-action-no-auth", "S01", "medium", "Server Action file without any auth check",
         r"\A\s*[\"']use server[\"']", "Server Actions are public POST endpoints: authenticate and authorize inside every "
         "action (and validate input with zod).", exts=JS,
         file_unless=r"\bauth\(\)|getServerSession|getSession|currentUser|getUser\(|requireUser|requireAuth|auth\.getUser|"
                     r"verifySession|getCurrentUser|session", once=True),

    # ---------------- S09 admin routes ----------------
    Rule("admin-route-no-role", "S09", "high", "Admin route without a visible role check",
         r"(?:app|router|server|api)\.(?:get|post|put|patch|delete|all|use)\(\s*[\"'`]/(?:api/)?admin[^\"'`]*[\"'`]\s*,"
         r"(?![^\n]{0,200}(?:admin|role|authori[sz]e|permission|can\(|isStaff|superuser|rbac|acl|guard)\w*)",
         "Add server-side role middleware (requireRole('admin')) on every admin route — hiding links is not protection.",
         exts=JS, flags=I),
    Rule("admin-page-no-role", "S09", "medium", "Admin page/route file without a role check",
         r"\A", "Check the user's role on the server inside this page/route/action (not only in middleware or the UI).",
         exts=JS, path_rx=r"(^|/)(?:src/)?(?:app|pages)/(?:\([\w-]+\)/)*(?:api/)?admin(?:/|\.)",
         file_unless=r"\b(?:role|isAdmin|is_admin|requireAdmin|requireRole|hasRole|permission|authorize|ADMIN)\b", once=True),
    Rule("middleware-only-auth", "S09", "info", "Auth/role gating in Next.js middleware — re-check on the server too",
         r"matcher[^\n]{0,200}admin|pathname\.startsWith\(\s*[\"']/admin", "Middleware can be bypassed (CVE-2025-29927 on "
         "unpatched Next.js); verify session + role again in each admin page, route handler and server action.",
         exts=JS, names=r"^middleware\.(?:t|j)s$", once=True),

    # ---------------- S18 uploads ----------------
    Rule("upload-no-limits", "S18", "medium", "Upload middleware without size/type limits",
         r"\bmulter\(\s*\)|\bmulter\(\s*\{(?:(?!limits)[^}]){0,400}\}\s*\)|\bformidable\(\s*(?:\{(?:(?!maxFileSize)[^}]){0,300}\})?\s*\)"
         r"|\bfileUpload\(\s*\)|\.any\(\s*\)", "Set limits.fileSize, an allow-list fileFilter (extension + magic bytes via "
         "file-type), random server-side filenames, and store outside the web root / in private object storage.",
         exts=JS, flags=S),
    Rule("upload-to-public-dir", "S18", "high", "Uploads saved into a web-served folder",
         r"(?:dest|destination|uploadDir|upload_dir|UPLOAD_FOLDER)\s*[:=(]\s*[\"'`](?:\./)?(?:public|static|www|htdocs)\b",
         "Store uploads outside the web root (or private bucket) and serve via a controller with Content-Disposition.",
         exts=JS | PY | PHP),
    Rule("upload-original-name", "S18", "medium", "Client-supplied filename used on disk",
         r"(?:file\.originalname|\.filename\b(?!\s*=\s*secure_filename)|\$_FILES\[[^\]]+\]\[[\"']name[\"']\])",
         "Generate a random name (crypto.randomUUID()) and derive the extension from the validated type.",
         exts=JS | PY | PHP, near_require=r"path\.join|filename\s*[:(]|move_uploaded_file|\.save\(|writeFile|cb\(\s*null", window=150,
         conf="low"),
    Rule("py-upload-no-secure-filename", "S18", "high", "Uploaded file saved with its original filename",
         r"\.save\(\s*os\.path\.join\([^)]{0,200}\.filename", "Use werkzeug secure_filename + extension allow-list + "
         "MAX_CONTENT_LENGTH.", exts=PY, near_unless=r"secure_filename"),
    Rule("php-move-uploaded-unchecked", "S18", "medium", "move_uploaded_file without visible type checks",
         r"move_uploaded_file\s*\(", "Validate size, extension allow-list and finfo MIME; random names; no PHP execution "
         "in the upload dir.", exts=PHP, file_unless=r"finfo|mime_content_type|getimagesize|pathinfo\([^)]*PATHINFO_EXTENSION|allowed",
         unless_action="downgrade"),

    # ---------------- S20 debug / error leakage ----------------
    Rule("stack-trace-in-response", "S20", "high", "Stack trace / raw error returned to the client",
         r"(?:res|response|reply)\.(?:status\(\s*\d+\s*\)\s*\.)?(?:json|send|end)\(\s*[^)]{0,200}(?:err|error|e|ex)\.stack",
         "Log the error server-side (with a request id) and return a generic message: 500 · Something went wrong.", exts=JS),
    Rule("dev-error-handler", "S20", "medium", "Development error handler enabled",
         r"app\.use\(\s*errorhandler\(\)\s*\)|app\.use\(\s*express\.errorHandler", "Use it only when NODE_ENV=development.", exts=JS),
    Rule("py-debug-true", "S20", "high", "DEBUG / debug mode enabled",
         r"^\s*DEBUG\s*=\s*True\b|\.run\([^)\n]{0,200}debug\s*=\s*True|app\.debug\s*=\s*True",
         "Read DEBUG from env and default to False; never run the Werkzeug debugger in production (RCE).", exts=PY, flags=M),
    Rule("php-display-errors", "S20", "medium", "PHP errors displayed to visitors",
         r"ini_set\(\s*[\"']display_errors[\"']\s*,\s*[\"']?(?:1|on|true)|define\(\s*[\"']WP_DEBUG(?:_DISPLAY)?[\"']\s*,\s*true"
         r"|public\s+\$debug\s*=\s*[\"']?1|public\s+\$error_reporting\s*=\s*[\"'](?:maximum|development)",
         "display_errors=Off in production; log to a file outside the web root.", exts=PHP, flags=I),
    Rule("ini-display-errors", "S20", "medium", "display_errors / allow_url_include enabled in ini",
         r"^\s*(?:display_errors\s*=\s*(?:On|1)|allow_url_include\s*=\s*On|expose_php\s*=\s*On)", "Turn them off.",
         names=r"(^|/)(php\.ini|\.user\.ini)$", flags=M | I),
    Rule("source-maps-in-prod", "X11", "medium", "Browser source maps published in production",
         r"productionBrowserSourceMaps\s*:\s*true|devtool\s*:\s*[\"'](?:eval|source-map|inline-source-map)[\"']|"
         r"sourcemap\s*:\s*true", "Disable public source maps (or upload them privately to Sentry).", exts=JS),
    Rule("secrets-in-logs", "S08", "medium", "Credentials/tokens written to logs",
         r"(?:console\.(?:log|info|debug|warn)|logger\.\w+|logging\.\w+|print)\s*\([^)\n]{0,200}\b(?:password|passwd|secret|"
         r"token|apiKey|api_key|authorization|cookie|creditCard|card_number)\b",
         "Never log secrets/PII; log user id + event + IP instead. Redact in the logger config.", exts=JS | PY, flags=I,
         conf="low"),

    # ---------------- S04 HTTPS ----------------
    Rule("http-url-in-code", "S04", "low", "Plain http:// URL to a non-local host",
         r"[\"'`]http://(?!localhost|127\.0\.0\.1|0\.0\.0\.0|\[::1\]|[\w.\-]*\.local\b|[\w.\-]*\.test\b|www\.w3\.org|"
         r"schemas\.|json-schema\.org|ns\.adobe|purl\.org|xmlns|example\.(?:com|org)|[\w.\-]*\.example\b)[^\"'`\s]{3,}",
         "Use https:// (and HSTS) for every external call and asset.", exts=JS | PY | PHP, conf="low"),

    # ---------------- S03 database access ----------------
    Rule("supabase-service-role-in-client", "S03", "critical", "Supabase service_role used in client-side code",
         r"service_?role|SERVICE_?ROLE", "Use the anon/publishable key in browsers with RLS; keep service_role in server-only "
         "modules (import 'server-only').", exts=JS, file_require=r"\A\s*[\"']use client[\"']", conf="high"),
    Rule("supabase-admin-in-client", "S03", "critical", "supabase.auth.admin called from client-side code",
         r"\.auth\.admin\.", "Admin APIs need the service key — move to a server route.", exts=JS,
         file_require=r"\A\s*[\"']use client[\"']"),
    Rule("admin-client-in-client-component", "S03", "critical",
         "Privileged DB client (service role/admin SDK) used in a client component — its key ships to the browser",
         r"\b(?:supabaseAdmin|adminClient|serviceRoleClient|supabaseService|serviceClient|adminDb|firebaseAdmin)\b",
         "Move privileged queries to server code (route handler/server action with auth + role checks); keep the admin "
         "client in a `server-only` module and rotate its key.", exts=JS, file_require=r"\A\s*[\"']use client[\"']",
         once=True),
    Rule("supabase-idor-eq-param", "X01", "medium", "Rows selected by an id from the URL without an ownership filter",
         r"\.eq\(\s*[\"'`]\w*id[\"'`]\s*,\s*(?:params\.\w+|req\.params\.\w+|searchParams\.get\([^)]*\)|body\.\w+)\s*\)",
         "Add the owner/tenant filter (or rely on RLS with the user's client, not the service-role client) and return 404 "
         "for other people's records.", exts=JS, near_unless=r"auth\.uid|user\.id|getUser|session\.user|owner|client_id\s*,\s*user",
         window=200),
    Rule("route-handler-no-auth", "S01", "medium", "API route handler without any visible authentication",
         r"\A", "Authenticate (session/JWT) and authorize inside the handler — or document why it is intentionally public "
         "(then rate-limit it).", exts=JS, path_rx=r"(^|/)(src/)?(app/api/.+/route|pages/api/.+)\.(t|j)sx?$",
         file_unless=r"\bauth\(|getServerSession|getSession|getUser|getClaims|currentUser|requireUser|requireAuth|verifyToken|"
                     r"jwt\.verify|jwtVerify|clerk|auth\.uid|session|authorization|x-api-key|constructEvent|signature|"
                     r"x-telegram|verifySignature|webhook", once=True, conf="low"),
    Rule("ai-endpoint-unprotected", "X08", "medium", "AI/LLM endpoint without auth or rate limiting (cost abuse)",
         r"new\s+(?:OpenAI|Anthropic|GoogleGenerativeAI|Groq|Mistral)\s*\(|\bstreamText\(|\bgenerateText\(",
         "Require a session, rate-limit per user/IP, cap max_tokens, set provider spend limits, treat output as untrusted.",
         exts=JS | PY, file_unless=r"rateLimit|ratelimit|limiter|quota|\bauth\(|getUser|getServerSession|requireUser|session",
         once=True),
    Rule("form-object-from-entries", "X01", "medium", "Whole form copied into a DB update (mass assignment)",
         r"Object\.fromEntries\(\s*(?:await\s+)?(?:formData|form|req\.formData\(\))\s*\)", "Parse with a strict schema "
         "and pick allowed fields — otherwise users can set role/status/price.", exts=JS,
         file_unless=r"\bz\.object|\.safeParse\(|\.parse\(|\bpick\(", unless_action="downgrade"),
    Rule("error-details-in-response", "S20", "medium", "Raw error object/details returned to the client",
         r"json\(\s*\{[^}]{0,120}\b(?:details|stack|trace|debug)\s*:\s*(?:err|error|e|ex)\b", "Return a generic message "
         "and log the details server-side.", exts=JS),
    Rule("public-storage-bucket", "S18", "high", "Public storage bucket (anyone with the path can download)",
         r"insert\s+into\s+storage\.buckets[^;]{0,200}?values\s*\([^)]*\btrue\b|createBucket\([^)]*public\s*:\s*true",
         "Make the bucket private, add storage.objects policies, serve files via short-lived signed URLs.",
         exts=SQL | JS, flags=I | S),
    Rule("long-signed-url", "S18", "medium", "Signed URL valid for a long time", r"createSignedUrl\([^,]+,\s*(?:60\s*\*\s*60\s*\*\s*24|"
         r"86400|\d{6,}|3600\s*\*\s*24)", "Use minutes, not days (e.g. 300 s), and generate on demand after an ownership check.",
         exts=JS),
    Rule("view-bypasses-rls", "S03", "medium", "View without security_invoker (runs with owner rights, bypassing RLS)",
         r"create\s+(?:or\s+replace\s+)?view\s+[\w.\"]+\s+as\b", "Use `create view … with (security_invoker = true)` "
         "(Postgres 15+) or revoke access to the view from anon/authenticated.", exts=SQL, flags=I),
    Rule("firebase-rules-open", "S03", "critical", "Firebase rules allow public read/write",
         r"allow\s+(?:read|write|read\s*,\s*write|write\s*,\s*read)\s*(?::\s*if\s+true\s*)?;|[\"']\.(?:read|write)[\"']\s*:\s*(?:true|[\"']true[\"'])",
         "Require request.auth and ownership checks in every rule.", names=r"\.rules$|database\.rules\.json$"),
    Rule("sql-security-definer", "S03", "medium", "SECURITY DEFINER function without fixed search_path",
         r"security\s+definer", "Add `SET search_path = ''` (or pg_catalog, public) and check auth.uid() inside.",
         exts=SQL, near_unless=r"set\s+search_path", window=600, flags=I),
    Rule("sql-grant-all-anon", "S03", "high", "Broad GRANT to anon/public/authenticated",
         r"grant\s+all\s+(?:privileges\s+)?on\s+[^;]{1,200}\s+to\s+(?:anon|public|authenticated)\b",
         "Grant least privilege and rely on RLS policies.", exts=SQL, flags=I),
    Rule("sql-policy-using-true", "S03", "medium", "RLS policy with USING (true)",
         r"create\s+policy[^;]{0,500}?using\s*\(\s*true\s*\)", "OK only for intentionally public read data; otherwise "
         "use auth.uid() = user_id.", exts=SQL, flags=I | S),

    # ---------------- X07 webhooks / X08 AI ----------------
    Rule("webhook-unverified", "X07", "medium", "Webhook handler without signature verification",
         r"\A", "Verify the provider signature (stripe.webhooks.constructEvent, HMAC + timingSafeEqual, Telegram "
         "X-Telegram-Bot-Api-Secret-Token) before trusting the payload.", exts=JS | PY | PHP, path_rx=r"webhook",
         file_unless=r"constructEvent|verifySignature|verify\(|createHmac|hmac|timingSafeEqual|svix|signature|secret_token|"
                     r"X-Telegram-Bot-Api-Secret-Token|compare_digest", once=True),
    Rule("ai-key-in-browser", "X08", "critical", "AI SDK used directly in the browser (API key exposed)",
         r"dangerouslyAllowBrowser\s*:\s*true", "Call the model from a server route with per-user rate limits & quotas.",
         exts=JS),
    Rule("ai-sdk-client-component", "X08", "critical", "AI SDK instantiated in a client component",
         r"new\s+(?:OpenAI|Anthropic|GoogleGenerativeAI|Groq|Mistral)\s*\(", "Move to a server route/action.", exts=JS,
         file_require=r"\A\s*[\"']use client[\"']"),

    # ---------------- X12 malware / backdoors (compromised PHP/CMS sites) ----------------
    Rule("php-backdoor-eval", "X12", "critical", "Obfuscated eval (classic PHP backdoor)",
         r"eval\s*\(\s*(?:base64_decode|gzinflate|gzuncompress|str_rot13|strrev|rawurldecode|hex2bin|gzdecode)\s*\(",
         "Treat the site as compromised: isolate, restore from a known-good backup/fresh core, rotate all credentials.",
         exts=PHP | {".js"}),
    Rule("php-backdoor-input-exec", "X12", "critical", "Code/command execution from request input",
         r"(?:assert|system|shell_exec|passthru|exec|popen|proc_open|pcntl_exec|unserialize)\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)"
         r"|\$_(?:GET|POST|REQUEST|COOKIE)\s*\[[^\]]{1,40}\]\s*\(|(?:include|require)(?:_once)?\s*\(?\s*\$_(?:GET|POST|REQUEST|COOKIE)"
         r"|preg_replace\s*\(\s*[\"']([^\"'])(?:(?!\1).){0,200}\1[a-df-z]*e[a-z]*[\"']",
         "Remove and investigate how it got there (outdated extension? stolen FTP creds?).", exts=PHP),
    Rule("php-webshell-marker", "X12", "critical", "Known web-shell / injector signature",
         r"FilesMan|b374k|c99shell|r57shell|WSO\s?\d|\$GLOBALS\[[\"']\w+[\"']\]\[\d+\]\(|@include\s*\(?\s*[\"']\\x|"
         r"base64_decode\s*\(\s*[\"'][A-Za-z0-9+/=]{300,}", "Quarantine the file and audit the whole web root.", exts=PHP),
    Rule("php-create-function", "X12", "high", "create_function() (deprecated, eval-like)", r"\bcreate_function\s*\(",
         "Replace with closures; check whether this file belongs to the original codebase.", exts=PHP),

    # ---------------- X10 infra ----------------
    Rule("docker-db-port-public", "X10", "high", "Database/cache port published on all interfaces",
         r"^\s*-\s*[\"']?(?:0\.0\.0\.0:)?(?:5432|3306|33060|27017|6379|9200|5984|11211|8086|15672|5672):\d+",
         "Bind to localhost: \"127.0.0.1:5432:5432\" (Docker-published ports bypass ufw), or don't publish at all.",
         names=r"(^|/)(docker-)?compose[\w.\-]*\.ya?ml$", flags=M),
    Rule("dockerfile-secret", "X10", "high", "Secret baked into the Docker image",
         r"^\s*(?:ENV|ARG)\s+\w*(?:SECRET|PASSWORD|TOKEN|API_KEY|PRIVATE)\w*(?:\s*=\s*|\s+)\S+",
         "Pass secrets at runtime (env_file, Docker secrets), never in image layers.", names=r"(^|/)Dockerfile[\w.\-]*$",
         flags=M, mask_literals=True),
    Rule("nginx-autoindex", "S23", "medium", "Directory listing enabled", r"^\s*autoindex\s+on|Options\s+\+?Indexes",
         "Disable autoindex / Options -Indexes.", names=r"\.conf$|nginx|\.htaccess$", flags=M),
    Rule("nginx-server-tokens", "X10", "low", "Server version disclosed", r"^\s*server_tokens\s+on",
         "server_tokens off;", names=r"\.conf$|nginx", flags=M),
    Rule("gha-pr-target-checkout", "X14", "high", "pull_request_target workflow checks out PR code",
         r"ref:\s*\$\{\{\s*github\.event\.pull_request\.head", "Never run untrusted PR code with secrets.",
         path_rx=r"\.github/workflows/", file_require=r"pull_request_target"),
    Rule("gha-script-injection", "X14", "high", "Untrusted GitHub event text interpolated into a run step",
         r"run:[^\n]*\$\{\{\s*github\.event\.(?:issue|pull_request|comment|review|head_commit)\.[\w.]*(?:title|body|message|name)",
         "Pass via env: and quote the variable.", path_rx=r"\.github/workflows/"),
]

# ---------------------------------------------------------------------------
# Project-level "missing control" checks
# ---------------------------------------------------------------------------
MARKERS = {
    "rate_limit": r"express-rate-limit|rate-limiter-flexible|@upstash/ratelimit|express-slow-down|express-brute|"
                  r"@nestjs/throttler|hono-rate-limiter|koa-ratelimit|@fastify/rate-limit|fastify-rate-limit|next-rate-limit|"
                  r"slowapi|flask_limiter|Flask-Limiter|django_ratelimit|django-ratelimit|axes|DEFAULT_THROTTLE_RATES|"
                  r"throttle:|RateLimiter::|limit_req|rateLimit\(|ratelimit|rate_limit|RateLimit",
    "headers": r"\bhelmet\b|Content-Security-Policy|contentSecurityPolicy|async\s+headers\s*\(|add_header\s|Talisman|"
               r"SECURE_HSTS_SECONDS|django-csp|CSP_DEFAULT_SRC|Strict-Transport-Security|X-Frame-Options|secure-headers|"
               r"SecurityHeaders|laravel-csp|@fastify/helmet",
    "csrf": r"csrf-csrf|csrf-sync|\blusca\b|\bcsurf\b|csrfToken|X-CSRF-Token|_csrf|csrf_token|@fastify/csrf|CSRFProtect|"
            r"CsrfViewMiddleware|VerifyCsrfToken|@csrf|wp_nonce|check_admin_referer|sameSite\s*:\s*['\"]strict|SameSite=Strict",
    "cookie_session": r"express-session|cookie-session|iron-session|res\.cookie\(|cookies\(\)\.set|session_start\(|"
                      r"flask\.session|from flask import[^\n]*session|SESSION_ENGINE|setcookie\(",
    "hashing": r"\bbcrypt|bcryptjs|argon2|@node-rs/argon2|\bscrypt|pbkdf2|password_hash\(|passlib|generate_password_hash|"
               r"make_password|django\.contrib\.auth|Hash::make|hashPassword|better-auth|lucia",
    "managed_auth": r"@supabase/(?:supabase-js|ssr|auth-helpers)|firebase/auth|@clerk/|auth0|@auth0/|next-auth|@auth/|"
                    r"@kinde-oss|@workos|better-auth|lucia|passport-google|@stackframe",
    "password_handling": r"\bpassword\b",
    "user_registration": r"register|signup|sign-up|createUser|INSERT\s+INTO\s+users|users\.create|User\.create",
    "validation": r"\bzod\b|from ['\"]zod|\bjoi\b|\byup\b|valibot|class-validator|express-validator|\bajv\b|superstruct|"
                  r"typebox|@vinejs|pydantic|BaseModel|marshmallow|cerberus|wtforms|forms\.Form|serializers\.|->validate\(|"
                  r"Validator::make|FormRequest|filter_var\(",
    "api_handlers": r"app\.(?:get|post|put|patch|delete)\(|router\.(?:get|post|put|patch|delete)\(|export\s+async\s+function\s+"
                    r"(?:GET|POST|PUT|PATCH|DELETE)\b|['\"]use server['\"]|@app\.(?:get|post|route)|@router\.|def\s+\w+\(request|"
                    r"Route::(?:get|post)|\$_POST",
    "logging": r"winston|\bpino\b|bunyan|morgan|log4js|@sentry/|logtail|datadog|newrelic|import logging|getLogger|Monolog|"
               r"Log::(?:info|warning|error)|logger\.",
    "login_route": r"[\"'`]/(?:api/)?(?:auth/)?(?:login|signin|sign-in|session|token|otp|verify-otp|forgot-password|reset-password)\b|"
                   r"signInWithPassword|function\s+(?:login|signIn)\b|def\s+login\b|CredentialsProvider|Credentials\(",
    "node_env_prod": r"NODE_ENV=production|NODE_ENV:\s*['\"]?production|env_production|ENV\s+NODE_ENV[= ]production",
    "ci_security": r"gitleaks|trufflehog|npm audit|pnpm audit|yarn audit|pip-audit|composer audit|dependency-review|"
                   r"codeql|snyk|osv-scanner|semgrep|trivy",
}
MARKERS_RX = {k: re.compile(v, re.I) for k, v in MARKERS.items()}

RLS_TABLE_RX = re.compile(r"create\s+table\s+(?:if\s+not\s+exists\s+)?(?:\"?(\w+)\"?\.)?\"?(\w+)\"?", re.I)
RLS_ENABLE_RX = re.compile(r"alter\s+table\s+(?:if\s+exists\s+)?(?:only\s+)?(?:\"?(\w+)\"?\.)?\"?(\w+)\"?\s+enable\s+row\s+level\s+security", re.I)


def _mask_literals(s: str) -> str:
    return re.sub(r"([\"'`])([^\"'`]{6,})\1", lambda m: m.group(1) + mask(m.group(2)) + m.group(1), s)


def scan(root: Path, include_tests: bool = False) -> dict:
    root = root.resolve()
    findings: List[dict] = []
    found_markers: Dict[str, List[str]] = {k: [] for k in MARKERS}
    tables, rls = {}, set()
    pkg = load_package_json(root)
    dep_blob = json.dumps(pkg) + " "
    for f in ("requirements.txt", "pyproject.toml", "Pipfile", "composer.json"):
        if (root / f).exists():
            dep_blob += read_text(root / f)
    files_scanned = 0
    for path in iter_files(root):
        r = rel(root, path)
        name = path.name
        ext = path.suffix.lower()
        if name.endswith(".blade.php"):
            ext = ".php"
        is_test = bool(TEST_PATH.search(r))
        text = read_text(path)
        if not text:
            continue
        files_scanned += 1
        if ext in JS | PY | PHP | TPL | SQL or name in {"Dockerfile"} or r.startswith(".github/") or ext in {".conf", ".yml", ".yaml", ".json", ".toml", ".ini"}:
            for k, rx in MARKERS_RX.items():
                if len(found_markers[k]) < 5 and rx.search(text):
                    found_markers[k].append(r)
        if ext in SQL:
            for m in RLS_TABLE_RX.finditer(text):
                schema = (m.group(1) or "public").lower()
                if schema in {"public", ""}:
                    tables.setdefault(m.group(2).lower(), (r, line_of(text, m.start())))
            for m in RLS_ENABLE_RX.finditer(text):
                rls.add(m.group(2).lower())
        if is_test and not include_tests:
            continue
        if len(text) > 400_000 or (text.count("\n") < 3 and len(text) > 20_000):
            continue  # minified/generated
        for rule in R:
            if not rule.applies(r, name, ext):
                continue
            if rule.file_require and not rule.file_require.search(text):
                continue
            file_unless_hit = bool(rule.file_unless and rule.file_unless.search(text))
            if file_unless_hit and rule.unless_action == "suppress":
                continue
            count = 0
            for m in rule.rx.finditer(text):
                lo, hi = max(0, m.start() - rule.window), min(len(text), m.end() + rule.window)
                win = text[lo:hi]
                if rule.near_require and not rule.near_require.search(win):
                    continue
                sev, title, conf = rule.sev, rule.title, rule.conf
                if rule.near_unless and rule.near_unless.search(win):
                    if rule.unless_action == "suppress":
                        continue
                    sev, conf = DOWN[sev], "low"
                if file_unless_hit:
                    sev, conf = DOWN[sev], "low"
                if rule.post:
                    res = rule.post(m, text)
                    if res is None and rule.id == "cookie-flags":
                        continue
                    if res:
                        sev, title = res
                ln = line_of(text, m.start())
                ev = line_text(text, ln).strip()
                if rule.mask_literals:
                    ev = _mask_literals(ev)
                ev = ev[:180]
                findings.append(finding(rule.id, rule.step, sev, title, r, ln, ev, rule.fix, conf, "scan_code_patterns"))
                count += 1
                if rule.once or count >= rule.max_per_file:
                    break

    # ---- project-level checks ----
    has = {k: bool(v) for k, v in found_markers.items()}
    for k in ("rate_limit", "headers", "csrf", "hashing", "managed_auth", "validation", "logging", "cookie_session"):
        if MARKERS_RX[k].search(dep_blob):
            has[k] = True
    uses_supabase = "@supabase" in dep_blob or (root / "supabase").is_dir()
    node_server = any(d in dep_blob for d in ('"express"', '"fastify"', '"koa"', '"hono"', '"next"', '"@nestjs/core"'))

    def missing(rule_id, step, sev, title, fix, conf="medium"):
        findings.append(finding(rule_id, step, sev, title, "", 0, "", fix, conf, "scan_code_patterns", missing_control=True))

    if has["login_route"] and not has["rate_limit"]:
        missing("no-rate-limiting", "S12", "high", "Login/auth endpoints found but no rate limiting library or config",
                "Add per-IP + per-account limits on login, signup, OTP, password reset and costly APIs (express-rate-limit / "
                "@upstash/ratelimit / nginx limit_req / slowapi / Laravel throttle). Behind a proxy set `trust proxy` correctly.")
    if has["api_handlers"] and not has["headers"]:
        missing("no-security-headers", "S14", "medium", "No security-header configuration found in code (helmet/headers()/CSP)",
                "Add CSP, HSTS, X-Frame-Options/frame-ancestors, X-Content-Type-Options, Referrer-Policy, Permissions-Policy — "
                "or confirm they are set by Nginx/CDN with check_live.py.")
    if has["cookie_session"] and not has["csrf"]:
        missing("no-csrf-protection", "S16", "medium", "Cookie-based sessions without visible CSRF protection",
                "Use SameSite=Lax/Strict cookies + a CSRF token (csrf-csrf / framework middleware) for state-changing "
                "requests, or check Origin/Host. (Next.js Server Actions already compare Origin/Host.)")
    if has["password_handling"] and has["user_registration"] and not has["hashing"] and not has["managed_auth"]:
        missing("no-password-hashing", "S05", "high", "Passwords handled but no password-hashing library found",
                "Hash with argon2id (or bcrypt cost ≥ 12) on signup/reset; verify with the library's compare.")
    if has["api_handlers"] and not has["validation"]:
        missing("no-validation-library", "S06", "medium", "API handlers found but no schema validation library",
                "Validate every request body/query/params on the server with a schema (zod/joi/pydantic/FormRequest): types, "
                "ranges (quantity 1..10), lengths, enums.")
    if has["api_handlers"] and not has["logging"]:
        missing("no-logging", "S08", "low", "No structured logging / error monitoring detected",
                "Log auth failures, permission denials, rate-limit hits and admin actions (pino/winston + Sentry) and alert on "
                "bursts (e.g. 5 failed logins / minute).", conf="low")
    if node_server and not has["node_env_prod"]:
        missing("node-env-production", "S20", "low", "NODE_ENV=production not set in start scripts / PM2 / Dockerfile",
                "Set NODE_ENV=production for the production process (Express hides stack traces and enables caching).",
                conf="low")
    if (root / ".github").is_dir() and not has["ci_security"]:
        missing("no-ci-security", "X14", "info", "No automated security checks in CI",
                "Add assets/ci/security.yml (gitleaks + npm audit + dependency review) and Dependabot.", conf="high")
    if uses_supabase and tables:
        for t, (f, ln) in sorted(tables.items()):
            if t not in rls:
                findings.append(finding("supabase-table-without-rls", "S03", "high",
                                        f"Table public.{t} created without ENABLE ROW LEVEL SECURITY", f, ln,
                                        f"create table {t} …", f"ALTER TABLE public.{t} ENABLE ROW LEVEL SECURITY; then add "
                                        "policies using auth.uid(). Without RLS anyone with the anon key can read/write it.",
                                        "high", "scan_code_patterns"))
    # Next.js versions affected by the middleware bypass (CVE-2025-29927)
    nv = (pkg.get("dependencies") or {}).get("next") or ""
    mv = re.match(r"[\^~>=\s]*(\d+)\.(\d+)\.(\d+)", nv)
    if mv:
        maj, mi, pa = map(int, mv.groups())
        vuln = (maj == 11) or (maj == 12 and (mi, pa) < (3, 5)) or (maj == 13 and (mi, pa) < (5, 9)) or \
               (maj == 14 and (mi, pa) < (2, 25)) or (maj == 15 and (mi, pa) < (2, 3))
        if vuln:
            findings.append(finding("nextjs-middleware-bypass", "S21", "critical" if (root / "middleware.ts").exists() or
                                    (root / "middleware.js").exists() or (root / "src/middleware.ts").exists() else "high",
                                    f"next@{nv} is affected by CVE-2025-29927 (middleware auth bypass) and later advisories",
                                    "package.json", 0, f'"next": "{nv}"', "Upgrade Next.js to the latest patched release "
                                    "of your major and re-run npm audit; never rely on middleware alone for auth.",
                                    "high", "scan_code_patterns"))
    return {"scanner": "scan_code_patterns", "root": str(root), "findings": sort_findings(findings),
            "meta": {"files_scanned": files_scanned, "controls_detected": {k: v for k, v in found_markers.items() if v},
                     "supabase_tables": len(tables), "supabase_rls_enabled": len(rls)}}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("project")
    ap.add_argument("--json")
    ap.add_argument("--include-tests", action="store_true")
    a = ap.parse_args(argv)
    res = scan(Path(a.project), a.include_tests)
    print(f"scan_code_patterns: {len(res['findings'])} lead(s) in {res['meta']['files_scanned']} files "
          "(verify each one by reading the code)")
    print_table(res["findings"])
    if a.json:
        write_json(Path(a.json), res)
    return 0


if __name__ == "__main__":
    sys.exit(main())
