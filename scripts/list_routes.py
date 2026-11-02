#!/usr/bin/env python3
"""Inventory every HTTP entry point so authorization can be checked route by
route (S09 admin routes, X01 IDOR, S26 full review).

Detects: Express/Koa/Fastify/Hono/Nest-style `app.get('/x', ...)`, Next.js App
Router route handlers (app/**/route.ts) and pages (app/**/page.tsx), Pages
Router API routes (pages/api/**), Server Actions ('use server'), Socket.IO
events, FastAPI/Flask/Django, Laravel routes, plain PHP entry files.

Output: markdown table (method, path, file:line, guards seen) — the starting
point of an authorization matrix (anonymous / user / other user / admin).

Usage:
  python3 list_routes.py <project_dir> [--json out.json]
"""
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path
from typing import List

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _common import iter_files, line_of, read_text, rel, write_json  # noqa: E402

GUARD_RX = re.compile(r"\b(require\w*|ensure\w*|is(?:Admin|Auth\w*|LoggedIn|Staff)|auth\w*|protect\w*|verify\w*|"
                      r"checkRole|hasRole|can|authorize|login_required|permission_classes|Depends\(\s*get_current\w*|"
                      r"middleware\(\s*['\"][\w:,]+['\"]\s*\)|getServerSession|getUser|currentUser|session)\b", re.I)
JS_ROUTE = re.compile(r"\b(?:app|router|server|api|routes?|fastify|r)\.(get|post|put|patch|delete|all|use|options|head)\(\s*"
                      r"[\"'`]([^\"'`]+)[\"'`]\s*(,[^\n]*)?", re.I)
PY_ROUTE = re.compile(r"@(?:\w+)\.(get|post|put|patch|delete|route|api_route|websocket)\(\s*[\"']([^\"']+)[\"']([^\n]*)")
DJ_ROUTE = re.compile(r"\b(?:re_)?path\(\s*r?[\"']([^\"']*)[\"']\s*,\s*([\w.]+)")
LV_ROUTE = re.compile(r"Route::(get|post|put|patch|delete|any|match|resource|apiResource)\(\s*[\"']([^\"']+)[\"']([^\n]*)")
SOCKET_EV = re.compile(r"socket\.on\(\s*[\"'`]([^\"'`]+)[\"'`]")
NEXT_METHODS = re.compile(r"export\s+(?:async\s+)?(?:function|const)\s+(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\b")
USE_SERVER = re.compile(r"\A\s*[\"']use server[\"']")
EXPORTED_FN = re.compile(r"export\s+(?:async\s+)?function\s+(\w+)|export\s+const\s+(\w+)\s*=\s*(?:async\s*)?\(")


def next_path(r: str) -> str:
    p = re.sub(r"^(src/)?(app|pages)", "", r)
    p = re.sub(r"/\([^)]+\)", "", p)  # route groups
    p = re.sub(r"/(route|page|index)\.(t|j)sx?$", "", p)
    p = re.sub(r"\.(t|j)sx?$", "", p)
    p = re.sub(r"\[\.\.\.(\w+)\]", r"*\1", p)
    p = re.sub(r"\[(\w+)\]", r":\1", p)
    return p or "/"


def scan(root: Path) -> List[dict]:
    root = root.resolve()
    out: List[dict] = []
    for path in iter_files(root, max_bytes=600_000):
        r = rel(root, path)
        ext = path.suffix.lower()
        text = read_text(path)
        if not text:
            continue
        file_guard = sorted({m.group(1) for m in GUARD_RX.finditer(text)})[:6]
        if ext in {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"}:
            if re.search(r"(^|/)(src/)?app/.*route\.(t|j)sx?$", r):
                for m in NEXT_METHODS.finditer(text):
                    out.append({"kind": "next-route-handler", "method": m.group(1), "path": next_path(r), "file": r,
                                "line": line_of(text, m.start()), "guards": ", ".join(file_guard)})
            elif re.search(r"(^|/)(src/)?app/.*page\.(t|j)sx?$", r):
                out.append({"kind": "next-page", "method": "GET", "path": next_path(r), "file": r, "line": 1,
                            "guards": ", ".join(file_guard)})
            elif re.search(r"(^|/)(src/)?pages/api/", r):
                out.append({"kind": "next-api-route", "method": "ANY", "path": next_path(r), "file": r, "line": 1,
                            "guards": ", ".join(file_guard)})
            if USE_SERVER.search(text):
                for m in EXPORTED_FN.finditer(text):
                    out.append({"kind": "server-action", "method": "POST", "path": f"(action) {m.group(1) or m.group(2)}",
                                "file": r, "line": line_of(text, m.start()), "guards": ", ".join(file_guard)})
            for m in JS_ROUTE.finditer(text):
                if not m.group(2).startswith("/") and m.group(1).lower() != "use":
                    continue
                args = m.group(3) or ""
                g = sorted({x.group(1) for x in GUARD_RX.finditer(args)})
                out.append({"kind": "http", "method": m.group(1).upper(), "path": m.group(2), "file": r,
                            "line": line_of(text, m.start()), "guards": ", ".join(g) or "(none on the route line)"})
            for m in SOCKET_EV.finditer(text):
                if m.group(1) in {"connect", "disconnect", "error", "connection"}:
                    continue
                out.append({"kind": "socket-event", "method": "EVENT", "path": m.group(1), "file": r,
                            "line": line_of(text, m.start()), "guards": ", ".join(file_guard)})
        elif ext == ".py":
            for m in PY_ROUTE.finditer(text):
                out.append({"kind": "python", "method": m.group(1).upper(), "path": m.group(2), "file": r,
                            "line": line_of(text, m.start()),
                            "guards": ", ".join(sorted({x.group(1) for x in GUARD_RX.finditer(m.group(3) or "")})) or "-"})
            if path.name == "urls.py":
                for m in DJ_ROUTE.finditer(text):
                    out.append({"kind": "django", "method": "ANY", "path": "/" + m.group(1), "file": r,
                                "line": line_of(text, m.start()), "guards": m.group(2)})
        elif ext == ".php":
            for m in LV_ROUTE.finditer(text):
                out.append({"kind": "laravel", "method": m.group(1).upper(), "path": m.group(2), "file": r,
                            "line": line_of(text, m.start()),
                            "guards": ", ".join(re.findall(r"middleware\(([^)]*)\)", m.group(3) or "")) or "-"})
            if not r.startswith(("vendor/", "routes/", "app/", "config/", "database/")) and \
                    re.search(r"\$_(GET|POST|REQUEST|FILES)", text):
                out.append({"kind": "php-entry", "method": "ANY", "path": "/" + r, "file": r, "line": 1,
                            "guards": ", ".join(file_guard) or "-"})
    return out


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("project")
    ap.add_argument("--json")
    a = ap.parse_args(argv)
    routes = scan(Path(a.project))
    print(f"{len(routes)} entry points\n")
    print("| method | path | file:line | guards seen | anon | user | other user | admin |")
    print("|---|---|---|---|---|---|---|---|")
    for x in routes:
        print(f"| {x['method']} | `{x['path']}` | `{x['file']}:{x['line']}` | {x['guards'] or '-'} |  |  |  |  |")
    print("\nFill the last four columns with the EXPECTED result (200/401/403/404) and test each one.")
    if a.json:
        write_json(Path(a.json), routes)
    return 0


if __name__ == "__main__":
    sys.exit(main())
