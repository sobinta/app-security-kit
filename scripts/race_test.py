#!/usr/bin/env python3
"""Race-condition tester (X06): fire N identical requests at the same instant and
count how many succeed. Use it on anything that must happen at most once:
redeeming a coupon/gift card, spending credit/wallet balance, using a reset
token or invite, claiming a limited item, voting, signup bonuses, withdrawals.

A single-threaded test passes ("second redeem → 400") while 20 parallel
requests can still all succeed if the code does check-then-act without a
transaction/lock/unique constraint.

Only test systems you own (non-local targets need --i-own-this).

Usage:
  python3 race_test.py http://localhost:3000/api/coupons/redeem -X POST \
      --json '{"code":"WELCOME50"}' -H 'Cookie: session=...' -n 20 --max-success 1 \
      [--success-status 200,201] [--success-regex '"ok":\\s*true']
Exit code 1 when more than --max-success requests succeeded (race detected).
"""
from __future__ import annotations

import argparse
import http.client
import re
import ssl
import sys
import threading
import time
from pathlib import Path
from urllib.parse import urlparse

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _common import is_local_host, write_json  # noqa: E402


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("url")
    ap.add_argument("-X", "--method", default="POST")
    ap.add_argument("--json", dest="json_body")
    ap.add_argument("--data")
    ap.add_argument("-H", "--header", action="append", default=[])
    ap.add_argument("-n", "--count", type=int, default=20)
    ap.add_argument("--max-success", type=int, default=1, help="how many successes are legitimate")
    ap.add_argument("--success-status", default="200,201,202,204")
    ap.add_argument("--success-regex", help="body must match to count as success")
    ap.add_argument("--timeout", type=float, default=20)
    ap.add_argument("--insecure", action="store_true")
    ap.add_argument("--i-own-this", action="store_true")
    ap.add_argument("--json-out")
    a = ap.parse_args(argv)

    u = urlparse(a.url)
    if not is_local_host(u.hostname or "") and not a.i_own_this:
        print("Refusing non-local target without --i-own-this (only test systems you own).")
        return 2
    n = max(2, min(a.count, 200))
    body = None
    headers = {"User-Agent": "app-security-kit-race/1.0"}
    if a.json_body is not None:
        body = a.json_body.encode()
        headers["Content-Type"] = "application/json"
    elif a.data is not None:
        body = a.data.encode()
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    for h in a.header:
        k, _, v = h.partition(":")
        headers[k.strip()] = v.strip()
    ok_status = {int(x) for x in a.success_status.split(",") if x.strip()}
    rx = re.compile(a.success_regex) if a.success_regex else None
    path = (u.path or "/") + (("?" + u.query) if u.query else "")
    ctx = (ssl._create_unverified_context() if a.insecure else ssl.create_default_context()) if u.scheme == "https" else None  # noqa: S323

    conns = []
    for _ in range(n):  # open + warm TCP/TLS first so the requests leave together
        c = (http.client.HTTPSConnection(u.hostname, u.port or 443, timeout=a.timeout, context=ctx) if u.scheme == "https"
             else http.client.HTTPConnection(u.hostname, u.port or 80, timeout=a.timeout))
        c.connect()
        conns.append(c)
    barrier = threading.Barrier(n)
    results = [None] * n

    def go(i):
        c = conns[i]
        try:
            barrier.wait()
            t0 = time.perf_counter()
            c.request(a.method, path, body=body, headers=headers)
            r = c.getresponse()
            data = r.read(4000).decode("utf-8", "replace")
            results[i] = {"status": r.status, "ms": round((time.perf_counter() - t0) * 1000, 1), "body": data[:300]}
        except Exception as e:  # noqa: BLE001
            results[i] = {"status": 0, "error": type(e).__name__, "body": str(e)[:200]}
        finally:
            c.close()

    ths = [threading.Thread(target=go, args=(i,)) for i in range(n)]
    for t in ths:
        t.start()
    for t in ths:
        t.join()
    succ = [r for r in results if r and r["status"] in ok_status and (not rx or rx.search(r.get("body", "")))]
    by_status = {}
    for r in results:
        by_status[r["status"]] = by_status.get(r["status"], 0) + 1
    race = len(succ) > a.max_success
    print(f"race_test: {n} simultaneous {a.method} {a.url}")
    print(f"  status counts: {by_status}")
    print(f"  successes: {len(succ)} (allowed: {a.max_success})")
    for r in succ[:5]:
        print(f"    success body: {r.get('body', '')[:160]}")
    print("RESULT: " + (f"RACE CONDITION — {len(succ)} requests succeeded where at most {a.max_success} should. Use an "
                        "atomic UPDATE ... WHERE used = false RETURNING, a unique constraint, SELECT ... FOR UPDATE in a "
                        "transaction, or an idempotency key." if race else "OK — no double success observed (repeat a few "
                        "times; races are probabilistic)"))
    if a.json_out:
        write_json(Path(a.json_out), {"url": a.url, "n": n, "status_counts": by_status, "successes": len(succ),
                                      "max_success": a.max_success, "race_detected": race, "results": results})
    return 1 if race else 0


if __name__ == "__main__":
    sys.exit(main())
