#!/usr/bin/env python3
"""Zero-dependency HTTP load / stress / spike / soak / breakpoint tester (X15).

Answers "will the site survive N people at the same time?" with numbers:
throughput, latency percentiles, error rate, the load level where it starts to
degrade, and whether it recovers after a spike.

Only test systems you own. Non-local targets require --i-own-this, and
production should only be tested with the owner's explicit OK at a quiet time.

Profiles (peak = --target, default 50):
  smoke       2 users for 30s (always run first)
  load        ramp 0→peak in 1m, hold 3m, ramp down 30s       (expected busy hour)
  stress      peak → 2×peak → 3×peak, 2m each, then down      (where does it bend?)
  spike       5 → peak in 10s, hold 1m, back to 5 for 1m      (viral post / live stream)
  soak        ramp 2m, hold --soak-minutes (30), down 1m      (memory leaks, pool exhaustion)
  breakpoint  linear 0 → 5×peak over 10m, aborts when badly broken (max capacity)
  or --stages "30s:20,2m:20,30s:0" (duration:target pairs, linear ramps)

Modes:
  --mode vus   (default) closed model: target = concurrent virtual users, each
               doing request → think time → request ...
  --mode rate  open model: target = requests/second arriving regardless of how
               slow the server is (more realistic for spikes); --max-vus caps workers.

Examples:
  python3 load_test.py http://localhost:3000/ --profile smoke
  python3 load_test.py http://localhost:3000/ --profile load --target 200 --think 2
  python3 load_test.py https://staging.example.com --scenario scenario.json --profile spike --target 500 --i-own-this
  python3 load_test.py http://localhost:3000/api/products --mode rate --stages "30s:50,1m:300,30s:0" --max-vus 400
  python3 load_test.py http://localhost:3000/ --profile soak --target 100 --soak-minutes 30 --watch-pid $(pgrep -f "node server.js")

Scenario JSON:
  {"headers": {"Cookie": "session=..."}, "think": [0.5, 2.0], "requests": [
     {"name": "home", "path": "/", "weight": 5},
     {"name": "list", "path": "/api/products?page=1", "weight": 3},
     {"name": "login", "method": "POST", "path": "/api/login", "json": {"email": "load@test.dev", "password": "x"},
      "weight": 1, "expect": [200, 401, 429]}]}
"""
from __future__ import annotations

import argparse
import http.client
import json
import math
import queue
import random
import re
import ssl
import sys
import threading
import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _common import is_local_host, write_json  # noqa: E402

MAX_WORKERS = 3000


def parse_duration(s: str) -> float:
    m = re.fullmatch(r"\s*(\d+(?:\.\d+)?)\s*(ms|s|m|h)?\s*", s)
    if not m:
        raise ValueError(f"bad duration: {s}")
    v, u = float(m.group(1)), (m.group(2) or "s")
    return v / 1000 if u == "ms" else v * {"s": 1, "m": 60, "h": 3600}[u]


def parse_stages(spec: str) -> List[Tuple[float, float]]:
    out = []
    for part in spec.split(","):
        d, t = part.split(":")
        out.append((parse_duration(d), float(t)))
    return out


def profile_stages(name: str, peak: int, soak_minutes: float) -> List[Tuple[float, float]]:
    p = max(1, peak)
    return {
        "smoke": [(1, 2), (29, 2)],
        "load": [(60, p), (180, p), (30, 0)],
        "stress": [(60, p), (120, p), (60, 2 * p), (120, 2 * p), (60, 3 * p), (120, 3 * p), (60, 0)],
        "spike": [(10, 5), (20, 5), (10, p), (60, p), (10, 5), (60, 5)],
        "soak": [(120, p), (soak_minutes * 60, p), (60, 0)],
        "breakpoint": [(600, 5 * p)],
    }[name]


def target_at(stages: List[Tuple[float, float]], t: float) -> float:
    start_val, elapsed = 0.0, 0.0
    for dur, tgt in stages:
        if t <= elapsed + dur:
            frac = (t - elapsed) / dur if dur > 0 else 1.0
            return start_val + (tgt - start_val) * frac
        elapsed += dur
        start_val = tgt
    return stages[-1][1] if stages else 0.0


def rss_mb(pids: List[int]) -> Optional[float]:
    """Resident memory of local processes in MB (Linux /proc, else `ps`). None when unreadable."""
    if not pids:
        return None
    total = 0.0
    for pid in pids:
        status = Path(f"/proc/{pid}/status")
        try:
            if status.exists():
                m = re.search(r"^VmRSS:\s+(\d+)\s+kB", status.read_text(), re.M)
                if not m:
                    return None
                total += int(m.group(1)) / 1024
                continue
            import subprocess
            out = subprocess.run(["ps", "-o", "rss=", "-p", str(pid)], capture_output=True, text=True, timeout=5).stdout.strip()
            if not out:
                return None
            total += int(out.split()[0]) / 1024
        except Exception:  # noqa: BLE001 - best effort, any failure means "unknown"
            return None
    return total


def pct(sorted_vals: List[float], p: float) -> float:
    if not sorted_vals:
        return 0.0
    k = max(0, min(len(sorted_vals) - 1, math.ceil(p / 100 * len(sorted_vals)) - 1))
    return sorted_vals[k]


class Request:
    def __init__(self, d: dict, base_path: str):
        self.name = d.get("name") or d.get("path", "/")
        self.method = d.get("method", "GET").upper()
        path = d.get("path", "/")
        self.path = path if path.startswith("/") else base_path.rstrip("/") + "/" + path
        self.headers = dict(d.get("headers") or {})
        self.body: Optional[bytes] = None
        if "json" in d:
            self.body = json.dumps(d["json"]).encode()
            self.headers.setdefault("Content-Type", "application/json")
        elif "body" in d:
            self.body = str(d["body"]).encode()
        self.weight = float(d.get("weight", 1))
        self.expect = set(d.get("expect") or [])


class Recorder:
    """Per-thread sample lists → no lock contention on the hot path."""

    def __init__(self):
        self.lists: List[list] = []
        self.lock = threading.Lock()

    def new_list(self) -> list:
        lst: list = []
        with self.lock:
            self.lists.append(lst)
        return lst

    def snapshot_since(self, marks: Dict[int, int]) -> list:
        out = []
        for i, lst in enumerate(self.lists):
            n = len(lst)
            start = marks.get(i, 0)
            if n > start:
                out.extend(lst[start:n])
            marks[i] = n
        return out

    def all(self) -> list:
        out = []
        for lst in self.lists:
            out.extend(lst)
        return out


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("url", help="base URL (path used when no scenario is given)")
    ap.add_argument("--profile", choices=["smoke", "load", "stress", "spike", "soak", "breakpoint"], default="smoke")
    ap.add_argument("--stages", help='custom "30s:20,1m:20,30s:0" (overrides --profile)')
    ap.add_argument("--target", type=int, default=50, help="peak users (vus mode) or requests/s (rate mode)")
    ap.add_argument("--mode", choices=["vus", "rate"], default="vus")
    ap.add_argument("--max-vus", type=int, default=500, help="worker cap in rate mode")
    ap.add_argument("--soak-minutes", type=float, default=30)
    ap.add_argument("--scenario", help="JSON scenario file (weighted requests)")
    ap.add_argument("--method", default="GET")
    ap.add_argument("--body")
    ap.add_argument("--header", action="append", default=[], help="'Name: value' (repeatable)")
    ap.add_argument("--think", type=float, default=1.0, help="mean think time between a user's requests (s), vus mode")
    ap.add_argument("--timeout", type=float, default=15.0)
    ap.add_argument("--p95", type=float, default=800.0, help="threshold: p95 latency ms")
    ap.add_argument("--max-error-rate", type=float, default=1.0, help="threshold: %% errors (network + 5xx + unexpected)")
    ap.add_argument("--abort-on-fail", action="store_true", help="stop early when error rate > 20%% (breakpoint implies)")
    ap.add_argument("--insecure", action="store_true", help="accept self-signed TLS")
    ap.add_argument("--i-own-this", action="store_true", help="required for non-local targets")
    ap.add_argument("--watch-pid", type=int, action="append", default=[],
                    help="PID of the LOCAL server process (repeatable, e.g. each PM2 worker): samples its memory (RSS) "
                         "during the test — rising memory in a soak test = leak")
    ap.add_argument("--json-out")
    ap.add_argument("--quiet", action="store_true")
    a = ap.parse_args(argv)

    u = urlparse(a.url)
    if u.scheme not in ("http", "https") or not u.hostname:
        print("URL must be http(s)://host[:port]/path")
        return 2
    if not is_local_host(u.hostname) and not a.i_own_this:
        print(f"Refusing to load-test {u.hostname} without --i-own-this.\n"
              "Only test systems you own/are authorized to test. For production: get explicit approval, pick a quiet\n"
              "time, warn the hosting provider/CDN if needed, and exclude paid third-party calls (payments, email, AI).")
        return 2

    stages = parse_stages(a.stages) if a.stages else profile_stages(a.profile, a.target, a.soak_minutes)
    total_dur = sum(d for d, _ in stages)
    peak = max(t for _, t in stages)
    base_path = u.path or "/"
    if u.query:
        base_path += "?" + u.query

    default_headers = {"User-Agent": "app-security-kit-loadtest/1.0", "Accept": "*/*", "Accept-Encoding": "gzip"}
    think_range = (a.think * 0.5, a.think * 1.5)
    if a.scenario:
        sc = json.loads(Path(a.scenario).read_text(encoding="utf-8"))
        default_headers.update(sc.get("headers") or {})
        if "think" in sc:
            t = sc["think"]
            think_range = (float(t[0]), float(t[1])) if isinstance(t, list) else (float(t) * 0.5, float(t) * 1.5)
        reqs = [Request(d, base_path) for d in sc["requests"]]
    else:
        d = {"name": f"{a.method} {base_path}", "method": a.method, "path": base_path}
        if a.body:
            d["body"] = a.body
        reqs = [Request(d, base_path)]
    for h in a.header:
        k, _, v = h.partition(":")
        default_headers[k.strip()] = v.strip()
    weights = [r.weight for r in reqs]

    n_workers = int(min(MAX_WORKERS, math.ceil(peak) if a.mode == "vus" else a.max_vus))
    if n_workers > 1000:
        print(f"note: {n_workers} workers from one Python process may bottleneck on the client; for >1000 users use k6 "
              "(assets/k6/load-test.js) or several machines.")
    ctx = None
    if u.scheme == "https":
        ctx = ssl._create_unverified_context() if a.insecure else ssl.create_default_context()  # noqa: S323

    def new_conn():
        if u.scheme == "https":
            return http.client.HTTPSConnection(u.hostname, u.port or 443, timeout=a.timeout, context=ctx)
        return http.client.HTTPConnection(u.hostname, u.port or 80, timeout=a.timeout)

    stop = threading.Event()
    rec = Recorder()
    state = {"target": 0.0, "dropped": 0}
    work_q: "queue.Queue[float]" = queue.Queue()
    t_start = time.perf_counter()

    def do_request(conn, samples):
        r = random.choices(reqs, weights)[0]
        hdrs = dict(default_headers)
        hdrs.update(r.headers)
        t0 = time.perf_counter()
        status, err, nbytes = 0, "", 0
        for attempt in (1, 2):
            reused = conn is not None
            try:
                if conn is None:
                    conn = new_conn()
                conn.request(r.method, r.path, body=r.body, headers=hdrs)
                resp = conn.getresponse()
                data = resp.read()
                status, nbytes, err = resp.status, len(data), ""
                if (resp.getheader("Connection") or "").lower() == "close":
                    conn.close()
                    conn = None
                break
            except Exception as e:  # noqa: BLE001
                err = type(e).__name__
                try:
                    if conn:
                        conn.close()
                except Exception:  # noqa: BLE001
                    pass
                conn = None
                # an idle keep-alive socket closed by the server: browsers silently retry, so do we (once)
                if not (reused and attempt == 1 and err in {"RemoteDisconnected", "BrokenPipeError",
                                                           "ConnectionResetError", "BadStatusLine"}):
                    break
        lat = (time.perf_counter() - t0) * 1000
        bad = bool(err) or status >= 500 or (bool(r.expect) and status not in r.expect)
        samples.append((t0 - t_start, r.name, lat, status, err, bad, nbytes))
        return conn

    def vu_worker(idx: int):
        samples = rec.new_list()
        conn = None
        while not stop.is_set():
            if idx >= state["target"]:
                if conn is not None:
                    try:
                        conn.close()
                    except Exception:  # noqa: BLE001
                        pass
                    conn = None
                time.sleep(0.05)
                continue
            conn = do_request(conn, samples)
            if think_range[1] > 0:
                stop.wait(random.uniform(*think_range))
        if conn is not None:
            conn.close()

    def rate_worker(_idx: int):
        samples = rec.new_list()
        conn = None
        while not stop.is_set():
            try:
                work_q.get(timeout=0.2)
            except queue.Empty:
                continue
            conn = do_request(conn, samples)
            work_q.task_done()
        if conn is not None:
            conn.close()

    def rate_dispatcher():
        tokens, last = 0.0, time.perf_counter()
        while not stop.is_set():
            now = time.perf_counter()
            tokens += state["target"] * (now - last)
            last = now
            while tokens >= 1:
                tokens -= 1
                if work_q.qsize() < n_workers:
                    work_q.put(now)
                else:
                    state["dropped"] += 1
            time.sleep(0.005)

    mem_samples: List[Tuple[float, float]] = []

    def mem_sampler():
        while not stop.is_set():
            mb = rss_mb(a.watch_pid)
            if mb is not None:
                mem_samples.append((time.perf_counter() - t_start, mb))
            stop.wait(5)

    if a.watch_pid:
        if rss_mb(a.watch_pid) is None:
            print(f"note: cannot read memory of PID(s) {a.watch_pid} (process missing or unsupported OS) — skipping memory watch")
        else:
            threading.Thread(target=mem_sampler, daemon=True).start()

    workers = []
    fn = vu_worker if a.mode == "vus" else rate_worker
    for i in range(n_workers):
        th = threading.Thread(target=fn, args=(i,), daemon=True)
        th.start()
        workers.append(th)
    if a.mode == "rate":
        threading.Thread(target=rate_dispatcher, daemon=True).start()

    print(f"load_test: {a.mode} mode, {'custom stages' if a.stages else a.profile} profile, peak {peak:g} "
          f"{'users' if a.mode == 'vus' else 'req/s'}, ~{total_dur:.0f}s, target {u.scheme}://{u.netloc}")
    timeseries = []
    marks: Dict[int, int] = {}
    window = 10.0
    next_report = window
    abort_reason = ""
    try:
        while True:
            el = time.perf_counter() - t_start
            if el >= total_dur:
                break
            state["target"] = target_at(stages, el)
            if el >= next_report:
                samp = rec.snapshot_since(marks)
                lats = sorted(s[2] for s in samp)
                errs = sum(1 for s in samp if s[5])
                rl = sum(1 for s in samp if s[3] == 429)
                row = {"t": round(el), "target": round(state["target"], 1), "rps": round(len(samp) / window, 1),
                       "p50": round(pct(lats, 50)), "p95": round(pct(lats, 95)), "p99": round(pct(lats, 99)),
                       "error_pct": round(100 * errs / len(samp), 2) if samp else 0.0, "rate_limited": rl,
                       "requests": len(samp)}
                if mem_samples:
                    row["rss_mb"] = round(mem_samples[-1][1], 1)
                timeseries.append(row)
                if not a.quiet:
                    print(f"  t={row['t']:>5}s target={row['target']:>7} rps={row['rps']:>7} p50={row['p50']:>5}ms "
                          f"p95={row['p95']:>6}ms p99={row['p99']:>6}ms err={row['error_pct']:>5}% 429s={rl}"
                          + (f" rss={row['rss_mb']}MB" if "rss_mb" in row else ""))
                if (a.abort_on_fail or a.profile == "breakpoint") and samp and row["error_pct"] > 20:
                    abort_reason = f"aborted at t={row['t']}s: error rate {row['error_pct']}% > 20%"
                    break
                next_report += window
            time.sleep(0.1)
    except KeyboardInterrupt:
        abort_reason = "interrupted"
    stop.set()
    for th in workers:
        th.join(timeout=a.timeout + 1)
    wall = time.perf_counter() - t_start
    tail_s = wall - (next_report - window)
    if tail_s > 2:  # last partial window
        samp = rec.snapshot_since(marks)
        lats_w = sorted(s[2] for s in samp)
        timeseries.append({"t": round(wall), "target": round(state["target"], 1), "rps": round(len(samp) / tail_s, 1),
                           "p50": round(pct(lats_w, 50)), "p95": round(pct(lats_w, 95)), "p99": round(pct(lats_w, 99)),
                           "error_pct": round(100 * sum(1 for s in samp if s[5]) / len(samp), 2) if samp else 0.0,
                           "rate_limited": sum(1 for s in samp if s[3] == 429), "requests": len(samp)})

    samples = rec.all()
    lats = sorted(s[2] for s in samples)
    total = len(samples)
    bad = sum(1 for s in samples if s[5])
    net_err: Dict[str, int] = {}
    codes: Dict[str, int] = {}
    per: Dict[str, list] = {}
    for s in samples:
        codes[str(s[3])] = codes.get(str(s[3]), 0) + 1
        if s[4]:
            net_err[s[4]] = net_err.get(s[4], 0) + 1
        per.setdefault(s[1], []).append(s)
    per_stats = {}
    for name, ss in per.items():
        ls = sorted(x[2] for x in ss)
        per_stats[name] = {"requests": len(ss), "p50": round(pct(ls, 50)), "p95": round(pct(ls, 95)),
                           "p99": round(pct(ls, 99)), "error_pct": round(100 * sum(1 for x in ss if x[5]) / len(ss), 2)}
    err_rate = 100 * bad / total if total else 100.0
    p95 = pct(lats, 95)
    degr = next((r for r in timeseries if r["requests"] and (r["p95"] > a.p95 or r["error_pct"] > a.max_error_rate)), None)
    recovered = None
    if a.profile == "spike" and not a.stages and timeseries:
        tail = [r for r in timeseries if r["t"] >= total_dur - 50]
        recovered = all(r["p95"] <= a.p95 and r["error_pct"] <= a.max_error_rate for r in tail) if tail else None
    passed = (p95 <= a.p95 and err_rate <= a.max_error_rate and total > 0 and not abort_reason.startswith("aborted"))
    memory = None
    if mem_samples:
        start_mb, end_mb = mem_samples[0][1], mem_samples[-1][1]
        max_mb = max(m for _, m in mem_samples)
        growth = (end_mb - start_mb) / start_mb * 100 if start_mb else 0.0
        memory = {"pids": a.watch_pid, "start_mb": round(start_mb, 1), "end_mb": round(end_mb, 1), "max_mb": round(max_mb, 1),
                  "growth_pct": round(growth, 1), "samples": len(mem_samples),
                  "possible_leak": bool(end_mb > start_mb * 1.5 and end_mb - start_mb > 50)}
    summary = {
        "url": a.url, "mode": a.mode, "profile": "custom" if a.stages else a.profile, "stages": stages, "peak": peak,
        "duration_s": round(wall, 1), "requests": total, "avg_rps": round(total / wall, 1) if wall else 0,
        "latency_ms": {"min": round(lats[0], 1) if lats else 0, "p50": round(pct(lats, 50), 1), "p90": round(pct(lats, 90), 1),
                       "p95": round(p95, 1), "p99": round(pct(lats, 99), 1), "max": round(lats[-1], 1) if lats else 0},
        "error_rate_pct": round(err_rate, 2), "status_codes": codes, "network_errors": net_err,
        "rate_limited_429": codes.get("429", 0), "dropped_arrivals": state["dropped"], "per_request": per_stats,
        "thresholds": {"p95_ms": a.p95, "max_error_rate_pct": a.max_error_rate},
        "passed": passed, "first_degradation": degr, "recovered_after_spike": recovered, "abort": abort_reason,
        "server_memory": memory, "timeseries": timeseries,
    }
    print("\n=== load test summary ===")
    print(f"requests {total} in {wall:.0f}s  avg {summary['avg_rps']} req/s   errors {err_rate:.2f}%   "
          f"p50 {summary['latency_ms']['p50']}ms  p95 {summary['latency_ms']['p95']}ms  p99 {summary['latency_ms']['p99']}ms  "
          f"max {summary['latency_ms']['max']}ms")
    print(f"status codes {codes}   network errors {net_err or '-'}   dropped arrivals {state['dropped']}")
    for name, st in per_stats.items():
        print(f"  {name:<40} n={st['requests']:<7} p95={st['p95']}ms err={st['error_pct']}%")
    if degr:
        print(f"first degradation at t={degr['t']}s with target≈{degr['target']} ({degr['rps']} req/s): "
              f"p95={degr['p95']}ms err={degr['error_pct']}%")
    else:
        print("no degradation window crossed the thresholds")
    if memory:
        print(f"server memory (RSS): start {memory['start_mb']}MB → end {memory['end_mb']}MB (max {memory['max_mb']}MB, "
              f"{memory['growth_pct']:+}%)" + ("  ⚠ possible memory leak — run a longer soak and take heap snapshots"
                                               if memory["possible_leak"] else ""))
    if recovered is not None:
        print("recovered after spike: " + ("yes" if recovered else "NO — still slow/erroring after the spike"))
    if abort_reason:
        print(abort_reason)
    print(f"RESULT: {'PASS' if passed else 'FAIL'} (p95 ≤ {a.p95}ms and errors ≤ {a.max_error_rate}%)")
    if a.json_out:
        write_json(Path(a.json_out), summary)
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
