# Load, stress & concurrency testing (X15)

Goal: know — with numbers — whether the app survives launch day, an Instagram live, a newsletter blast or a viral post, where it breaks, and why.

## Safety first
- Only systems the user owns. Default target: **local production build** or **staging** with production-like data and the same server size. Production only with the owner's explicit OK, at a quiet hour, after warning the host/CDN if needed (they may block it as an attack).
- Never load-test through paid third parties: mock or exclude payments, SMS/email, AI APIs, maps (cost + bans).
- Test accounts only; don't create thousands of real users/orders in production data.
- Rate limits will (correctly) return 429 to a single-IP load generator. Measure capacity with the load generator allow-listed **or** on endpoints without limits, and test the limiter separately.
- `next dev`/`nodemon`/debug mode are not representative — build and run in production mode (`NODE_ENV=production`).
- Run the load generator on a different machine than the server when possible (same machine = the generator steals CPU).

## Test types
| Type | Shape | Question it answers | `load_test.py` |
|---|---|---|---|
| Smoke | 1–2 users, 30 s | Does the script/target work at all? | `--profile smoke` |
| Load | ramp to expected peak, hold 3–10 min | Is the normal busy hour OK? | `--profile load --target N` |
| Stress | 1× → 2× → 3× peak | Where does it bend, how does it fail? | `--profile stress --target N` |
| Spike | baseline → peak in ~10 s → back | Survives a sudden rush? Recovers afterwards? | `--profile spike --target N` |
| Soak | expected load for 30 min–hours | Memory leaks, connection-pool exhaustion, disk/log growth | `--profile soak --target N --soak-minutes 60` |
| Breakpoint | linear ramp until failure | Maximum capacity (for planning) | `--profile breakpoint --target N` |
| Race | N identical requests at the same instant | Can money/stock/coupons be double-spent? | `race_test.py` |

Always run smoke first, then grow. Stop as soon as the error rate explodes — you've found the limit.

## From "users" to numbers
Concurrent users ≠ requests per second. With think time `T` (seconds between a user's clicks) and response time `R`:
`RPS ≈ concurrent_users / (T + R)`. 500 people on the site, clicking every ~10 s → ≈ 50 RPS (each page view may trigger several API/asset requests — count them in the scenario). Spikes from a live stream/viral post: assume 5–10× normal concurrency arriving within a minute.

Default pass criteria (adjust with the owner): p95 < 500–800 ms for pages/APIs (heavy reports < 2 s), error rate < 1 %, no 5xx under expected load, graceful 429/503 (not crashes/timeouts) beyond capacity, back to normal within ~1 min after a spike, flat memory in soak tests.

## Tools
- **`scripts/load_test.py`** (zero dependencies): VU (closed) or arrival-rate (open) model, profiles above, scenario files with weighted requests, thresholds, degradation point, spike recovery, server memory watch (`--watch-pid <server pid>`: RSS over time, flags likely leaks), JSON output. Good up to several hundred concurrent users (thousands of req/s) from one machine.
  ```bash
  python3 load_test.py http://localhost:3000/ --profile smoke
  python3 load_test.py http://localhost:3000/ --scenario scenario.json --profile load --target 200 --think 3 --json-out load.json
  python3 load_test.py http://localhost:3000/api/products --mode rate --stages "30s:50,1m:400,30s:0" --max-vus 600
  python3 load_test.py http://localhost:3000/ --profile soak --target 100 --soak-minutes 30 --watch-pid $(pgrep -f 'node server.js')
  ```
  Scenario file example:
  ```json
  {"think": [1, 5], "headers": {"Cookie": "session=TEST_USER_SESSION"},
   "requests": [{"name": "home", "path": "/", "weight": 5},
                {"name": "product list", "path": "/api/products?page=1", "weight": 3},
                {"name": "product", "path": "/api/products/42", "weight": 3},
                {"name": "search", "path": "/api/search?q=monstera", "weight": 1}]}
  ```
- **k6** (recommended for big/regular tests, CI thresholds, WebSockets): `assets/k6/load-test.js` — `k6 run -e BASE_URL=http://localhost:3000 -e PROFILE=spike -e PEAK=500 load-test.js`. Install: `brew install k6` / `sudo apt install k6` (Grafana repo) / `docker run --rm -i grafana/k6 run - <load-test.js`.
- **autocannon** (Node, quick throughput): `npx autocannon -c 100 -d 30 http://localhost:3000/api/products`.
- **Artillery** (Socket.IO/WebSocket flows), **Locust** (Python scenarios), **oha/hey/wrk** (raw HTTP).
- Front-end weight: `npx lighthouse https://site --only-categories=performance` — heavy pages multiply server load.

## What to watch on the server during the test
CPU & RAM (`htop`, `pm2 monit`, `docker stats`), Node event-loop lag (blocking code shows as rising p50 for *all* endpoints), DB connections (`select count(*) from pg_stat_activity`), slow queries (`pg_stat_statements`, MySQL slow log), Nginx `error.log` (upstream timeouts, `worker_connections are not enough`), 5xx/429 counts, disk (logs!).

## Symptoms → likely causes → fixes
| Symptom | Likely cause | Fix |
|---|---|---|
| Every endpoint slows together, CPU 100 % on one core | Event loop blocked: sync crypto/bcrypt in loops, `readFileSync`, big `JSON.parse`/sort per request, image/PDF work | Cache computed results, move heavy work to worker threads/queue, async APIs, precompute at startup/build |
| Latency grows with DB load, few CPU | Missing indexes, N+1 queries, `SELECT *` on big tables, no pagination | Indexes (EXPLAIN), joins/batching, pagination, cache hot reads (Redis / in-memory with TTL) |
| Errors at N users: `ECONNRESET`, `too many connections` | DB pool exhausted / too small / connections leaked | Right-size pool (pgbouncer), always release connections, timeouts |
| 502/504 from Nginx | Upstream too slow, Node crashed, keepalive mismatch | Fix the slow path, PM2 cluster mode, `proxy_read_timeout`, upstream keepalive |
| Memory climbs in soak until restart | Unbounded arrays/maps/caches, listeners never removed, global request logs | Bounded LRU caches, remove references, heap snapshot (`node --inspect`, clinic.js) |
| Good until spike, then never recovers | Queue build-up, retries storm, no timeouts | Timeouts everywhere, load shedding (503 + Retry-After), autoscaling/more instances, CDN caching of public pages |
| Only one CPU core busy | Single Node process | PM2 `instances: 'max'` (then shared session/rate-limit store) |
| Static assets dominate | No CDN/compression/caching | `Cache-Control` immutable for hashed assets, gzip/brotli, CDN |

## Concurrency/race tests (security + correctness)
Run `race_test.py` against every "at most once" operation: coupons, gift cards, referral bonuses, wallet spend/withdraw, limited stock, voting, invite acceptance, password-reset token use. 20 parallel requests, repeat 3–5 times. A pass on a single sequential retry proves nothing. Fix with atomic DB statements, unique constraints, row locks or idempotency keys (`references/extra-checks.md` X06), then re-run.

## Report section
Include: environment (machine, build, data size), scenarios & profiles, a table per run (peak users, RPS, p50/p95/p99, error %, 429s), the degradation point ("p95 crossed 800 ms at ≈180 users / 65 RPS"), bottleneck + evidence, fixes applied with before/after numbers, and the capacity estimate with headroom ("handles ~250 concurrent users today; launch target 500 → needs X").
