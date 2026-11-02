// k6 load test — https://k6.io
// Run:  k6 run -e BASE_URL=http://localhost:3000 -e PROFILE=smoke load-test.js
//       k6 run -e BASE_URL=https://staging.example.com -e PROFILE=spike -e PEAK=500 load-test.js
// PROFILE: smoke | load | stress | spike | soak | breakpoint     PEAK: peak virtual users (default 100)
// Only test systems you own; exclude paid third-party calls (payments, SMS/email, AI).
import http from 'k6/http';
import { check, sleep, group } from 'k6';

const BASE = __ENV.BASE_URL || 'http://localhost:3000';
const PROFILE = __ENV.PROFILE || 'smoke';
const PEAK = Number(__ENV.PEAK || 100);
const P95 = Number(__ENV.P95 || 800);

const profiles = {
  smoke: { executor: 'constant-vus', vus: 2, duration: '30s' },
  load: { executor: 'ramping-vus', startVUs: 0, stages: [
    { duration: '1m', target: PEAK }, { duration: '3m', target: PEAK }, { duration: '30s', target: 0 }] },
  stress: { executor: 'ramping-vus', startVUs: 0, stages: [
    { duration: '1m', target: PEAK }, { duration: '2m', target: PEAK },
    { duration: '1m', target: PEAK * 2 }, { duration: '2m', target: PEAK * 2 },
    { duration: '1m', target: PEAK * 3 }, { duration: '2m', target: PEAK * 3 }, { duration: '1m', target: 0 }] },
  spike: { executor: 'ramping-vus', startVUs: 0, stages: [
    { duration: '30s', target: 5 }, { duration: '10s', target: PEAK }, { duration: '1m', target: PEAK },
    { duration: '10s', target: 5 }, { duration: '1m', target: 5 }] },
  soak: { executor: 'ramping-vus', startVUs: 0, stages: [
    { duration: '2m', target: PEAK }, { duration: __ENV.SOAK || '30m', target: PEAK }, { duration: '1m', target: 0 }] },
  breakpoint: { executor: 'ramping-arrival-rate', startRate: 1, timeUnit: '1s', preAllocatedVUs: 50,
    maxVUs: PEAK * 5, stages: [{ duration: '10m', target: PEAK * 5 }] },
};

export const options = {
  scenarios: { main: profiles[PROFILE] },
  thresholds: {
    http_req_failed: [{ threshold: 'rate<0.01', abortOnFail: PROFILE === 'breakpoint', delayAbortEval: '30s' }],
    http_req_duration: [{ threshold: `p(95)<${P95}`, abortOnFail: PROFILE === 'breakpoint', delayAbortEval: '30s' }],
    'checks': ['rate>0.99'],
  },
};

// Edit the journey to match real usage (weights ≈ how often users do each thing).
export default function () {
  group('home', () => {
    const r = http.get(`${BASE}/`, { tags: { name: 'home' } });
    check(r, { 'home 200': (res) => res.status === 200 });
  });
  sleep(Math.random() * 2 + 1);
  group('products', () => {
    const r = http.get(`${BASE}/api/products?page=${1 + Math.floor(Math.random() * 5)}`, { tags: { name: 'products' } });
    check(r, { 'products 200': (res) => res.status === 200 });
  });
  sleep(Math.random() * 3 + 1);
}
