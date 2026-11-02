---
type: llm
focus: trace
weight: 1
---

After the fix, GET /api/products?page=1 under 200 concurrent users (think time 0.5 s) has p95 below 300 ms with less than 1% errors.
