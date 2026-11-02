---
type: llm
focus: trace
weight: 1
---

The report identifies the per-request synchronous work in /api/products (pbkdf2Sync price signatures and/or readFileSync + re-sorting the whole catalog) as the bottleneck.
