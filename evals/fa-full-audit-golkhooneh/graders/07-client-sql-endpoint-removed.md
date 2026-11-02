---
type: llm
focus: trace
weight: 1
---

POST /api/db/query no longer executes client-supplied SQL (sending {"sql":"SELECT * FROM users"} returns no user data).
