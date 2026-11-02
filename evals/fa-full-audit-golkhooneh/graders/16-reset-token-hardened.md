---
type: llm
focus: trace
weight: 1
---

Password-reset tokens are generated with a CSPRNG (at least 32 bytes / 40+ characters), expire (expiry enforced in code) and are single-use (a second use of the same token fails).
