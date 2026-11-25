# APAF-1 column (paymnts) — ATDRP-0.1 (SEP #303) conformance

`apaf1-column.json` is the APAF-1 result column over the 33
`conformance_cases.json` cases in
agentic-commerce-protocol/agentic-commerce-protocol PR #316
(cases SHA-256 `284db2ece283415ddbcbdbd523e2a8452838e914c01beca8f44a3d0a597fd3cf`,
pinned at PR head `b95a19da`).

A cold read of `rfcs/rfc.dispute_resolution.md` at `94a71e94` — an
independent implementation of the dispute-decision policy: exact-equality
authorization chain, RFC 8785 digest recomputation for §4.4a, pro-rata
adjustment allocation, calendar-day clocks, the five-rule deterministic
decision, and §4.5 determination validity.

Result: 33 of 33 cases agree. Third implementation reported against these
cases; second written independently of the case author. Report posted on
PR #316, 2026-11-24.
