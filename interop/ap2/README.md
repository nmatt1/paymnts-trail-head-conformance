# paymnts column — AP2 #402 independent-verifier interop

`paymnts-column.json` is the paymnts verdict column over the pinned third-party wire fixtures used for the independent-verifier crosswalk in google-agentic-commerce/AP2 issue #402, alongside the AMEP and AER-1
columns.

Fixtures (SHA-256, recomputed before judging; matches the published pins in zambodotdev/aer1-kit `interop/`):

- sdk family: `sdk-bundles.json` `7e1dd6d97003d11f61ee2b60625bc1fff282d9a5f1eaa7426b276bbd3140b61f`
- synthetic family: `bundles.json` `bd530228cb9880d33f49016ab85f426a6c0e9668f3b6e47734b4aa779a71c4fc`

Join key: bundle name + payment index (a closed mandate presented twice is one over-redeemed payment, not a second one — 25 presentations, 22 payment rows).

## What the column judges

Decision semantics on the presented artifacts, including cumulative mandate state (spend, use count, closed-mandate replay) carried across the bundle — the cross-payment state a single-record judgment cannot
carry. Open-mandate expiry is judged at each hop's `iat`. Every ES256 signature and every digest binding (sd_hash, issuer_jwt_hash, disclosure digests, receipt references) is recomputed.

Vocabulary:

- `approved` — chain, signatures, bindings, constraints, receipt verify
- `declined` — hard failure: bad signature/binding, constraint violation, altered evidence, closed-mandate replay
- `escalated` — a required check is unverifiable from the presented set (receipt absent or bound to another mandate, prior outcome unknown under stateful constraints)
- `not_evaluated` — processor reported a failed execution

Each row's `checks` detail and `evidence` codes are recomputable by any third party from the public fixtures — no paymnts code execution is required to audit a row. The `spec_schema` check axis reports
conformance of the presented mandates to the ap2-protocol.org JSON schemas (finding published verbatim per row: every fixture open payment mandate lacks the schema-required `payment.reference` constraint); it
measures a different axis than decision semantics and does not drive the verdict.

