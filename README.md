# paymnts trail-head conformance

Independent second implementation of `trail-head-ref-v1`
(giskard09/argentum-core), continuously verified byte-identical against the
vendored upstream reference.

`trail_verify.py` is written from the spec — own JCS (RFC 8785) canonicalizer,
own Merkle inclusion proof handling, stdlib only. It is not vendored from, nor
derived from, upstream code.

`differential_check.py` runs every pinned vector through BOTH implementations
and requires identical output on every field the reference emits:

- 14 cadence-ceiling vectors (`verify_checkpoint_cadence`) — includes the
  interleave-masking case (`agent_mixed`) reported upstream by this
  implementation's author and fixed in `argentum-core@f5eee83`
- 11 window vectors (`verify_trail`) — `verdict`, `completeness`, `reason`,
  `window_anchor`

## Run

    python3 differential_check.py
    # PARITY: 25/25 vectors identical (14 cadence, 11 window)

CI runs the same check on every push (`.github/workflows/conformance.yml`).

## Provenance

- `ref/` is vendored from giskard09/argentum-core under Apache-2.0, pinned
  at `f5eee83` (the `agent_mixed` fix — a bug this implementation's author
  reported upstream via differential testing).
- `trail_verify.py`: check order, verdict/reason strings, and result
  fields are spec-mandated. The input-validation strings and the aligned
  check semantics in `verify_trail` and `verify_checkpoint_cadence`
  derive from `trail_head.py@f5eee83` (adopted during differential
  alignment, 2026-10-26). The JCS canonicalizer, Merkle proof code, and
  all surrounding pipeline code are original.
- `vectors/cadence-vectors.json` was authored by us and proposed upstream.
- `pin.json` pins the upstream reference at `f5eee83` and records SHA-256
  of every file in this package. Upstream spec text has since moved to
  `217009a` — documentation wording only; the pinned code+vectors are
  unaffected.

## License

`ref/` is vendored from giskard09/argentum-core under Apache-2.0.
`vectors/cadence-vectors.json` was authored by us and proposed upstream.
`trail_verify.py` is provided here for conformance verification purposes.
