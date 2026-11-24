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

`pin.json` pins the upstream reference at `giskard09/argentum-core@f5eee83`
(the `agent_mixed` fix) and records SHA-256 of every file in this package.
Upstream spec text has since moved to `217009a` — documentation wording only,
no verdict/reason/field changes; the pinned code+vectors are unaffected.

## License

`ref/` is vendored from giskard09/argentum-core under Apache-2.0.
`vectors/cadence-vectors.json` was authored by us and proposed upstream.
`trail_verify.py` is provided here for conformance verification purposes.
