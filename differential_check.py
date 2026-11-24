#!/usr/bin/env python3
"""Differential conformance: Paymnts trail_verify vs vendored upstream reference.

Runs every pinned vector through BOTH implementations and requires identical
output on every field the reference emits (FR-THV-08 semantics):

  - 14 cadence vectors  -> verify_checkpoint_cadence (all ref-emitted fields)
  - 11 window vectors   -> verify_trail (verdict, completeness, reason,
                            window_anchor)

Exit 0 on full parity, 1 on any divergence. Stdlib only; Python >= 3.10.
"""

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "ref"))

import trail_verify as tv  # noqa: E402
from plugins.agt_evidence_anchor import trail_head as ref  # noqa: E402

FIELDS = ("verdict", "completeness", "reason", "window_anchor")


def main() -> int:
    window = json.loads((ROOT / "vectors" / "vectors.json").read_text())["vectors"]
    cadence = json.loads((ROOT / "vectors" / "cadence-vectors.json").read_text())["vectors"]

    failures = []

    for v in cadence:
        inp = v["input"]
        ours = tv.verify_checkpoint_cadence(inp["checkpoints"], inp["declared_max_period_s"])
        theirs = ref.verify_checkpoint_cadence(inp["checkpoints"], inp["declared_max_period_s"])
        if {k: ours.get(k) for k in theirs} != theirs:
            failures.append(("cadence", v["id"], ours, theirs))

    for v in window:
        inp = v["input"]
        kw = {k: x for k, x in inp.items() if k != "entries"}
        ours = tv.verify_trail(inp["entries"], **kw)
        theirs = ref.verify_trail(inp["entries"], **kw)
        if {f: ours.get(f) for f in FIELDS} != {f: theirs.get(f) for f in FIELDS}:
            failures.append(("window", v["id"], ours, theirs))

    total = len(cadence) + len(window)
    if failures:
        print(f"DIVERGENCE: {len(failures)}/{total} vectors differ")
        for kind, vid, ours, theirs in failures:
            print(f"  [{kind}] {vid}\n    ours: {ours}\n    ref:  {theirs}")
        return 1
    print(f"PARITY: {total}/{total} vectors identical ({len(cadence)} cadence, {len(window)} window)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
