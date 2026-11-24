"""FR-THV: trail-head-ref-v1 conformance verification (independent implementation).

Verify-side counterpart to FR-BCA/FR-AREG: checks a presented agent trail for
continuity (per-agent hash chain) and completeness (externally-anchored
periodic checkpoint), per the `trail-head-ref-v1` draft
(giskard09/argentum-core, Apache-2.0). Distinct failure verdicts are
preserved on purpose — a verifier reports WHICH attack it saw.

The producer bridge (`entries_from_governance`, `append_entry`,
`make_checkpoint`, `seal_period`) derives spec-conformant trails from our
governance chain so emitted trails verify under ANY conformant verifier.

Independence notes:
- RFC 8785 JCS is implemented here (`_jcs_bytes`); the repo's
  `canonical_json` is JSON-sort-keys, not JCS.
- Merkle inclusion follows batch-anchor.md: 0x00 leaf / 0x01 node domain
  separation, sorted sibling pairs, odd node carried up unhashed.
- `root_anchoring` is always reported "not_checked": confirming the period
  root on an anchor stream is the caller's job (same contract as upstream).

What this does NOT prove (per spec, unchanged):
- that the root was actually anchored externally;
- that the checkpoint supplied is the latest one;
- pre-anchor honesty — a producer that never records an action leaves no
  trace for this layer to find (signing-trust / observation problem).
"""

from __future__ import annotations

import datetime
import hashlib
from itertools import pairwise
from typing import Any

ENTRY_V = "trail-head-ref/v1"
CHECKPOINT_V = "trail-head-ref/v1/checkpoint"

PROVEN = "proven"
PROVEN_THROUGH_CHECKPOINT = "proven_through_checkpoint"
PROVEN_FROM_SEQ = "proven_from_seq"
PROVEN_FROM_SEQ_THROUGH_CHECKPOINT = "proven_from_seq_through_checkpoint"
NOT_EVALUATED = "not_evaluated"
FAILED = "failed"

# ---------------------------------------------------------------------------
# RFC 8785 JCS — implemented for the trail-head input domain.
# dict keys sorted by UTF-16BE code units; strings escaped per ECMAScript
# JSON.stringify (short escapes for \b\f\n\r\t, \u00XX for other C0); ints
# decimal; true/false/null. Floats are outside this spec's input domain and
# raise rather than approximating ECMAScript Number.toString.
# ---------------------------------------------------------------------------

_SHORT_ESCAPES = {
    '"': '\\"',
    "\\": "\\\\",
    "\b": "\\b",
    "\f": "\\f",
    "\n": "\\n",
    "\r": "\\r",
    "\t": "\\t",
}


def _jcs_string(s: str) -> str:
    out = ['"']
    for ch in s:
        if ch in _SHORT_ESCAPES:
            out.append(_SHORT_ESCAPES[ch])
        elif ord(ch) < 0x20:
            out.append(f"\\u{ord(ch):04x}")
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def _jcs_bytes(obj: Any) -> bytes:
    if obj is None:
        return b"null"
    if obj is True:
        return b"true"
    if obj is False:
        return b"false"
    if isinstance(obj, bool):
        raise TypeError("unreachable")  # bool handled above (True/False identity)
    if isinstance(obj, int):
        return str(obj).encode()
    if isinstance(obj, float):
        raise TypeError("JCS float serialization is outside this spec's input domain")
    if isinstance(obj, str):
        return _jcs_string(obj).encode("utf-8")
    if isinstance(obj, dict):
        parts = []
        for key in sorted(obj, key=lambda k: k.encode("utf-16-be")):
            if not isinstance(key, str):
                raise TypeError("JCS object keys must be strings")
            parts.append(_jcs_string(key).encode("utf-8") + b":" + _jcs_bytes(obj[key]))
        return b"{" + b",".join(parts) + b"}"
    if isinstance(obj, (list, tuple)):
        return b"[" + b",".join(_jcs_bytes(v) for v in obj) + b"]"
    raise ValueError(f"unsupported JCS type: {type(obj)}")


def _sha256_jcs(obj: dict) -> str:
    return hashlib.sha256(_jcs_bytes(obj)).hexdigest()


def _is_hex64(v: Any) -> bool:
    if not isinstance(v, str) or len(v) != 64:
        return False
    try:
        bytes.fromhex(v)
    except ValueError:
        return False
    return v == v.lower()


# ---------------------------------------------------------------------------
# Merkle tree (batch-anchor.md construction, independently written)
# ---------------------------------------------------------------------------

_LEAF_PREFIX = b"\x00"
_NODE_PREFIX = b"\x01"


def _leaf_hash(digest_hex: str) -> bytes:
    return hashlib.sha256(_LEAF_PREFIX + bytes.fromhex(digest_hex)).digest()


def _node_hash(a: bytes, b: bytes) -> bytes:
    left, right = (a, b) if a <= b else (b, a)
    return hashlib.sha256(_NODE_PREFIX + left + right).digest()


def build_merkle_tree(digests: list[str]) -> dict:
    """Return {"root": hex, "levels": [[hex,...],...]} over leaf digests."""
    if not digests:
        raise ValueError("build_merkle_tree requires at least one digest")
    for d in digests:
        if not _is_hex64(d):
            raise ValueError(f"not a 64-hex digest: {d!r}")
    levels = [[_leaf_hash(d) for d in digests]]
    while len(levels[-1]) > 1:
        cur = levels[-1]
        nxt = [
            _node_hash(cur[i], cur[i + 1]) if i + 1 < len(cur) else cur[i]
            for i in range(0, len(cur), 2)
        ]
        levels.append(nxt)
    return {
        "root": levels[-1][0].hex(),
        "levels": [[h.hex() for h in lvl] for lvl in levels],
        "leaves": list(digests),
    }


def get_proof(digest_hex: str, tree: dict) -> list[str]:
    """Sibling-hash proof (leaf-to-root order) for a leaf in `tree`."""
    idx = tree["leaves"].index(digest_hex)  # ValueError if absent, on purpose
    proof = []
    for lvl in tree["levels"][:-1]:
        sib = idx ^ 1
        if sib < len(lvl):
            proof.append(lvl[sib])
        idx //= 2
    return proof


def verify_inclusion(digest_hex: str, proof: list[str], root: str) -> bool:
    """Recompute root from digest + proof; True only on exact match.

    Proves inclusion in the tree that produced `root` — NOT that `root`
    was anchored anywhere, and nothing about the digest's legitimacy.
    """
    if not _is_hex64(digest_hex) or not _is_hex64(root):
        return False
    try:
        current = _leaf_hash(digest_hex)
        siblings = [bytes.fromhex(p) for p in proof]
    except ValueError:
        return False
    for sib in siblings:
        current = _node_hash(current, sib)
    return current.hex() == root


# ---------------------------------------------------------------------------
# Producer side
# ---------------------------------------------------------------------------


def entry_preimage(
    agent_id: str,
    seq: int,
    action_ref: str,
    prev_head: str | None = None,
    agent_seq: int | None = None,
) -> dict:
    if not isinstance(seq, int) or isinstance(seq, bool) or seq < 1:
        raise ValueError("seq must be an integer >= 1")
    if not _is_hex64(action_ref):
        raise ValueError("action_ref must be 64 lowercase hex chars")
    if (seq == 1) != (prev_head is None):
        raise ValueError("prev_head is absent exactly at seq 1")
    if prev_head is not None and not _is_hex64(prev_head):
        raise ValueError("prev_head must be 64 lowercase hex chars")
    pre = {"v": ENTRY_V, "agent_id": agent_id, "seq": seq, "action_ref": action_ref}
    if prev_head is not None:
        pre["prev_head"] = prev_head
    if agent_seq is not None:
        if not isinstance(agent_seq, int) or isinstance(agent_seq, bool) or agent_seq < 1:
            raise ValueError("agent_seq must be an integer >= 1")
        pre["agent_seq"] = agent_seq
    return pre


def append_entry(
    log: list[dict], agent_id: str, action_ref: str, agent_seq: int | None = None
) -> dict:
    seq = len(log) + 1
    prev = log[-1]["head"] if log else None
    pre = entry_preimage(agent_id, seq, action_ref, prev, agent_seq)
    entry = dict(pre)
    del entry["v"]
    entry["head"] = _sha256_jcs(pre)
    log.append(entry)
    return entry


def entries_from_governance(agent_id: str, digests: list[str]) -> list[dict]:
    """FR-THV-04: derive a spec-conformant trail from ordered per-event
    digests (e.g. a mandate's governance-event hashes). `agent_id` is the
    trail's subject (our dispute subject is the mandate)."""
    log: list[dict] = []
    for d in digests:
        append_entry(log, agent_id, d)
    return log


def _parse_ts(ts: str) -> datetime.datetime:
    if not isinstance(ts, str) or not ts.endswith("Z"):
        raise ValueError(f"not an RFC 3339 UTC timestamp: {ts!r}")
    return datetime.datetime.fromisoformat(ts[:-1] + "+00:00")


def make_checkpoint(agent_id: str, period_end: str, log: list[dict]) -> dict:
    """Checkpoint of an agent's log at period end. Emit every period,
    including empty ones (repeat seq/head, new period_end): a missing
    checkpoint is itself evidence instead of looking like an idle agent."""
    if not log:
        raise ValueError("no checkpoint for an agent with no entries")
    _parse_ts(period_end)
    last = log[-1]
    return {
        "v": CHECKPOINT_V,
        "agent_id": agent_id,
        "period_end": period_end,
        "seq": last["seq"],
        "head": last["head"],
    }


def checkpoint_digest(cp: dict) -> str:
    return _sha256_jcs(cp)


def seal_period(checkpoints: list[dict]) -> dict:
    """Merkle-seal one period's checkpoints (one per agent, shared
    period_end, sorted by agent_id). Returns the tree; `root` is what an
    external anchor commits to."""
    ordered = sorted(checkpoints, key=lambda c: c["agent_id"])
    ids = [c["agent_id"] for c in ordered]
    if len(set(ids)) != len(ids):
        raise ValueError("one checkpoint per agent per period")
    if len({c["period_end"] for c in ordered}) != 1:
        raise ValueError("all checkpoints in a seal share one period_end")
    return build_merkle_tree([checkpoint_digest(c) for c in ordered])


# ---------------------------------------------------------------------------
# Declared-maximum cadence (FR-THV-05 — the AP2#290 cadence-floor mechanism)
# ---------------------------------------------------------------------------


def verify_checkpoint_cadence(checkpoints: list[dict], declared_max_period_s: float) -> dict:
    """Check one agent's consecutive checkpoints against a declared ceiling.

    Output shape matches the upstream reference implementation exactly on
    all shared fields (verdict / reason / prev_period_end / period_end /
    gap_s / declared_max_period_s); `violations` is a Paymnts extension
    carrying EVERY breaching gap where the reference returns the first —
    consumers pattern-match only on `verdict` either way.

    sorted-compare on period_end alone (well-formedness is verify_trail's
    job); strict `>` so a gap equal to the ceiling is within bound;
    fewer than two checkpoints has no gap to measure -> ok; malformed
    inputs report distinct reasons rather than raising.
    """
    if (
        not isinstance(declared_max_period_s, (int, float))
        or isinstance(declared_max_period_s, bool)
        or declared_max_period_s <= 0
    ):
        raise ValueError("declared_max_period_s must be a positive number")
    if not isinstance(checkpoints, list):
        return {"verdict": "malformed", "reason": "not_a_list"}
    if len(checkpoints) < 2:
        return {"verdict": "ok"}
    # Mixed-agent input: interleaving agents' streams can mask a breach each
    # committed alone (sorted cross-agent gaps look compliant). Reject like
    # verify_trail's agent_mixed check — silent masking must be a verdict.
    agent_ids = {c.get("agent_id") if isinstance(c, dict) else None for c in checkpoints}
    if len(agent_ids) > 1:
        return {"verdict": "malformed", "reason": "agent_mixed"}
    try:
        ordered = sorted(checkpoints, key=lambda c: _parse_ts(c["period_end"]))
    except (KeyError, TypeError, ValueError):
        return {"verdict": "malformed", "reason": "period_end"}
    violations = []
    for prev, cur in pairwise(ordered):
        gap = (_parse_ts(cur["period_end"]) - _parse_ts(prev["period_end"])).total_seconds()
        if gap > declared_max_period_s:
            violations.append(
                {
                    "prev_period_end": prev["period_end"],
                    "period_end": cur["period_end"],
                    "gap_s": gap,
                    "declared_max_period_s": declared_max_period_s,
                }
            )
    if violations:
        return {
            "verdict": "period_exceeds_declared_maximum",
            **violations[0],
            "violations": violations,
        }
    return {"verdict": "ok"}


# ---------------------------------------------------------------------------
# Verifier side
# ---------------------------------------------------------------------------


def _result(verdict, completeness, at_seq=None, reason=None, **extra):
    r = {
        "verdict": verdict,
        "completeness": completeness,
        "at_seq": at_seq,
        "reason": reason,
        "root_anchoring": "not_checked",
    }
    r.update(extra)
    return r


def verify_trail(
    entries: list[dict],
    checkpoint: dict | None = None,
    proof: list[str] | None = None,
    root: str | None = None,
    now: str | None = None,
    max_checkpoint_age_s: int | None = None,
    anchor: dict | None = None,
    anchor_proof: list[str] | None = None,
    anchor_root: str | None = None,
    from_seq: int = 1,
) -> dict:
    """Check an agent's presented log for continuity and, given an anchored
    checkpoint, for completeness — trail-head-ref-v1 checks 1..8 in order.

    The first failing check decides the verdict. `continuity_only` means the
    log is internally intact and completeness was NOT evaluated — never a
    pass. A window (from_seq > 1) must be declared by the caller and gets
    its own positive verdicts; its start is genesis/certified/uncertified.
    """
    # 1. shape
    if not isinstance(entries, list) or not entries:
        return _result("malformed", FAILED, reason="empty_or_not_a_list")
    agent_id = entries[0].get("agent_id") if isinstance(entries[0], dict) else None
    for e in entries:
        if (
            not isinstance(e, dict)
            or not _is_hex64(e.get("head"))
            or not _is_hex64(e.get("action_ref"))
            or not isinstance(e.get("seq"), int)
            or isinstance(e.get("seq"), bool)
        ):
            return _result("malformed", FAILED, reason="entry_shape")
        if e.get("agent_id") != agent_id:
            return _result("malformed", FAILED, at_seq=e.get("seq"), reason="agent_mixed")

    if not isinstance(from_seq, int) or isinstance(from_seq, bool) or from_seq < 1:
        raise ValueError("from_seq must be an integer >= 1")

    # 2. continuity — reorder told apart from removal up front
    seqs = [e["seq"] for e in entries]
    if sorted(seqs) == list(range(from_seq, from_seq + len(seqs))) and seqs != sorted(seqs):
        first_bad = next(s for i, s in enumerate(seqs) if s != from_seq + i)
        return _result("broken", FAILED, at_seq=first_bad, reason="seq_order")
    prev_seq, prev_head = from_seq - 1, None
    for e in entries:
        seq = e["seq"]
        if seq != prev_seq + 1:
            return _result("broken", FAILED, at_seq=seq, reason="seq_gap")
        stated_prev = e.get("prev_head")
        try:
            pre = entry_preimage(agent_id, seq, e["action_ref"], stated_prev, e.get("agent_seq"))
        except ValueError:
            return _result("malformed", FAILED, at_seq=seq, reason="entry_preimage")
        if _sha256_jcs(pre) != e["head"]:
            return _result("broken", FAILED, at_seq=seq, reason="head_mismatch")
        if seq > from_seq and stated_prev != prev_head:
            return _result("broken", FAILED, at_seq=seq, reason="link_mismatch")
        prev_seq, prev_head = seq, e["head"]

    # 2e. window start — only an anchor checkpoint at seq k-1 (proven in its
    # period root) can certify the first record's prev_head
    if anchor is not None:
        if (
            not isinstance(anchor, dict)
            or anchor.get("v") != CHECKPOINT_V
            or not _is_hex64(anchor.get("head"))
            or not isinstance(anchor.get("seq"), int)
            or isinstance(anchor.get("seq"), bool)
        ):
            return _result("anchor_unproven", FAILED, reason="anchor_shape")
        if anchor.get("agent_id") != agent_id:
            return _result("anchor_unproven", FAILED, reason="anchor_other_agent")
        if (
            anchor_root is None
            or anchor_proof is None
            or not verify_inclusion(checkpoint_digest(anchor), anchor_proof, anchor_root)
        ):
            return _result("anchor_unproven", FAILED, reason="anchor_not_in_root")
        if from_seq == 1 or anchor["seq"] != from_seq - 1:
            return _result("anchor_unproven", FAILED, at_seq=from_seq, reason="anchor_not_adjacent")
        if entries[0]["prev_head"] != anchor["head"]:
            return _result(
                "anchor_mismatch", FAILED, at_seq=from_seq, reason="prev_head_differs_from_anchor"
            )
        window_anchor = "certified"
    else:
        window_anchor = "genesis" if from_seq == 1 else "uncertified"
    scope = {"from_seq": from_seq, "window_anchor": window_anchor}

    # 3. agent-side counter
    with_agent_seq = [e for e in entries if "agent_seq" in e]
    if with_agent_seq:
        if len(with_agent_seq) != len(entries):
            return _result("agent_gap", FAILED, reason="agent_seq_partial")
        if from_seq == 1 and entries[0]["agent_seq"] != 1:
            return _result("agent_gap", FAILED, at_seq=1, reason="agent_seq_not_contiguous")
        for a, b in pairwise(entries):
            if b["agent_seq"] != a["agent_seq"] + 1:
                return _result(
                    "agent_gap", FAILED, at_seq=b["seq"], reason="agent_seq_not_contiguous"
                )

    last_seq = entries[-1]["seq"]

    # 4. completeness needs an external checkpoint
    if checkpoint is None:
        return _result(
            "continuity_only", NOT_EVALUATED, reason="no_checkpoint", last_seq=last_seq, **scope
        )

    if (
        not isinstance(checkpoint, dict)
        or checkpoint.get("v") != CHECKPOINT_V
        or not _is_hex64(checkpoint.get("head"))
        or not isinstance(checkpoint.get("seq"), int)
    ):
        return _result("malformed", FAILED, reason="checkpoint_shape")
    if checkpoint.get("agent_id") != agent_id:
        return _result("checkpoint_unproven", FAILED, reason="checkpoint_other_agent")
    if (
        root is None
        or proof is None
        or not verify_inclusion(checkpoint_digest(checkpoint), proof, root)
    ):
        return _result("checkpoint_unproven", FAILED, reason="not_in_root")

    if max_checkpoint_age_s is not None and now is not None:
        age = (_parse_ts(now) - _parse_ts(checkpoint["period_end"])).total_seconds()
        if age > max_checkpoint_age_s:
            return _result(
                "stale_checkpoint", FAILED, reason="checkpoint_too_old", checkpoint_age_s=int(age)
            )

    cp_seq = checkpoint["seq"]
    if cp_seq < from_seq:
        return _result(
            "continuity_only",
            NOT_EVALUATED,
            reason="checkpoint_before_window",
            last_seq=last_seq,
            checkpoint_seq=cp_seq,
            **scope,
        )
    if last_seq < cp_seq:
        return _result(
            "truncated",
            FAILED,
            at_seq=last_seq + 1,
            reason="log_shorter_than_checkpoint",
            last_seq=last_seq,
            checkpoint_seq=cp_seq,
        )
    if entries[cp_seq - from_seq]["head"] != checkpoint["head"]:
        return _result(
            "checkpoint_mismatch", FAILED, at_seq=cp_seq, reason="head_differs_from_checkpoint"
        )
    window = from_seq > 1
    if last_seq == cp_seq:
        return _result(
            "window_complete" if window else "complete",
            PROVEN_FROM_SEQ if window else PROVEN,
            last_seq=last_seq,
            as_of=checkpoint["period_end"],
            **scope,
        )
    return _result(
        "window_complete_unsealed_tail" if window else "complete_unsealed_tail",
        PROVEN_FROM_SEQ_THROUGH_CHECKPOINT if window else PROVEN_THROUGH_CHECKPOINT,
        last_seq=last_seq,
        checkpoint_seq=cp_seq,
        unsealed_entries=last_seq - cp_seq,
        as_of=checkpoint["period_end"],
        **scope,
    )


# ---------------------------------------------------------------------------
# FR-THV-06: machine-explicit consumer assessment
# ---------------------------------------------------------------------------

_POSITIVE_VERDICTS = frozenset(
    {
        "complete",
        "complete_unsealed_tail",
        "window_complete",
        "window_complete_unsealed_tail",
    }
)


def assess_verdict(result: dict) -> dict:
    """Map a verify_trail result to a consumer-facing assessment so callers
    never pattern-match verdict strings.

    assessment:
      "verified"     — proven (a window is proven from from_seq only)
      "unverifiable" — continuity_only: internally intact, completeness
                       NOT evaluated; not a pass
      "failed"       — every other verdict, with the specific reason

    warnings surface states that are true but easy to misread:
      window_start_uncertified — the window's first prev_head came from the
                                 presented records, not an anchor
      tail_not_externally_witnessed — records after the last checkpoint are
                                      continuous but not yet witnessed
      completeness_not_evaluated — no usable checkpoint was supplied
    """
    verdict = result.get("verdict")
    warnings: list[str] = []
    if result.get("window_anchor") == "uncertified":
        warnings.append("window_start_uncertified")
    if verdict in ("complete_unsealed_tail", "window_complete_unsealed_tail"):
        warnings.append("tail_not_externally_witnessed")
    if result.get("reason") in ("no_checkpoint", "checkpoint_before_window"):
        warnings.append("completeness_not_evaluated")
    if verdict in _POSITIVE_VERDICTS:
        assessment = "verified"
    elif verdict == "continuity_only":
        assessment = "unverifiable"
    else:
        assessment = "failed"
    return {
        "assessment": assessment,
        "verdict": verdict,
        "reason": result.get("reason"),
        "warnings": warnings,
    }
