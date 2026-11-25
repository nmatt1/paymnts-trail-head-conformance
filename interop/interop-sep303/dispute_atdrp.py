"""ATDRP-0.1 dispute-resolution evaluator — an independent (cold-read)
implementation of rfcs/rfc.dispute_resolution.md from ACP SEP #303 /
agentic-commerce-protocol PR #316.

Evaluates a DisputeRecord under the RFC's deterministic policy: Section 4.4
authorization-chain checks, Section 4.4a bound user approvals, Section 7.4
per-line decision rules, Section 7.5 clocks, and Section 4.5 determination
validation. Written against the vendored RFC at
fixtures/spec/sep303/rfc.dispute_resolution.md (PR head b95a19d); used by the
SEP #303 conformance column (scripts/build_sep303_column.py) and the
conformance runner provider (scripts/dispute_provider.py).
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from fractions import Fraction

WINDOW_DAYS = 120
DETERMINATION_DAYS = 10
COUNTED_ADJUSTMENT_TYPES = {"refund", "credit", "price_adjustment"}
FACTORS = (
    "mandate_scope",
    "intent_fidelity",
    "merchant_performance",
    "adjustments_already_made",
    "agent_platform_conduct",
)
DET_REQUIRED = (
    "determination_id",
    "dispute_id",
    "policy_version",
    "per_line",
    "factors",
    "prohibited_screened",
    "signer",
    "opened_at",
    "issued_at",
    "seal",
    "fee_disposition",
)


def _jcs(value) -> str:
    """RFC 8785 canonical serialization for the ATDRP value space (objects,
    arrays, ASCII strings, integers, booleans, null)."""
    if isinstance(value, dict):
        return "{" + ",".join(json.dumps(k) + ":" + _jcs(v) for k, v in sorted(value.items())) + "}"
    if isinstance(value, list):
        return "[" + ",".join(_jcs(x) for x in value) + "]"
    return json.dumps(value)


def _utc_date(ts_or_str) -> datetime.date | None:
    if isinstance(ts_or_str, (int, float)):
        return datetime.fromtimestamp(ts_or_str, tz=timezone.utc).date()
    if isinstance(ts_or_str, str):
        try:
            return datetime.fromisoformat(ts_or_str.replace("Z", "+00:00")).date()
        except ValueError:
            return None
    return None


def _frac(value) -> Fraction | None:
    """Exact decimal value for JSON numbers — pro-rata allocation compares
    must not lose a boundary case to float representation."""
    from fractions import Fraction

    if isinstance(value, bool) or value is None:
        return None
    try:
        return Fraction(str(value))
    except (ValueError, ArithmeticError):
        return None


def _line_amount(line: dict) -> float | None:
    if line.get("subtotal") is not None:
        return line["subtotal"]
    if (
        line.get("unit_price") is not None
        and (line.get("quantity") or {}).get("ordered") is not None
    ):
        return line["unit_price"] * line["quantity"]["ordered"]
    return None


def _counted_adjustments(order: dict) -> list[dict]:
    return [
        a
        for a in order.get("adjustments") or []
        if a.get("status") == "completed" and a.get("type") in COUNTED_ADJUSTMENT_TYPES
    ]


def _allocated_credit(order: dict, line_id: str) -> float:
    """Rule-1 credit for one line: line-labelled adjustments count in full;
    adjustments naming no line allocate pro rata by line amount over the
    lines with a known amount."""
    total = 0.0
    for adj in _counted_adjustments(order):
        names = [li.get("id") for li in adj.get("line_items") or []]
        if line_id in names:
            total += adj.get("amount") or 0
        elif not names:
            known = [li for li in order.get("line_items") or [] if _line_amount(li) is not None]
            denom = sum(_frac(_line_amount(li)) for li in known)
            target = next((li for li in known if li.get("id") == line_id), None)
            if denom and target is not None:
                total += float(_frac(adj.get("amount") or 0) * _frac(_line_amount(target)) / denom)
    return total


def _approval_bound(record: dict, complete_digest: str | None) -> bool:
    """Section 4.4a: recompute the digest over JCS({items, approved_at}) and
    check it equals both the record's digest and the one the merchant
    received on complete (complete_digest at the input root)."""
    ua = record.get("user_approval")
    if not ua or not complete_digest:
        return False
    recomputed = hashlib.sha256(
        _jcs({"items": ua.get("items"), "approved_at": ua.get("approved_at")}).encode()
    ).hexdigest()
    return recomputed == ua.get("approval_digest") == complete_digest


def _line_matches_approval(line: dict, ua: dict) -> bool:
    item = line.get("item") or {}
    sku = item.get("id") or item.get("sku")
    variant = item.get("variant")
    for it in ua.get("items") or []:
        if it.get("sku") != sku:
            continue
        if it.get("variant") is None or it.get("variant") == variant:
            return True
    return False


def _unfulfilled_share(line: dict, order: dict, opened_at: str | None, now_date) -> bool:
    q = line.get("quantity") or {}
    current = q.get("current", q.get("ordered")) or 0
    fulfilled = q.get("fulfilled") or 0
    if current - fulfilled <= 0:
        return False
    latest = (order.get("estimated_delivery") or {}).get("latest")
    if latest is None:
        return False
    assessed = _utc_date(opened_at) if opened_at else now_date
    return assessed is not None and _utc_date(latest) is not None and assessed > _utc_date(latest)


def _per_line(record: dict, bound: bool, opened_at: str | None, now_date) -> list[dict]:
    order = record.get("order") or {}
    mandate = record.get("payment_mandate") or {}
    claim = record.get("claim") or {}
    ua = record.get("user_approval") or {}
    order_total = next(
        (t.get("amount") for t in order.get("totals") or [] if t.get("type") == "total"), None
    )
    payment_amount = mandate.get("payment_amount")
    excess = max(0, (order_total or 0) - (payment_amount or 0)) if order_total is not None else 0
    after_exp = False
    exec_date, exp_date = _utc_date(mandate.get("execution_date")), _utc_date(mandate.get("exp"))
    if exec_date and exp_date and exec_date > exp_date:
        after_exp = True
    any_counted = bool(_counted_adjustments(order))
    canceled = order.get("status") == "canceled"

    lines = {li.get("id"): li for li in order.get("line_items") or []}
    out = []
    remaining_excess = excess
    for line_id in claim.get("line_ids") or []:
        line = lines.get(line_id) or {}
        amount = _line_amount(line)
        row = {
            "line_id": line_id,
            "outcome": "uphold",
            "amount": 0,
            "rule": "5_default",
            "finding": None,
        }
        if amount is not None and _allocated_credit(order, line_id) >= amount:
            row["rule"] = "1_moot"
        elif after_exp:
            row.update(outcome="overturn", amount=amount, rule="2_after_exp")
        elif remaining_excess > 0 and amount is not None:
            take = min(remaining_excess, amount)
            remaining_excess -= take
            row.update(outcome="overturn", amount=take, rule="2_over_mandate")
        elif canceled and not any_counted:
            row.update(outcome="overturn", amount=amount, rule="3_canceled")
        elif _unfulfilled_share(line, order, opened_at, now_date):
            q = line.get("quantity") or {}
            current = q.get("current", q.get("ordered")) or 0
            share = amount * (current - (q.get("fulfilled") or 0)) / current
            row.update(outcome="overturn", amount=share, rule="3_unfulfilled")
        elif bound and ua and not _line_matches_approval(line, ua):
            row.update(rule="4_intent", finding="agent_platform")
        if isinstance(row["amount"], float) and row["amount"].is_integer():
            row["amount"] = int(row["amount"])
        out.append(row)
    return out


def _det_amount(value) -> float | None:
    if isinstance(value, dict):
        return value.get("amount")
    return value


def check_determination(
    record: dict,
    det: dict,
    recomputed: list[dict],
    opened_at: str | None = None,
    eligible: bool = True,
    not_eligible: str | None = None,
) -> list[str]:
    """Validate a presented determination against Section 4.5 required
    fields and the recomputed Section 7.4 decision (loser-pays fee from the
    recomputed outcome). Problems are emitted in check order."""
    problems: list[str] = []
    for field in DET_REQUIRED:
        if det.get(field) is None:
            problems.append(f"missing:{field}")
    # Section 4.5: presented identity must match the record being decided.
    if "dispute_id" in det and det.get("dispute_id") != record.get("dispute_id"):
        problems.append("dispute_id_differs")
    if "policy_version" in det and det.get("policy_version") != record.get("policy_version"):
        problems.append("policy_version_differs")
    factors = det.get("factors") or {}
    absent = [f for f in FACTORS if f not in factors]
    if absent:
        problems.append(f"factors_absent:{','.join(absent)}")
    for f in sorted(set(factors) - set(FACTORS)):
        problems.append(f"factor_not_permitted:{f}")
    if det.get("prohibited_screened") is False:
        problems.append("prohibited_not_screened")
    signer = det.get("signer") or {}
    if "signer" in det and not (signer.get("name") and signer.get("credential")):
        problems.append("signer_incomplete")
    expected = {r["line_id"]: r for r in recomputed}
    for line in det.get("per_line") or []:
        want = expected.get(line.get("line_id"))
        if (
            want is None
            or line.get("outcome") != want["outcome"]
            or _det_amount(line.get("amount")) != want["amount"]
        ):
            problems.append(f"outcome_differs:{line.get('line_id')}")
    # Section 7.5: the determination's opened_at is the time the provider
    # received the record; a signed determination lands within 10 calendar
    # days of opening.
    if (
        opened_at is not None
        and det.get("opened_at") is not None
        and _utc_date(opened_at) != _utc_date(det.get("opened_at"))
    ):
        problems.append("opened_at_differs")
    if det.get("opened_at") and det.get("issued_at"):
        span = _utc_date(det["issued_at"]) - _utc_date(det["opened_at"])
        if span is not None and (span.days < 0 or span.days > DETERMINATION_DAYS):
            problems.append("issued_outside_clock")
    if not eligible:
        problems.append(f"record_not_eligible:{not_eligible}")
    fee = det.get("fee_disposition") or {}
    if "fee_disposition" in det:
        paid_by = "merchant" if any(r["outcome"] == "overturn" for r in recomputed) else "payer"
        if fee.get("paid_by") != paid_by:
            problems.append("fee_paid_by_differs")
    return problems


def evaluate(case_input: dict, now: datetime | None = None) -> dict:
    """Evaluate one conformance-case input ({record, opened_at?,
    complete_digest?, determination?}) under ATDRP-0.1. Returns the keys the
    harness compares: eligible, not_eligible, approval_bound, per_line,
    det_ok, det_problems."""
    record = case_input.get("record") or {}
    opened_at = case_input.get("opened_at")
    now_date = (now or datetime.now(timezone.utc)).date()
    out: dict = {}

    # Section 4.4: exact-equality authorization chain before anything else.
    checkout_hash = record.get("checkout_hash")
    receipts = (record.get("checkout_receipt") or {}, record.get("payment_receipt") or {})
    nel: str | None = None
    if (record.get("payment_mandate") or {}).get("transaction_id") != checkout_hash or any(
        r.get("reference") != checkout_hash for r in receipts
    ):
        nel = "authorization_chain_broken"
    elif any(r.get("status") != "success" for r in receipts):
        nel = "receipt_status"
    lines = {li.get("id"): li for li in (record.get("order") or {}).get("line_items") or []}
    if nel is None and any(
        _line_amount(lines.get(lid) or {}) is None
        for lid in (record.get("claim") or {}).get("line_ids") or []
    ):
        nel = "line_amount_missing"
    if opened_at:
        pay_date, open_date = _utc_date(
            (record.get("payment_receipt") or {}).get("iat")
        ), _utc_date(opened_at)
        window = record.get("window_days") or WINDOW_DAYS
        if nel is None and pay_date and open_date:
            days = (open_date - pay_date).days
            if days < 0 or days > window:
                nel = "outside_window"

    if nel is not None:
        out.update(eligible=False, not_eligible=nel)
        # An ineligible record cannot carry a valid determination — the
        # check still runs so a presented one is explicitly convicted.
        recomputed = []
        eligible, code = False, nel
    else:
        bound = _approval_bound(record, case_input.get("complete_digest"))
        out["eligible"], out["not_eligible"] = True, None
        if record.get("user_approval") is not None:
            out["approval_bound"] = bound
        recomputed = _per_line(record, bound, opened_at, now_date)
        out["per_line"] = recomputed
        eligible, code = True, None

    det = case_input.get("determination")
    if det is not None:
        problems = check_determination(
            record,
            det,
            recomputed,
            opened_at=opened_at,
            eligible=eligible,
            not_eligible=code,
        )
        out["det_ok"] = not problems
        out["det_problems"] = problems
    return out
