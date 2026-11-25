#!/usr/bin/env python3
"""APAF-1 ATDRP-0.1 conformance provider (SEP #303 / ACP PR #316).

Reads one case `input` JSON object on stdin, prints the evaluation on
stdout — compatible with the PR's scripts/run-dispute-conformance.js:

  DISPUTE_PROVIDER_CMD="python3 provider.py" \
    node run-dispute-conformance.js
"""

import json
import sys

from dispute_atdrp import evaluate


def main() -> int:
    try:
        case_input = json.load(sys.stdin)
    except json.JSONDecodeError:
        print(json.dumps({"not_evaluable": "stdin is not JSON"}))
        return 0
    try:
        print(json.dumps(evaluate(case_input)))
    except Exception as e:
        print(json.dumps({"not_evaluable": f"evaluator error: {e}"}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
