#!/usr/bin/env python3
"""Validate B005 CLI fixtures against the published root schema, without dependencies.

The base fixtures match b005-envelope-v2.txt's v1_envelope at ENIN 6000000
and its expected receipt. Boundary fixtures below test JSON shape only; schema
validation cannot establish cryptographic validity or compare lease fields.
"""

from __future__ import annotations

import json
import re
import runpy
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = ROOT / "schema/barnard/v2/b005-envelope-verifier.schema.json"
FIXTURES_PATH = ROOT / "scripts/b005-envelope-verifier-schema-fixtures.json"


def fixtures(base: dict[str, Any]) -> list[tuple[str, Any, bool]]:
    request, receipt = base["request"], base["receipt"]
    cases = [("request/vector", request, True), ("receipt/vector", receipt, True)]
    # These expectations are independent of the schema: weakening a constraint
    # must accept an invalid fixture and fail this contract check.
    for label, value in [("request", request), ("receipt", receipt)]:
        for field in value:
            cases.append((f"{label}/missing/{field}", {k: v for k, v in value.items() if k != field}, False))
            wrong_types = [None, True, False, [], {}]
            wrong_types += [0, 0.5] if isinstance(value[field], str) else [str(value[field]), 0.5]
            for index, wrong in enumerate(wrong_types):
                cases.append((f"{label}/type/{field}/{index}", {**value, field: wrong}, False))
        cases.append((f"{label}/extra", {**value, "extra": 0}, False))

    for label, value, fields in [
        ("request", request, ["currentEnin"]),
        ("receipt", receipt, ["validFromEnin", "validThroughEnin", "relayExpiresAtEnin"]),
    ]:
        for field in fields:
            for boundary, expected in [(0, True), (4294967295, True), (-1, False), (4294967296, False)]:
                cases.append((f"{label}/{field}/{boundary}", {**value, field: boundary}, expected))

    for mode, expected in [(0, True), (1, True), (-1, False), (2, False)]:
        cases.append((f"receipt/joinMode/{mode}", {**receipt, "joinMode": mode}, expected))
    cases.append(("receipt/kind/unknown", {**receipt, "kind": "BARNARD_B005_VERIFIED_V2"}, False))
    for label, value, expected in [
        ("lowercase", "ab" * 32, True),
        ("short", "a" * 63, False),
        ("long", "a" * 65, False),
        ("uppercase", "AB" * 32, False),
        ("nonhex", "g" * 64, False),
        ("prefix", "0x" + "ab" * 32, False),
        ("newline", "ab" * 32 + "\n", False),
    ]:
        cases.append((f"receipt/eventIdHex/{label}", {**receipt, "eventIdHex": value}, expected))
    for label, value, expected in [
        ("minimum", "ab" * 199, True),
        ("maximum", "ab" * 508, True),
        ("short", "ab" * 198, False),
        ("long", "ab" * 509, False),
        ("empty", "", False),
        ("odd", "a" * 399, False),
        ("uppercase", "AB" * 199, False),
        ("nonhex", "gg" * 199, False),
        ("prefix", "0x" + "ab" * 199, False),
        ("newline", "ab" * 199 + "\n", False),
    ]:
        cases.append((f"request/signedEnvelopeHex/{label}", {**request, "signedEnvelopeHex": value}, expected))
    # Every instance goes through root oneOf, including zero-match objects,
    # mixed request/receipt fields, and non-object roots.
    for index, value in enumerate([{}, {**request, **receipt}, None, True, 0, 0.5, "receipt", [], [receipt]]):
        cases.append((f"root/invalid/{index}", value, False))
    return cases


def main() -> int:
    validator = runpy.run_path(str(ROOT / "scripts/check-adoption-census-schema-contract.py"))
    validates = validator["validates"]
    schema_path = SCHEMA_PATH.resolve()
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    documents = {schema_path: schema}
    cases = fixtures(json.loads(FIXTURES_PATH.read_text(encoding="utf-8")))
    failures = []
    for name, value, expected in cases:
        actual = validates(schema, value, schema_path, documents)
        if actual != expected:
            failures.append(f"{name}: expected {'valid' if expected else 'invalid'}, got {'valid' if actual else 'invalid'}")
    if failures:
        raise AssertionError("\n".join(failures))
    accepted = sum(expected for _, _, expected in cases)
    print(f"B005 envelope verifier schema contract: OK ({len(cases)} fixtures: {accepted} valid, {len(cases) - accepted} invalid)")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (AssertionError, KeyError, OSError, json.JSONDecodeError, re.error) as error:
        print(f"B005 envelope verifier schema contract: FAIL: {error}", file=sys.stderr)
        raise SystemExit(1)
