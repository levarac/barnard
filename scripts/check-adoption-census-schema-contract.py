#!/usr/bin/env python3
"""Focused v3 schema regressions for AdoptionCredential and census decisions.

This is intentionally a small, dependency-free validator for the JSON Schema
keywords exercised by the public adoption/census fixtures below. It checks the
actual schema documents rather than duplicating their intended values in a
fixture-only assertion.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
COMMON_PATH = ROOT / "schema/barnard/v3/common.schema.json"
ADOPTION_PATH = ROOT / "schema/barnard/v3/adoption-census.schema.json"


def pointer(document: dict[str, Any], fragment: str) -> dict[str, Any]:
    value: Any = document
    for segment in fragment.removeprefix("#/").split("/"):
        if not isinstance(value, dict):
            raise AssertionError(f"reference {fragment} does not resolve to an object")
        value = value[segment.replace("~1", "/").replace("~0", "~")]
    if not isinstance(value, dict):
        raise AssertionError(f"reference {fragment} does not resolve to a schema object")
    return value


def resolve_ref(
    reference: str,
    current_path: Path,
    documents: dict[Path, dict[str, Any]],
) -> tuple[dict[str, Any], Path]:
    filename, separator, fragment = reference.partition("#")
    target_path = current_path if not filename else (current_path.parent / filename).resolve()
    target = documents.get(target_path)
    if target is None:
        raise AssertionError(f"missing schema reference {reference} from {current_path}")
    return (pointer(target, f"#{fragment}") if separator else target), target_path


def matches_type(value: Any, expected: str) -> bool:
    if expected == "object":
        return isinstance(value, dict)
    if expected == "string":
        return isinstance(value, str)
    if expected == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if expected == "null":
        return value is None
    return False


def validates(
    schema: dict[str, Any],
    value: Any,
    current_path: Path,
    documents: dict[Path, dict[str, Any]],
) -> bool:
    reference = schema.get("$ref")
    if isinstance(reference, str):
        resolved, resolved_path = resolve_ref(reference, current_path, documents)
        return validates(resolved, value, resolved_path, documents)

    if "const" in schema and value != schema["const"]:
        return False
    if "enum" in schema and value not in schema["enum"]:
        return False
    schema_type = schema.get("type")
    if isinstance(schema_type, str) and not matches_type(value, schema_type):
        return False
    if isinstance(value, str):
        pattern = schema.get("pattern")
        if isinstance(pattern, str) and re.fullmatch(pattern, value) is None:
            return False
    if isinstance(value, int) and not isinstance(value, bool):
        if "minimum" in schema and value < schema["minimum"]:
            return False
        if "maximum" in schema and value > schema["maximum"]:
            return False
    if isinstance(value, dict):
        required = schema.get("required", [])
        if any(name not in value for name in required):
            return False
        properties = schema.get("properties", {})
        if schema.get("additionalProperties") is False and any(name not in properties for name in value):
            return False
        if isinstance(properties, dict):
            for name, property_schema in properties.items():
                if name in value and isinstance(property_schema, dict):
                    if not validates(property_schema, value[name], current_path, documents):
                        return False
    one_of = schema.get("oneOf")
    if isinstance(one_of, list):
        if sum(
            validates(branch, value, current_path, documents)
            for branch in one_of
            if isinstance(branch, dict)
        ) != 1:
            return False
    all_of = schema.get("allOf")
    if isinstance(all_of, list):
        if not all(
            validates(branch, value, current_path, documents)
            for branch in all_of
            if isinstance(branch, dict)
        ):
            return False
    condition = schema.get("if")
    if isinstance(condition, dict) and validates(condition, value, current_path, documents):
        then = schema.get("then")
        if isinstance(then, dict) and not validates(then, value, current_path, documents):
            return False
    return True


def decision(result: str, credential_id: str | None, reason: str | None) -> dict[str, Any]:
    return {
        "type": "adoption_decision",
        "result": result,
        "credentialId": credential_id,
        "reason": reason,
    }


def main() -> int:
    documents = {
        COMMON_PATH.resolve(): json.loads(COMMON_PATH.read_text(encoding="utf-8")),
        ADOPTION_PATH.resolve(): json.loads(ADOPTION_PATH.read_text(encoding="utf-8")),
    }
    common = documents[COMMON_PATH.resolve()]
    adoption = documents[ADOPTION_PATH.resolve()]
    hex_bytes = pointer(common, "#/$defs/HexBytes")
    b005_v2_bytes = pointer(common, "#/$defs/B005V2Bytes")
    failures: list[str] = []

    def require(condition: bool, message: str) -> None:
        if not condition:
            failures.append(message)

    require(
        not validates(hex_bytes, "a", COMMON_PATH.resolve(), documents),
        "HexBytes accepts an odd-length hex value",
    )
    require(
        not validates(b005_v2_bytes, "a" * 647, COMMON_PATH.resolve(), documents),
        "B005V2Bytes accepts an odd-length byte string",
    )

    identifier = "ab" * 32
    valid_cases = [
        decision("auto_adopt", identifier, None),
        decision("requires_chooser", None, "no_clear_majority"),
        decision("domain_authority_inconsistency", None, None),
    ]
    invalid_cases = [
        decision("auto_adopt", None, None),
        decision("auto_adopt", identifier, "gated"),
        decision("requires_chooser", identifier, "gated"),
        decision("requires_chooser", None, None),
        decision("domain_authority_inconsistency", identifier, None),
        decision("domain_authority_inconsistency", None, "domain_mismatch"),
    ]
    for value in valid_cases:
        require(
            validates(adoption, value, ADOPTION_PATH.resolve(), documents),
            f"AdoptionDecision rejects a required valid combination: {value}",
        )
    for value in invalid_cases:
        require(
            not validates(adoption, value, ADOPTION_PATH.resolve(), documents),
            f"AdoptionDecision accepts a forbidden result-dependent combination: {value}",
        )
    if failures:
        raise AssertionError("\n".join(failures))
    print("adoption/census v3 schema contract: OK")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (AssertionError, KeyError, OSError, json.JSONDecodeError, re.error) as error:
        print(f"adoption/census v3 schema contract: FAIL: {error}", file=sys.stderr)
        raise SystemExit(1)
