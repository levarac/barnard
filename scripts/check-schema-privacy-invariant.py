#!/usr/bin/env python3
"""Reject stable owner-key and wallet-address shapes in public/on-wire schemas."""

from __future__ import annotations

import argparse
import json
import re
import sys
import tempfile
from pathlib import Path
from typing import Any
from urllib.parse import urldefrag


SCOPE_KEY = "x-barnard-disclosure-scope"
PUBLIC_SCOPE = "public-on-wire"
HOLDER_SCOPE = "holder-held"
ALLOWED_SCOPES = {PUBLIC_SCOPE, HOLDER_SCOPE}
FORBIDDEN_BYTE_LENGTHS = {20, 33}
FORBIDDEN_HEX_LENGTHS = {40, 42, 66, 68}
FORBIDDEN_BASE64_LENGTHS = {28, 44}
SEMANTIC_FIELD_NAMES = {
    "evmaddress",
    "ownerpublickey",
    "ownerpubkey",
    "walletaddress",
}
HEX_PATTERN_LENGTH = re.compile(
    r"(?:\{(?:40|42|66|68)\}"
    r"|(?:02\|03|03\|02).*?\{64\})",
    re.IGNORECASE,
)
PAIRED_BYTE_PATTERN_LENGTH = re.compile(
    r"(?:"
    r"\(\?:\[[^\]]+\]\{2\}\)\{(?:20|33)\}"
    r"|(?:02\|03|03\|02).*?"
    r"\(\?:\[[^\]]+\]\{2\}\)\{32\}"
    r")",
    re.IGNORECASE,
)
FORBIDDEN_DESCRIPTION = re.compile(
    r"(?:33[\s-]*byte.*compressed.*(?:public[\s-]*key|pubkey)"
    r"|20[\s-]*byte.*(?:evm|wallet)?\s*address)",
    re.IGNORECASE,
)


def normalized_field_name(value: str) -> str:
    return re.sub(r"[^a-z0-9]", "", value.lower())


def walk(value: Any, path: str = "$"):
    yield path, value
    if isinstance(value, dict):
        for key, child in value.items():
            yield from walk(child, f"{path}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            yield from walk(child, f"{path}[{index}]")


def shape_violations(document: dict[str, Any]) -> list[str]:
    violations: list[str] = []
    for path, node in walk(document):
        if not isinstance(node, dict):
            continue

        byte_length = node.get("x-barnard-byte-length")
        if byte_length in FORBIDDEN_BYTE_LENGTHS:
            violations.append(
                f"{path}: declares forbidden {byte_length}-byte stable identifier shape"
            )

        if (
            node.get("type") == "array"
            and node.get("minItems") == node.get("maxItems")
            and node.get("minItems") in FORBIDDEN_BYTE_LENGTHS
        ):
            violations.append(
                f"{path}: declares fixed {node['minItems']}-byte array shape"
            )
        prefix_items = node.get("prefixItems")
        if (
            node.get("type") == "array"
            and isinstance(prefix_items, list)
            and len(prefix_items) in FORBIDDEN_BYTE_LENGTHS
            and node.get("items") is False
        ):
            violations.append(
                f"{path}: declares fixed {len(prefix_items)}-byte prefixItems shape"
            )

        if node.get("type") == "string":
            minimum = node.get("minLength")
            maximum = node.get("maxLength")
            if minimum == maximum and minimum in FORBIDDEN_HEX_LENGTHS:
                violations.append(
                    f"{path}: declares fixed {minimum}-character address/public-key shape"
                )
            if (
                node.get("contentEncoding") == "base64"
                and minimum == maximum
                and minimum in FORBIDDEN_BASE64_LENGTHS
            ):
                violations.append(
                    f"{path}: declares base64 length consistent with a 20/33-byte identifier"
                )
            pattern = node.get("pattern")
            if isinstance(pattern, str) and HEX_PATTERN_LENGTH.search(pattern):
                violations.append(
                    f"{path}: declares exact hex length consistent with a 20/33-byte identifier"
                )
            if (
                isinstance(pattern, str)
                and PAIRED_BYTE_PATTERN_LENGTH.search(pattern)
            ):
                violations.append(
                    f"{path}: declares paired-byte hex shape consistent with a 20/33-byte identifier"
                )

        properties = node.get("properties")
        if isinstance(properties, dict):
            for field_name in properties:
                if normalized_field_name(field_name) in SEMANTIC_FIELD_NAMES:
                    violations.append(
                        f"{path}.properties.{field_name}: stable identifier field is public/on-wire"
                    )

        description = node.get("description")
        if isinstance(description, str) and FORBIDDEN_DESCRIPTION.search(description):
            violations.append(
                f"{path}.description: describes a 20/33-byte stable identifier"
            )
    return violations


def reference_violations(
    schema_path: Path,
    document: dict[str, Any],
    scopes_by_path: dict[Path, str],
    paths_by_id: dict[str, Path],
) -> list[str]:
    violations: list[str] = []
    for path, node in walk(document):
        if not isinstance(node, dict) or not isinstance(node.get("$ref"), str):
            continue
        reference, _ = urldefrag(node["$ref"])
        if not reference:
            continue
        if reference in paths_by_id:
            target = paths_by_id[reference]
        else:
            target = (schema_path.parent / reference).resolve()
        if scopes_by_path.get(target) == HOLDER_SCOPE:
            violations.append(
                f"{path}.$ref: public/on-wire schema references holder-held schema {reference}"
            )
    return violations


def check(schema_root: Path) -> tuple[list[str], int, int]:
    failures: list[str] = []
    documents: dict[Path, dict[str, Any]] = {}
    scopes_by_path: dict[Path, str] = {}
    paths_by_id: dict[str, Path] = {}

    for schema_path in sorted(schema_root.rglob("*.schema.json")):
        resolved_path = schema_path.resolve()
        try:
            raw = json.loads(schema_path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as error:
            failures.append(f"{schema_path}: invalid JSON schema document: {error}")
            continue
        if not isinstance(raw, dict):
            failures.append(f"{schema_path}: schema document root must be an object")
            continue
        scope = raw.get(SCOPE_KEY, PUBLIC_SCOPE)
        if scope not in ALLOWED_SCOPES:
            failures.append(
                f"{schema_path}: {SCOPE_KEY} must be one of {sorted(ALLOWED_SCOPES)}"
            )
            continue
        for path, node in walk(raw):
            if (
                path != "$"
                and isinstance(node, dict)
                and SCOPE_KEY in node
            ):
                failures.append(
                    f"{schema_path}:{path}: {SCOPE_KEY} is valid only at the document root"
                )
        documents[resolved_path] = raw
        scopes_by_path[resolved_path] = scope
        schema_id = raw.get("$id")
        if isinstance(schema_id, str):
            paths_by_id[schema_id] = resolved_path

    for schema_path, document in documents.items():
        if scopes_by_path[schema_path] != PUBLIC_SCOPE:
            continue
        for violation in shape_violations(document):
            failures.append(f"{schema_path}: {violation}")
        for violation in reference_violations(
            schema_path,
            document,
            scopes_by_path,
            paths_by_id,
        ):
            failures.append(f"{schema_path}: {violation}")

    public_count = sum(scope == PUBLIC_SCOPE for scope in scopes_by_path.values())
    holder_count = sum(scope == HOLDER_SCOPE for scope in scopes_by_path.values())
    return failures, public_count, holder_count


def self_test() -> list[str]:
    failures: list[str] = []
    with tempfile.TemporaryDirectory() as temporary_directory:
        root = Path(temporary_directory)
        holder = {
            "$id": "https://example.invalid/holder.schema.json",
            SCOPE_KEY: HOLDER_SCOPE,
            "type": "string",
            "pattern": "^0x(?:02|03)[0-9a-f]{64}$",
            "x-barnard-byte-length": 33,
        }
        public_address = {
            "type": "object",
            "properties": {
                "walletAddress": {
                    "type": "string",
                    "pattern": "^0x[0-9a-f]{40}$",
                }
            },
        }
        public_reference = {
            "type": "object",
            "properties": {
                "leak": {"$ref": "https://example.invalid/holder.schema.json"}
            },
        }
        public_paired_address = {
            "type": "object",
            "properties": {
                "value": {
                    "type": "string",
                    "pattern": "^0x(?:[0-9a-f]{2}){20}$",
                }
            },
        }
        public_paired_public_key = {
            "type": "object",
            "properties": {
                "value": {
                    "type": "string",
                    "pattern": "^(?:02|03)(?:[0-9a-f]{2}){32}$",
                }
            },
        }
        byte_item = {
            "type": "integer",
            "minimum": 0,
            "maximum": 255,
        }
        public_prefix_items_20 = {
            "type": "array",
            "prefixItems": [byte_item] * 20,
            "items": False,
        }
        public_prefix_items_33 = {
            "type": "array",
            "prefixItems": [byte_item] * 33,
            "items": False,
        }
        (root / "holder.schema.json").write_text(
            json.dumps(holder),
            encoding="utf-8",
        )
        (root / "public-address.schema.json").write_text(
            json.dumps(public_address),
            encoding="utf-8",
        )
        (root / "public-reference.schema.json").write_text(
            json.dumps(public_reference),
            encoding="utf-8",
        )
        (root / "public-paired-address.schema.json").write_text(
            json.dumps(public_paired_address),
            encoding="utf-8",
        )
        (root / "public-paired-public-key.schema.json").write_text(
            json.dumps(public_paired_public_key),
            encoding="utf-8",
        )
        (root / "public-prefix-items-20.schema.json").write_text(
            json.dumps(public_prefix_items_20),
            encoding="utf-8",
        )
        (root / "public-prefix-items-33.schema.json").write_text(
            json.dumps(public_prefix_items_33),
            encoding="utf-8",
        )

        violations, public_count, holder_count = check(root)
        joined = "\n".join(violations)
        if "exact hex length" not in joined:
            failures.append("self-test did not reject a public 20-byte hex shape")
        if "stable identifier field" not in joined:
            failures.append("self-test did not reject a public walletAddress field")
        if "references holder-held schema" not in joined:
            failures.append("self-test did not reject a public reference to holder-held data")
        if joined.count("paired-byte hex shape") != 2:
            failures.append(
                "self-test did not reject both 20- and 33-byte paired-hex shapes"
            )
        if joined.count("prefixItems shape") != 2:
            failures.append(
                "self-test did not reject both 20- and 33-byte prefixItems shapes"
            )
        if public_count != 6 or holder_count != 1:
            failures.append(
                "self-test scope counts drifted "
                f"(public={public_count}, holder={holder_count})"
            )

        positive_root = root / "holder-only"
        positive_root.mkdir()
        (positive_root / "holder.schema.json").write_text(
            json.dumps(holder),
            encoding="utf-8",
        )
        positive_violations, _, _ = check(positive_root)
        if positive_violations:
            failures.append(
                "self-test rejected an explicitly holder-held identifier shape"
            )
    return failures


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    default_root = Path(__file__).resolve().parents[1] / "schema"
    parser.add_argument(
        "--schema-root",
        type=Path,
        default=default_root,
        help="schema directory to scan (defaults to the repository schema directory)",
    )
    parser.add_argument(
        "--self-test",
        action="store_true",
        help="exercise synthetic forbidden and holder-held fixtures before scanning",
    )
    arguments = parser.parse_args()

    if arguments.self_test:
        self_test_failures = self_test()
        if self_test_failures:
            for failure in self_test_failures:
                print(f"ERROR: {failure}", file=sys.stderr)
            return 1
        print("OK: schema privacy invariant self-tests passed.")

    failures, public_count, holder_count = check(arguments.schema_root)
    if failures:
        for failure in failures:
            print(f"ERROR: {failure}", file=sys.stderr)
        return 1
    print(
        "OK: schema privacy invariant holds "
        f"({public_count} public/on-wire, {holder_count} holder-held documents)."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
