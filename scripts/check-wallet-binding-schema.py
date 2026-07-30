#!/usr/bin/env python3
"""Exercise canonical wallet-binding schema boundaries without dependencies."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Any


def binding_message_schema(schema_path: Path) -> dict[str, Any]:
    document = json.loads(schema_path.read_text(encoding="utf-8"))
    message = document.get("$defs", {}).get("BindingMessage")
    if not isinstance(message, dict):
        raise ValueError("$defs.BindingMessage is missing or is not an object")
    return message


def matches(schema: dict[str, Any], value: str) -> bool:
    patterns = [schema.get("pattern")]
    all_of = schema.get("allOf")
    if not isinstance(all_of, list):
        return False
    patterns.extend(
        constraint.get("pattern")
        for constraint in all_of
        if isinstance(constraint, dict)
    )
    return all(
        isinstance(pattern, str) and re.search(pattern, value) is not None
        for pattern in patterns
    )


def message(
    *,
    domain: str = "beid.levarac.org",
    chain_id: str = "1",
    issued_at: str = "2026-07-30T09:00:00Z",
) -> str:
    return "\n".join(
        [
            f"{domain} wants to bind this wallet to a Levarac owner key.",
            "",
            "This signature authorizes no transaction and moves no assets.",
            "",
            "Domain-Tag: barnard-account-binding:v1",
            "Wallet: 0x14791697260e4c9a71f18484c9f997b308e59325",
            (
                "Owner-Key: "
                "0x0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d"
                "959f2815b16f81798"
            ),
            f"Chain-ID: eip155:{chain_id}",
            "Scope: global",
            "Nonce: 0x000102030405060708090a0b0c0d0e0f",
            f"Issued-At: {issued_at}",
        ]
    )


def main() -> int:
    schema_path = (
        Path(__file__).resolve().parents[1]
        / "schema"
        / "barnard"
        / "v1"
        / "wallet-binding.schema.json"
    )
    try:
        schema = binding_message_schema(schema_path)
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as error:
        print(f"ERROR: cannot load binding-message schema: {error}", file=sys.stderr)
        return 1

    accepted = [
        message(),
        message(domain="beid.levarac.org:0"),
        message(domain="beid.levarac.org:65535"),
        message(chain_id="0"),
        message(chain_id="18446744073709551615"),
        message(issued_at="2024-02-29T23:59:59Z"),
        message(issued_at="2000-02-29T00:00:00Z"),
    ]
    rejected = [
        message(domain="beid.levarac.org:00080"),
        message(domain="beid.levarac.org:65536"),
        message(domain="beid.levarac.org:99999"),
        message(chain_id="01"),
        message(chain_id="18446744073709551616"),
        message(issued_at="2026-02-29T09:00:00Z"),
        message(issued_at="2026-02-31T09:00:00Z"),
        message(issued_at="1900-02-29T09:00:00Z"),
        message(issued_at="2026-04-31T09:00:00Z"),
        message().replace("\nScope: global", ""),
        message().replace("Scope: global", "Scope: event"),
        message().replace(
            (
                "\nScope: global"
                "\nNonce: 0x000102030405060708090a0b0c0d0e0f"
            ),
            (
                "\nNonce: 0x000102030405060708090a0b0c0d0e0f"
                "\nScope: global"
            ),
        ),
        message() + "\n",
        message().replace("\n", "\r\n"),
    ]

    failures: list[str] = []
    for index, fixture in enumerate(accepted):
        if not matches(schema, fixture):
            failures.append(f"valid fixture {index} was rejected")
    for index, fixture in enumerate(rejected):
        if matches(schema, fixture):
            failures.append(f"invalid fixture {index} was accepted")

    if failures:
        for failure in failures:
            print(f"ERROR: {failure}", file=sys.stderr)
        return 1
    print(
        "OK: wallet-binding schema accepts canonical boundary fixtures "
        f"({len(accepted)} valid, {len(rejected)} invalid)."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
