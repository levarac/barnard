#!/usr/bin/env python3
"""Exercise canonical wallet-binding schema boundaries without dependencies."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Any


def message_schemas(
    schema_path: Path,
) -> tuple[
    dict[str, Any],
    dict[str, Any],
    dict[str, Any],
    dict[str, Any],
    dict[str, Any],
]:
    document = json.loads(schema_path.read_text(encoding="utf-8"))
    definitions = document.get("$defs", {})
    binding_message = definitions.get("BindingMessage")
    unbinding_message = definitions.get("UnbindingMessage")
    unbinding_record = definitions.get("AccountUnbindingRecord")
    owner_unbinding_record = definitions.get("OwnerAccountUnbindingRecord")
    wallet_unbinding_record = definitions.get("WalletAccountUnbindingRecord")
    if not isinstance(binding_message, dict):
        raise ValueError("$defs.BindingMessage is missing or is not an object")
    if not isinstance(unbinding_message, dict):
        raise ValueError("$defs.UnbindingMessage is missing or is not an object")
    if not isinstance(unbinding_record, dict):
        raise ValueError(
            "$defs.AccountUnbindingRecord is missing or is not an object"
        )
    if not isinstance(owner_unbinding_record, dict):
        raise ValueError(
            "$defs.OwnerAccountUnbindingRecord is missing or is not an object"
        )
    if not isinstance(wallet_unbinding_record, dict):
        raise ValueError(
            "$defs.WalletAccountUnbindingRecord is missing or is not an object"
        )
    return (
        binding_message,
        unbinding_message,
        unbinding_record,
        owner_unbinding_record,
        wallet_unbinding_record,
    )


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
    ceremony: str = "binding",
    domain: str = "beid.levarac.org",
    chain_id: str = "1",
    issued_at: str = "2026-07-30T09:00:00Z",
) -> str:
    if ceremony == "binding":
        header = f"{domain} wants to bind this wallet to a Levarac owner key."
        statement = "This signature authorizes no transaction and moves no assets."
        domain_tag = "barnard-account-binding:v1"
    elif ceremony == "unbinding":
        header = (
            f"{domain} wants to revoke this wallet's binding "
            "to a Levarac owner key."
        )
        statement = (
            "This signature REVOKES a wallet binding "
            "and authorizes no transaction."
        )
        domain_tag = "barnard-account-unbinding:v1"
    else:
        raise ValueError(f"unsupported ceremony: {ceremony}")
    return "\n".join(
        [
            header,
            "",
            statement,
            "",
            f"Domain-Tag: {domain_tag}",
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
        (
            binding_schema,
            unbinding_schema,
            unbinding_record,
            owner_unbinding_record,
            wallet_unbinding_record,
        ) = message_schemas(schema_path)
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as error:
        print(f"ERROR: cannot load binding-message schema: {error}", file=sys.stderr)
        return 1

    binding_accepted = [
        message(),
        message(domain="beid.levarac.org:0"),
        message(domain="beid.levarac.org:65535"),
        message(chain_id="0"),
        message(chain_id="18446744073709551615"),
        message(issued_at="2024-02-29T23:59:59Z"),
        message(issued_at="2000-02-29T00:00:00Z"),
    ]
    binding_rejected = [
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
    unbinding_accepted = [
        message(ceremony="unbinding"),
        message(ceremony="unbinding", domain="beid.levarac.org:0"),
        message(ceremony="unbinding", domain="beid.levarac.org:65535"),
        message(ceremony="unbinding", chain_id="0"),
        message(ceremony="unbinding", chain_id="18446744073709551615"),
        message(
            ceremony="unbinding",
            issued_at="2024-02-29T23:59:59Z",
        ),
    ]
    unbinding_rejected = [
        message(ceremony="unbinding").replace(
            "Domain-Tag: barnard-account-unbinding:v1",
            "Domain-Tag: barnard-account-binding:v1",
        ),
        message(),
        message(ceremony="unbinding", domain="beid.levarac.org:00080"),
        message(ceremony="unbinding", domain="beid.levarac.org:65536"),
        message(ceremony="unbinding", chain_id="01"),
        message(ceremony="unbinding", chain_id="18446744073709551616"),
        message(ceremony="unbinding", issued_at="2026-02-29T09:00:00Z"),
        message(ceremony="unbinding").replace(
            "This signature REVOKES a wallet binding "
            "and authorizes no transaction.",
            "This signature authorizes no transaction and moves no assets.",
        ),
        message(ceremony="unbinding") + "\n",
        message(ceremony="unbinding").replace("\n", "\r\n"),
    ]

    failures: list[str] = []
    for name, schema, accepted, rejected in [
        (
            "binding",
            binding_schema,
            binding_accepted,
            binding_rejected,
        ),
        (
            "unbinding",
            unbinding_schema,
            unbinding_accepted,
            unbinding_rejected,
        ),
    ]:
        for index, fixture in enumerate(accepted):
            if not matches(schema, fixture):
                failures.append(f"valid {name} fixture {index} was rejected")
        for index, fixture in enumerate(rejected):
            if matches(schema, fixture):
                failures.append(f"invalid {name} fixture {index} was accepted")

    expected_variant_refs = {
        "#/$defs/OwnerAccountUnbindingRecord",
        "#/$defs/WalletAccountUnbindingRecord",
    }
    actual_variant_refs = {
        variant.get("$ref")
        for variant in unbinding_record.get("oneOf", [])
        if isinstance(variant, dict)
    }
    if actual_variant_refs != expected_variant_refs:
        failures.append("account-unbinding record does not define both signer variants")

    record_expectations = [
        (
            "owner",
            owner_unbinding_record,
            {
                "type",
                "schemaVersion",
                "ownerPublicKey",
                "walletAddress",
                "walletSignatureHash",
                "signer",
                "signature",
            },
            "#/$defs/BarnardRecoverableSignature",
        ),
        (
            "wallet",
            wallet_unbinding_record,
            {"type", "schemaVersion", "message", "signer", "signature"},
            "#/$defs/WalletSignature",
        ),
    ]
    for signer, record, required, signature_ref in record_expectations:
        properties = record.get("properties", {})
        if (
            record.get("additionalProperties") is not False
            or set(record.get("required", [])) != required
            or properties.get("signer", {}).get("const") != signer
            or properties.get("signature", {}).get("$ref") != signature_ref
        ):
            failures.append(
                f"{signer} account-unbinding record shape is not canonical"
            )
    if (
        wallet_unbinding_record.get("properties", {})
        .get("message", {})
        .get("$ref")
        != "#/$defs/UnbindingMessage"
    ):
        failures.append("wallet account-unbinding record does not use UnbindingMessage")

    if failures:
        for failure in failures:
            print(f"ERROR: {failure}", file=sys.stderr)
        return 1
    print(
        "OK: wallet-binding schema accepts canonical binding and unbinding "
        "boundary fixtures "
        f"({len(binding_accepted) + len(unbinding_accepted)} valid, "
        f"{len(binding_rejected) + len(unbinding_rejected)} invalid)."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
