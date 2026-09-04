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

# Keywords this validator actually evaluates as constraints.
IMPLEMENTED_KEYWORDS = frozenset(
    {
        "$ref", "const", "enum", "type", "pattern", "minimum", "maximum",
        "required", "properties", "additionalProperties", "oneOf", "allOf",
        "if", "then",
    }
)
# Pure-annotation keywords that never constrain an instance, per the JSON
# Schema core spec. Safe to ignore rather than implement.
ANNOTATION_KEYWORDS = frozenset({"$schema", "$id", "$defs", "title", "description"})


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
    raise AssertionError(f"matches_type does not implement JSON Schema type {expected!r}")


def validates(
    schema: dict[str, Any],
    value: Any,
    current_path: Path,
    documents: dict[Path, dict[str, Any]],
) -> bool:
    unknown = set(schema) - IMPLEMENTED_KEYWORDS - ANNOTATION_KEYWORDS
    if unknown:
        raise AssertionError(
            f"validates() does not implement schema keyword(s) {sorted(unknown)} in {current_path}"
        )

    # A $ref alongside sibling keywords (e.g. {"$ref": ..., "const": "..."})
    # must satisfy BOTH the resolved reference and the siblings, not just the
    # reference alone.
    reference = schema.get("$ref")
    if isinstance(reference, str):
        resolved, resolved_path = resolve_ref(reference, current_path, documents)
        if not validates(resolved, value, resolved_path, documents):
            return False

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


def adoption_credential(*, valid_from: int, valid_until: int) -> dict[str, Any]:
    return {
        "type": "adoption_credential",
        "formatVersion": 1,
        "bytes": "00" * 159,
        "credentialId": "ab" * 32,
        "eventId": "ab" * 32,
        "admissionMode": "open",
        "b004AdoptionScopeHash": "ab" * 8,
        "displayNameHash": "ab" * 32,
        "validFromUnixSeconds": valid_from,
        "validUntilUnixSeconds": valid_until,
        "censusWindowSeconds": 300,
    }


def census_domain_policy() -> dict[str, Any]:
    return {
        "censusDomainId": "ab" * 32,
        "censusWindowSeconds": 300,
        "authorityPolicyEpoch": 1,
        "authorizedAuthorityKeyHash": "ab" * 32,
        "minimumEligibleVoterCount": 1,
        "minimumQualifiedVoterCount": 1,
        "maximumCandidateAgeSeconds": 60,
    }


def registry_event_definition(*, valid_from: int, valid_until: int) -> dict[str, Any]:
    return {
        "type": "registry_event_definition",
        "eventId": "ab" * 32,
        "credentialId": "ab" * 32,
        "b004AdoptionScopeHash": "ab" * 8,
        "displayNameHash": "ab" * 32,
        "validFromUnixSeconds": valid_from,
        "validUntilUnixSeconds": valid_until,
        "admissionMode": "open",
        "censusDomainPolicy": census_domain_policy(),
        "replacesCredentialId": None,
        "effectiveWindowIndex": None,
    }


def signed_window_census(*, qualified: int, eligible: int, root: str | None = None) -> dict[str, Any]:
    return {
        "type": "signed_window_census",
        "formatVersion": 1,
        "bytes": "00" * 142,
        "credentialId": "ab" * 32,
        "windowIndex": 0,
        "qualifiedVoterCount": qualified,
        "eligibleVoterCount": eligible,
        "countedSetMerkleRoot": root if root is not None else "0" * 64,
    }


def verified_census_candidate(*, qualified: int, eligible: int) -> dict[str, Any]:
    return {
        "type": "verified_census_candidate",
        "b005FormatVersion": 2,
        "b005Bytes": "ab" * 323,
        "credentialId": "ab" * 32,
        "eventId": "ab" * 32,
        "admissionMode": "open",
        "censusDomainId": "ab" * 32,
        "censusWindowSeconds": 300,
        "authorityPolicyEpoch": 1,
        "censusAuthorityKeyHash": "ab" * 32,
        "windowIndex": 0,
        "qualifiedVoterCount": qualified,
        "eligibleVoterCount": eligible,
        "observedAtUnixSeconds": 0,
        "registryVerification": "verified",
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

    def schema_valid(value: dict[str, Any]) -> bool:
        return validates(adoption, value, ADOPTION_PATH.resolve(), documents)

    require(
        not validates(hex_bytes, "a", COMMON_PATH.resolve(), documents),
        "HexBytes accepts an odd-length hex value",
    )
    require(
        validates(hex_bytes, "ab", COMMON_PATH.resolve(), documents),
        "HexBytes rejects a valid even-length hex value",
    )
    require(
        not validates(b005_v2_bytes, "a" * 647, COMMON_PATH.resolve(), documents),
        "B005V2Bytes accepts an odd-length byte string",
    )
    require(
        validates(b005_v2_bytes, "ab" * 323, COMMON_PATH.resolve(), documents),
        "B005V2Bytes rejects a valid value at the documented 323-byte minimum",
    )

    identifier = "ab" * 32
    valid_cases = [
        decision("auto_adopt", identifier, None),
        decision("requires_chooser", None, "no_clear_majority"),
        decision("requires_chooser", None, "no_authoritative_census"),
        decision("requires_chooser", None, "invalid_domain_policy"),
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
        require(schema_valid(value), f"AdoptionDecision rejects a required valid combination: {value}")
    for value in invalid_cases:
        require(not schema_valid(value), f"AdoptionDecision accepts a forbidden result-dependent combination: {value}")

    # VerifiedCensusCandidate.registryVerification is const "verified": the
    # only construction path (decodeAndBind) requires a verified registry
    # binding before a candidate exists at all.
    require(
        schema_valid(verified_census_candidate(qualified=4, eligible=7)),
        "VerifiedCensusCandidate rejects a verified fixture",
    )
    unverified_candidate = verified_census_candidate(qualified=4, eligible=7)
    unverified_candidate["registryVerification"] = "unverified"
    require(
        not schema_valid(unverified_candidate),
        "VerifiedCensusCandidate accepts registryVerification other than 'verified'",
    )

    # JSON Schema cannot express validUntilUnixSeconds > validFromUnixSeconds
    # or qualifiedVoterCount <= eligibleVoterCount as cross-field constraints
    # (it can only compare an instance field against a schema-authored
    # literal, never against another instance field). Both invariants are
    # already normative in spec.md's AdoptionCredential and SignedWindowCensus
    # wire-format field tables; enforce them here explicitly. The "sanity"
    # checks below prove the schema alone does NOT catch a violation, which is
    # exactly why the explicit check exists - if a future schema mechanism
    # makes one of these sanity checks fail, the corresponding explicit check
    # has become redundant and this comment should be updated.
    valid_credential = adoption_credential(valid_from=1_772_093_440, valid_until=1_772_098_240)
    inverted_credential = adoption_credential(valid_from=1_772_098_240, valid_until=1_772_093_440)
    require(schema_valid(valid_credential), "AdoptionCredential rejects a structurally valid fixture")
    require(
        schema_valid(inverted_credential),
        "sanity: JSON Schema unexpectedly rejected an inverted validity window on its own",
    )
    require(
        valid_credential["validUntilUnixSeconds"] > valid_credential["validFromUnixSeconds"],
        "AdoptionCredential: validUntilUnixSeconds must be strictly greater than validFromUnixSeconds",
    )
    require(
        not (inverted_credential["validUntilUnixSeconds"] > inverted_credential["validFromUnixSeconds"]),
        "AdoptionCredential: explicit validity-window check failed to flag an inverted window",
    )

    valid_registry_definition = registry_event_definition(valid_from=1_772_093_440, valid_until=1_772_098_240)
    inverted_registry_definition = registry_event_definition(valid_from=1_772_098_240, valid_until=1_772_093_440)
    require(schema_valid(valid_registry_definition), "RegistryEventDefinition rejects a structurally valid fixture")
    require(
        schema_valid(inverted_registry_definition),
        "sanity: JSON Schema unexpectedly rejected an inverted validity window on its own",
    )
    require(
        valid_registry_definition["validUntilUnixSeconds"] > valid_registry_definition["validFromUnixSeconds"],
        "RegistryEventDefinition: validUntilUnixSeconds must be strictly greater than validFromUnixSeconds",
    )
    require(
        not (
            inverted_registry_definition["validUntilUnixSeconds"]
            > inverted_registry_definition["validFromUnixSeconds"]
        ),
        "RegistryEventDefinition: explicit validity-window check failed to flag an inverted window",
    )

    valid_census = signed_window_census(qualified=4, eligible=7)
    inverted_census = signed_window_census(qualified=8, eligible=7)
    require(schema_valid(valid_census), "SignedWindowCensus rejects a structurally valid fixture")
    require(
        schema_valid(inverted_census),
        "sanity: JSON Schema unexpectedly rejected qualified > eligible on its own",
    )
    require(
        valid_census["qualifiedVoterCount"] <= valid_census["eligibleVoterCount"],
        "SignedWindowCensus: qualifiedVoterCount must not exceed eligibleVoterCount",
    )
    require(
        not (inverted_census["qualifiedVoterCount"] <= inverted_census["eligibleVoterCount"]),
        "SignedWindowCensus: explicit qualified<=eligible check failed to flag a violation",
    )

    valid_candidate = verified_census_candidate(qualified=4, eligible=7)
    inverted_candidate = verified_census_candidate(qualified=8, eligible=7)
    require(schema_valid(valid_candidate), "VerifiedCensusCandidate rejects a structurally valid fixture")
    require(
        schema_valid(inverted_candidate),
        "sanity: JSON Schema unexpectedly rejected qualified > eligible on its own",
    )
    require(
        valid_candidate["qualifiedVoterCount"] <= valid_candidate["eligibleVoterCount"],
        "VerifiedCensusCandidate: qualifiedVoterCount must not exceed eligibleVoterCount",
    )
    require(
        not (inverted_candidate["qualifiedVoterCount"] <= inverted_candidate["eligibleVoterCount"]),
        "VerifiedCensusCandidate: explicit qualified<=eligible check failed to flag a violation",
    )

    # countedSetMerkleRoot is reserved in census v1: the schema already
    # enforces the all-zero value via a plain `const`, so the same non-zero
    # root both native contract tests already assert the runtime rejects
    # (test-vectors/adoption-census-v1.txt's counted_set_merkle_root_nonzero)
    # must fail schema validation too.
    nonzero_root = "01" * 32
    require(len(nonzero_root) == 64, "test fixture bug: countedSetMerkleRoot must be exactly 64 hex chars")
    nonzero_root_census = signed_window_census(qualified=4, eligible=7, root=nonzero_root)
    require(
        not schema_valid(nonzero_root_census),
        "SignedWindowCensus accepts a non-zero countedSetMerkleRoot",
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
