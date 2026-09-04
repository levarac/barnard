# Barnard Schema v3

This directory introduces the host-facing public contract for the
AdoptionCredential and signed per-window census protocol defined in
[`specs/123-128-adoption-credential-census/spec.md`](../../../specs/123-128-adoption-credential-census/spec.md).

- [`common.schema.json`](common.schema.json) defines strict lowercase-hex
  byte fields and excludes device-unique identifiers, RPIs, peripheral IDs,
  and raw observation counts.
- [`adoption-census.schema.json`](adoption-census.schema.json) defines the
  credential, signed census, registry binding, verified candidate, decision,
  and explicit relay-conflict projections. A replacement registry definition
  carries its prior credential ID and future effective window here, never in
  B005 or the fixed AdoptionCredential bytes.

Schema v3 corresponds to B005 **wire** `formatVersion=0x02`. This does not
alter the B005 v1 parser or any v1/v2 schema: wire and JSON-schema versions
are independent compatibility surfaces. A parsed v2 candidate is not
automatically an admission or a vote; the host must provide an authenticated
Registry Event Definition and the SDK must pass the fresh cross-event decision
gate.
