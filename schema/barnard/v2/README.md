# Barnard Schema v2

JSON Schema (draft 2020-12) for the Barnard SDK v2 event stream.

- [`common.schema.json`](common.schema.json) — shared type definitions (`RpidHex`, `DisplayIdHex`, `TekHex`, etc.).
- [`events.schema.json`](events.schema.json) — `DetectionEvent`, `RssiUpdateEvent`, `StateEvent`, `ConstraintEvent`, `ErrorEvent`, `DebugEvent`.

Byte-valued fields are lowercase hex strings at the method-channel / RN bridge boundary. TEK is never emitted over BLE and therefore never appears in a DetectionEvent — it is only exposed to host apps via `exportCurrentTek()` / `exportCurrentTek` on the respective SDK.

See [`specs/004-resolvable-id/spec.md`](../../../specs/004-resolvable-id/spec.md) for the normative v2 protocol description.

## v1 → v2 migration reference

For consumers still on v1, the following field renames apply:

| v1 DetectionEvent | v2 DetectionEvent |
|-------------------|-------------------|
| `displayId` (6 hex, RPID[0:3]) | *(removed)* |
| `resolvedDisplayId` (6 hex, TEK[0:3]) | `detectedDisplayId` (8 hex, `SHA256(TEK)[0:4]`, nullable) |
| `resolvedTek` (base64) | *(removed — TEK never on wire)* |
| `rpid` (base64, 16 B) | `rpid` (lowercase hex, 17 B wire form) |
| — | `reporterRpid` (new, 17 B hex) |
| — | `enin` (new, integer) |
| `payloadRaw` (base64) | `payloadRaw` (hex) |

v1 remains untouched at [`../v1/`](../v1/) for existing deployments.

## Non-normative: server-report projection

A backend ingesting v2 DetectionEvents might project them into something like:

```json
{
  "reporterRpid": "01a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6",
  "detectedRpid": "01d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9",
  "detectedDisplayId": "9abcdef0",
  "rssi": -62,
  "enin": 2948599,
  "timestamp": "2026-04-20T10:00:00.000Z"
}
```

This is a host-app concern, not part of the Barnard schema.
