# Barnard Schema v1

JSON Schema definitions for Barnard v1.

This is the shared source of truth for:
- Events (detection/state/constraint/error + debug events)
- Config and capabilities

Notes
- Terminology is not translated: **Scan / Advertise / Central / Peripheral / GATT / Transport**
- `DetectionEvent` is based on receiver-observed facts: `rpid + rssi + timestamp`
- ENIN derivation is explicit in config/capabilities/state:
  - `fixedLength`: `floor(unix_seconds / eninSeconds)`, with `eninSeconds` in `12..3600`
  - `beaconSlot`: ENIN is the Beacon Chain slot number for the configured chain
