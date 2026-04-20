# Changelog

## 0.1.0 — Barnard v2 BLE protocol (#42)

### Breaking changes (v1 → v2)

- **TEK no longer transmitted over BLE.** GATT B003 characteristic redefined
  from TEK (16 B, Read+Write) to `displayId = SHA256(TEK)[0:4]` (4 B, Read-only).
  No characteristic has the Write property in v2.
- **Byte-valued method-channel fields now use lowercase hex** (were base64 in v1).
  `rpid`, `reporterRpid`, `payloadRaw` are 34-char hex (17 B wire form).
  `detectedDisplayId` is 8-char hex or null.
- **`DetectionEvent` reshaped**:
  - Added: `enin` (int), `reporterRpid` (`Uint8List`, 17 B), `detectedDisplayId`
    (`String?`, 8 hex chars or null on B003 read failure).
  - Removed: `displayId` (v1 6-char RPID prefix), `resolvedTek`,
    `resolvedDisplayId`, `isResolved`.
  - `rpid` now documented as 17-byte `[formatVersion(1) + RPI(16)]` wire form.
- **`RssiUpdateEvent` reshaped**: drops `displayId`/`resolvedDisplayId`; adds
  nullable `detectedDisplayId` (only populated when cached from a prior GATT
  exchange).
- **`BarnardClient` public API changes**:
  - Added: `myDisplayId` (String, 8 hex chars), `currentEnin` (int),
    `getCurrentRpi()` (`Future<Uint8List>`, 16 B), `exportCurrentTek()`
    (`Future<Uint8List>`, 16 B — **explicit privacy egress**, the SDK never
    transmits TEK over BLE).
  - Removed: `EventMode` enum, `currentMode`, `myResolvedDisplayId`,
    `getExchangedTeks`, `clearTeksForEvent`, `clearAllTeks`.
  - `joinEvent` / `leaveEvent` retained with simpler semantics (TEK
    regeneration only; no exchange plumbing).
- **`tek_storage.dart` deleted** (no on-device peer TEK store in v2).

### Additions

- `lib/src/domain/hex.dart` — `bytesToHex` / `hexToBytes` helpers.
- `parseBarnardEvent` (public) for decoding v2 method-channel payloads.
- Strict validation at the parser boundary: RPID must be 17 bytes,
  `detectedDisplayId` must match `/^[0-9a-f]{8}$/`, malformed payloads raise
  `FormatException`.

### Migration reference

Downstream consumers of v1 must:
1. Replace `DetectionEvent.resolvedDisplayId` / `displayId` with
   `DetectionEvent.detectedDisplayId`.
2. Switch any `base64Decode(rpid)` → `hexToBytes(rpid)` at bridge consumers
   (relevant only if decoding raw method-channel payloads; the Dart parser
   handles this automatically).
3. Replace `BarnardClient.myResolvedDisplayId` with `myDisplayId` (now
   non-nullable `String`).
4. Remove all `getExchangedTeks` / `clearTeks*` / `EventMode` usage. If
   the host app needs the TEK, call `exportCurrentTek()` explicitly.

See [`specs/004-resolvable-id/spec.md`](../../../specs/004-resolvable-id/spec.md)
for the normative v2 description.

## 0.0.1

Initial v1 release (not published).
