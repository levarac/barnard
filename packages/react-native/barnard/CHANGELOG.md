# Changelog

## 0.2.0 — Barnard v2 BLE protocol (#42)

### Breaking changes (v1 → v2)

- **TEK no longer transmitted over BLE.** GATT B003 redefined from TEK
  (16 B, Read+Write) to `displayId = SHA256(TEK)[0:4]` (4 B, Read-only).
  No characteristic has the Write property.
- **Byte-valued bridge fields switch from base64 to lowercase hex.**
  `rpid`, `reporterRpid`, `payloadRaw` are 34-char hex. `detectedDisplayId`
  is 8-char hex or null.
- **`DetectionEvent` v2 shape** — see `src/types.ts`:
  - Added: `enin` (number), `reporterRpid` (hex string, 17 B), `detectedDisplayId`
    (string | null, nullable when B003 read failed).
  - Removed: `displayId`, `resolvedTek`, `resolvedDisplayId`.
  - `rpid` is now the 17-byte wire form hex string.
- **`RssiUpdateEvent`** — drops `displayId`/`resolvedDisplayId`; adds nullable
  `detectedDisplayId`.
- **`BarnardManager` public API**:
  - Added: `getCurrentEventCode()`, `getMyDisplayId()` (8-char hex),
    `getCurrentRpi()` (32-char hex), `getCurrentEnin()`, `exportCurrentTek()`
    (32-char hex — **explicit privacy egress**).
  - Added event: `onRssiUpdate()` for cached-peer high-rate RSSI.
  - Removed: `getEventMode()`, `getExchangedTeks()`, `clearTeksForEvent()`,
    `clearAllTeks()`.
- **Removed types**: `EventMode`, `EventModeState`, `TekEntry`.
- **BarnardState v2**: `eventMode` key removed. Presence of `eventCode`
  signals whether an event is joined.

### Native layer

- iOS: `BarnardBleController.swift` rewritten for v2 GATT flow. Write
  handler rejects everything. `BarnardTekStorage.swift` deleted.
- Android: `BarnardController.kt` rewritten. `BarnardTekStorage.kt` deleted.
- `BarnardCrypto.{swift,kt}`: `displayId4` / `displayIdString`
  (SHA256-based) added; `resolveRpi` and 3-byte `displayId` removed.

### Migration for host apps

1. Replace `event.displayId` / `event.resolvedDisplayId` with
   `event.detectedDisplayId` (now nullable).
2. Replace `barnard.getEventMode()` with `barnard.getCurrentEventCode()`.
3. Replace any `getExchangedTeks` / `clearTeks*` usage: v2 has no peer
   TEK store. Use `exportCurrentTek()` to disclose **your own** TEK out-of-band.
4. Adjust any consumer that decoded base64 bridge payloads — they are
   hex strings now.

See [`specs/004-resolvable-id/spec.md`](../../../../specs/004-resolvable-id/spec.md)
for the normative v2 description.

## 0.1.0

Initial v1 release of the React Native Barnard package.
