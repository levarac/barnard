# Changelog

## Unreleased

### Fixed

- iOS Simulator now reports `canScan: false` and `canAdvertise: false` from
  `getPermissionStatus()` / `requestPermissions()` even when CoreBluetooth
  authorization is granted, reflecting the fact that CoreBluetooth Scan /
  Advertise are not available on iOS Simulator. Host apps can drop any
  simulator-detection workarounds and branch on these capability flags
  directly. See issue #57.
- Android `getPermissionStatus()` now also checks hardware capability
  (`PackageManager.FEATURE_BLUETOOTH_LE`, `BluetoothLeAdvertiser`
  availability, `isMultipleAdvertisementSupported`) in addition to runtime
  permissions. Android Emulators and BLE-less devices therefore report
  `canScan: false` / `canAdvertise: false` even when permissions are
  granted, matching the iOS Simulator behavior above. See issue #57.

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
  `detectedDisplayId`; adds required `reporterRpid` (34-char hex) and `enin`
  (number), derived natively from the observation timestamp with the same
  atomic-snapshot contract as `DetectionEvent`.
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

### Migration guide (v1 → v2)

The v2 public surface is a breaking change; there is no compatibility
shim. Apply each of the following before upgrading.

#### 1. `DetectionEvent` field renames

```ts
// v1
manager.onDetection((e) => {
  const peer = e.resolvedDisplayId ?? e.displayId;  // 6-char hex
  // e.rpid is base64 (16 B), e.resolvedTek is base64 (16 B)
});

// v2
manager.onDetection((e) => {
  // 8 lowercase hex chars (SHA256(TEK)[0:4]), or null when B003 read
  // failed. The detection is still emitted on failure.
  const peer = e.detectedDisplayId ?? '(no B003)';
  // e.rpid is 34-char hex (17 B wire form).
  // e.enin is a number (floor(unix_seconds / 300)).
  // e.reporterRpid is 34-char hex for this device's own RPID at the
  // observation timestamp.
  // e.resolvedTek is GONE — TEK never travels on the wire in v2.
});
```

#### 2. Drop `getEventMode` / `EventMode`

```ts
// v1
const mode = await manager.getEventMode(); // { mode: 'anonymous' | 'event', eventCode?: string }

// v2
const eventCode = await manager.getCurrentEventCode(); // string | null
const joined = eventCode !== null;
```

#### 3. Remove TEK-exchange plumbing

```ts
// v1
const peerTeks = await manager.getExchangedTeks('CONF-2025'); // TekEntry[]
await manager.clearTeksForEvent('CONF-2025');
await manager.clearAllTeks();

// v2 — all three methods removed. v2 does not store peer TEKs.
// If the host app wants to disclose its OWN TEK, call exportCurrentTek:
const myTek = await manager.exportCurrentTek(); // 32-char hex
// The SDK never transmits TEK over BLE. The host app decides whether
// to upload it.
```

The `TekEntry` type is removed from `barnard` exports. Delete any
`import { TekEntry } from 'barnard'` lines.

#### 4. BarnardState field removed

```ts
// v1
if (state.eventMode === 'event') { /* joined */ }

// v2 — `eventMode` is gone; use the new eventCode field.
if (state.eventCode) { /* joined */ }
```

#### 5. RSSI-update shape

```ts
// v1
manager.onDetection(...)  // only detection stream existed.

// v2 — optional high-rate RSSI updates from cached peers.
manager.onRssiUpdate((e) => {
  // e.rpid is 34-char hex, e.detectedDisplayId may be a hex string or omitted.
  console.log('peer', e.detectedDisplayId, 'rssi', e.rssi);
});
```

#### 6. Bridge base64 → hex

If you have code that decoded `event.rpid` as base64, switch to a hex
decoder (or just keep the hex string — it round-trips fine as-is).

#### 7. New v2-only capabilities

```ts
const myDisplayId  = await manager.getMyDisplayId();     // 8-char hex
const rpiHex       = await manager.getCurrentRpi();      // 32-char hex
const enin         = await manager.getCurrentEnin();     // number
const tekHex       = await manager.exportCurrentTek();   // 32-char hex
```

See [`specs/004-resolvable-id/spec.md`](../../../../specs/004-resolvable-id/spec.md)
for the normative v2 description, and
[`schema/barnard/v2/README.md`](../../../../schema/barnard/v2/README.md)
for a concise field-rename table.

## 0.1.0

Initial v1 release of the React Native Barnard package.
