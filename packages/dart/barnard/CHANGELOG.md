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

### Migration guide (v1 → v2)

The v2 public surface is a breaking change; there is no compatibility
shim. Apply each of the following before upgrading.

#### 1. `DetectionEvent` field renames / removals

```dart
// v1
client.events.listen((e) {
  if (e is DetectionEvent) {
    final peerLabel = e.resolvedDisplayId ?? e.displayId; // 6-char hex
    final tek = e.resolvedTek;                            // Uint8List? (bytes)
    print('peer=$peerLabel rssi=${e.rssi}');
  }
});

// v2
client.events.listen((e) {
  if (e is DetectionEvent) {
    // detectedDisplayId is SHA256(TEK)[0:4] (8 hex chars) or null when
    // the B003 GATT read failed; the detection is still emitted.
    final peerLabel = e.detectedDisplayId ?? '(no B003)';
    print('peer=$peerLabel enin=${e.enin} rssi=${e.rssi}');
    // NOTE: e.resolvedTek / e.displayId / e.resolvedDisplayId no longer
    // exist. TEK is never on the wire in v2.
  }
});
```

`rpid` in v2 is the 17-byte wire form `[formatVersion(1) + RPI(16)]`.
If you previously indexed into `rpid[0..16]` as the inner RPI, switch to
`rpid.sublist(1)`.

#### 2. `myResolvedDisplayId` → `myDisplayId`

```dart
// v1
final String? myId = client.myResolvedDisplayId; // nullable, 6 hex chars

// v2
final String myId = client.myDisplayId;          // non-nullable, 8 hex chars
```

#### 3. Drop `EventMode` / `currentMode`

```dart
// v1
if (client.currentMode == EventMode.event) { /* joined */ }

// v2
if (client.currentEventCode != null) { /* joined */ }
```

#### 4. Remove TEK-exchange plumbing

```dart
// v1
final List<TekEntry> peerTeks = await client.getExchangedTeks('CONF-2025');
await client.clearTeksForEvent('CONF-2025');
await client.clearAllTeks();

// v2 — these methods no longer exist. v2 never stores peer TEKs.
// If the host app wants to disclose its OWN TEK (e.g. to a backend),
// call exportCurrentTek() explicitly:
final Uint8List myTek = await client.exportCurrentTek(); // 16 bytes
// The SDK never transmits TEK over BLE. The host app decides whether
// to upload it.
```

Delete any `import "package:barnard/src/domain/tek_storage.dart";`
lines — the file is gone.

#### 5. Bridge-side base64 → hex (only if decoding method-channel payloads manually)

The Dart parser handles this automatically; you only need to migrate if
you consume raw method-channel maps outside the SDK.

```dart
// v1
final Uint8List rpid = base64Decode(map["rpid"] as String);

// v2
import "package:barnard/barnard.dart"; // exports hexToBytes
final Uint8List rpid = hexToBytes(map["rpid"] as String);
```

#### 6. New v2-only capabilities

```dart
// 32-char hex for the inner 16-byte RPI at current ENIN
final Uint8List rpi = await client.getCurrentRpi();

// Current ENIN, useful for ENIN-aligned bucketing
final int enin = client.currentEnin;

// One-shot TEK disclosure (explicit privacy egress)
final Uint8List tek = await client.exportCurrentTek();
```

See [`specs/004-resolvable-id/spec.md`](../../../specs/004-resolvable-id/spec.md)
for the normative v2 description, and
[`schema/barnard/v2/README.md`](../../../schema/barnard/v2/README.md) for a
concise field-rename table.

## 0.0.1

Initial v1 release (not published).
