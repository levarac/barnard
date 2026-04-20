# Feature Spec 004 — Resolvable ID v2

**Issue:** [#42](https://github.com/thegreeting/barnard/issues/42)
**Ancestor:** [#31](https://github.com/thegreeting/barnard/issues/31), [spec 003](../003-flutter-poc-real-ble/spec.md)
**Status:** Implemented in `feature/42-barnard-v2`.

## 1. Problem with v1

Resolvable ID v1 had two hard-to-fix problems:

1. **TEK exchanged over BLE.** The GATT flow was *RPID read → EventCodeHash read → TEK read → TEK write*. Whoever could observe either direction of the exchange had access to the other device's TEK, which is equivalent to unmasking every RPID that device would ever broadcast under that event. Whether two devices in the same event "really" belonged there was decided by a client-side hash match (EventCodeHash, `SHA256(EventCode)[0:8]`), but nothing stopped a hostile client from simulating the hash check and completing the exchange anyway.
2. **displayId collisions at modest crowd sizes.** v1 used `TEK[0:3]` (3 bytes, 6 hex chars). Birthday bound in a 24-bit space exceeds 50% collision probability around 4,800 distinct TEKs — well inside real-world event scale.

The rest of the v1 design (GAEN-compatible HKDF/AES chain, RPID rotation, fixed service UUID for iOS background discovery) stays sound. v2 only replaces the broken parts.

## 2. v2 design principles

1. **TEK never transmitted over BLE.** The SDK refuses every path that would send TEK over the wire.
2. **B003 carries `displayId = SHA256(TEK)[0:4]`.** Read-only, 4 bytes. 32-bit space → birthday bound ~0.05% collision at 2,000 distinct TEKs (`p ≈ 1 − exp(−n(n−1)/2 / 2³²)` for `n = 2000` gives `p ≈ 4.7 × 10⁻⁴`).
3. **Fixed service UUID.** Not dynamic per-event. iOS background scan requires the service UUID to be pinned into `scanForPeripherals(withServices:)`; dynamic UUIDs break background discovery. Event scoping is done at a higher layer via B004 (EventCodeHash) and out-of-band event membership.
4. **Detection is event-scoped at the consumer.** B004 still exposes `EventCodeHash` so consumers that want to filter "same-event" can. The SDK itself does not filter; it always emits a `DetectionEvent` on any successful RPID read.
5. **Explicit TEK egress.** The host app can request the raw TEK via `exportCurrentTek()`. The SDK never transmits it; the host app decides if/when to send it to a backend.

## 3. Glossary

| Term | Description |
|------|-------------|
| DeviceSecret | Random 32 bytes, device-unique, never transmitted. |
| TEK | Temporary Exposure Key. 16 bytes. HKDF-derived from DeviceSecret (+ optional EventCode). |
| RPIK | Rolling Proximity Identifier Key. 16 bytes. `HKDF(TEK, "EN-RPIK", 16)`. |
| RPI | Rolling Proximity Identifier. 16 bytes. `AES-128-ECB(RPIK, paddedData(enin))`. Rotates per ENIN. |
| RPID (wire form) | `[formatVersion(1) + RPI(16)] = 17 bytes`. Served by B002 and emitted as `rpid` / `reporterRpid` fields. |
| ENIN | Exposure Notification Interval Number. `floor(unix_seconds / 600)`. One ENIN per 10-minute window. |
| displayId (v2) | `SHA256(TEK)[0:4] = 4 bytes`, 8 lowercase hex chars. Served by B003. |
| EventCodeHash | `SHA256(EventCode)[0:8] = 8 bytes`. Served by B004. Empty when no event is joined. |
| formatVersion | Protocol version byte, currently `1`. |

## 4. Cryptographic chain

```
DeviceSecret (32 B)
    │
    ├── no event:     TEK = HKDF(DeviceSecret, info="barnard-tek-anonymous", 16)
    └── event joined: TEK = HKDF(DeviceSecret || EventCode, info="barnard-tek", 16)
        │
        └── RPIK = HKDF(TEK, info="EN-RPIK", 16)
            │
            └── RPI(enin) = AES128-ECB(RPIK, "EN-RPI" || 0x000000000000 || ENIN_be32)

displayId = SHA256(TEK)[0:4]       // 4 bytes, 8 hex chars
```

HKDF salt is 32 zero bytes (RFC 5869 §2.2). AES-ECB is appropriate here because the plaintext is a single 16-byte block per ENIN and uniqueness comes from the ENIN counter, not IV nonces (GAEN v1.2 convention).

## 5. GATT service

Service UUID: `0000B001-0000-1000-8000-00805F9B34FB`.

| UUID | Role | Properties | Value | Length |
|------|------|------------|-------|--------|
| `0000B002-…` | RPID | Read | `[formatVersion + RPI(enin_now)]` | 17 B |
| `0000B003-…` | displayId | Read | `SHA256(TEK)[0:4]` | 4 B |
| `0000B004-…` | EventCodeHash | Read | `SHA256(EventCode)[0:8]` when joined, empty otherwise | 0 or 8 B |

**v2 has no Write characteristics.** Any inbound write request is rejected with `.writeNotPermitted` (iOS) / `GATT_WRITE_NOT_PERMITTED` (Android).

### 5.1 GATT exchange flow

```
Central                                   Peripheral
   │ ── connect ─────────────────────────▶ │
   │ ◀───── services/chars discovered ─── │
   │                                       │
   │ ── read B004 (EventCodeHash) ──────▶ │
   │ ◀──── 0 or 8 bytes ─────────────── │
   │                                       │
   │ ── read B002 (RPID wire form) ─────▶ │
   │ ◀──── 17 bytes ─────────────────── │
   │                                       │
   │ ── read B003 (displayId) ──────────▶ │
   │ ◀──── 4 bytes ──────────────────── │   (or error → see §5.2)
   │                                       │
   │ ── disconnect ─────────────────────▶ │
   │                                       │
   Central emits DetectionEvent with
   rpid, reporterRpid, enin, rssi,
   detectedDisplayId = hex(B003).
```

### 5.2 B003 read-failure policy

If B002 succeeds but the subsequent B003 read fails (timeout, error, missing characteristic, invalid length), the central side **still emits a `DetectionEvent`** with `detectedDisplayId = null`. Consumers always see the detection.

A debug event with name `gatt_b003_read_failed` (error path) or `gatt_b003_missing` / `gatt_b003_invalid_length` accompanies the detection for diagnostics.

If B002 itself fails, no detection is emitted (no identifier available).

## 6. `DetectionEvent` (v2)

```
{
  "type": "detection",
  "timestamp": "2026-04-20T10:00:00.000Z",
  "transport": "ble",
  "formatVersion": 1,
  "rpid":          "01<32 hex>",           // 17 B wire form of the detected peer
  "reporterRpid":  "01<32 hex>",           // 17 B wire form of this device at `timestamp`
  "detectedDisplayId": "9abcdef0" | null,  // 8 hex chars or null (B003 read failed)
  "enin": 2948599,                          // floor(unix_s / 600) at `timestamp`
  "rssi": -62,
  "rssiSummary": null | { count, min, max, mean },
  "payloadRaw":    "01<32 hex>",           // same 17 B as rpid, for consumers that want raw
  "debugLocalName": "…" | null             // debug builds only
}
```

**Atomic reporter snapshot.** Native layers compute `enin` and `reporterRpid` from the **same observation `timestamp`**. The pair is coherent across ENIN rotation boundaries.

**Byte-vs-hex.** At the Dart method-channel / RN bridge boundary, byte-valued fields are **lowercase hex strings**. Native layers use raw `Data`/`ByteArray` internally. Dart public-API return types re-decode to `Uint8List` for ergonomics.

## 7. SDK public API

### 7.1 Dart (`BarnardClient`)

```dart
abstract class BarnardClient {
  BarnardCapabilities get capabilities;
  BarnardState get state;

  String? get currentEventCode;
  String get myDisplayId;       // 8 lowercase hex chars (SHA256(TEK)[0:4])
  int    get currentEnin;

  Stream<BarnardEvent> get events;
  Stream<BarnardDebugEvent> get debugEvents;

  Future<void> startScan([ScanConfig? config]);
  Future<void> stopScan();
  Future<void> startAdvertise([AdvertiseConfig? config]);
  Future<void> stopAdvertise();
  Future<BarnardStartResult> startAuto([AutoConfig? config]);
  Future<void> stopAuto();

  Future<void> joinEvent(String eventCode);
  Future<void> leaveEvent();

  Future<Uint8List> getCurrentRpi();      // 16 bytes
  Future<Uint8List> exportCurrentTek();   // 16 bytes, explicit privacy egress

  Future<void> dispose();
}
```

### 7.2 React Native (`BarnardManager`)

```ts
class BarnardManager {
  getCapabilities(): Promise<BarnardCapabilities>;
  getState(): Promise<BarnardState>;
  getCurrentEventCode(): Promise<string | null>;
  getMyDisplayId(): Promise<string>;            // 8 hex chars
  getCurrentRpi(): Promise<string>;             // 32 hex chars
  getCurrentEnin(): Promise<number>;
  exportCurrentTek(): Promise<string>;          // 32 hex chars, privacy egress

  startScan / stopScan / startAdvertise / stopAdvertise /
    startAuto / stopAuto / joinEvent / leaveEvent / dispose;

  onDetection / onRssiUpdate / onStateChange /
    onConstraint / onError / onDebug / onEvent;
}
```

### 7.3 TEK disclosure boundary

`exportCurrentTek()` is the sole TEK egress path. The SDK does not transmit TEK over BLE, IP, or any other transport. What the host app does with the returned bytes is the host app's responsibility.

Host apps are expected to document to end-users (a) when TEK is disclosed, (b) to which party, and (c) for what purpose. The SDK makes no claims on behalf of the host about such disclosure.

## 8. Byte serialization at the bridge

| Field | Native type | Bridge type (Dart channel / RN bridge) | Length |
|-------|-------------|-----------------------------------------|--------|
| `rpid`, `reporterRpid`, `payloadRaw` | bytes | lowercase hex string | 34 chars (17 B) |
| `detectedDisplayId` | bytes \| null | lowercase hex string \| null | 8 chars (4 B) or null |
| `getCurrentRpi` result | bytes | hex string (Dart: decoded to `Uint8List`) | 32 chars (16 B) |
| `exportCurrentTek` result | bytes | hex string (Dart: decoded to `Uint8List`) | 32 chars (16 B) |
| `enin`, `rssi`, `formatVersion` | int | int | — |
| `timestamp` | Date | ISO 8601 string | — |
| `transport` | enum | string `"ble"` | — |

Strict validation: malformed or wrong-length hex at the Dart parser boundary raises `FormatException`.

## 9. Attack vectors and mitigations

| Vector | v1 behaviour | v2 behaviour |
|--------|--------------|--------------|
| Passive BLE sniffer | Can extract TEK via GATT read (even without event code). | TEK never on wire. Sniffer sees RPID and 4-byte displayId only. |
| Active GATT write | Can inject TEK entries into peer storage. | No writable characteristics. Writes are rejected. |
| On-device peer TEK extraction by hostile app | Plugin exposed exchanged TEK store. | No TEK store. `exportCurrentTek()` returns **own** TEK only. |
| displayId collision at scale | 3 bytes → ~50% at ~4.8k users. | 4 bytes → ~0.05% at 2k, ~11% at 25k. Acceptable for same-event disambiguation at realistic scale. |
| Cross-event linkability | TEK pinned to (DeviceSecret, EventCode). Leaving one event and joining another regenerates TEK. | Unchanged. TEK egress is explicit per `exportCurrentTek()` call. |
| RPI replay outside ENIN window | RPI is valid only for one ENIN (10 min). | Unchanged. |

## 10. Non-normative: server-report projection example

An operator wishing to receive proximity reports on a backend might project v2 DetectionEvents into a record like:

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

This is **not** part of the Barnard schema. Consumers customise the projection and the upload path per product.

## 11. Changes from v1

### Removed
- TEK on-wire transmission (Read+Write on B003).
- TEK storage (`BarnardTekStorage` on both platforms, `tek_storage.dart` on Dart side).
- On-device peer-RPI resolution (`resolveRpi`, `tryResolveRpi`).
- `DetectionEvent.resolvedTek`, `resolvedDisplayId`, v1 `displayId`.
- `EventMode` enum, `currentMode`, `myResolvedDisplayId`, `getExchangedTeks`, `clearTeksForEvent`, `clearAllTeks`.
- "eventMode" key on state events.

### Added
- B003 serves 4-byte `SHA256(TEK)[0:4]`, Read-only.
- `DetectionEvent.enin`, `reporterRpid`, `detectedDisplayId` (nullable).
- `BarnardClient.myDisplayId`, `currentEnin`, `getCurrentRpi()`, `exportCurrentTek()`.
- Lowercase-hex at the bridge boundary (was base64 in v1).
- Atomic reporter RPID + ENIN snapshot.

### Compatibility
- **v1 ⇄ v2 BLE interoperability is not supported.** A v1 peer attempts a TEK Write on B003, which a v2 peripheral rejects; a v2 peer expects 4 bytes on B003, which a v1 peripheral cannot provide.
- Existing host apps must migrate to the new API surface (no shim).

## 12. References

- GAEN Cryptography Spec v1.2 — https://covid19-static.cdn-apple.com/applications/covid19/current/static/contact-tracing/pdf/ExposureNotification-CryptographySpecificationv1.2.pdf
- RFC 5869 (HKDF) — https://datatracker.ietf.org/doc/html/rfc5869
- FIPS 197 (AES) — https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf
- Barnard issue #42 (this spec's primary source) — https://github.com/thegreeting/barnard/issues/42
