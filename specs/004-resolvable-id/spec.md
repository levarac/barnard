# Feature Specification: Resolvable ID

**Feature Directory**: `specs/004-resolvable-id`  
**Created**: 2026-01-22  
**Status**: In Progress  
**Issue**: [#31](https://github.com/thegreeting/barnard/issues/31)

## Problem Statement

The current RPID implementation uses simple random value rotation (`HMAC-SHA256(rpidSeed, windowIndex)`), but lacks a mechanism for **authorized parties to identify a device within an event**.

Current limitations:
- **Detection only**: We can detect "a Barnard user is nearby"
- **No identification**: We cannot determine "who it is" (event-scoped device ID)
- **No continuous tracking**: We cannot correlate "the person at 10:00 and 10:15 is the same"

Key constraint: **No global device uniqueness** - identity must be scoped to a specific event only.

## Goals

- Implement GAEN (Google/Apple Exposure Notification) v1.2 compatible key derivation
- Enable event-scoped device identification via GATT TEK exchange
- Support two modes: Anonymous Mode and Event Mode
- Maintain privacy: no device-unique persistent identifiers on-wire
- No server required for TEK exchange

## Non-goals

- Server-side TEK registry (GAEN's diagnosis key upload model)
- Daily key rotation (TEKi derivation)
- Background TEK exchange
- Cross-event device tracking (by design)

## Glossary

| Term | Definition |
|------|------------|
| **Detection** | Knowing "a Barnard user is nearby" |
| **Identification** | Knowing "this is the holder of TEK_A" (event-scoped device ID) |
| **Continuous Tracking** | Knowing "RPI at 10:00 and RPI at 10:15 belong to the same device" |
| **DeviceSecret** | 32-byte random value, generated once per device, never leaves device |
| **Event Code** | User-input string (e.g., "TECH2026") shared among event participants |
| **TEK** | Temporary Exposure Key (16 bytes), derived from DeviceSecret + Event Code |
| **RPIK** | RPI Key (16 bytes), derived from TEK |
| **RPI** | Rolling Proximity Identifier (16 bytes), rotates every 10-15 minutes |
| **ENIN** | EN Interval Number = floor(unix_timestamp / 600) |
| **displayId** | Event-scoped device ID: first 3 bytes of TEK as hex (6 chars) |

## Two Modes

| Mode | EventCodeHash | TEK Exchange | Identification | Continuous Tracking |
|------|---------------|--------------|----------------|---------------------|
| **Anonymous Mode** | Empty (0 bytes) | No | No | No |
| **Event Mode** | 8 bytes | Yes | Yes | Yes |

### Anonymous Mode

- Default mode when no Event Code is set
- RPI generation uses GAEN algorithm with a deterministic TEK derived from DeviceSecret
- Other devices can detect presence but cannot identify or track
- Privacy-first for users who don't want to be identifiable

### Event Mode

- Activated when user joins an event with an Event Code
- TEK derived from DeviceSecret + Event Code
- TEK exchanged via GATT with other Event Mode participants
- Enables identification and continuous tracking within event scope

## Key Derivation (GAEN v1.2 Compatible)

```
DeviceSecret (32 bytes, device-generated, never transmitted)
     │
     ├── Anonymous Mode (no Event Code)
     │   └── TEK = HKDF-SHA256(DeviceSecret, info="barnard-tek-anonymous", length=16)
     │
     └── Event Mode (Event Code present)
         │
         ▼
    TEK = HKDF-SHA256(DeviceSecret ‖ EventCode, info="barnard-tek", length=16)
         │
         ▼
    RPIK = HKDF-SHA256(TEK, info="EN-RPIK", length=16)
         │
         ▼
    RPI = AES128-ECB(RPIK, PaddedData)
    
    where PaddedData = "EN-RPI" (6 bytes) ‖ 0x000000000000 (6 bytes) ‖ ENIN (4 bytes, big-endian)
```

### ENIN Calculation

```
ENIN = floor(unix_timestamp_seconds / 600)
```

Each ENIN represents a 10-minute interval. RPI rotates at ENIN boundaries.

### EventCodeHash Calculation

```
EventCodeHash = SHA256(EventCode)[0:8]  // First 8 bytes
```

Used to verify same-event participation before TEK exchange.

## GATT Service Specification

### Service and Characteristic UUIDs

| Name | UUID | Notes |
|------|------|-------|
| Discovery Service | `0000B001-0000-1000-8000-00805F9B34FB` | Existing |
| RPID Characteristic | `0000B002-0000-1000-8000-00805F9B34FB` | Existing |
| TEK Characteristic | `0000B003-0000-1000-8000-00805F9B34FB` | **New** |
| EventCodeHash Characteristic | `0000B004-0000-1000-8000-00805F9B34FB` | **New** |

### Characteristic Details

#### RPID Characteristic (existing, unchanged)

- **Properties**: Read
- **Value**: `[formatVersion(1 byte) + RPI(16 bytes)]` = 17 bytes
- **formatVersion**: `1` (unchanged)

#### TEK Characteristic (new)

- **Properties**: Read, Write
- **Value**: `[TEK(16 bytes)]` = 16 bytes
- **Behavior**:
  - Read: Returns this device's TEK (only in Event Mode)
  - Write: Stores the remote device's TEK
- **Access Control**: Only accessible when EventCodeHash matches

#### EventCodeHash Characteristic (new)

- **Properties**: Read
- **Value**: `[SHA256(EventCode)[0:8]]` = 8 bytes, or empty (0 bytes) in Anonymous Mode
- **Purpose**: Verify same-event participation before TEK exchange

## GATT Exchange Flow

### Case 1: Both in Event Mode (Same Event)

```
Central (B)                    Peripheral (A)
    │                              │
    │◄── Advertisement ────────────│  (Service UUID only)
    │──── GATT Connect ───────────►│
    │                              │
    │──── EventCodeHash Read ─────►│
    │◄─── [hash_A = 8 bytes] ──────│
    │                              │
    │   hash_A == hash_B? → YES    │
    │                              │
    │──── RPID Read ──────────────►│
    │◄─── [ver + RPI_A] ───────────│
    │                              │
    │──── TEK Read ───────────────►│
    │◄─── [TEK_A] ─────────────────│
    │                              │
    │──── TEK Write ──────────────►│
    │     [TEK_B] ─────────────────►│
    │                              │
    │◄─── Disconnect ──────────────│
```

**Result**: Both devices store each other's TEK → Identification & continuous tracking enabled

### Case 2: Both in Event Mode (Different Events)

```
Central (B)                    Peripheral (A)
    │                              │
    │──── EventCodeHash Read ─────►│
    │◄─── [hash_A = 8 bytes] ──────│
    │                              │
    │   hash_A == hash_B? → NO     │
    │                              │
    │──── RPID Read ──────────────►│  (detection only)
    │◄─── [ver + RPI_A] ───────────│
    │                              │
    │   (skip TEK exchange)        │
    │                              │
    │◄─── Disconnect ──────────────│
```

**Result**: Detection only, no TEK exchange

### Case 3: Either in Anonymous Mode

```
Central (B)                    Peripheral (A)
    │                              │
    │──── EventCodeHash Read ─────►│
    │◄─── [empty = 0 bytes] ───────│  ← A is Anonymous
    │                              │
    │   A is Anonymous → skip TEK  │
    │                              │
    │──── RPID Read ──────────────►│
    │◄─── [ver + RPI_A] ───────────│
    │                              │
    │   (skip TEK exchange)        │
    │                              │
    │◄─── Disconnect ──────────────│
```

**Result**: Detection only, Anonymous party's privacy preserved

## TEK Storage Specification

### Storage Structure

```
TEK Storage Entry:
├── tek: 16 bytes (primary key)
├── eventCodeHash: 8 bytes
├── exchangedAt: timestamp (when TEK was received)
├── lastSeenAt: timestamp (updated on successful RPI resolution)
└── ttl: configurable (default 24 hours)
```

### Eviction Policy

```
if (now - lastSeenAt > ttl):
    delete entry
```

Eviction runs periodically (e.g., on app launch, every hour).

### Re-exchange Behavior

| Case | Condition | Action |
|------|-----------|--------|
| **First exchange** | TEK not in storage | Save new entry |
| **Re-exchange (same TEK)** | TEK already exists | Update `lastSeenAt` |
| **Re-exchange (different TEK)** | Same peer, different TEK | Add as new entry |

### Storage Limits

- **maxEntries**: 1000 (configurable)
- **Eviction**: LRU when limit exceeded

### Platform Implementation

- **iOS**: UserDefaults (JSON-encoded array)
- **Android**: SharedPreferences (JSON-encoded array)

## Identification Algorithm

```python
def resolve_rpi(received_rpi: bytes, known_teks: List[bytes], current_enin: int) -> Optional[Match]:
    """
    Attempt to resolve a received RPI to a known TEK.
    
    Args:
        received_rpi: 16-byte RPI from remote device
        known_teks: List of TEKs from exchanged peers
        current_enin: Current EN Interval Number
    
    Returns:
        Match object with tek and display_id if resolved, None otherwise
    """
    for tek in known_teks:
        rpik = hkdf_sha256(tek, info=b"EN-RPIK", length=16)
        
        # Search within ±1 hour window (±6 intervals)
        for enin in range(current_enin - 6, current_enin + 2):
            padded_data = b"EN-RPI" + b"\x00" * 6 + enin.to_bytes(4, 'big')
            candidate_rpi = aes128_ecb_encrypt(rpik, padded_data)
            
            if candidate_rpi == received_rpi:
                display_id = tek[:3].hex()  # First 3 bytes as hex
                return Match(tek=tek, display_id=display_id, enin=enin)
    
    return None
```

### Performance Considerations

- **Lookup complexity**: O(known_teks × enin_window) = O(N × 8)
- **Optimization**: Pre-compute RPIK for all known TEKs on storage load
- **Caching**: Cache recent (RPI, TEK) resolutions to avoid repeated computation

## Barnard Library Interface

### Configuration

```dart
class BarnardConfig {
  const BarnardConfig({
    this.transport = TransportKind.ble,
    this.eventCode,  // null for Anonymous Mode
    this.tekStorage = const TekStorageConfig(),
    // ... existing fields
  });
  
  final String? eventCode;
  final TekStorageConfig tekStorage;
}

class TekStorageConfig {
  const TekStorageConfig({
    this.ttlSeconds = 86400,  // 24 hours
    this.maxEntries = 1000,
  });
  
  final int ttlSeconds;
  final int maxEntries;
}
```

### Client API

```dart
abstract class BarnardClient {
  // Existing methods...
  
  /// Join an event, switching to Event Mode.
  /// Derives TEK from DeviceSecret + eventCode.
  Future<void> joinEvent(String eventCode);
  
  /// Leave the current event, switching to Anonymous Mode.
  Future<void> leaveEvent();
  
  /// Current operating mode.
  EventMode get currentMode;
  
  /// List all exchanged TEKs (for debugging/UI).
  Future<List<ExchangedTek>> getExchangedTeks();
  
  /// Clear TEKs for a specific event.
  Future<void> clearTeksForEvent(String eventCode);
  
  /// Clear all stored TEKs.
  Future<void> clearAllTeks();
}

enum EventMode { anonymous, event }

class ExchangedTek {
  final Uint8List tek;
  final String displayId;  // TEK[0:3] as hex (6 chars)
  final Uint8List eventCodeHash;
  final DateTime exchangedAt;
  final DateTime lastSeenAt;
}
```

### Detection Event Extension

```dart
class DetectionEvent extends BarnardEvent {
  // Existing fields...
  
  /// TEK of the resolved peer (null if not resolved).
  final Uint8List? resolvedTek;
  
  /// Display ID of the resolved peer (null if not resolved).
  /// Format: first 3 bytes of TEK as lowercase hex (6 chars).
  final String? resolvedDisplayId;

  /// Debug-only local name observed in advertisements, if present.
  /// May be omitted in release builds.
  final String? debugLocalName;
}
```

## Concrete Example

### Setup

```
Event Code: "TECH2026"

Device A:
  DeviceSecret_A: 0x1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF
  TEK_A = HKDF(DeviceSecret_A ‖ "TECH2026", info="barnard-tek", 16)
        = 0x7A3F8B2C91D4E6F0A2B5C8D1E4F7A0B3
  displayId_A = "7a3f8b"

Device B:
  DeviceSecret_B: 0xABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789
  TEK_B = HKDF(DeviceSecret_B ‖ "TECH2026", info="barnard-tek", 16)
        = 0x4E2D9A1BF8C7E6D5A4B3C2D1E0F9A8B7
  displayId_B = "4e2d9a"

EventCodeHash = SHA256("TECH2026")[0:8] = 0x9F8E7D6C5B4A3928
```

### GATT Exchange

```
1. B connects to A
2. B reads EventCodeHash from A → 0x9F8E7D6C5B4A3928
3. B compares with own hash → Match!
4. B reads RPID from A → [0x01, RPI_A...]
5. B reads TEK from A → 0x7A3F8B2C91D4E6F0A2B5C8D1E4F7A0B3
6. B writes TEK_B to A → 0x4E2D9A1BF8C7E6D5A4B3C2D1E0F9A8B7
7. Disconnect
```

### After Exchange

```
Device A's TEK Storage:
  └── { tek: TEK_B, displayId: "4e2d9a", eventCodeHash: 0x9F8E..., exchangedAt: ..., lastSeenAt: ... }

Device B's TEK Storage:
  └── { tek: TEK_A, displayId: "7a3f8b", eventCodeHash: 0x9F8E..., exchangedAt: ..., lastSeenAt: ... }
```

### Later Detection

```
Time: 10:15 AM, ENIN = 2948599

Device B receives RPI from advertisement, connects, reads RPID characteristic:
  RPI = 0x2C5E8A1F7B4D9C3E6A2F8D1B5C7E4A9F

Resolution by Device B:
  for tek in [TEK_A]:
    rpik = HKDF(TEK_A, info="EN-RPIK", 16) = 0x91B2C3D4E5F6A7B8C9D0E1F2A3B4C5D6
    for enin in [2948593..2948600]:
      candidate = AES128(rpik, "EN-RPI" ‖ 0x000000000000 ‖ enin)
      if enin == 2948599:
        candidate == received_rpi → Match!
        
Result: DetectionEvent with:
  - rpid: RPI
  - displayId: "2c5e8a1f" (from RPI, for non-resolved display)
  - resolvedTek: TEK_A
  - resolvedDisplayId: "7a3f8b" (from TEK_A)
```

## Security & Privacy Analysis

| Property | Status | Notes |
|----------|--------|-------|
| No device-unique persistent identifiers on-wire | ✓ | RPI rotates every 10-15 min |
| No cross-event tracking | ✓ | Different TEK per event |
| Third-party unlinkability | ✓ | RPI appears random without RPIK |
| Event Code leak safety | ✓ | TEK requires DeviceSecret (never shared) |
| Minimum privilege | ✓ | Only GATT-exchanged peers can identify |

### Replay Attack Protection

- **ENIN window**: Only accept RPIs within ±1 hour of current time
- **Duplicate detection**: Cache seen (RPI, timestamp) pairs, reject exact duplicates
- **Cache bounds**: TTL = 2 hours, max = 10000 entries (LRU eviction)

### EventCodeHash Collision

- **Probability**: 8 bytes = 64 bits → ~10^19 possible values
- **Impact**: If collision occurs, TEK exchange proceeds but identification fails
- **Mitigation**: Acceptable for practical use; no security impact

## Compatibility

### With Existing Implementation

- **formatVersion**: Remains `1` (internal logic change only)
- **RPID Characteristic**: Unchanged (17 bytes: version + RPI)
- **Advertisement**: Unchanged (Service UUID only)
- **Backward compatibility**: None required (development phase)

### With GAEN v1.2

- **Key derivation**: Compatible (HKDF-SHA256, AES-128)
- **RPI format**: Compatible (16 bytes, ENIN-based rotation)
- **Differences**:
  - GAEN uses daily TEK rotation; Barnard uses event-scoped TEK
  - GAEN uses server for TEK distribution; Barnard uses GATT exchange

## Test Plan

### Unit Tests

1. **Key derivation tests** (`test/crypto_test.dart`)
   - HKDF-SHA256 output matches expected values
   - AES-128-ECB encryption matches expected values
   - TEK derivation is deterministic for same inputs
   - RPIK derivation is deterministic
   - RPI generation matches GAEN spec

2. **TEK storage tests** (`test/tek_storage_test.dart`)
   - Add/retrieve TEK entries
   - TTL-based eviction
   - LRU eviction when limit exceeded
   - Re-exchange updates lastSeenAt
   - Event-specific clearing

3. **Identifier tests** (`test/identifier_test.dart`)
   - Resolve RPI to known TEK
   - Handle unknown RPI (no match)
   - ENIN window boundaries
   - Multiple known TEKs

### Integration Tests

4. **GATT exchange tests** (`test/gatt_exchange_integration_test.dart`)
   - Same event: full TEK exchange
   - Different event: detection only
   - Anonymous mode: detection only
   - Re-exchange: lastSeenAt update

## References

- [GAEN Cryptography Specification v1.2](https://blog.google/documents/69/Exposure_Notification_-_Cryptography_Specification_v1.2.1.pdf)
- [Wikipedia: Exposure Notification](https://en.wikipedia.org/wiki/Exposure_Notification)
- [DP-3T Protocol](https://github.com/DP-3T/documents)
- HKDF (RFC 5869)
- AES-128 (FIPS 197)
