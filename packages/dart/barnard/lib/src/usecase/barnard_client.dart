import "../domain/rssi.dart";
import "../domain/capabilities.dart";
import "../domain/config.dart";
import "../domain/events.dart";
import "../domain/state.dart";
import "../domain/tek_storage.dart";

/// Operating mode for the Barnard client.
enum EventMode {
  /// Anonymous mode: detections only, no identification.
  /// TEK is randomly generated and not exchanged.
  anonymous,

  /// Event mode: identification and tracking enabled.
  /// TEK is derived from DeviceSecret + EventCode, exchanged with peers
  /// that have matching EventCodeHash.
  event,
}

class BarnardStartResult {
  const BarnardStartResult({
    required this.scanningStarted,
    required this.advertisingStarted,
    required this.issues,
  });

  final bool scanningStarted;
  final bool advertisingStarted;
  final List<BarnardIssue> issues;
}

class BarnardIssue {
  const BarnardIssue({
    required this.severity,
    required this.code,
    this.message,
  });

  final BarnardIssueSeverity severity;
  final String code;
  final String? message;
}

enum BarnardIssueSeverity { info, warn, error }

abstract class BarnardClient {
  BarnardCapabilities get capabilities;
  BarnardState get state;

  /// Current operating mode: anonymous or event.
  EventMode get currentMode;

  /// The active event code when in Event Mode, null otherwise.
  String? get currentEventCode;

  Stream<BarnardEvent> get events;
  Stream<BarnardDebugEvent> get debugEvents;

  Future<void> startScan([ScanConfig? config]);
  Future<void> stopScan();

  Future<void> startAdvertise([AdvertiseConfig? config]);
  Future<void> stopAdvertise();

  /// Starts Scan + Advertise concurrently.
  ///
  /// Implementations should represent partial success via events and/or the
  /// returned result.
  Future<BarnardStartResult> startAuto([AutoConfig? config]);
  Future<void> stopAuto();

  // ─────────────────────────────────────────────────────────────────────────
  // Event Mode APIs
  // ─────────────────────────────────────────────────────────────────────────

  /// Joins an event, switching from Anonymous to Event Mode.
  ///
  /// [eventCode] is the shared event code (e.g., "CONF2025-HALL-A").
  /// This triggers:
  /// 1. TEK derivation from DeviceSecret + eventCode
  /// 2. EventCodeHash calculation (first 8 bytes of SHA256)
  /// 3. RPID generation using GAEN-compatible derivation
  /// 4. TEK exchange with peers having matching EventCodeHash
  ///
  /// Throws [StateError] if already in Event Mode.
  Future<void> joinEvent(String eventCode);

  /// Leaves the current event, switching back to Anonymous Mode.
  ///
  /// This triggers:
  /// 1. TEK regeneration (random)
  /// 2. EventCodeHash cleared (empty)
  /// 3. Stored TEKs for this event are retained until explicitly cleared
  ///
  /// Throws [StateError] if not in Event Mode.
  Future<void> leaveEvent();

  /// Returns all exchanged TEKs for the specified event code.
  ///
  /// Each [TekEntry] contains the TEK bytes, timestamp, and optional metadata.
  /// Returns empty list if no TEKs stored for this event.
  Future<List<TekEntry>> getExchangedTeks(String eventCode);

  /// Clears all stored TEKs for the specified event code.
  ///
  /// Returns the number of entries removed.
  Future<int> clearTeksForEvent(String eventCode);

  /// Clears all stored TEKs across all events.
  ///
  /// Returns the number of entries removed.
  Future<int> clearAllTeks();

  // ─────────────────────────────────────────────────────────────────────────
  // Pull APIs
  // ─────────────────────────────────────────────────────────────────────────

  /// Pull: read the in-memory debug buffer snapshot.
  List<BarnardDebugEvent> getDebugBuffer({int? limit});

  /// Pull: read RSSI time-series samples from the in-memory buffer.
  List<RssiSample> getRssiSamples({
    DateTime? since,
    int? limit,
    List<int>? rpidBytes,
  });

  Future<void> dispose();
}
