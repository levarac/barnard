import "dart:typed_data";

import "../domain/rssi.dart";
import "../domain/capabilities.dart";
import "../domain/config.dart";
import "../domain/events.dart";
import "../domain/permissions.dart";
import "../domain/state.dart";

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

  /// The active event code when joined to an event, null otherwise.
  String? get currentEventCode;

  /// This device's own v2 displayId: `SHA256(TEK)[0:4]` as 8 lowercase hex chars.
  String get myDisplayId;

  /// Current ENIN: floor(unix_seconds / 600). Computed now.
  int get currentEnin;

  Stream<BarnardEvent> get events;
  Stream<BarnardDebugEvent> get debugEvents;

  /// Returns the current platform BLE permission state without prompting.
  Future<BarnardPermissionStatus> getPermissionStatus();

  /// Requests platform BLE permissions at an app-controlled moment.
  Future<BarnardPermissionStatus> requestPermissions();

  Future<void> startScan([ScanConfig? config]);
  Future<void> stopScan();

  Future<void> startAdvertise([AdvertiseConfig? config]);
  Future<void> stopAdvertise();

  /// Starts Scan + Advertise concurrently.
  Future<BarnardStartResult> startAuto([AutoConfig? config]);
  Future<void> stopAuto();

  /// Joins an event. Regenerates TEK from DeviceSecret + [eventCode].
  Future<void> joinEvent(String eventCode);

  /// Leaves the current event. Regenerates TEK deterministically from the
  /// device secret alone (pre-event derivation).
  Future<void> leaveEvent();

  /// Inner 16-byte RPI for the current ENIN.
  ///
  /// For host-app consumption; the SDK does not transmit bare RPI — the
  /// wire form via GATT B002 is `[formatVersion(1) + RPI(16)] = 17 bytes`.
  Future<Uint8List> getCurrentRpi();

  /// Explicit privacy boundary: returns the raw 16-byte TEK.
  ///
  /// The SDK never transmits TEK over BLE. Calling this exposes the TEK
  /// to the host-app caller, which then decides whether/how to transmit
  /// it elsewhere (e.g. to a server). The SDK makes no such decision.
  Future<Uint8List> exportCurrentTek();

  // Pull APIs

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
