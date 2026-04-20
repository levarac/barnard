import "dart:typed_data";

import "package:meta/meta.dart";

import "rssi.dart";
import "state.dart";
import "transport.dart";

@immutable
sealed class BarnardEvent {
  const BarnardEvent({required this.timestamp});

  final DateTime timestamp;
}

/// v2 Detection event.
///
/// Emitted after a successful GATT exchange with a nearby peer.
///
/// - [rpid]: 17-byte wire form `[formatVersion(1) + RPI(16)]`.
/// - [reporterRpid]: 17-byte wire form of this device's own RPID at the
///   moment of the observation.
/// - [detectedDisplayId]: 8-char lowercase hex, `SHA256(peerTEK)[0:4]`, or
///   `null` when the B003 read failed (per v2 policy: detection is still
///   emitted on B003 failure).
/// - [enin]: ENIN (Exposure Notification Interval Number) at observation time.
final class DetectionEvent extends BarnardEvent {
  const DetectionEvent({
    required super.timestamp,
    required this.transport,
    required this.formatVersion,
    required this.rpid,
    required this.reporterRpid,
    required this.detectedDisplayId,
    required this.rssi,
    required this.enin,
    this.rssiSummary,
    this.payloadRaw,
    this.debugLocalName,
  });

  final Uint8List rpid;
  final Uint8List reporterRpid;
  final String? detectedDisplayId;
  final int rssi;
  final int enin;
  final TransportKind transport;
  final int formatVersion;

  /// Optional aggregation summary for push streams.
  final RssiSummary? rssiSummary;

  /// Optional raw payload bytes as observed (if available).
  final Uint8List? payloadRaw;

  /// Debug-only local name of the peer, if present in advertisements.
  final String? debugLocalName;
}

final class StateEvent extends BarnardEvent {
  const StateEvent({
    required super.timestamp,
    required this.state,
    this.reasonCode,
  });

  final BarnardState state;
  final String? reasonCode;
}

final class ConstraintEvent extends BarnardEvent {
  const ConstraintEvent({
    required super.timestamp,
    required this.code,
    this.message,
    this.requiredAction,
  });

  final String code;
  final String? message;
  final String? requiredAction;
}

final class ErrorEvent extends BarnardEvent {
  const ErrorEvent({
    required super.timestamp,
    required this.code,
    required this.message,
    this.recoverable,
  });

  final String code;
  final String message;
  final bool? recoverable;
}

/// High-frequency RSSI update event for known peers.
///
/// Emitted on each BLE scan without requiring a GATT connection. The
/// [detectedDisplayId] is only populated when it has been cached from a
/// prior GATT exchange with the same peer; otherwise it is `null`.
final class RssiUpdateEvent extends BarnardEvent {
  const RssiUpdateEvent({
    required super.timestamp,
    required this.rpid,
    required this.rssi,
    this.detectedDisplayId,
  });

  /// The 17-byte RPID wire form `[formatVersion(1) + RPI(16)]`.
  final Uint8List rpid;

  /// Signal strength in dBm.
  final int rssi;

  /// v2 displayId (8-char lowercase hex) if cached from a prior GATT read,
  /// else null.
  final String? detectedDisplayId;
}

@immutable
sealed class BarnardDebugEvent {
  const BarnardDebugEvent({
    required this.timestamp,
    required this.level,
    required this.name,
    this.data,
  });

  final DateTime timestamp;
  final DebugLevel level;
  final String name;
  final Map<String, Object?>? data;
}

enum DebugLevel { trace, info, warn, error }

final class DebugEvent extends BarnardDebugEvent {
  const DebugEvent({
    required super.timestamp,
    required super.level,
    required super.name,
    super.data,
  });
}
