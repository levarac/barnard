import "config.dart";
import "transport.dart";

class BarnardCapabilities {
  const BarnardCapabilities({
    required this.supportedTransports,
    required this.supportsConnectionlessRpid,
    required this.supportsGattFallback,
    required this.supportsBackground,
    required this.supportsHighRateRssi,
    this.eninMode = EninMode.fixedLength,
    this.eninSeconds = 120,
    this.beaconChain = BeaconChainConfig.ethereumMainnet,
  });

  final Set<TransportKind> supportedTransports;

  /// Whether this Transport can carry `rpid` without connecting (connectionless).
  final bool supportsConnectionlessRpid;

  /// Whether this Transport supports an optional GATT-like connection fallback.
  final bool supportsGattFallback;

  /// Whether background operation is supported by the implementation.
  final bool supportsBackground;

  /// Whether this implementation can produce high-rate RSSI observations.
  final bool supportsHighRateRssi;

  /// ENIN mode currently used by this implementation.
  final EninMode eninMode;

  /// Effective fixed-length ENIN window when [eninMode] is [EninMode.fixedLength].
  final int eninSeconds;

  /// Beacon Chain timing parameters when [eninMode] is [EninMode.beaconSlot].
  final BeaconChainConfig beaconChain;
}
