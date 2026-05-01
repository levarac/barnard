import "transport.dart";

class BarnardConfig {
  const BarnardConfig({
    this.transport = TransportKind.ble,
    this.eventCode,
    this.eninMode = EninMode.fixedLength,
    this.eninSeconds = 600,
    this.beaconChain = BeaconChainConfig.ethereumMainnet,
    this.rpid = const RpidConfig(),
    this.rssi = const RssiConfig(),
    this.connect = const ConnectConfig(),
  });

  final TransportKind transport;

  /// Optional event code. In v2, joining an event rederives TEK from
  /// `HKDF(DeviceSecret || EventCode, "barnard-tek")`; TEK is never
  /// transmitted over BLE.
  final String? eventCode;

  /// ENIN derivation mode. Defaults to GAEN-compatible fixed-length windows.
  final EninMode eninMode;

  /// Fixed-length ENIN window in seconds. Effective value is clamped to 12..3600.
  final int eninSeconds;

  /// Beacon Chain timing parameters used when [eninMode] is [EninMode.beaconSlot].
  final BeaconChainConfig beaconChain;

  final RpidConfig rpid;
  final RssiConfig rssi;
  final ConnectConfig connect;

  int get effectiveEninSeconds => eninSeconds.clamp(12, 3600);
}

enum EninMode { fixedLength, beaconSlot }

class BeaconChainConfig {
  const BeaconChainConfig({
    required this.chainId,
    required this.genesisUnixSeconds,
    required this.slotSeconds,
  });

  static const ethereumMainnet = BeaconChainConfig(
    chainId: "mainnet",
    genesisUnixSeconds: 1606824023,
    slotSeconds: 12,
  );

  final String chainId;
  final int genesisUnixSeconds;
  final int slotSeconds;

  int get effectiveGenesisUnixSeconds =>
      genesisUnixSeconds < 0 ? 0 : genesisUnixSeconds;

  int get effectiveSlotSeconds => slotSeconds < 1 ? 1 : slotSeconds;

  @override
  bool operator ==(Object other) {
    return other is BeaconChainConfig &&
        other.chainId == chainId &&
        other.genesisUnixSeconds == genesisUnixSeconds &&
        other.slotSeconds == slotSeconds;
  }

  @override
  int get hashCode => Object.hash(chainId, genesisUnixSeconds, slotSeconds);
}

class ScanConfig {
  const ScanConfig({
    this.transport = TransportKind.ble,
    this.allowDuplicates = true,
  });

  final TransportKind transport;

  /// If true, the implementation may emit repeated observations for the same
  /// sender, which is useful for RSSI time-series. Implementations should still
  /// apply sampling/aggregation to remain stable.
  final bool allowDuplicates;
}

class AdvertiseConfig {
  const AdvertiseConfig({
    this.transport = TransportKind.ble,
    this.formatVersion = 1,
  });

  final TransportKind transport;
  final int formatVersion;
}

class AutoConfig {
  const AutoConfig({
    this.scan = const ScanConfig(),
    this.advertise = const AdvertiseConfig(),
  });

  final ScanConfig scan;
  final AdvertiseConfig advertise;
}

class RpidConfig {
  const RpidConfig({
    this.rotationSeconds = 600,
    this.minRotationSeconds = 60,
    this.maxRotationSeconds = 3600,
    this.epochOffsetSeconds,
  });

  final int rotationSeconds;
  final int minRotationSeconds;
  final int maxRotationSeconds;

  /// Optional per-device epoch offset to avoid synchronizing rotation boundaries.
  /// If null, the implementation may choose its own offset.
  final int? epochOffsetSeconds;
}

class RssiConfig {
  const RssiConfig({
    this.minPushIntervalMs = 1000,
    this.bufferMaxSamples = 20000,
  });

  /// Minimum interval for push events per `rpid`. Implementations may aggregate
  /// observations during the interval.
  final int minPushIntervalMs;

  /// Max number of RSSI samples to retain in memory (ring buffer).
  final int bufferMaxSamples;
}

class ConnectConfig {
  const ConnectConfig({
    this.enableGattFallback = false,
    this.maxConcurrentConnections = 1,
    this.cooldownPerPeerSeconds = 30,
    this.connectBudgetPerMinute = 30,
    this.maxConnectQueue = 20,
  });

  /// Optional fallback path. This should default to off for high-density
  /// environments.
  final bool enableGattFallback;

  final int maxConcurrentConnections;
  final int cooldownPerPeerSeconds;
  final int connectBudgetPerMinute;
  final int maxConnectQueue;
}
